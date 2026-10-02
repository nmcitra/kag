package authn

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

const transportRegressionTimeout = 5 * time.Second

type transportRegressionTask struct {
	done chan struct{}
	err  error
}

func startTransportRegressionTask(fn func() error) *transportRegressionTask {
	task := &transportRegressionTask{done: make(chan struct{})}
	go func() {
		defer close(task.done)
		task.err = fn()
	}()
	return task
}

func waitTransportRegressionTask(t *testing.T, task *transportRegressionTask) error {
	t.Helper()
	select {
	case <-task.done:
		return task.err
	case <-time.After(transportRegressionTimeout):
		t.Fatal("transport regression goroutine did not terminate")
		return nil
	}
}

func transportRegressionFixture(t *testing.T) (*Acceptor, *pipeListener, tls.Certificate, *x509.CertPool, time.Time) {
	t.Helper()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	server, client, roots := certificates(t, now)
	p := &pipeListener{q: make(chan net.Conn), done: make(chan struct{})}
	a, err := NewAcceptor(p, Config{
		ServerCertificate: server, ClientRoots: roots,
		TrustDomain: "trust.local", CredentialProfile: "client-cert", TrustRevision: 1,
		TrustValidFrom: now.Add(-time.Second), TrustExpiresAt: now.Add(time.Hour),
		SessionMaxAge: 30 * time.Second, HandshakeTimeout: transportRegressionTimeout,
		MaxHandshakes: 1, MaxSessions: 1, Now: func() time.Time { return now },
	})
	if err != nil {
		p.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	return a, p, client, roots, now
}

// Both endpoints and the client handshake remain owned even on rejected admission.
func transportRegressionConnect(t *testing.T, a *Acceptor, p *pipeListener, cert tls.Certificate, roots *x509.CertPool, now time.Time, wrap func(net.Conn) net.Conn, drainRejectedAlert bool) (Accepted, *tls.Conn, error) {
	t.Helper()
	serverRaw, clientRaw := net.Pipe()
	deadline := time.Now().Add(transportRegressionTimeout)
	if err := clientRaw.SetDeadline(deadline); err != nil {
		serverRaw.Close()
		clientRaw.Close()
		t.Fatal(err)
	}
	clientTransport := clientRaw
	if wrap != nil {
		clientTransport = wrap(clientRaw)
	}
	client := tls.Client(clientTransport, &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "server",
		Certificates: []tls.Certificate{cert}, Time: func() time.Time { return now },
	})
	handshake := startTransportRegressionTask(func() error {
		err := client.Handshake()
		if err == nil && drainRejectedAlert {
			// A TLS 1.3 client may finish before the server rejects its signature.
			// Read the rejection alert so its write cannot block on net.Pipe.
			_, err = client.Read(make([]byte, 1))
		}
		return err
	})
	t.Cleanup(func() {
		serverRaw.Close()
		clientRaw.Close()
		waitTransportRegressionTask(t, handshake)
	})
	ctx, cancel := context.WithTimeout(context.Background(), transportRegressionTimeout)
	defer cancel()
	select {
	case p.q <- serverRaw:
	case <-ctx.Done():
		t.Fatal("listener did not consume synthetic connection", ctx.Err())
	}
	got, err := a.Accept(ctx)
	if err != nil {
		serverRaw.Close()
		clientRaw.Close()
	}
	clientErr := waitTransportRegressionTask(t, handshake)
	if err == nil && clientErr != nil {
		t.Fatal("server admitted a connection whose client handshake failed", clientErr)
	}
	return got, client, err
}

func transportRegressionValidate(t *testing.T, a *Acceptor, got Accepted, now time.Time) {
	t.Helper()
	if got.Conn() == nil {
		t.Fatal("authentic admission returned no connection")
	}
	if _, err := a.Validate(got.Handle(), now); err != nil {
		t.Fatal("authentic transport handle denied", err)
	}
}

func transportRegressionReject(t *testing.T, a *Acceptor, got Accepted, err error, expected error, now time.Time) {
	t.Helper()
	if err != expected || got.Conn() != nil {
		t.Fatalf("rejected admission: error=%v connection=%v; want %v and nil", err, got.Conn(), expected)
	}
	if _, validationErr := a.Validate(got.Handle(), now); validationErr != ErrInvalid {
		t.Fatal("rejected admission returned a valid handle", validationErr)
	}
}

func TestSpoofedCertificatePrivateKeyRejectedAndRecovery(t *testing.T) {
	a, p, cert, roots, now := transportRegressionFixture(t)
	_, other, _ := certificates(t, now)
	spoofed := cert
	spoofed.PrivateKey = other.PrivateKey
	got, _, err := transportRegressionConnect(t, a, p, spoofed, roots, now, nil, true)
	transportRegressionReject(t, a, got, err, ErrInvalid, now)

	recovered, _, err := transportRegressionConnect(t, a, p, cert, roots, now, nil, false)
	if err != nil {
		t.Fatal("spoofed handshake retained admission capacity", err)
	}
	transportRegressionValidate(t, a, recovered, now)
}

type transportRegressionTamperConn struct {
	net.Conn
	armed    atomic.Bool
	tampered atomic.Int32
}

func (c *transportRegressionTamperConn) Write(b []byte) (int, error) {
	// TLS 1.3 application records use content type 23. Leave handshake bytes intact.
	if len(b) > 5 && b[0] == 23 && c.armed.CompareAndSwap(true, false) {
		b = append([]byte(nil), b...)
		b[len(b)-1] ^= 1
		c.tampered.Add(1)
	}
	return c.Conn.Write(b)
}

func transportRegressionExchange(t *testing.T, server net.Conn, client *tls.Conn, payload []byte) {
	t.Helper()
	deadline := time.Now().Add(transportRegressionTimeout)
	if err := server.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := client.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	write := startTransportRegressionTask(func() error {
		n, err := client.Write(payload)
		if err == nil && n != len(payload) {
			return Error("transport_regression_short_write")
		}
		return err
	})
	t.Cleanup(func() {
		server.Close()
		client.NetConn().Close()
		waitTransportRegressionTask(t, write)
	})
	buf := make([]byte, len(payload)+1)
	n, err := server.Read(buf)
	writeErr := waitTransportRegressionTask(t, write)
	if err != nil || writeErr != nil || !bytes.Equal(buf[:n], payload) {
		t.Fatalf("authentic TLS exchange: plaintext=%q read=%v write=%v", buf[:n], err, writeErr)
	}
}

func TestTamperedTLSRecordInvalidatesHandleAndReleasesSession(t *testing.T) {
	a, p, cert, roots, now := transportRegressionFixture(t)
	var tamper *transportRegressionTamperConn
	got, client, err := transportRegressionConnect(t, a, p, cert, roots, now, func(raw net.Conn) net.Conn {
		tamper = &transportRegressionTamperConn{Conn: raw}
		return tamper
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	transportRegressionValidate(t, a, got, now)
	transportRegressionExchange(t, got.Conn(), client, []byte("authentic positive control"))
	transportRegressionValidate(t, a, got, now)

	// The peer reads the alert concurrently, preventing net.Pipe alert writes from blocking.
	tamper.armed.Store(true)
	peerRead := startTransportRegressionTask(func() error {
		_, err := client.Read(make([]byte, 64))
		return err
	})
	peerWrite := startTransportRegressionTask(func() error {
		_, err := client.Write([]byte("must never become accepted plaintext"))
		return err
	})
	t.Cleanup(func() {
		got.Conn().Close()
		client.NetConn().Close()
		waitTransportRegressionTask(t, peerWrite)
		waitTransportRegressionTask(t, peerRead)
	})
	buf := make([]byte, 64)
	n, readErr := got.Conn().Read(buf)
	writeErr := waitTransportRegressionTask(t, peerWrite)
	alertErr := waitTransportRegressionTask(t, peerRead)
	if tamper.tampered.Load() != 1 {
		t.Fatal("test did not corrupt exactly one encrypted TLS record")
	}
	if n != 0 || readErr == nil {
		t.Fatalf("corrupted record yielded plaintext=%q error=%v", buf[:n], readErr)
	}
	if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
		t.Fatal("corrupted record was not rejected before the I/O deadline", readErr)
	}
	if writeErr != nil || alertErr == nil {
		t.Fatalf("corrupted record was not delivered and rejected: write=%v peer read=%v", writeErr, alertErr)
	}
	if _, err := a.Validate(got.Handle(), now); err != ErrInvalid {
		t.Fatal("corrupted transport retained handle authority", err)
	}

	recovered, recoveredClient, err := transportRegressionConnect(t, a, p, cert, roots, now, nil, false)
	if err != nil {
		t.Fatal("corrupted transport retained session admission capacity", err)
	}
	transportRegressionValidate(t, a, recovered, now)
	transportRegressionExchange(t, recovered.Conn(), recoveredClient, []byte("recovered positive control"))
}

func TestCanceledActiveHandshakeReleasesSlotAndRecovers(t *testing.T) {
	a, p, cert, roots, now := transportRegressionFixture(t)
	serverRaw, clientRaw := net.Pipe()
	if err := clientRaw.SetDeadline(time.Now().Add(transportRegressionTimeout)); err != nil {
		serverRaw.Close()
		clientRaw.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), transportRegressionTimeout)
	started := make(chan struct{})
	var canceled Accepted
	accept := startTransportRegressionTask(func() error {
		var err error
		canceled, err = a.Accept(ctx)
		return err
	})
	t.Cleanup(func() {
		cancel()
		serverRaw.Close()
		clientRaw.Close()
		waitTransportRegressionTask(t, accept)
	})
	select {
	case p.q <- &signalDeadlineConn{Conn: serverRaw, started: started}:
	case <-ctx.Done():
		t.Fatal("listener did not consume silent peer", ctx.Err())
	}
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("silent peer did not enter active handshake", ctx.Err())
	}
	busy, err := a.Accept(ctx)
	transportRegressionReject(t, a, busy, err, ErrBusy, now)
	cancel()
	err = waitTransportRegressionTask(t, accept)
	transportRegressionReject(t, a, canceled, err, ErrCanceled, now)
	if _, err := clientRaw.Read(make([]byte, 1)); err == nil {
		t.Fatal("canceled handshake did not close its raw transport")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("canceled raw transport remained open until its deadline", err)
	}

	recovered, _, err := transportRegressionConnect(t, a, p, cert, roots, now, nil, false)
	if err != nil {
		t.Fatal("canceled active handshake retained admission capacity", err)
	}
	transportRegressionValidate(t, a, recovered, now)
}
