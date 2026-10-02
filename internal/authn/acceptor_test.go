package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

type pipeListener struct {
	q    chan net.Conn
	done chan struct{}
	once sync.Once
}

func (p *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-p.q:
		return c, nil
	case <-p.done:
		return nil, net.ErrClosed
	}
}
func (p *pipeListener) Close() error   { p.once.Do(func() { close(p.done) }); return nil }
func (p *pipeListener) Addr() net.Addr { return pipeAddr{} }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }
func certificates(t *testing.T, now time.Time) (tls.Certificate, tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ = x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	issue := func(n int64, usage x509.ExtKeyUsage) tls.Certificate {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		leaf := &x509.Certificate{SerialNumber: big.NewInt(n), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute), DNSNames: []string{"server"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		b, e := x509.CreateCertificate(rand.Reader, leaf, ca, &k.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		return tls.Certificate{Certificate: [][]byte{b, der}, PrivateKey: k}
	}
	return issue(2, x509.ExtKeyUsageServerAuth), issue(3, x509.ExtKeyUsageClientAuth), pool
}
func fixture(t *testing.T, max int) (*Acceptor, *pipeListener, tls.Certificate, *x509.CertPool, time.Time) {
	t.Helper()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	server, client, roots := certificates(t, now)
	p := &pipeListener{q: make(chan net.Conn), done: make(chan struct{})}
	a, e := NewAcceptor(p, Config{ServerCertificate: server, ClientRoots: roots, TrustDomain: "trust.local", CredentialProfile: "client-cert", TrustRevision: 1, TrustValidFrom: now.Add(-time.Second), TrustExpiresAt: now.Add(time.Hour), SessionMaxAge: 30 * time.Second, HandshakeTimeout: time.Second, MaxHandshakes: 2, MaxSessions: max, Now: func() time.Time { return now }})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { a.Close() })
	return a, p, client, roots, now
}
func connect(t *testing.T, a *Acceptor, p *pipeListener, cert tls.Certificate, roots *x509.CertPool, now time.Time) (Accepted, error) {
	t.Helper()
	s, c := net.Pipe()
	go func() {
		select {
		case p.q <- s:
		case <-p.done:
			s.Close()
		}
	}()
	cl := tls.Client(c, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "server", Certificates: []tls.Certificate{cert}, Time: func() time.Time { return now }})
	done := make(chan error, 1)
	go func() { done <- cl.Handshake() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got, e := a.Accept(ctx)
	if e == nil {
		if ce := <-done; ce != nil {
			t.Fatal(ce)
		}
	}
	t.Cleanup(func() { c.Close() })
	return got, e
}
func TestZeroAndForeignHandleRejected(t *testing.T) {
	var zero Acceptor
	if _, e := zero.Validate(TransportHandle{}, time.Now()); e != ErrInvalid {
		t.Fatal(e)
	}
	a, p, cert, roots, now := fixture(t, 2)
	b, _, _, _, _ := fixture(t, 2)
	got, e := connect(t, a, p, cert, roots, now)
	if e != nil {
		t.Fatal(e)
	}
	projection, e := a.Validate(got.Handle(), now)
	if e != nil || projection.PrincipalID == "" || projection.ConnectionDigest == ([32]byte{}) {
		t.Fatal(projection, e)
	}
	if _, e = b.Validate(got.Handle(), now); e != ErrInvalid {
		t.Fatal(e)
	}
	got.Conn().Close()
	if _, e = a.Validate(got.Handle(), now); e != ErrInvalid {
		t.Fatal(e)
	}
}
func TestPossessionAndCapacity(t *testing.T) {
	a, p, cert, roots, now := fixture(t, 1)
	first, e := connect(t, a, p, cert, roots, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = connect(t, a, p, cert, roots, now); e != ErrBusy {
		t.Fatal(e)
	}
	first.Conn().Close()
	if _, e = connect(t, a, p, tls.Certificate{}, roots, now); e != ErrInvalid {
		t.Fatal(e)
	}
	_, _, wrong := certificates(t, now)
	if _, e = connect(t, a, p, cert, wrong, now); e != ErrInvalid {
		t.Fatal(e)
	}
}
func TestExpiryCloseCancellation(t *testing.T) {
	a, p, cert, roots, now := fixture(t, 2)
	got, e := connect(t, a, p, cert, roots, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.Validate(got.Handle(), now.Add(30*time.Second)); e != ErrInvalid {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = a.Accept(ctx); e != ErrCanceled {
		t.Fatal(e)
	}
	if _, e = a.Accept(nil); e != ErrInvalid {
		t.Fatal(e)
	}
	a.Close()
	if _, e = a.Validate(got.Handle(), now); e != ErrInvalid {
		t.Fatal(e)
	}
}
func TestOwnerClockIndependentAndPromptClose(t *testing.T) {
	a, p, cert, roots, now := fixture(t, 2)
	got, e := connect(t, a, p, cert, roots, now)
	if e != nil {
		t.Fatal(e)
	}
	a.config.Now = func() time.Time { return now.Add(time.Nanosecond) }
	if _, e = a.Validate(got.Handle(), now); e != nil {
		t.Fatal("tiny protected clock advance denies authentic handle", e)
	}
	a.config.Now = func() time.Time { return now.Add(31 * time.Second) }
	if _, e = a.Validate(got.Handle(), now); e != ErrInvalid {
		t.Fatal("backdated caller bypassed expiry", e)
	}
	start := time.Now()
	got.Conn().Close()
	if time.Since(start) > time.Second {
		t.Fatal("close waited for quiet TLS peer")
	}
}
func TestCanceledAcceptWorkerRemainsOwned(t *testing.T) {
	a, p, cert, roots, now := fixture(t, 2)
	for i := 0; i < 32; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { _, e := a.Accept(ctx); done <- e }()
		cancel()
		if e := <-done; e != ErrCanceled {
			t.Fatal(e)
		}
	}
	if _, e := connect(t, a, p, cert, roots, now); e != nil {
		t.Fatal("canceled accepts damaged listener", e)
	}
}
func TestConcurrentHandshakeCapacityAndClose(t *testing.T) {
	a, p, _, _, _ := fixture(t, 2)
	a.config.HandshakeTimeout = 5 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 2)
	clients := []net.Conn{}
	for i := 0; i < 2; i++ {
		s, c := net.Pipe()
		clients = append(clients, c)
		go func() { _, e := a.Accept(ctx); done <- e }()
		started := make(chan struct{})
		p.q <- &signalDeadlineConn{Conn: s, started: started}
		<-started
	}
	if _, e := a.Accept(context.Background()); e != ErrBusy {
		t.Fatal(e)
	}
	a.Close()
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()
	for i := 0; i < 2; i++ {
		select {
		case e := <-done:
			if e != ErrInvalid {
				t.Fatal(e)
			}
		case <-time.After(time.Second):
			t.Fatal("close failed to terminate owned handshake")
		}
	}
}

type failingDeadlineConn struct{ net.Conn }

func (failingDeadlineConn) SetDeadline(time.Time) error { return net.ErrClosed }
func TestFailedDeadlineCannotAuthenticate(t *testing.T) {
	a, p, _, _, _ := fixture(t, 1)
	s, c := net.Pipe()
	defer c.Close()
	go func() { p.q <- failingDeadlineConn{s} }()
	if _, e := a.Accept(context.Background()); e != ErrInvalid {
		t.Fatal(e)
	}
}

type signalDeadlineConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *signalDeadlineConn) SetDeadline(t time.Time) error {
	c.once.Do(func() { close(c.started) })
	return c.Conn.SetDeadline(t)
}
func TestCancellationDuringProtectedCapture(t *testing.T) {
	a, p, cert, roots, now := fixture(t, 2)
	entered, release := make(chan struct{}), make(chan struct{})
	calls := 0
	a.config.Now = func() time.Time {
		calls++
		if calls == 2 {
			close(entered)
			<-release
		}
		return now
	}
	s, c := net.Pipe()
	defer c.Close()
	go func() { p.q <- s }()
	client := tls.Client(c, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "server", Certificates: []tls.Certificate{cert}, Time: func() time.Time { return now }})
	go client.Handshake()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		got, e := a.Accept(ctx)
		if got.Conn() != nil {
			done <- ErrInvalid
		} else {
			done <- e
		}
	}()
	<-entered
	cancel()
	close(release)
	if e := <-done; e != ErrCanceled {
		t.Fatal("canceled owned capture minted a handle", e)
	}
}
func TestDefaultClockAuthenticHandle(t *testing.T) {
	now := time.Now()
	server, client, roots := certificates(t, now)
	p := &pipeListener{q: make(chan net.Conn), done: make(chan struct{})}
	a, e := NewAcceptor(p, Config{ServerCertificate: server, ClientRoots: roots, TrustDomain: "trust.local", CredentialProfile: "client-cert", TrustRevision: 1, TrustValidFrom: now.Add(-time.Second), TrustExpiresAt: now.Add(time.Hour), SessionMaxAge: 30 * time.Second, HandshakeTimeout: time.Second, MaxHandshakes: 1, MaxSessions: 1})
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	got, e := connect(t, a, p, client, roots, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.Validate(got.Handle(), time.Now()); e != nil {
		t.Fatal("default clock authentic handle denied", e)
	}
}
func TestExpiredCredentialDenied(t *testing.T) {
	a, p, cert, roots, now := fixture(t, 1)
	a.tlsConfig.Time = func() time.Time { return now.Add(2 * time.Minute) }
	if got, e := connect(t, a, p, cert, roots, now); e != ErrInvalid || got.Conn() != nil {
		t.Fatal("expired actual client certificate accepted", e)
	}
}
func TestCertificateSignatureAlgorithmsAreOwned(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	server, client, roots := certificates(t, now)
	server.SupportedSignatureAlgorithms = []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}
	p := &pipeListener{q: make(chan net.Conn), done: make(chan struct{})}
	a, e := NewAcceptor(p, Config{ServerCertificate: server, ClientRoots: roots, TrustDomain: "trust.local", CredentialProfile: "client-cert", TrustRevision: 1, TrustValidFrom: now.Add(-time.Second), TrustExpiresAt: now.Add(time.Hour), SessionMaxAge: 30 * time.Second, HandshakeTimeout: time.Second, MaxHandshakes: 1, MaxSessions: 1, Now: func() time.Time { return now }})
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	server.SupportedSignatureAlgorithms[0] = tls.PSSWithSHA256
	if got := a.tlsConfig.Certificates[0].SupportedSignatureAlgorithms[0]; got != tls.ECDSAWithP256AndSHA256 {
		t.Fatal("caller mutation changed owned TLS signature policy", got)
	}
	if _, e = connect(t, a, p, client, roots, now); e != nil {
		t.Fatal("owned signature policy failed real authentic handshake", e)
	}
}
