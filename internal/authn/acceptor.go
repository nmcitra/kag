// Package authn owns TLS possession capture. Its handles cannot be restored from records.
package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"math"
	"net"
	"sync"
	"time"
)

type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrInvalid          Error = "transport_invalid"
	ErrBusy             Error = "transport_busy"
	ErrCanceled         Error = "transport_canceled"
	ErrDeadlineExceeded Error = "transport_deadline_exceeded"
)

type Config struct {
	ServerCertificate               tls.Certificate
	ClientRoots                     *x509.CertPool
	TrustDomain, CredentialProfile  string
	TrustRevision                   uint64
	TrustValidFrom, TrustExpiresAt  time.Time
	SessionMaxAge, HandshakeTimeout time.Duration
	MaxHandshakes, MaxSessions      int
	Now                             func() time.Time
}
type TransportProjection struct {
	TrustDomain, CredentialProfile, PrincipalID                                                                  string
	CredentialDigest, ConnectionDigest                                                                           [32]byte
	TrustRevision                                                                                                uint64
	AuthenticatedUnixNS, CredentialExpiresUnixNS, SessionExpiresUnixNS, TrustValidFromUnixNS, TrustExpiresUnixNS int64
}
type TransportHandle struct{ state *transportState }
type transportState struct {
	owner      *Acceptor
	conn       *ownedConn
	projection TransportProjection
	valid      bool
}
type Accepted struct {
	conn   net.Conn
	handle TransportHandle
}

func (a Accepted) Conn() net.Conn          { return a.conn }
func (a Accepted) Handle() TransportHandle { return a.handle }

type Acceptor struct {
	mu           sync.Mutex
	listener     net.Listener
	config       Config
	tlsConfig    *tls.Config
	closed       bool
	sessions     map[*transportState]struct{}
	pending      map[net.Conn]struct{}
	handshakes   chan struct{}
	accepted     chan net.Conn
	done, joined chan struct{}
}

func nanos(t time.Time) (int64, bool) {
	s := t.Unix()
	if s < 0 || s > math.MaxInt64/1000000000 {
		return 0, false
	}
	n := int64(t.Nanosecond())
	if s == math.MaxInt64/1000000000 && n > math.MaxInt64%1000000000 {
		return 0, false
	}
	return s*1000000000 + n, true
}
func NewAcceptor(l net.Listener, c Config) (*Acceptor, error) {
	if c.Now == nil {
		c.Now = time.Now
	}
	now, ok := nanos(c.Now())
	from, fok := nanos(c.TrustValidFrom)
	to, tok := nanos(c.TrustExpiresAt)
	if l == nil || !ok || !fok || !tok || from <= 0 || now < from || now >= to || c.ClientRoots == nil || len(c.ClientRoots.Subjects()) == 0 || len(c.ServerCertificate.Certificate) == 0 || c.ServerCertificate.PrivateKey == nil || c.TrustDomain == "" || len(c.TrustDomain) > 128 || c.CredentialProfile == "" || len(c.CredentialProfile) > 128 || c.TrustRevision == 0 || c.SessionMaxAge <= 0 || c.SessionMaxAge > time.Duration(math.MaxInt64-now) || c.HandshakeTimeout <= 0 || c.MaxHandshakes < 1 || c.MaxHandshakes > 64 || c.MaxSessions < 1 || c.MaxSessions > 4096 {
		return nil, ErrInvalid
	}
	c.ClientRoots = c.ClientRoots.Clone()
	cert := c.ServerCertificate
	cert.SupportedSignatureAlgorithms = append([]tls.SignatureScheme(nil), cert.SupportedSignatureAlgorithms...)
	cert.Certificate = append([][]byte(nil), cert.Certificate...)
	for i, b := range cert.Certificate {
		cert.Certificate[i] = append([]byte(nil), b...)
	}
	cert.OCSPStaple = append([]byte(nil), cert.OCSPStaple...)
	cert.SignedCertificateTimestamps = append([][]byte(nil), cert.SignedCertificateTimestamps...)
	for i, b := range cert.SignedCertificateTimestamps {
		cert.SignedCertificateTimestamps[i] = append([]byte(nil), b...)
	}
	cert.Leaf = nil
	c.ServerCertificate = cert
	a := &Acceptor{listener: l, config: c, sessions: make(map[*transportState]struct{}), pending: make(map[net.Conn]struct{}), handshakes: make(chan struct{}, c.MaxHandshakes), accepted: make(chan net.Conn, 1), done: make(chan struct{}), joined: make(chan struct{})}
	a.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: c.ClientRoots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true, Time: c.Now}
	go a.worker()
	return a, nil
}
func (a *Acceptor) worker() {
	defer close(a.joined)
	defer close(a.accepted)
	for {
		c, e := a.listener.Accept()
		if e != nil {
			return
		}
		select {
		case a.accepted <- c:
		case <-a.done:
			c.Close()
			return
		}
	}
}
func contextError(ctx context.Context) error {
	if ctx.Err() == context.DeadlineExceeded {
		return ErrDeadlineExceeded
	}
	return ErrCanceled
}
func (a *Acceptor) Accept(ctx context.Context) (Accepted, error) {
	if a == nil || a.done == nil || ctx == nil {
		return Accepted{}, ErrInvalid
	}
	if ctx.Err() != nil {
		return Accepted{}, contextError(ctx)
	}
	select {
	case <-a.done:
		return Accepted{}, ErrInvalid
	default:
	}
	select {
	case a.handshakes <- struct{}{}:
	default:
		return Accepted{}, ErrBusy
	}
	defer func() { <-a.handshakes }()
	var raw net.Conn
	select {
	case raw = <-a.accepted:
		if raw == nil {
			return Accepted{}, ErrInvalid
		}
	case <-ctx.Done():
		return Accepted{}, contextError(ctx)
	case <-a.done:
		return Accepted{}, ErrInvalid
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		raw.Close()
		return Accepted{}, ErrInvalid
	}
	a.pending[raw] = struct{}{}
	nowBefore, validBefore := nanos(a.config.Now())
	detached := a.pruneLocked(nowBefore)
	full := len(a.sessions) >= a.config.MaxSessions
	a.mu.Unlock()
	for _, c := range detached {
		c.Close()
	}
	defer func() { a.mu.Lock(); delete(a.pending, raw); a.mu.Unlock() }()
	failed := true
	defer func() {
		if failed {
			raw.Close()
		}
	}()
	if !validBefore {
		return Accepted{}, ErrInvalid
	}
	if full {
		return Accepted{}, ErrBusy
	}
	deadline := time.Now().Add(a.config.HandshakeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if e := raw.SetDeadline(deadline); e != nil {
		return Accepted{}, ErrInvalid
	}
	handshakeCtx, cancelHandshake := context.WithTimeout(ctx, a.config.HandshakeTimeout)
	defer cancelHandshake()
	stop := context.AfterFunc(handshakeCtx, func() { raw.Close() })
	conn := tls.Server(raw, a.tlsConfig)
	handshakeErr := conn.HandshakeContext(handshakeCtx)
	stop()
	if handshakeErr != nil || handshakeCtx.Err() != nil {
		if ctx.Err() != nil {
			return Accepted{}, contextError(ctx)
		}
		return Accepted{}, ErrInvalid
	}
	if e := raw.SetDeadline(time.Time{}); e != nil {
		return Accepted{}, ErrInvalid
	}
	if ctx.Err() != nil {
		return Accepted{}, contextError(ctx)
	}
	cs := conn.ConnectionState()
	if cs.Version != tls.VersionTLS13 || len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 {
		return Accepted{}, ErrInvalid
	}
	now, ok := nanos(a.config.Now())
	from, _ := nanos(a.config.TrustValidFrom)
	to, _ := nanos(a.config.TrustExpiresAt)
	if !ok || now < from || now >= to || int64(a.config.SessionMaxAge) > math.MaxInt64-now {
		return Accepted{}, ErrInvalid
	}
	expiry := int64(math.MaxInt64)
	for _, chain := range cs.VerifiedChains {
		for _, cert := range chain {
			end, valid := nanos(cert.NotAfter)
			if !valid {
				return Accepted{}, ErrInvalid
			}
			if end < expiry {
				expiry = end
			}
		}
	}
	if now >= expiry {
		return Accepted{}, ErrInvalid
	}
	digest := sha256.Sum256(cs.PeerCertificates[0].Raw)
	p := TransportProjection{TrustDomain: a.config.TrustDomain, CredentialProfile: a.config.CredentialProfile, PrincipalID: "cert-sha256:" + hex.EncodeToString(digest[:]), CredentialDigest: digest, TrustRevision: a.config.TrustRevision, AuthenticatedUnixNS: now, CredentialExpiresUnixNS: expiry, SessionExpiresUnixNS: now + int64(a.config.SessionMaxAge), TrustValidFromUnixNS: from, TrustExpiresUnixNS: to}
	var nonce [32]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return Accepted{}, ErrInvalid
	}
	p.ConnectionDigest = sha256.Sum256(nonce[:])
	state := &transportState{owner: a, projection: p, valid: true}
	wrapped := &ownedConn{Conn: conn, state: state, raw: raw}
	state.conn = wrapped
	a.mu.Lock()
	if ctx.Err() != nil {
		a.mu.Unlock()
		return Accepted{}, contextError(ctx)
	}
	current, currentOK := nanos(a.config.Now())
	if !currentOK || current < now || current >= p.CredentialExpiresUnixNS || current >= p.SessionExpiresUnixNS || current >= p.TrustExpiresUnixNS {
		a.mu.Unlock()
		return Accepted{}, ErrInvalid
	}
	if ctx.Err() != nil {
		a.mu.Unlock()
		return Accepted{}, contextError(ctx)
	}

	if a.closed {
		a.mu.Unlock()
		return Accepted{}, ErrInvalid
	}
	detached = a.pruneLocked(now)
	if len(a.sessions) >= a.config.MaxSessions {
		a.mu.Unlock()
		for _, c := range detached {
			c.Close()
		}
		return Accepted{}, ErrBusy
	}
	a.sessions[state] = struct{}{}
	a.mu.Unlock()
	for _, c := range detached {
		c.Close()
	}
	failed = false
	return Accepted{wrapped, TransportHandle{state}}, nil
}
func (a *Acceptor) Validate(h TransportHandle, at time.Time) (TransportProjection, error) {
	if a == nil || a.done == nil || h.state == nil {
		return TransportProjection{}, ErrInvalid
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s := h.state
	now, ok := nanos(at)
	actual, aok := nanos(a.config.Now())
	_, present := a.sessions[s]
	if !ok || !aok || a.closed || s.owner != a || !present || !s.valid || now < s.projection.AuthenticatedUnixNS || now < s.projection.TrustValidFromUnixNS || now >= s.projection.CredentialExpiresUnixNS || now >= s.projection.SessionExpiresUnixNS || now >= s.projection.TrustExpiresUnixNS || actual < s.projection.AuthenticatedUnixNS || actual < s.projection.TrustValidFromUnixNS || actual >= s.projection.CredentialExpiresUnixNS || actual >= s.projection.SessionExpiresUnixNS || actual >= s.projection.TrustExpiresUnixNS {
		return TransportProjection{}, ErrInvalid
	}
	return s.projection, nil
}
func (a *Acceptor) Close() error {
	if a == nil || a.done == nil {
		return nil
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	close(a.done)
	raws := make([]net.Conn, 0, len(a.sessions)+len(a.pending))
	for s := range a.sessions {
		s.valid = false
		raws = append(raws, s.conn.raw)
		delete(a.sessions, s)
	}
	for c := range a.pending {
		raws = append(raws, c)
	}
	a.mu.Unlock()
	for _, c := range raws {
		c.Close()
	}
	e := a.listener.Close()
	<-a.joined
	for c := range a.accepted {
		c.Close()
	}
	return e
}

type ownedConn struct {
	net.Conn
	state *transportState
	raw   net.Conn
}

func (c *ownedConn) invalidate() {
	a := c.state.owner
	a.mu.Lock()
	c.state.valid = false
	delete(a.sessions, c.state)
	a.mu.Unlock()
}
func (c *ownedConn) Close() error { c.invalidate(); return c.raw.Close() }
func (c *ownedConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	if e != nil {
		if ne, ok := e.(net.Error); !ok || !ne.Timeout() {
			c.invalidate()
			c.raw.Close()
		}
	}
	return n, e
}
func (c *ownedConn) Write(b []byte) (int, error) {
	n, e := c.Conn.Write(b)
	if e != nil {
		if ne, ok := e.(net.Error); !ok || !ne.Timeout() {
			c.invalidate()
			c.raw.Close()
		}
	}
	return n, e
}

// pruneLocked detaches authority under the mutex; callers close raw transports outside it.
func (a *Acceptor) pruneLocked(now int64) []net.Conn {
	var raws []net.Conn
	for s := range a.sessions {
		if !s.valid || now >= s.projection.SessionExpiresUnixNS || now >= s.projection.CredentialExpiresUnixNS || now >= s.projection.TrustExpiresUnixNS {
			s.valid = false
			delete(a.sessions, s)
			raws = append(raws, s.conn.raw)
		}
	}
	return raws
}
