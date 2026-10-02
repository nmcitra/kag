package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/gatekeeper454/KTP-Component-Dev/internal/action"
	"github.com/gatekeeper454/KTP-Component-Dev/internal/authn"
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
func fixture(t *testing.T, max int) (*authn.Acceptor, *pipeListener, tls.Certificate, *x509.CertPool, time.Time) {
	t.Helper()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	server, client, roots := certificates(t, now)
	p := &pipeListener{q: make(chan net.Conn), done: make(chan struct{})}
	a, e := authn.NewAcceptor(p, authn.Config{ServerCertificate: server, ClientRoots: roots, TrustDomain: "trust.local", CredentialProfile: "client-cert", TrustRevision: 1, TrustValidFrom: now.Add(-time.Second), TrustExpiresAt: now.Add(time.Hour), SessionMaxAge: 30 * time.Second, HandshakeTimeout: time.Second, MaxHandshakes: 2, MaxSessions: max, Now: func() time.Time { return now }})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { a.Close() })
	return a, p, client, roots, now
}
func connect(t *testing.T, a *authn.Acceptor, p *pipeListener, cert tls.Certificate, roots *x509.CertPool, now time.Time) (authn.Accepted, error) {
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

type modelClock struct {
	mu sync.Mutex
	s  ClockSample
}

func (c *modelClock) Sample() (ClockSample, error) { c.mu.Lock(); defer c.mu.Unlock(); return c.s, nil }

type modelPort struct {
	mu              sync.Mutex
	n               NormalizedSnapshot
	reads, verifies int
	raw             []byte
	block           chan struct{}
	entered         chan struct{}
}

func (p *modelPort) Read(ctx context.Context, q Query) ([]byte, error) {
	p.mu.Lock()
	p.reads++
	b := append([]byte(nil), p.raw...)
	block, entered := p.block, p.entered
	p.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if block != nil {
		<-block
	}
	return b, nil
}
func (p *modelPort) Normalize(ctx context.Context, b []byte, q Query) (NormalizedSnapshot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.verifies++
	n := clone(p.n)
	if n.Origin.Mode == "terminated" {
		n.Origin.BrokerConnectionDigest = q.ConnectionDigest
		n.Origin.OriginalIntentDigest = q.IntentDigest
		for i := range n.Delegation {
			n.Delegation[i].BrokerConnectionDigest = q.ConnectionDigest
			n.Delegation[i].OriginalIntentDigest = q.IntentDigest
		}
	}
	return n, nil
}
func identityFixture(t *testing.T) (*Resolver, *modelPort, *modelClock, authn.TransportHandle, ResolveScope) {
	t.Helper()
	a, p, cert, roots, now := fixture(t, 16)
	accepted, e := connect(t, a, p, cert, roots, now)
	if e != nil {
		t.Fatal(e)
	}
	clock := &modelClock{s: ClockSample{WallUnixNS: now.UnixNano(), ElapsedNS: 1}}
	wall := clock.s.WallUnixNS
	n := NormalizedSnapshot{Mappings: []Mapping{{TenantID: "t-a", ActorID: "a-1", ActorKind: "workload-level", InstanceID: "i-1", InstancePresent: true, Granularity: "instance-required", OriginID: "o-1", Revision: 7, ContinuityEpoch: 3}}, Lifecycle: Lifecycle{Enrollment: "enrolled", Authority: "enabled", CredentialState: "valid", NodeState: "active", Revision: 12, ContinuityEpoch: 3}, Origin: Origin{Mode: "direct", ID: "o-1"}, FloorWitness: FloorWitness{Current: true}}
	contracts := []SourceContract{}
	for _, v := range []struct {
		id, kind string
		rev      uint64
		age      int64
	}{{"mapping", "mapping", 7, 20e9}, {"lifecycle", "lifecycle", 12, 5e9}, {"origin", "origin", 1, 20e9}, {"profile", "profile", 1, 20e9}} {
		d := sha256.Sum256([]byte(v.id))
		n.Sources = append(n.Sources, SourceReference{ID: v.id, Kind: v.kind, ContractDigest: d, EvidenceDigest: d, Revision: v.rev, ObservedUnixNS: wall, ValidatedUnixNS: wall, ValidFromUnixNS: wall - 1e9, ExpiresUnixNS: wall + 60e9, BoundID: v.id + "-age"})
		n.FloorWitness.Heads = append(n.FloorWitness.Heads, Head{SourceID: v.id, Domain: v.kind, TenantID: "t-a", ActorID: "a-1", Revision: v.rev, ContinuityEpoch: 3, ContentDigest: d})
		contracts = append(contracts, SourceContract{ID: v.id, BoundID: v.id + "-age", ContractDigest: d, MaxAgeNS: v.age})
	}
	port := &modelPort{n: n, raw: []byte("snapshot")}
	r, e := NewResolver(Config{Acceptor: a, Source: port, Verifier: port, Clock: clock, Registration: Registration{Lane: Modeled, Sources: contracts, ProfileDigest: sha256.Sum256([]byte("profile"))}, Profiles: []OperationProfile{{OperationID: "lab.read_status", AudienceID: action.TargetID, Granularity: "instance-required", HumanApplicability: "forbidden"}}, MaxSourceCalls: 2, MaxHandles: 16, MaxHeads: 16, MaxTombstones: 16, SourceTimeout: time.Second, MaxClockDriftNS: 0})
	if e != nil {
		t.Fatal(e)
	}
	act, e := action.ParseMCPArguments("lab.read_status", []byte("{}"))
	if e != nil {
		t.Fatal(e)
	}
	scope, e := NewResolveScope(act, action.TargetID)
	if e != nil {
		t.Fatal(e)
	}
	return r, port, clock, accepted.Handle(), scope
}
func zeroTransport() authn.TransportHandle { return authn.TransportHandle{} }
