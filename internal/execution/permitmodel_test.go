// These synthetic fixtures transparently reuse the reviewed decision test
// composition pattern. They compile only in tests; no fixture API is exported.
package execution

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"github.com/gatekeeper454/KTP-Component-Dev/internal/action"
	"github.com/gatekeeper454/KTP-Component-Dev/internal/authn"
	"github.com/gatekeeper454/KTP-Component-Dev/internal/decision"
	"github.com/gatekeeper454/KTP-Component-Dev/internal/identity"
	"math/big"
	"net"
	"strconv"
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
func certificates(t testing.TB, now time.Time) (tls.Certificate, tls.Certificate, *x509.CertPool) {
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

type modelClock struct {
	mu sync.Mutex
	s  identity.ClockSample
}

func (c *modelClock) Sample() (identity.ClockSample, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.s, nil
}
func (c *modelClock) advance(n int64) {
	c.mu.Lock()
	c.s.WallUnixNS += n
	c.s.ElapsedNS += n
	c.mu.Unlock()
}

type identityPort struct {
	mu sync.Mutex
	n  identity.NormalizedSnapshot
}

func (p *identityPort) Read(context.Context, identity.Query) ([]byte, error) {
	return []byte("modeled"), nil
}
func (p *identityPort) Normalize(context.Context, []byte, identity.Query) (identity.NormalizedSnapshot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	b, _ := json.Marshal(p.n)
	var n identity.NormalizedSnapshot
	json.Unmarshal(b, &n)
	return n, nil
}

type permissionPort struct {
	mu             sync.Mutex
	o              decision.PermissionObservation
	e              error
	block, entered chan struct{}
}

func (p *permissionPort) Check(ctx context.Context, h identity.ActorHandle, b action.Binding) (decision.PermissionObservation, error) {
	p.mu.Lock()
	o, e, block, entered := p.o, p.e, p.block, p.entered
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
	return o, e
}

type inspectionPort struct {
	mu             sync.Mutex
	o              decision.InspectionObservation
	e              error
	block, entered chan struct{}
}

func (p *inspectionPort) Inspect(ctx context.Context, b action.Binding) (decision.InspectionObservation, error) {
	p.mu.Lock()
	o, e, block, entered := p.o, p.e, p.block, p.entered
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
	return o, e
}

type decisionFixture struct {
	validator    *decision.Validator
	config       decision.Config
	actor        identity.ActorHandle
	scope        identity.ResolveScope
	binding      action.Binding
	claims       decision.Claims
	key          ed25519.PrivateKey
	clock        *modelClock
	permission   *permissionPort
	inspection   *inspectionPort
	identityPort *identityPort
	resolver     *identity.Resolver
	accepted     authn.Accepted
}

func newDecisionFixture(t testing.TB, marker bool) *decisionFixture {
	return newDecisionFixtureWithDrift(t, marker, 0)
}
func newDecisionFixtureWithDrift(t testing.TB, marker bool, drift int64) *decisionFixture {
	t.Helper()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &modelClock{s: identity.ClockSample{WallUnixNS: now.UnixNano(), ElapsedNS: 1}}
	server, client, roots := certificates(t, now)
	p := &pipeListener{q: make(chan net.Conn), done: make(chan struct{})}
	acceptor, e := authn.NewAcceptor(p, authn.Config{ServerCertificate: server, ClientRoots: roots, TrustDomain: "trust.local", CredentialProfile: "client-cert", TrustRevision: 1, TrustValidFrom: now.Add(-time.Second), TrustExpiresAt: now.Add(time.Hour), SessionMaxAge: 30 * time.Second, HandshakeTimeout: time.Second, MaxHandshakes: 2, MaxSessions: 16, Now: func() time.Time { s, _ := clock.Sample(); return time.Unix(0, s.WallUnixNS) }})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { acceptor.Close() })
	s, c := net.Pipe()
	go func() {
		select {
		case p.q <- s:
		case <-p.done:
			s.Close()
		}
	}()
	cl := tls.Client(c, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "server", Certificates: []tls.Certificate{client}, Time: func() time.Time { return now }})
	done := make(chan error, 1)
	go func() { done <- cl.Handshake() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	accepted, e := acceptor.Accept(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	wall := now.UnixNano()
	n := identity.NormalizedSnapshot{Mappings: []identity.Mapping{{TenantID: "t-a", ActorID: "a-1", ActorKind: "workload", InstanceID: "i-1", InstancePresent: true, Granularity: "instance-required", OriginID: "o-1", Revision: 7, ContinuityEpoch: 3}}, Lifecycle: identity.Lifecycle{Enrollment: "enrolled", Authority: "enabled", CredentialState: "valid", NodeState: "active", Revision: 12, ContinuityEpoch: 3}, Origin: identity.Origin{Mode: "direct", ID: "o-1"}, FloorWitness: identity.FloorWitness{Current: true}}
	contracts := []identity.SourceContract{}
	for _, v := range []struct {
		id  string
		rev uint64
		age int64
	}{{"mapping", 7, 20e9}, {"lifecycle", 12, 5e9}, {"origin", 1, 20e9}, {"profile", 1, 20e9}} {
		d := sha256.Sum256([]byte(v.id))
		n.Sources = append(n.Sources, identity.SourceReference{ID: v.id, Kind: v.id, ContractDigest: d, EvidenceDigest: d, Revision: v.rev, ObservedUnixNS: wall, ValidatedUnixNS: wall, ValidFromUnixNS: wall - 1e9, ExpiresUnixNS: wall + 60e9, BoundID: v.id + "-age"})
		n.FloorWitness.Heads = append(n.FloorWitness.Heads, identity.Head{SourceID: v.id, Domain: v.id, TenantID: "t-a", ActorID: "a-1", Revision: v.rev, ContinuityEpoch: 3, ContentDigest: d})
		contracts = append(contracts, identity.SourceContract{ID: v.id, BoundID: v.id + "-age", ContractDigest: d, MaxAgeNS: v.age})
	}
	port := &identityPort{n: n}
	operation := "lab.read_status"
	if marker {
		operation = "lab.set_marker"
	}
	resolver, e := identity.NewResolver(identity.Config{Acceptor: acceptor, Source: port, Verifier: port, Clock: clock, Registration: identity.Registration{Lane: identity.Modeled, Sources: contracts, ProfileDigest: sha256.Sum256([]byte("profile"))}, Profiles: []identity.OperationProfile{{OperationID: operation, AudienceID: action.TargetID, Granularity: "instance-required", HumanApplicability: "forbidden"}}, MaxSourceCalls: 8, MaxHandles: 32, MaxHeads: 32, MaxTombstones: 32, SourceTimeout: time.Second, MaxClockDriftNS: drift})
	if e != nil {
		t.Fatal(e)
	}
	_, a := localBinding(t, marker, hash(7), wall)
	scope, e := identity.NewResolveScope(a, action.TargetID)
	if e != nil {
		t.Fatal(e)
	}
	actor, e := resolver.Resolve(context.Background(), accepted.Handle(), scope)
	if e != nil {
		t.Fatal(e)
	}
	projection, e := actor.Projection()
	if e != nil {
		t.Fatal(e)
	}
	binding, _ := localBinding(t, marker, projection.IdentityProjectionDigest, wall)
	v, _ := binding.View()
	claims := decision.Claims{ProducerID: "producer-01", ProfileID: decision.ProfileID, ResultKind: "final", ResultID: "result-01", BindingDigest: binding.Digest(), OperationDigest: v.OperationDigest, IdentityProjectionDigest: v.IdentityProjectionDigest, ActorID: v.ActorID, TenantID: v.TenantID, InstanceID: v.InstanceID, ZoneID: v.ZoneID, AudienceID: v.AudienceID, ReplayID: v.ReplayID, CatalogDigest: v.CatalogDigest, PolicyDigest: v.PolicyDigest, GatewayBuildDigest: v.GatewayBuildDigest, ProtectedConfigDigest: v.ProtectedConfigDigest, TargetBuildDigest: v.TargetBuildDigest, TargetContractDigest: v.TargetContractDigest, DecisionProfileDigest: v.DecisionProfileDigest, IssuedAtUnixNS: wall, ExpiresUnixNS: wall + 3e9, Outcome: "allow", CapacityKnown: true, EffectiveCapacity: 1, Tier: "Observer", Supervision: "stable", Magnitude: "fixture-effects", Unit: "effects", ConstraintCeiling: 1}
	if marker {
		claims.AutonomyDemand = 1
		claims.Tier = "Operator"
		claims.AllowedMarkers = 3
	}
	permission := &permissionPort{o: decision.PermissionObservation{SourceID: "permission-01", ContractDigest: hash(8), EvidenceDigest: hash(9), ActorID: v.ActorID, TenantID: v.TenantID, IdentityProjectionDigest: v.IdentityProjectionDigest, BindingDigest: binding.Digest(), OperationDigest: v.OperationDigest, ObservedAtUnixNS: wall, ExpiresUnixNS: wall + 3e9, Outcome: "allowed", AllowedMarkers: claims.AllowedMarkers}}
	inspection := &inspectionPort{o: decision.InspectionObservation{SourceID: "inspection-01", ContractDigest: hash(10), EvidenceDigest: hash(11), BindingDigest: binding.Digest(), OperationDigest: v.OperationDigest, ObservedAtUnixNS: wall, ExpiresUnixNS: wall + 3e9, Outcome: "allowed"}}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	cfg := decision.Config{Resolver: resolver, Inspector: inspection, PermissionSource: permission, Clock: clock, EvidenceLane: identity.Modeled, ProducerID: "producer-01", PublicKey: pub, ProfileDigest: hash(6), InspectorID: "inspection-01", InspectorContractDigest: hash(10), PermissionID: "permission-01", PermissionContractDigest: hash(8), MaxPermissionAge: 2 * time.Second, MaxInspectionAge: 2 * time.Second, MaxProofAge: 3 * time.Second, SourceTimeout: time.Second, MaxCalls: 8}
	validator, e := decision.NewValidator(cfg)
	if e != nil {
		t.Fatal(e)
	}
	return &decisionFixture{validator, cfg, actor, scope, binding, claims, key, clock, permission, inspection, port, resolver, accepted}
}
func (f *decisionFixture) signed(t testing.TB) decision.SignedResult {
	t.Helper()
	p, e := decision.EncodeClaims(f.claims)
	if e != nil {
		t.Fatal(e)
	}
	return decision.SignedResult{Payload: p, Signature: ed25519.Sign(f.key, p)}
}

func hash(b byte) (d [32]byte) {
	for i := range d {
		d[i] = b
	}
	return
}
func localBinding(t testing.TB, marker bool, identityDigest [32]byte, wall int64) (action.Binding, action.ParsedAction) {
	t.Helper()
	tool, raw := "lab.read_status", []byte("{}")
	if marker {
		tool = "lab.set_marker"
		raw = []byte(`{"marker":"set","expected_version":"7"}`)
	}
	a, e := action.ParseMCPArguments(tool, raw)
	if e != nil {
		t.Fatal(e)
	}
	g, _ := action.NewIdentityGranularityProfile("instance-required")
	target, _ := action.NewTenantTargetProjection("t-a", "z-1", action.TargetID, action.TargetID)
	b, e := action.Bind(a, action.BindingContext{SchemaVersion: action.SchemaVersion, CatalogID: action.CatalogID, CatalogVersion: action.CatalogVersion, CatalogDigest: action.CatalogDigest(), PolicyDigest: hash(1), GatewayBuildDigest: hash(2), ProtectedConfigDigest: hash(3), TargetBuildDigest: hash(4), TargetContractDigest: hash(5), DecisionProfileDigest: hash(6), ActorID: "a-1", TenantID: "t-a", InstanceID: "i-1", IdentityProjectionDigest: identityDigest, IdentityGranularity: g, ZoneID: "z-1", AudienceID: action.TargetID, TenantTarget: target, TargetVersion: "7", ReplayID: "0123456789abcdef0123456789abcdef", ValidFromUnixNS: strconv.FormatInt(wall-1e9, 10), ExpiresUnixNS: strconv.FormatInt(wall+4e9, 10)})
	if e != nil {
		t.Fatal(e)
	}
	return b, a
}
