package identity

import (
	"context"
	"crypto/sha256"
	"github.com/gatekeeper454/KTP-Component-Dev/internal/action"
	"github.com/gatekeeper454/KTP-Component-Dev/internal/authn"
	"math"
	"sort"
	"sync"
	"time"
)

type actorKey struct{ tenant, actor string }
type headKey struct{ source, domain, tenant, actor string }
type storedHead struct {
	head     Head
	semantic [32]byte
}
type actorState struct {
	owner         *Resolver
	transport     authn.TransportHandle
	scope         ScopeProjection
	projection    BindingProjection
	key           actorKey
	generation    uint64
	elapsedExpiry int64
	snapshot      []byte

	valid bool
}
type Resolver struct {
	capacityFailed              bool
	probe                       authn.TransportHandle
	mu                          sync.Mutex
	config                      Config
	contracts                   map[string]SourceContract
	profiles                    map[string]OperationProfile
	calls                       chan struct{}
	handles                     map[*actorState]struct{}
	heads                       map[headKey]storedHead
	tombstones                  map[actorKey]Head
	generations                 map[actorKey]uint64
	baseline, last              ClockSample
	clockFailed, restored, held bool
}

func validID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for i, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			continue
		}
		if i > 0 && (c == '.' || c == '_' || c == ':' || c == '-') {
			continue
		}
		return false
	}
	return true
}
func nonzero(d [32]byte) bool { return d != ([32]byte{}) }
func NewResolver(c Config) (*Resolver, error) {
	if c.Acceptor == nil || c.Source == nil || c.Verifier == nil || c.Clock == nil || c.Registration.Lane != Modeled || !nonzero(c.Registration.ProfileDigest) || len(c.Registration.Sources) < 1 || len(c.Registration.Sources) > 8 || len(c.Profiles) < 1 || len(c.Profiles) > 2 || c.MaxSourceCalls < 1 || c.MaxSourceCalls > 64 || c.MaxHandles < 1 || c.MaxHandles > 4096 || c.MaxHeads < 1 || c.MaxHeads > 4096 || c.MaxTombstones < 1 || c.MaxTombstones > 4096 || c.SourceTimeout <= 0 || c.MaxClockUncertaintyNS < 0 || c.AllowedFutureSkewNS < 0 || c.MaxClockDriftNS < 0 {
		return nil, ErrContractIncompatible
	}
	r := &Resolver{config: c, contracts: map[string]SourceContract{}, profiles: map[string]OperationProfile{}, calls: make(chan struct{}, c.MaxSourceCalls), handles: map[*actorState]struct{}{}, heads: map[headKey]storedHead{}, tombstones: map[actorKey]Head{}, generations: map[actorKey]uint64{}}
	c.Registration.Sources = append([]SourceContract(nil), c.Registration.Sources...)
	for _, s := range c.Registration.Sources {
		if !validID(s.ID) || !validID(s.BoundID) || !nonzero(s.ContractDigest) || s.MaxAgeNS <= 0 {
			return nil, ErrContractIncompatible
		}
		if _, exists := r.contracts[s.ID]; exists {
			return nil, ErrContractIncompatible
		}
		r.contracts[s.ID] = s
	}
	c.Profiles = append([]OperationProfile(nil), c.Profiles...)
	for i, p := range c.Profiles {
		if _, ok := action.LookupOperation(p.OperationID); !ok || p.AudienceID != action.TargetID || (p.Granularity != "instance-required" && p.Granularity != "workload-level") || (p.HumanApplicability != "required" && p.HumanApplicability != "optional" && p.HumanApplicability != "forbidden") || len(p.RequiredContext) > 8 {
			return nil, ErrContractIncompatible
		}
		if _, exists := r.profiles[p.OperationID]; exists {
			return nil, ErrContractIncompatible
		}
		p.RequiredContext = append([]string(nil), p.RequiredContext...)
		sort.Strings(p.RequiredContext)
		for j, k := range p.RequiredContext {
			if !validID(k) || j > 0 && k == p.RequiredContext[j-1] {
				return nil, ErrContractIncompatible
			}
		}
		c.Profiles[i] = p
		r.profiles[p.OperationID] = p
	}
	r.config = c
	s, e := c.Clock.Sample()
	if e != nil || !sampleShape(s, c) {
		return nil, ErrClockUncertain
	}
	r.baseline = s
	r.last = s
	return r, nil
}
func sampleShape(s ClockSample, c Config) bool {
	return s.WallUnixNS > 0 && s.ElapsedNS >= 0 && s.UncertaintyNS >= 0 && s.UncertaintyNS <= c.MaxClockUncertaintyNS
}
func (r *Resolver) sampleLocked() (ClockSample, error) {
	if r.clockFailed {
		return ClockSample{}, ErrClockUncertain
	}
	s, e := r.config.Clock.Sample()
	if e != nil || !sampleShape(s, r.config) || s.WallUnixNS < r.last.WallUnixNS || s.ElapsedNS < r.last.ElapsedNS {
		r.clockFailed = true
		return ClockSample{}, ErrClockUncertain
	}
	wall := s.WallUnixNS - r.baseline.WallUnixNS
	elapsed := s.ElapsedNS - r.baseline.ElapsedNS
	var drift int64
	if wall >= elapsed {
		drift = wall - elapsed
	} else {
		drift = elapsed - wall
	}
	if drift > r.config.MaxClockDriftNS {
		r.clockFailed = true
		return ClockSample{}, ErrClockUncertain
	}
	effective, ok := elapsedMappedWall(s, r.baseline)
	if !ok {
		r.clockFailed = true
		return ClockSample{}, ErrClockUncertain
	}
	r.last = s // retain actual raw wall/elapsed samples for monotonic and drift checks
	s.WallUnixNS = effective
	return s, nil
}
func (r *Resolver) Status(ctx context.Context) DependencyStatus {
	d := DependencyStatus{State: "unavailable", Reason: "unavailable", Contract: "kag.identity-snapshot/v1"}
	if r == nil || r.config.Clock == nil || ctx == nil || ctx.Err() != nil {
		return d
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if sample, e := r.sampleLocked(); e == nil && r.restored && !r.held && !r.capacityFailed {
		if _, e := r.config.Acceptor.Validate(r.probe, time.Unix(0, sample.WallUnixNS)); e == nil {
			d.State = "model_only"
			d.Reason = "modeled"
		}
	}
	return d
}
func (r *Resolver) actorValidLocked(s *actorState) bool {
	_, present := r.handles[s]
	effective, ok := elapsedMappedWall(r.last, r.baseline)
	return ok && present && s.owner == r && s.valid && !r.clockFailed && !r.held && !r.capacityFailed && s.generation == r.generations[s.key] && effective < s.projection.ExpiresUnixNS && r.last.ElapsedNS < s.elapsedExpiry
}
func clone(n NormalizedSnapshot) NormalizedSnapshot {
	n.Mappings = append([]Mapping(nil), n.Mappings...)
	n.Sources = append([]SourceReference(nil), n.Sources...)
	n.Context = append([]ContextEntry(nil), n.Context...)
	n.Delegation = append([]DelegationHop(nil), n.Delegation...)
	for i := range n.Delegation {
		n.Delegation[i].Operations = append([]string(nil), n.Delegation[i].Operations...)
		sort.Strings(n.Delegation[i].Operations)
	}
	sort.Slice(n.Context, func(i, j int) bool { return n.Context[i].Key < n.Context[j].Key })
	sort.Slice(n.Sources, func(i, j int) bool { return n.Sources[i].ID < n.Sources[j].ID })
	n.FloorWitness.Heads = append([]Head(nil), n.FloorWitness.Heads...)
	if n.Human != nil {
		h := *n.Human
		n.Human = &h
	}
	return n
}
func bounded(n NormalizedSnapshot) bool {
	if len(n.Mappings) > 2 || len(n.Sources) > 8 || len(n.Context) > 8 || len(n.Delegation) > 8 || len(n.FloorWitness.Heads) > 8 {
		return false
	}
	size := 0
	add := func(ss ...string) bool {
		for _, s := range ss {
			if len(s) > 8192-size {
				return false
			}
			size += len(s)
		}
		return true
	}
	for _, m := range n.Mappings {
		if !add(m.TenantID, m.ActorID, m.ActorKind, m.InstanceID, m.Granularity, m.OriginID) {
			return false
		}
	}
	if !add(n.Lifecycle.Enrollment, n.Lifecycle.Authority, n.Lifecycle.CredentialState, n.Lifecycle.NodeState, n.Origin.Mode, n.Origin.ID, n.Origin.BrokerID) {
		return false
	}
	for _, s := range n.Sources {
		if !add(s.ID, s.Kind, s.BoundID) {
			return false
		}
	}
	for _, h := range n.Delegation {
		if len(h.Operations) > 16 || !add(h.ParentTenantID, h.ParentActorID, h.ChildTenantID, h.ChildActorID, h.AudienceID, h.ResourceID, h.SourceID) {
			return false
		}
		if !add(h.Operations...) {
			return false
		}
	}
	for _, c := range n.Context {
		if !add(c.Key, c.Value, c.SourceID) {
			return false
		}
	}
	if n.Human != nil && !add(n.Human.TenantID, n.Human.ID, n.Human.SourceID) {
		return false
	}
	for _, h := range n.FloorWitness.Heads {
		if !add(h.SourceID, h.Domain, h.TenantID, h.ActorID) {
			return false
		}
	}
	return true
}
func contextErr(ctx context.Context) error {
	if ctx.Err() == context.DeadlineExceeded {
		return ErrDeadlineExceeded
	}
	return ErrCanceled
}

// read holds its nonblocking admission token until the port actually returns,
// including a misbehaving port that ignores its bounded cancellation context.
func (r *Resolver) read(ctx context.Context, q Query) (NormalizedSnapshot, error) {
	select {
	case r.calls <- struct{}{}:
	default:
		return NormalizedSnapshot{}, ErrBusy
	}
	boundedCtx, cancel := context.WithTimeout(ctx, r.config.SourceTimeout)
	type result struct {
		n   NormalizedSnapshot
		err error
	}
	done := make(chan result, 1)
	go func() {
		defer func() { <-r.calls }()
		b, e := r.config.Source.Read(boundedCtx, q)
		if e != nil {
			done <- result{err: ErrSourceUnavailable}
			return
		}
		if len(b) > 8192 {
			done <- result{err: ErrEvidenceInvalid}
			return
		}
		if boundedCtx.Err() != nil {
			done <- result{err: contextErr(boundedCtx)}
			return
		}
		owned := append([]byte(nil), b...)
		n, e := r.config.Verifier.Normalize(boundedCtx, owned, q)
		if e != nil {
			done <- result{err: ErrEvidenceInvalid}
			return
		}
		if !bounded(n) {
			done <- result{err: ErrEvidenceInvalid}
			return
		}
		if len(n.Mappings) == 1 && !negativeLifecycle(n.Lifecycle) {
			t := authn.TransportProjection{TrustDomain: q.TrustDomain, CredentialProfile: q.CredentialProfile, PrincipalID: q.PrincipalID}
			s := ScopeProjection{AudienceID: q.AudienceID, OperationID: q.OperationID, IntentDigest: q.IntentDigest}
			if _, e := measureSnapshot(n, t, s, r.profiles[q.OperationID]); e != nil {
				done <- result{err: e}
				return
			}
		}
		done <- result{n: clone(n)}
	}()
	defer cancel()
	select {
	case res := <-done:
		if boundedCtx.Err() != nil {
			return NormalizedSnapshot{}, contextErr(boundedCtx)
		}
		return res.n, res.err
	case <-boundedCtx.Done():
		return NormalizedSnapshot{}, contextErr(boundedCtx)
	}
}
func (r *Resolver) Resolve(ctx context.Context, h authn.TransportHandle, s ResolveScope) (ActorHandle, error) {
	return r.resolve(ctx, h, s, nil)
}
func (r *Resolver) Recheck(ctx context.Context, h ActorHandle, s ResolveScope) (ActorHandle, error) {
	if r == nil || r.config.Clock == nil {
		return ActorHandle{}, ErrContractIncompatible
	}
	if h.state == nil || h.state.owner != r {
		return ActorHandle{}, ErrForeignHandle
	}
	return r.resolve(ctx, h.state.transport, s, h.state)
}
func (r *Resolver) resolve(ctx context.Context, h authn.TransportHandle, s ResolveScope, old *actorState) (ActorHandle, error) {
	if r == nil || r.config.Clock == nil {
		return ActorHandle{}, ErrContractIncompatible
	}
	if ctx == nil {
		return ActorHandle{}, ErrCanceled
	}
	if ctx.Err() != nil {
		return ActorHandle{}, contextErr(ctx)
	}
	scope, e := s.Projection()
	if e != nil {
		return ActorHandle{}, ErrScopeInvalid
	}
	profile, ok := r.profiles[scope.OperationID]
	if !ok || profile.AudienceID != scope.AudienceID {
		return ActorHandle{}, ErrScopeInvalid
	}
	r.mu.Lock()
	sample, e := r.sampleLocked()
	if e == nil && r.capacityFailed {
		e = ErrBusy
	}
	if e == nil && old != nil {
		if !r.actorValidLocked(old) {
			e = ErrForeignHandle
		} else if old.scope != scope {
			e = ErrScopeInvalid
		}
	}
	r.mu.Unlock()
	if e != nil {
		return ActorHandle{}, e
	}
	transport, e := r.config.Acceptor.Validate(h, time.Unix(0, sample.WallUnixNS))
	if e != nil {
		return ActorHandle{}, ErrTransportInvalid
	}
	q := Query{TrustDomain: transport.TrustDomain, CredentialProfile: transport.CredentialProfile, PrincipalID: transport.PrincipalID, ConnectionDigest: transport.ConnectionDigest, IntentDigest: scope.IntentDigest, AudienceID: scope.AudienceID, OperationID: scope.OperationID}
	n, e := r.read(ctx, q)
	if e != nil {
		return ActorHandle{}, e
	}
	r.mu.Lock()
	sample, e = r.sampleLocked()
	rawNow := r.last.WallUnixNS // same protected paired capture as effective sample
	r.mu.Unlock()
	if e != nil {
		return ActorHandle{}, e
	}
	from, to, eligibility, e := r.validate(n, transport, scope, profile, sample.WallUnixNS, rawNow)
	if e != nil {
		return ActorHandle{}, e
	}
	if eligibility != nil {
		r.mu.Lock()
		defer r.mu.Unlock()
		sample, e = r.sampleLocked()
		if e != nil {
			return ActorHandle{}, e
		}
		if ctx.Err() != nil {
			return ActorHandle{}, contextErr(ctx)
		}
		if r.last.WallUnixNS < from || sample.WallUnixNS >= to {
			return ActorHandle{}, ErrSourceStale
		}
		if _, e = r.config.Acceptor.Validate(h, time.Unix(0, sample.WallUnixNS)); e != nil {
			return ActorHandle{}, ErrTransportInvalid
		}
		if e = r.commit(n, eligibility); e != nil {
			return ActorHandle{}, e
		}
		return ActorHandle{}, eligibility
	}
	encoded, e := encode(n, transport, scope, profile, from, to)
	if e != nil {
		return ActorHandle{}, e
	}
	digest := sha256.Sum256(encoded)
	r.mu.Lock()
	defer r.mu.Unlock()
	sample, e = r.sampleLocked()
	if e != nil {
		return ActorHandle{}, e
	}
	if ctx.Err() != nil {
		return ActorHandle{}, contextErr(ctx)
	}
	if r.last.WallUnixNS < from || sample.WallUnixNS >= to {
		return ActorHandle{}, ErrSourceStale
	}
	if _, e = r.config.Acceptor.Validate(h, time.Unix(0, sample.WallUnixNS)); e != nil {
		return ActorHandle{}, ErrTransportInvalid
	}
	if e = r.commit(n, eligibility); e != nil {
		return ActorHandle{}, e
	}
	if eligibility != nil {
		return ActorHandle{}, eligibility
	}
	if old != nil {
		if old.projection.IdentityProjectionDigest != digest {
			return ActorHandle{}, ErrSnapshotChanged
		}
		if !r.actorValidLocked(old) {
			return ActorHandle{}, ErrForeignHandle
		}
		return ActorHandle{old}, nil
	}
	for state := range r.handles {
		if !r.actorValidLocked(state) {
			state.valid = false
			delete(r.handles, state)
		}
	}
	if len(r.handles) >= r.config.MaxHandles {
		r.holdLocked()
		return ActorHandle{}, ErrBusy
	}
	if to-sample.WallUnixNS > math.MaxInt64-sample.ElapsedNS {
		return ActorHandle{}, ErrClockUncertain
	}
	m := n.Mappings[0]
	key := actorKey{m.TenantID, m.ActorID}
	projection := BindingProjection{ActorID: m.ActorID, TenantID: m.TenantID, InstanceID: m.InstanceID, Granularity: m.Granularity, IdentityProjectionDigest: digest, ContinuityEpoch: m.ContinuityEpoch, MappingRevision: m.Revision, LifecycleRevision: n.Lifecycle.Revision, DelegationRevision: n.DelegationRevision, ValidFromUnixNS: from, ExpiresUnixNS: to, EvidenceLane: Modeled}
	state := &actorState{snapshot: append([]byte(nil), encoded...), owner: r, transport: h, scope: scope, projection: projection, key: key, generation: r.generations[key], elapsedExpiry: sample.ElapsedNS + (to - sample.WallUnixNS), valid: true}
	r.handles[state] = struct{}{}
	r.probe = h
	return ActorHandle{state}, nil
}

func negativeLifecycle(l Lifecycle) bool {
	return l.Authority == "deleted" || l.Authority == "disabled" || l.Enrollment == "pending" || l.Enrollment == "removed" || l.CredentialState == "expired" || l.CredentialState == "revoked" || l.NodeState == "removed" || l.NodeState == "selector-changed"
}

// elapsedMappedWall prevents a lagging/frozen admitted wall clock from granting
// a new lifetime to unchanged evidence. The baseline is protected composition;
// raw samples remain separate so the configured drift budget stays enforceable.
func elapsedMappedWall(s, baseline ClockSample) (int64, bool) {
	if s.ElapsedNS < baseline.ElapsedNS || baseline.WallUnixNS <= 0 {
		return 0, false
	}
	delta := s.ElapsedNS - baseline.ElapsedNS
	if delta > math.MaxInt64-baseline.WallUnixNS {
		return 0, false
	}
	mapped := baseline.WallUnixNS + delta
	if mapped < s.WallUnixNS {
		mapped = s.WallUnixNS
	}
	return mapped, true
}
