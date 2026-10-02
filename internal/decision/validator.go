package decision

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"github.com/nmcitra/kag/internal/action"
	"github.com/nmcitra/kag/internal/identity"
	"math"
	"sync"
	"time"
)

type SignedResult struct{ Payload, Signature []byte }
type Inspector interface {
	Inspect(context.Context, action.Binding) (InspectionObservation, error)
}
type PermissionSource interface {
	Check(context.Context, identity.ActorHandle, action.Binding) (PermissionObservation, error)
}
type InspectionObservation struct {
	SourceID                                                       string
	ContractDigest, EvidenceDigest, BindingDigest, OperationDigest [32]byte
	ObservedAtUnixNS, ExpiresUnixNS                                int64
	Outcome                                                        string
}
type PermissionObservation struct {
	SourceID                                                 string
	ContractDigest, EvidenceDigest                           [32]byte
	ActorID, TenantID                                        string
	IdentityProjectionDigest, BindingDigest, OperationDigest [32]byte
	ObservedAtUnixNS, ExpiresUnixNS                          int64
	Outcome                                                  string
	AllowedMarkers                                           uint8
}
type Config struct {
	Resolver                               *identity.Resolver
	Inspector                              Inspector
	PermissionSource                       PermissionSource
	Clock                                  identity.Clock
	EvidenceLane                           identity.EvidenceLane
	ProducerID                             string
	PublicKey                              ed25519.PublicKey
	ProfileDigest                          [32]byte
	InspectorID                            string
	InspectorContractDigest                [32]byte
	PermissionID                           string
	PermissionContractDigest               [32]byte
	MaxPermissionAge                       time.Duration
	MaxClockUncertaintyNS, MaxClockDriftNS int64
	SourceTimeout                          time.Duration
	MaxCalls                               int
	MaxProofAge, MaxInspectionAge          time.Duration
}
type Validator struct {
	config     Config
	slots      chan struct{}
	mu         sync.Mutex
	base, last identity.ClockSample
	clockBad   bool
}
type Permit struct{ state *permitState }
type permitState struct {
	owner         *Validator
	actor         identity.ActorHandle
	scope         identity.ResolveScope
	result        SignedResult
	projection    PermitProjection
	elapsedExpiry int64
}
type PermitProjection struct {
	EvidenceScope                                                                                                                string
	BindingDigest, OperationDigest, IdentityProjectionDigest, DecisionDigest, PermissionEvidenceDigest, InspectionEvidenceDigest [32]byte
	ReplayID, ResultID, ProducerID, ProfileID                                                                                    string
	ValidFromUnixNS, ExpiresUnixNS                                                                                               int64
}

func NewValidator(c Config) (*Validator, error) {
	zero := [32]byte{}
	if c.Resolver == nil || c.PermissionSource == nil || c.Inspector == nil || c.Clock == nil || c.EvidenceLane != identity.Modeled || !id(c.ProducerID) || len(c.PublicKey) != ed25519.PublicKeySize || c.ProfileDigest == zero || !id(c.InspectorID) || c.InspectorContractDigest == zero || !id(c.PermissionID) || c.PermissionContractDigest == zero || c.MaxPermissionAge <= 0 || c.MaxInspectionAge <= 0 || c.MaxProofAge <= 0 || c.MaxProofAge > 5*time.Second || c.SourceTimeout <= 0 || c.MaxCalls < 1 || c.MaxCalls > 64 || c.MaxClockDriftNS < 0 || c.MaxClockUncertaintyNS < 0 {
		return nil, ErrInvalidConfig
	}
	c.PublicKey = bytes.Clone(c.PublicKey)
	v := &Validator{config: c, slots: make(chan struct{}, c.MaxCalls)}
	s, e := c.Clock.Sample()
	if e != nil || !v.goodSample(s) {
		return nil, ErrClock
	}
	v.base = s
	v.last = s
	return v, nil
}
func (v *Validator) goodSample(s identity.ClockSample) bool {
	return s.WallUnixNS > 0 && s.ElapsedNS >= 0 && s.UncertaintyNS >= 0 && s.UncertaintyNS <= v.config.MaxClockUncertaintyNS
}

// clockBounds retains raw lower and conservative elapsed-mapped upper walls
// from one protected paired capture; no unlocked reread can substitute either.
type clockBounds struct {
	identity.ClockSample
	rawWallUnixNS int64
}

func (v *Validator) sample() (clockBounds, error) {
	if v == nil || v.slots == nil {
		return clockBounds{}, ErrInvalidConfig
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.clockBad {
		return clockBounds{}, ErrClock
	}
	s, e := v.config.Clock.Sample()
	if e != nil || !v.goodSample(s) || s.WallUnixNS < v.last.WallUnixNS || s.ElapsedNS < v.last.ElapsedNS {
		v.clockBad = true
		return clockBounds{}, ErrClock
	}
	wall, elapsed := s.WallUnixNS-v.base.WallUnixNS, s.ElapsedNS-v.base.ElapsedNS
	drift := wall - elapsed
	if drift < 0 {
		drift = -drift
	}
	if drift > v.config.MaxClockDriftNS {
		v.clockBad = true
		return clockBounds{}, ErrClock
	}
	v.last = s
	rawWall := s.WallUnixNS
	// A frozen wall clock inside the allowed drift cannot restart proof lifetime.
	elapsedDelta := s.ElapsedNS - v.base.ElapsedNS
	if v.base.WallUnixNS > math.MaxInt64-elapsedDelta {
		v.clockBad = true
		return clockBounds{}, ErrClock
	}
	projected := v.base.WallUnixNS + elapsedDelta
	if projected > s.WallUnixNS {
		s.WallUnixNS = projected
	}
	return clockBounds{s, rawWall}, nil
}
func (p Permit) Projection() (PermitProjection, error) {
	if p.state == nil || p.state.owner == nil {
		return PermitProjection{}, ErrInvalidPermit
	}
	s, e := p.state.owner.sample()
	if e != nil {
		return PermitProjection{}, e
	}
	if s.rawWallUnixNS < p.state.projection.ValidFromUnixNS || s.WallUnixNS >= p.state.projection.ExpiresUnixNS || s.ElapsedNS >= p.state.elapsedExpiry {
		return PermitProjection{}, ErrExpired
	}
	return p.state.projection, nil
}
func (v *Validator) enter(ctx context.Context) error {
	if v == nil || v.slots == nil {
		return ErrInvalidConfig
	}
	if ctx == nil || ctx.Err() != nil {
		return ErrCanceled
	}
	select {
	case v.slots <- struct{}{}:
		return nil
	default:
		return ErrBusy
	}
}
func deadline(start, age int64) (int64, bool) {
	if start < 0 || age <= 0 || start > math.MaxInt64-age {
		return 0, false
	}
	return start + age, true
}
func evidenceTime(observed, expiry int64, age time.Duration, s clockBounds) (int64, error) {
	d, ok := deadline(observed, int64(age))
	if !ok || observed <= 0 || observed > s.rawWallUnixNS || expiry <= observed || s.WallUnixNS >= expiry || s.WallUnixNS >= d {
		return 0, ErrExpired
	}
	if expiry < d {
		return expiry, nil
	}
	return d, nil
}
func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
func (v *Validator) Evaluate(ctx context.Context, h identity.ActorHandle, scope identity.ResolveScope, b action.Binding, result SignedResult) (Permit, error) {
	if e := v.enter(ctx); e != nil {
		return Permit{}, e
	}
	lease := &callLease{validator: v}
	defer lease.finish()
	return v.evaluate(ctx, h, scope, b, result, nil, lease)
}
func (v *Validator) evaluate(ctx context.Context, h identity.ActorHandle, scope identity.ResolveScope, b action.Binding, result SignedResult, old *permitState, lease *callLease) (Permit, error) {
	start, e := v.sample()
	if e != nil {
		return Permit{}, e
	}
	if len(result.Payload) == 0 || len(result.Payload) > MaxPayloadBytes || len(result.Signature) != ed25519.SignatureSize {
		return Permit{}, ErrInvalidResult
	}
	owned := SignedResult{bytes.Clone(result.Payload), bytes.Clone(result.Signature)}
	if !ed25519.Verify(v.config.PublicKey, owned.Payload, owned.Signature) {
		return Permit{}, ErrInvalidResult
	}
	c, e := decodeClaims(owned.Payload)
	if e != nil {
		return Permit{}, e
	}
	view, e := b.View()
	if e != nil {
		return Permit{}, ErrWithheld
	}
	sp, e := scope.Projection()
	if e != nil || sp.AudienceID != view.TargetID || sp.AudienceID != view.AudienceID || sp.OperationID != view.OperationID || sp.IntentDigest != view.IntentDigest {
		return Permit{}, ErrWithheld
	}
	h, e = v.config.Resolver.Recheck(ctx, h, scope)
	if e != nil {
		return Permit{}, ErrWithheld
	}
	actor, e := h.Projection()
	if e != nil || actor.EvidenceLane != identity.Modeled || actor.ActorID != view.ActorID || actor.TenantID != view.TenantID || actor.InstanceID != view.InstanceID || actor.IdentityProjectionDigest != view.IdentityProjectionDigest {
		return Permit{}, ErrWithheld
	}
	if actor.Granularity != "instance-required" && actor.Granularity != "workload-level" || actor.Granularity == "instance-required" && actor.InstanceID == "" {
		return Permit{}, ErrWithheld
	}
	if !claimsMatch(c, view, b.Digest(), v.config) {
		return Permit{}, ErrWithheld
	}
	if e = semanticGate(c, view, b.Operation()); e != nil {
		return Permit{}, e
	}
	proofEnd, e := evidenceTime(c.IssuedAtUnixNS, c.ExpiresUnixNS, v.config.MaxProofAge, start)
	if e != nil || c.IssuedAtUnixNS < view.ValidFromUnixNS || c.ExpiresUnixNS > view.ExpiresUnixNS || start.rawWallUnixNS < view.ValidFromUnixNS || start.WallUnixNS >= view.ExpiresUnixNS || start.rawWallUnixNS < actor.ValidFromUnixNS || start.WallUnixNS >= actor.ExpiresUnixNS {
		return Permit{}, ErrExpired
	}
	from := max(c.IssuedAtUnixNS, max(view.ValidFromUnixNS, actor.ValidFromUnixNS))
	expiry := min(proofEnd, min(view.ExpiresUnixNS, actor.ExpiresUnixNS))
	permission, pe := boundedCall(ctx, v.config.SourceTimeout, lease, func(sourceCtx context.Context) (PermissionObservation, error) {
		return v.config.PermissionSource.Check(sourceCtx, h, b)
	})
	post, e := v.sample()
	if e != nil {
		return Permit{}, e
	}
	if ctx.Err() != nil {
		return Permit{}, ErrCanceled
	}
	if pe != nil {
		return Permit{}, ErrSource
	}
	permissionEnd, e := v.permissionGate(permission, h, b, view, post)
	if e != nil {
		return Permit{}, e
	}
	from = max(from, permission.ObservedAtUnixNS)
	expiry = min(expiry, permissionEnd)
	inspectionDigest := [32]byte{}
	if view.OperationID == "lab.set_marker" {
		inspection, ie := boundedCall(ctx, v.config.SourceTimeout, lease, func(sourceCtx context.Context) (InspectionObservation, error) {
			return v.config.Inspector.Inspect(sourceCtx, b)
		})
		post, e = v.sample()
		if e != nil {
			return Permit{}, e
		}
		if ctx.Err() != nil {
			return Permit{}, ErrCanceled
		}
		if ie != nil {
			return Permit{}, ErrSource
		}
		inspectionEnd, e := v.inspectionGate(inspection, b, view, post)
		if e != nil {
			return Permit{}, e
		}
		from = max(from, inspection.ObservedAtUnixNS)
		expiry = min(expiry, inspectionEnd)
		inspectionDigest = inspection.EvidenceDigest
	}
	// Recheck identity after independently read permission/inspection to expose known invalidation.
	h, e = v.config.Resolver.Recheck(ctx, h, scope)
	if e != nil {
		return Permit{}, ErrWithheld
	}
	last, e := v.sample()
	if e != nil {
		return Permit{}, e
	}
	if ctx.Err() != nil {
		return Permit{}, ErrCanceled
	}
	if last.rawWallUnixNS < from || last.WallUnixNS >= expiry {
		return Permit{}, ErrExpired
	}
	elapsedEnd, ok := deadline(start.ElapsedNS, expiry-start.WallUnixNS)
	if !ok || last.ElapsedNS >= elapsedEnd {
		return Permit{}, ErrExpired
	}
	if old != nil {
		expiry = min(expiry, old.projection.ExpiresUnixNS)
		from = max(from, old.projection.ValidFromUnixNS)
		elapsedEnd = min(elapsedEnd, old.elapsedExpiry)
		if last.WallUnixNS >= expiry || last.ElapsedNS >= elapsedEnd {
			return Permit{}, ErrExpired
		}
	}
	projection := PermitProjection{"modeled", b.Digest(), view.OperationDigest, view.IdentityProjectionDigest, sha256.Sum256(owned.Payload), permission.EvidenceDigest, inspectionDigest, view.ReplayID, c.ResultID, c.ProducerID, c.ProfileID, from, expiry}
	return Permit{&permitState{v, h, scope, owned, projection, elapsedEnd}}, nil
}
func claimsMatch(c Claims, b action.BindingView, d [32]byte, cfg Config) bool {
	return c.ProducerID == cfg.ProducerID && c.ProfileID == ProfileID && c.ResultKind == "final" && c.BindingDigest == d && c.OperationDigest == b.OperationDigest && c.IdentityProjectionDigest == b.IdentityProjectionDigest && c.ActorID == b.ActorID && c.TenantID == b.TenantID && c.InstanceID == b.InstanceID && c.ZoneID == b.ZoneID && c.AudienceID == b.AudienceID && c.ReplayID == b.ReplayID && c.CatalogDigest == b.CatalogDigest && c.PolicyDigest == b.PolicyDigest && c.GatewayBuildDigest == b.GatewayBuildDigest && c.ProtectedConfigDigest == b.ProtectedConfigDigest && c.TargetBuildDigest == b.TargetBuildDigest && c.TargetContractDigest == b.TargetContractDigest && c.DecisionProfileDigest == b.DecisionProfileDigest && b.DecisionProfileDigest == cfg.ProfileDigest
}
func (v *Validator) permissionGate(p PermissionObservation, h identity.ActorHandle, b action.Binding, view action.BindingView, s clockBounds) (int64, error) {
	a, e := h.Projection()
	if e != nil || p.SourceID != v.config.PermissionID || p.ContractDigest != v.config.PermissionContractDigest || p.EvidenceDigest == ([32]byte{}) || p.ActorID != a.ActorID || p.TenantID != a.TenantID || p.IdentityProjectionDigest != a.IdentityProjectionDigest || p.BindingDigest != b.Digest() || p.OperationDigest != view.OperationDigest || p.Outcome != "allowed" {
		return 0, ErrWithheld
	}
	if view.OperationID == "lab.set_marker" {
		mask, e := markerMask(b.Operation())
		if e != nil || p.AllowedMarkers == 0 || p.AllowedMarkers&^uint8(3) != 0 || p.AllowedMarkers&mask == 0 {
			return 0, ErrWithheld
		}
	} else if p.AllowedMarkers != 0 {
		return 0, ErrWithheld
	}
	return evidenceTime(p.ObservedAtUnixNS, p.ExpiresUnixNS, v.config.MaxPermissionAge, s)
}
func (v *Validator) inspectionGate(p InspectionObservation, b action.Binding, view action.BindingView, s clockBounds) (int64, error) {
	if p.SourceID != v.config.InspectorID || p.ContractDigest != v.config.InspectorContractDigest || p.EvidenceDigest == ([32]byte{}) || p.BindingDigest != b.Digest() || p.OperationDigest != view.OperationDigest || p.Outcome != "allowed" {
		return 0, ErrWithheld
	}
	return evidenceTime(p.ObservedAtUnixNS, p.ExpiresUnixNS, v.config.MaxInspectionAge, s)
}
func (v *Validator) Recheck(ctx context.Context, p Permit, b action.Binding) (Permit, error) {
	if e := v.enter(ctx); e != nil {
		return Permit{}, e
	}
	lease := &callLease{validator: v}
	defer lease.finish()
	if p.state == nil || p.state.owner != v || p.state.projection.BindingDigest != b.Digest() {
		return Permit{}, ErrInvalidPermit
	}
	if _, e := p.Projection(); e != nil {
		return Permit{}, e
	}
	return v.evaluate(ctx, p.state.actor, p.state.scope, b, p.state.result, p.state, lease)
}

// callLease transfers admission ownership to a noncooperative source worker.
// Only the calling goroutine writes detached; release may run in either owner.
type callLease struct {
	validator *Validator
	once      sync.Once
	detached  bool
}

func (l *callLease) release() { l.once.Do(func() { <-l.validator.slots }) }
func (l *callLease) finish() {
	if !l.detached {
		l.release()
	}
}
func boundedCall[T any](ctx context.Context, timeout time.Duration, lease *callLease, fn func(context.Context) (T, error)) (T, error) {
	var zero T
	sourceCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type result struct {
		value T
		err   error
	}
	done := make(chan result, 1)
	accepted := make(chan struct{})
	abandoned := make(chan struct{})
	go func() {
		value, e := fn(sourceCtx)
		done <- result{value, e}
		select {
		case <-accepted:
		case <-abandoned:
			lease.release()
		}
	}()
	abandon := func() { lease.detached = true; close(abandoned) }
	select {
	case res := <-done:
		if sourceCtx.Err() != nil {
			abandon()
			return zero, ErrSource
		}
		close(accepted)
		return res.value, res.err
	case <-sourceCtx.Done():
		abandon()
		return zero, ErrSource
	}
}
