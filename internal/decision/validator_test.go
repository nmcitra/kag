package decision

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"github.com/gatekeeper454/KTP-Component-Dev/internal/action"
	"github.com/gatekeeper454/KTP-Component-Dev/internal/identity"
	"reflect"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func deny(t testing.TB, p Permit, e error) {
	t.Helper()
	if e == nil {
		t.Fatal("unexpected permit")
	}
	if _, pe := p.Projection(); pe == nil {
		t.Fatal("usable permit returned with error")
	}
}
func TestEvaluateActualOpaqueActor(t *testing.T) {
	for _, marker := range []bool{false, true} {
		f := newDecisionFixture(t, marker)
		p, e := f.validator.Evaluate(context.Background(), f.actor, f.scope, f.binding, f.signed(t))
		if e != nil {
			t.Fatal(e)
		}
		v, e := p.Projection()
		if e != nil || v.EvidenceScope != "modeled" || v.BindingDigest != f.binding.Digest() || v.IdentityProjectionDigest != f.claims.IdentityProjectionDigest || v.ExpiresUnixNS != f.claims.IssuedAtUnixNS+2e9 {
			t.Fatal("projection/earliest source-age bound", e, v)
		}
		if _, e = f.validator.Recheck(context.Background(), p, f.binding); e != nil {
			t.Fatal("recheck positive", e)
		}
		var zero Permit
		deny(t, zero, ErrInvalidPermit)
	}
}
func TestEvaluateEverySignedContextMismatch(t *testing.T) {
	fields := []string{"ProducerID", "ProfileID", "ResultKind", "BindingDigest", "OperationDigest", "IdentityProjectionDigest", "ActorID", "TenantID", "InstanceID", "ZoneID", "AudienceID", "ReplayID", "CatalogDigest", "PolicyDigest", "GatewayBuildDigest", "ProtectedConfigDigest", "TargetBuildDigest", "TargetContractDigest", "DecisionProfileDigest"}
	for _, name := range fields {
		t.Run(name, func(t *testing.T) {
			f := newDecisionFixture(t, true)
			v := reflect.ValueOf(&f.claims).Elem().FieldByName(name)
			if v.Kind() == reflect.String {
				v.SetString(v.String() + "x")
			} else {
				v.Index(0).SetUint(v.Index(0).Uint() ^ 1)
			}
			p, e := f.validator.Evaluate(context.Background(), f.actor, f.scope, f.binding, f.signed(t))
			deny(t, p, e)
		})
	}
}
func TestEvaluateSignatureAndOpaqueBoundary(t *testing.T) {
	f := newDecisionFixture(t, true)
	valid := f.signed(t)
	for _, s := range []SignedResult{{}, {valid.Payload, valid.Signature[:63]}, {append([]byte(nil), valid.Payload...), append([]byte(nil), valid.Signature...)}} {
		if len(s.Signature) == 64 {
			s.Signature[0] ^= 1
		}
		p, e := f.validator.Evaluate(context.Background(), f.actor, f.scope, f.binding, s)
		deny(t, p, e)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	p, e := f.validator.Evaluate(context.Background(), f.actor, f.scope, f.binding, SignedResult{valid.Payload, ed25519.Sign(key, valid.Payload)})
	deny(t, p, e)
	p, e = f.validator.Evaluate(context.Background(), identity.ActorHandle{}, f.scope, f.binding, valid)
	deny(t, p, e)
	p, e = f.validator.Evaluate(context.Background(), f.actor, identity.ResolveScope{}, f.binding, valid)
	deny(t, p, e)
	p, e = f.validator.Evaluate(context.Background(), f.actor, f.scope, action.Binding{}, valid)
	deny(t, p, e)
	read, _ := action.ParseMCPArguments("lab.read_status", []byte("{}"))
	scope, _ := identity.NewResolveScope(read, action.TargetID)
	p, e = f.validator.Evaluate(context.Background(), f.actor, scope, f.binding, valid)
	deny(t, p, e)
}
func TestSourcesAndQueueRecheck(t *testing.T) {
	for _, name := range []string{"permission_deny", "permission_scope", "permission_mask", "permission_source", "permission_stale", "inspection_deny", "inspection_scope", "inspection_source", "inspection_stale", "actor_disabled"} {
		t.Run(name, func(t *testing.T) {
			f := newDecisionFixture(t, true)
			p, e := f.validator.Evaluate(context.Background(), f.actor, f.scope, f.binding, f.signed(t))
			if e != nil {
				t.Fatal(e)
			}
			switch name {
			case "permission_deny":
				f.permission.o.Outcome = "denied"
			case "permission_scope":
				f.permission.o.OperationDigest[0] ^= 1
			case "permission_mask":
				f.permission.o.AllowedMarkers = 1
			case "permission_source":
				f.permission.o.SourceID = "other"
			case "permission_stale":
				f.permission.o.ObservedAtUnixNS -= 3e9
			case "inspection_deny":
				f.inspection.o.Outcome = "denied"
			case "inspection_scope":
				f.inspection.o.BindingDigest[0] ^= 1
			case "inspection_source":
				f.inspection.o.ContractDigest[0] ^= 1
			case "inspection_stale":
				f.inspection.o.ObservedAtUnixNS -= 3e9
			case "actor_disabled":
				f.identityPort.n.Lifecycle.Authority = "disabled"
				f.identityPort.n.Lifecycle.Revision++
			}
			q, e := f.validator.Recheck(context.Background(), p, f.binding)
			deny(t, q, e)
		})
	}
	f := newDecisionFixture(t, true)
	p, e := f.validator.Evaluate(context.Background(), f.actor, f.scope, f.binding, f.signed(t))
	if e != nil {
		t.Fatal(e)
	}
	f.clock.advance(2e9)
	q, e := f.validator.Recheck(context.Background(), p, f.binding)
	deny(t, q, e)
	other := newDecisionFixture(t, true)
	q, e = other.validator.Recheck(context.Background(), p, other.binding)
	deny(t, q, e)
}
func TestConstructorRegistrationAndOwnership(t *testing.T) {
	f := newDecisionFixture(t, true)
	for _, lane := range []identity.EvidenceLane{0, 2, 99} {
		c := f.config
		c.EvidenceLane = lane
		if _, e := NewValidator(c); e == nil {
			t.Fatal("unsupported lane", lane)
		}
	}
	for _, edit := range []func(*Config){func(c *Config) { c.Clock = nil }, func(c *Config) { c.MaxCalls = 65 }, func(c *Config) { c.MaxProofAge = 6e9 }, func(c *Config) { c.PublicKey = c.PublicKey[:31] }, func(c *Config) { c.PermissionSource = nil }, func(c *Config) { c.PermissionContractDigest = [32]byte{} }, func(c *Config) { c.ProfileDigest = [32]byte{} }} {
		c := f.config
		edit(&c)
		if _, e := NewValidator(c); e == nil {
			t.Fatal("bad configuration")
		}
	}
	signed := f.signed(t)
	f.config.PublicKey[0] ^= 1
	p, e := f.validator.Evaluate(context.Background(), f.actor, f.scope, f.binding, signed)
	if e != nil {
		t.Fatal("retained caller key", e)
	}
	signed.Payload[0] ^= 1
	signed.Signature[0] ^= 1
	if _, e = f.validator.Recheck(context.Background(), p, f.binding); e != nil {
		t.Fatal("retained caller payload", e)
	}
	v, _ := p.Projection()
	v.EvidenceScope = "live"
	next, _ := p.Projection()
	if next.EvidenceScope != "modeled" {
		t.Fatal("mutable permit")
	}
}
func TestProofAndSourceTimeBoundaries(t *testing.T) {
	for _, name := range []string{"future_proof", "proof_expiry", "proof_age", "action_interval", "permission_future", "inspection_future", "permission_zero_digest", "inspection_zero_digest", "permission_outage", "inspection_outage", "cancel", "clock_wall_rollback", "clock_elapsed_rollback", "clock_frozen_wall", "clock_uncertain"} {
		t.Run(name, func(t *testing.T) {
			f := newDecisionFixture(t, true)
			ctx := context.Background()
			switch name {
			case "future_proof":
				f.claims.IssuedAtUnixNS++
			case "proof_expiry":
				f.claims.IssuedAtUnixNS -= 1e9
				f.claims.ExpiresUnixNS = f.clock.s.WallUnixNS
			case "proof_age":
				f.claims.IssuedAtUnixNS -= 3e9
			case "action_interval":
				f.claims.ExpiresUnixNS += 2e9
			case "permission_future":
				f.permission.o.ObservedAtUnixNS++
			case "inspection_future":
				f.inspection.o.ObservedAtUnixNS++
			case "permission_zero_digest":
				f.permission.o.EvidenceDigest = [32]byte{}
			case "inspection_zero_digest":
				f.inspection.o.EvidenceDigest = [32]byte{}
			case "permission_outage":
				f.permission.e = ErrSource
			case "inspection_outage":
				f.inspection.e = ErrSource
			case "cancel":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case "clock_wall_rollback":
				f.clock.s.WallUnixNS--
			case "clock_elapsed_rollback":
				f.clock.s.ElapsedNS--
			case "clock_frozen_wall":
				f.clock.s.ElapsedNS++
			case "clock_uncertain":
				f.clock.s.UncertaintyNS = 1
			}
			p, e := f.validator.Evaluate(ctx, f.actor, f.scope, f.binding, f.signed(t))
			deny(t, p, e)
		})
	}
	f := newDecisionFixture(t, true)
	f.clock.advance(2e9 - 1)
	p, e := f.validator.Evaluate(context.Background(), f.actor, f.scope, f.binding, f.signed(t))
	if e != nil {
		t.Fatal("age limit-1ns", e)
	}
	f.clock.advance(1)
	q, e := f.validator.Recheck(context.Background(), p, f.binding)
	deny(t, q, e)
}
func TestSourcePostReadExpiryAndBoundedConcurrency(t *testing.T) {
	f := newDecisionFixture(t, true)
	cfg := f.config
	cfg.MaxCalls = 1
	v, e := NewValidator(cfg)
	if e != nil {
		t.Fatal(e)
	}
	f.permission.block = make(chan struct{})
	f.permission.entered = make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan struct {
		p Permit
		e error
	}, 1)
	signed := f.signed(t)
	go func() {
		p, e := v.Evaluate(ctx, f.actor, f.scope, f.binding, signed)
		result <- struct {
			p Permit
			e error
		}{p, e}
	}()
	<-f.permission.entered
	cancel()
	p, e := v.Evaluate(context.Background(), f.actor, f.scope, f.binding, signed)
	if e != ErrBusy {
		t.Fatal("canceled source released occupied token", e)
	}
	deny(t, p, e)
	f.clock.advance(2e9)
	close(f.permission.block)
	got := <-result
	deny(t, got.p, got.e)
	f.permission.block = nil
	f.permission.entered = nil
	other := newDecisionFixture(t, true)
	other.permission.block = make(chan struct{})
	other.permission.entered = make(chan struct{}, 1)
	done := make(chan struct {
		p Permit
		e error
	}, 1)
	go func() {
		p, e := other.validator.Evaluate(context.Background(), other.actor, other.scope, other.binding, other.signed(t))
		done <- struct {
			p Permit
			e error
		}{p, e}
	}()
	<-other.permission.entered
	other.clock.advance(2e9)
	close(other.permission.block)
	got = <-done
	deny(t, got.p, got.e)
}
func TestConcurrentEvaluateAndRecheck(t *testing.T) {
	f := newDecisionFixture(t, true)
	signed := f.signed(t)
	done := make(chan error, 4)
	for i := 0; i < 4; i++ {
		go func() {
			p, e := f.validator.Evaluate(context.Background(), f.actor, f.scope, f.binding, signed)
			if e == nil {
				_, e = f.validator.Recheck(context.Background(), p, f.binding)
			}
			done <- e
		}()
	}
	for i := 0; i < 4; i++ {
		if e := <-done; e != nil {
			t.Fatal(e)
		}
	}
}
func TestIgnoringSourceReturnsPromptlyRetainsCapacity(t *testing.T) {
	for _, source := range []string{"permission", "inspection"} {
		t.Run(source, func(t *testing.T) {
			f := newDecisionFixture(t, true)
			cfg := f.config
			cfg.SourceTimeout = 20 * time.Millisecond
			cfg.MaxCalls = 1
			v, e := NewValidator(cfg)
			if e != nil {
				t.Fatal(e)
			}
			block := make(chan struct{})
			entered := make(chan struct{}, 1)
			if source == "permission" {
				f.permission.block = block
				f.permission.entered = entered
			} else {
				f.inspection.block = block
				f.inspection.entered = entered
			}
			closed := false
			defer func() {
				if !closed {
					close(block)
				}
			}()
			done := make(chan struct {
				p Permit
				e error
			}, 1)
			signed := f.signed(t)
			go func() {
				p, e := v.Evaluate(context.Background(), f.actor, f.scope, f.binding, signed)
				done <- struct {
					p Permit
					e error
				}{p, e}
			}()
			<-entered
			select {
			case got := <-done:
				deny(t, got.p, got.e)
			case <-time.After(300 * time.Millisecond):
				close(block)
				closed = true
				<-done
				t.Fatal("source ignoring context blocks Evaluate beyond bounded timeout")
			}
			p, e := v.Evaluate(context.Background(), f.actor, f.scope, f.binding, signed)
			if e != ErrBusy {
				t.Fatal("timed-out source released capacity before returning", e)
			}
			deny(t, p, e)
			close(block)
			closed = true
			until := time.After(time.Second)
			for len(v.slots) != 0 {
				select {
				case <-until:
					t.Fatal("source return did not release capacity")
				default:
					runtime.Gosched()
				}
			}
		})
	}
}
func TestFreshEvaluateProofAgeUsesBaselineElapsed(t *testing.T) {
	for _, delta := range []int64{500e6 - 1, 500e6, 500e6 + 1} {
		t.Run(strconv.FormatInt(delta, 10), func(t *testing.T) {
			f := newDecisionFixtureWithDrift(t, true, 10e9)
			cfg := f.config
			cfg.MaxClockDriftNS = 10e9
			cfg.MaxProofAge = 500 * time.Millisecond
			v, e := NewValidator(cfg)
			if e != nil {
				t.Fatal(e)
			}
			f.clock.mu.Lock()
			f.clock.s.ElapsedNS += delta
			f.clock.mu.Unlock()
			p, e := v.Evaluate(context.Background(), f.actor, f.scope, f.binding, f.signed(t))
			if delta < 500e6 {
				if e != nil {
					t.Fatal("baseline proof boundary-1ns", e)
				}
			} else {
				deny(t, p, e)
			}
		})
	}
}
func TestAllowedLagCannotAdmitFutureDecisionEvidence(t *testing.T) {
	for _, kind := range []string{"proof", "permission", "inspection"} {
		t.Run(kind, func(t *testing.T) {
			f := newDecisionFixtureWithDrift(t, true, 10_000_000_000)
			cfg := f.config
			cfg.MaxClockDriftNS = 10_000_000_000
			v, e := NewValidator(cfg)
			if e != nil {
				t.Fatal(e)
			}
			f.clock.mu.Lock()
			raw := f.clock.s.WallUnixNS
			f.clock.s.ElapsedNS += 1_000_000_000
			f.clock.mu.Unlock()
			if _, e = v.Evaluate(context.Background(), f.actor, f.scope, f.binding, f.signed(t)); e != nil {
				t.Fatal("unchanged-current allowed-lag control denied", e)
			}
			switch kind {
			case "proof":
				f.claims.IssuedAtUnixNS = raw + 1
			case "permission":
				f.permission.o.ObservedAtUnixNS = raw + 1
			case "inspection":
				f.inspection.o.ObservedAtUnixNS = raw + 1
			}
			permit, e := v.Evaluate(context.Background(), f.actor, f.scope, f.binding, f.signed(t))
			if e != ErrExpired || permit.state != nil {
				t.Fatal("raw-clock future evidence admitted under allowed lag", permit, e)
			}
		})
	}
}
