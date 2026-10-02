package decision

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nmcitra/kag/internal/action"
	"github.com/nmcitra/kag/internal/identity"
)

// These regressions exercise modeled decision contracts only; no operation is dispatched.
const hardeningWatchdog = 3 * time.Second

type hardeningResult struct {
	permit Permit
	err    error
}

func hardeningAwait[T any](t testing.TB, ch <-chan T, what string) T {
	t.Helper()
	select {
	case result := <-ch:
		return result
	case <-time.After(hardeningWatchdog):
		t.Fatalf("watchdog waiting for %s", what)
		var zero T
		return zero
	}
}

func hardeningDrain(t testing.TB, v *Validator) {
	t.Helper()
	timer := time.NewTimer(hardeningWatchdog)
	defer timer.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for len(v.slots) != 0 {
		select {
		case <-timer.C:
			t.Fatal("source worker did not return and release admission")
		case <-tick.C:
		}
	}
}

func hardeningDenied(t testing.TB, result hardeningResult, want error) {
	t.Helper()
	if result.err != want || result.permit != (Permit{}) {
		t.Fatalf("want %v and zero permit; got %v, %#v", want, result.err, result.permit)
	}
	if _, err := result.permit.Projection(); err != ErrInvalidPermit {
		t.Fatalf("failed decision returned usable permit: %v", err)
	}
}

func TestCanceledSourceRepeatedExhaustionLateReturnAndRecovery(t *testing.T) {
	for _, source := range []string{"permission", "inspection"} {
		t.Run(source, func(t *testing.T) {
			f := newDecisionFixture(t, true)
			cfg := f.config
			cfg.MaxCalls = 1
			cfg.SourceTimeout = 5 * time.Second
			v, err := NewValidator(cfg)
			if err != nil {
				t.Fatal(err)
			}
			for cycle := 0; cycle < 3; cycle++ {
				t.Run(fmt.Sprintf("cycle_%d", cycle+1), func(t *testing.T) {
					block := make(chan struct{})
					entered := make(chan struct{}, 1)
					var releaseOnce sync.Once
					release := func() { releaseOnce.Do(func() { close(block) }) }
					if source == "permission" {
						f.permission.mu.Lock()
						f.permission.block, f.permission.entered = block, entered
						f.permission.mu.Unlock()
					} else {
						f.inspection.mu.Lock()
						f.inspection.block, f.inspection.entered = block, entered
						f.inspection.mu.Unlock()
					}
					ctx, cancel := context.WithCancel(context.Background())
					results := make(chan hardeningResult, 1)
					joined := make(chan struct{})
					var arrivalJoins []<-chan struct{}
					t.Cleanup(func() {
						cancel()
						release()
						for _, done := range append([]<-chan struct{}{joined}, arrivalJoins...) {
							select {
							case <-done:
							case <-time.After(hardeningWatchdog):
								t.Error("watchdog joining Evaluate goroutine during cleanup")
							}
						}
						hardeningDrain(t, v)
					})
					canceledSigned := f.signed(t)
					go func() {
						defer close(joined)
						p, e := v.Evaluate(ctx, f.actor, f.scope, f.binding, canceledSigned)
						results <- hardeningResult{p, e}
					}()
					hardeningAwait(t, entered, "blocked source entry")
					cancel()
					canceled := hardeningAwait(t, results, "canceled Evaluate return")
					hardeningDenied(t, canceled, ErrCanceled)
					hardeningAwait(t, joined, "canceled Evaluate join")

					// Two waves of concurrent arrivals keep testing admission after cancellation.
					for wave := 0; wave < 2; wave++ {
						arrivals := make(chan hardeningResult, 8)
						start := make(chan struct{})
						for i := 0; i < cap(arrivals); i++ {
							done := make(chan struct{})
							arrivalJoins = append(arrivalJoins, done)
							go func() {
								defer close(done)
								<-start
								p, e := v.Evaluate(context.Background(), f.actor, f.scope, f.binding, canceledSigned)
								arrivals <- hardeningResult{p, e}
							}()
						}
						close(start)
						for i := 0; i < cap(arrivals); i++ {
							hardeningDenied(t, hardeningAwait(t, arrivals, "busy arrival"), ErrBusy)
						}
					}
					release() // The ignored cancellation now delivers its captured late allowed result.
					hardeningDrain(t, v)
					f.permission.mu.Lock()
					f.permission.block, f.permission.entered = nil, nil
					f.permission.o.EvidenceDigest = sha256.Sum256([]byte(fmt.Sprintf("fresh permission %s %d", source, cycle)))
					permissionDigest := f.permission.o.EvidenceDigest
					f.permission.mu.Unlock()
					f.inspection.mu.Lock()
					f.inspection.block, f.inspection.entered = nil, nil
					f.inspection.o.EvidenceDigest = sha256.Sum256([]byte(fmt.Sprintf("fresh inspection %s %d", source, cycle)))
					inspectionDigest := f.inspection.o.EvidenceDigest
					f.inspection.mu.Unlock()
					f.claims.ResultID = fmt.Sprintf("fresh-%s-%d", source, cycle)
					freshSigned := f.signed(t)
					fresh, err := v.Evaluate(context.Background(), f.actor, f.scope, f.binding, freshSigned)
					if err != nil {
						t.Fatal("fresh Evaluate after late return", err)
					}
					rechecked, err := v.Recheck(context.Background(), fresh, f.binding)
					if err != nil {
						t.Fatal("fresh Recheck after late return", err)
					}
					for _, p := range []Permit{fresh, rechecked} {
						projection, err := p.Projection()
						if err != nil || projection.EvidenceScope != "modeled" || projection.ResultID != f.claims.ResultID || projection.DecisionDigest != sha256.Sum256(freshSigned.Payload) || projection.PermissionEvidenceDigest != permissionDigest || projection.InspectionEvidenceDigest != inspectionDigest {
							t.Fatalf("fresh decision resurrected canceled/stale evidence: %#v, %v", projection, err)
						}
					}
					p, err := v.Recheck(context.Background(), canceled.permit, f.binding)
					hardeningDenied(t, hardeningResult{p, err}, ErrInvalidPermit)
				})
			}
		})
	}
}

type hardeningCountingPermission struct {
	source PermissionSource
	reads  atomic.Int64
}

func (p *hardeningCountingPermission) Check(ctx context.Context, h identity.ActorHandle, b action.Binding) (PermissionObservation, error) {
	p.reads.Add(1)
	return p.source.Check(ctx, h, b)
}

type hardeningCountingInspection struct {
	source Inspector
	reads  atomic.Int64
}

func (p *hardeningCountingInspection) Inspect(ctx context.Context, b action.Binding) (InspectionObservation, error) {
	p.reads.Add(1)
	return p.source.Inspect(ctx, b)
}

func TestEvaluateSignedMalformedDecisionStopsBeforeSources(t *testing.T) {
	f := newDecisionFixture(t, true)
	permission := &hardeningCountingPermission{source: f.permission}
	inspection := &hardeningCountingInspection{source: f.inspection}
	cfg := f.config
	cfg.PermissionSource, cfg.Inspector = permission, inspection
	v, err := NewValidator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	valid := f.signed(t)
	reordered := bytes.Clone(valid.Payload)
	first := 4 + len(decisionDomain)
	second := first + 6 + int(binary.BigEndian.Uint32(reordered[first+2:]))
	binary.BigEndian.PutUint16(reordered[first:], 2)
	binary.BigEndian.PutUint16(reordered[second:], 1)
	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{"boolean", replaceField(valid.Payload, 24, []byte{2})},
		{"optional_instance", replaceField(valid.Payload, 10, []byte{1})},
		{"numeric_width", replaceField(valid.Payload, 26, make([]byte, 7))},
		{"reordered_tag", reordered},
		{"truncated", bytes.Clone(valid.Payload[:len(valid.Payload)-1])},
		{"trailing", append(bytes.Clone(valid.Payload), 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Authentic producer signatures ensure malformed decoding, not signature rejection, is exercised.
			signed := SignedResult{tc.payload, ed25519.Sign(f.key, tc.payload)}
			if !ed25519.Verify(cfg.PublicKey, signed.Payload, signed.Signature) {
				t.Fatal("malformed frame signature is not authentic")
			}
			p, err := v.Evaluate(context.Background(), f.actor, f.scope, f.binding, signed)
			hardeningDenied(t, hardeningResult{p, err}, ErrInvalidResult)
			if permission.reads.Load() != 0 || inspection.reads.Load() != 0 {
				t.Fatalf("malformed frame reached sources: permission=%d inspection=%d", permission.reads.Load(), inspection.reads.Load())
			}
		})
	}
	t.Run("valid_positive_control", func(t *testing.T) {
		p, err := v.Evaluate(context.Background(), f.actor, f.scope, f.binding, valid)
		if err != nil {
			t.Fatal("valid signed positive control", err)
		}
		projection, err := p.Projection()
		if err != nil || projection.EvidenceScope != "modeled" {
			t.Fatal("positive control permit", projection, err)
		}
		if permission.reads.Load() != 1 || inspection.reads.Load() != 1 {
			t.Fatalf("positive control must read each source once: permission=%d inspection=%d", permission.reads.Load(), inspection.reads.Load())
		}
	})
}
