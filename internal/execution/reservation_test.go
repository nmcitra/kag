package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/gatekeeper454/KTP-Component-Dev/internal/action"
	"github.com/gatekeeper454/KTP-Component-Dev/internal/decision"
	"testing"
)

func TestNewReservationPermitBinding(t *testing.T) {
	f := newDecisionFixture(t, true)
	p, e := f.validator.Evaluate(context.Background(), f.actor, f.scope, f.binding, f.signed(t))
	if e != nil {
		t.Fatal(e)
	}
	r, e := NewReservation(f.binding, p, "model-ns")
	if e != nil || r.BindingDigest() != f.binding.Digest() || r.OperationDigest() != f.binding.Operation().Digest() || r.IdentityProjectionDigest() != f.claims.IdentityProjectionDigest {
		t.Fatal(r, e)
	}
	other := newDecisionFixture(t, true)
	p2, e := other.validator.Evaluate(context.Background(), other.actor, other.scope, other.binding, other.signed(t))
	if e != nil {
		t.Fatal(e)
	}
	if r, e := NewReservation(f.binding, p2, "model-ns"); e != ErrConflict || r.EvidenceScope() != "" {
		t.Fatal("foreign binding accepted", r, e)
	}
}
func TestNewReservationModeledOwnerLane(t *testing.T) {
	if _, e := NewReservation(action.Binding{}, decision.Permit{}, "model-ns"); e != ErrInvalid {
		t.Fatal(e)
	}
	f := newDecisionFixture(t, true)
	p, e := f.validator.Evaluate(context.Background(), f.actor, f.scope, f.binding, f.signed(t))
	if e != nil {
		t.Fatal(e)
	}
	for _, ns := range []string{"", "BAD", "-bad", string(make([]byte, 129))} {
		if _, e := NewReservation(f.binding, p, ns); e != ErrInvalid {
			t.Fatal(ns, e)
		}
	}
	var restored decision.Permit
	b, _ := json.Marshal(p)
	if e := json.Unmarshal(b, &restored); e != nil {
		t.Fatal(e)
	}
	if _, e := NewReservation(f.binding, restored, "model-ns"); e != ErrInvalid {
		t.Fatal("restored projection accepted", e)
	}
	f.clock.advance(3e9)
	if _, e := NewReservation(f.binding, p, "model-ns"); e != ErrInvalid {
		t.Fatal("expired permit admitted", e)
	}
}
func TestNewReservationSeedIsAbsent(t *testing.T) {
	for _, marker := range []bool{false, true} {
		f := newDecisionFixture(t, marker)
		p, e := f.validator.Evaluate(context.Background(), f.actor, f.scope, f.binding, f.signed(t))
		if e != nil {
			t.Fatal(e)
		}
		r, e := NewReservation(f.binding, p, "model-ns")
		if e != nil || r.State() != Absent || r.EvidenceScope() != "modeled" || r.Namespace() != "model-ns" || r.ReplayID() != f.binding.Operation().ReplayID() {
			t.Fatal(r, e)
		}
		b := r.BindingBytes()
		b[0] ^= 1
		if bytes.Equal(b, r.BindingBytes()) {
			t.Fatal("seed bytes alias")
		}
		o := r.OperationBytes()
		o[0] ^= 1
		if bytes.Equal(o, r.OperationBytes()) {
			t.Fatal("operation bytes alias")
		}
		q, _ := p.Projection()
		if r.ValidFromUnixNS() != q.ValidFromUnixNS || r.ExpiresUnixNS() != q.ExpiresUnixNS {
			t.Fatal("seed lifetime changed")
		}
	}
}
