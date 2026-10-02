package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"github.com/nmcitra/kag/internal/action"
	"testing"
)

func TestScopeAndZeroHandle(t *testing.T) {
	if _, e := NewResolveScope(action.ParsedAction{}, action.TargetID); e != ErrScopeInvalid {
		t.Fatal(e)
	}
	a, e := action.ParseMCPArguments("lab.read_status", []byte("{}"))
	if e != nil {
		t.Fatal(e)
	}
	s, e := NewResolveScope(a, action.TargetID)
	if e != nil {
		t.Fatal(e)
	}
	p, e := s.Projection()
	if e != nil || p.IntentDigest != a.IntentDigest() {
		t.Fatal(p, e)
	}
	if _, e = NewResolveScope(a, "wrong"); e != ErrScopeInvalid {
		t.Fatal(e)
	}
	if _, e = (ActorHandle{}).Projection(); e != ErrForeignHandle {
		t.Fatal(e)
	}
	var r Resolver
	if _, e = r.Resolve(context.Background(), zeroTransport(), s); e != ErrContractIncompatible {
		t.Fatal(e)
	}
}
func TestPrivateCanonicalSnapshotRetained(t *testing.T) {
	r, p, _, h, s := identityFixture(t)
	actor, e := r.Resolve(context.Background(), h, s)
	if e != nil {
		t.Fatal(e)
	}
	if len(actor.state.snapshot) == 0 || len(actor.state.snapshot) > 8192 || sha256.Sum256(actor.state.snapshot) != actor.state.projection.IdentityProjectionDigest {
		t.Fatal("private canonical snapshot missing")
	}
	original := bytes.Clone(actor.state.snapshot)
	p.mu.Lock()
	p.n.Mappings[0].ActorID = "changed"
	p.mu.Unlock()
	if !bytes.Equal(actor.state.snapshot, original) {
		t.Fatal("source mutation changed owned snapshot")
	}
}
