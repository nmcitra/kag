package identity

import (
	"context"
	"testing"
	"time"
)

func TestResolvePositiveAndInvalidTransport(t *testing.T) {
	r, p, _, h, s := identityFixture(t)
	got, e := r.Resolve(context.Background(), h, s)
	if e != nil {
		t.Fatal(e)
	}
	v, e := got.Projection()
	if e != nil || v.ActorID != "a-1" || v.EvidenceLane != Modeled || v.IdentityProjectionDigest == ([32]byte{}) {
		t.Fatal(v, e)
	}
	v.ActorID = "changed"
	v2, _ := got.Projection()
	if v2.ActorID != "a-1" {
		t.Fatal(v2)
	}
	if _, e = r.Recheck(context.Background(), got, s); e != nil {
		t.Fatal(e)
	}
	p.mu.Lock()
	before := p.reads
	p.mu.Unlock()
	if _, e = r.Resolve(context.Background(), zeroTransport(), s); e != ErrTransportInvalid {
		t.Fatal(e)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.reads != before {
		t.Fatal("source consulted for invalid transport")
	}
}
func TestResolveNegativeFacts(t *testing.T) {
	cases := []struct {
		name   string
		change func(*NormalizedSnapshot)
		want   error
	}{{"missing", func(n *NormalizedSnapshot) { n.Mappings = nil }, ErrMappingMissing}, {"ambiguous", func(n *NormalizedSnapshot) { n.Mappings = append(n.Mappings, n.Mappings[0]) }, ErrMappingAmbiguous}, {"instance", func(n *NormalizedSnapshot) { n.Mappings[0].InstancePresent = false; n.Mappings[0].InstanceID = "" }, ErrInstanceUnattributed}, {"origin", func(n *NormalizedSnapshot) { n.Origin.ID = "spoof" }, ErrOriginUnverified}, {"pending", func(n *NormalizedSnapshot) { n.Lifecycle.Enrollment = "pending" }, ErrActorPending}, {"disabled", func(n *NormalizedSnapshot) { n.Lifecycle.Authority = "disabled" }, ErrActorDisabled}, {"deleted", func(n *NormalizedSnapshot) { n.Lifecycle.Authority = "deleted" }, ErrActorDeleted}, {"removed", func(n *NormalizedSnapshot) { n.Lifecycle.NodeState = "removed" }, ErrNodeRemoved}, {"revoked", func(n *NormalizedSnapshot) { n.Lifecycle.CredentialState = "revoked" }, ErrCredentialExpired}, {"floor", func(n *NormalizedSnapshot) { n.FloorWitness.Current = false }, ErrRestoreUnreconciled}, {"duplicate", func(n *NormalizedSnapshot) { n.Sources = append(n.Sources, n.Sources[0]) }, ErrEvidenceInvalid}, {"contract", func(n *NormalizedSnapshot) { n.Sources[0].ContractDigest[0] ^= 1 }, ErrContractIncompatible}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, p, _, h, s := identityFixture(t)
			p.mu.Lock()
			tc.change(&p.n)
			p.mu.Unlock()
			got, e := r.Resolve(context.Background(), h, s)
			if e != tc.want || got.state != nil {
				t.Fatal(got, e, tc.want)
			}
		})
	}
}
func TestRecheckSnapshotChangedAndDisable(t *testing.T) {
	r, p, _, h, s := identityFixture(t)
	got, e := r.Resolve(context.Background(), h, s)
	if e != nil {
		t.Fatal(e)
	}
	p.mu.Lock()
	p.n.Mappings[0].InstanceID = "i-2"
	p.n.Mappings[0].Revision++
	for i := range p.n.Sources {
		if p.n.Sources[i].Kind == "mapping" {
			p.n.Sources[i].Revision++
			p.n.Sources[i].EvidenceDigest[0] ^= 1
			p.n.FloorWitness.Heads[i].Revision++
			p.n.FloorWitness.Heads[i].ContentDigest = p.n.Sources[i].EvidenceDigest
		}
	}
	p.mu.Unlock()
	if next, e := r.Recheck(context.Background(), got, s); e != ErrSnapshotChanged || next.state != nil {
		t.Fatal(next, e)
	}
	p.mu.Lock()
	p.n.Lifecycle.Authority = "disabled"
	p.n.Lifecycle.Revision++
	for i := range p.n.Sources {
		if p.n.Sources[i].Kind == "lifecycle" {
			p.n.Sources[i].Revision++
			p.n.Sources[i].EvidenceDigest[0] ^= 1
			p.n.FloorWitness.Heads[i].Revision++
			p.n.FloorWitness.Heads[i].ContentDigest = p.n.Sources[i].EvidenceDigest
		}
	}
	p.mu.Unlock()
	if _, e = r.Resolve(context.Background(), h, s); e != ErrActorDisabled {
		t.Fatal(e)
	}
	if _, e = got.Projection(); e != ErrForeignHandle {
		t.Fatal(e)
	}
}
func TestBoundsBeforeVerifierAndConcurrency(t *testing.T) {
	r, p, _, h, s := identityFixture(t)
	p.raw = make([]byte, 8193)
	if _, e := r.Resolve(context.Background(), h, s); e != ErrEvidenceInvalid {
		t.Fatal(e)
	}
	if p.verifies != 0 {
		t.Fatal(p.verifies)
	}
	p.raw = []byte("snapshot")
	p.block = make(chan struct{})
	p.entered = make(chan struct{}, 2)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := r.Resolve(ctx, h, s); done <- e }()
	<-p.entered
	cancel()
	select {
	case e := <-done:
		if e != ErrCanceled {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation stuck")
	}
	r.config.MaxSourceCalls = 1 // configured semaphore itself still has two slots: occupy remaining.
	ctx2, cancel2 := context.WithCancel(context.Background())
	go func() { _, e := r.Resolve(ctx2, h, s); done <- e }()
	<-p.entered
	cancel2()
	<-done
	if _, e := r.Resolve(context.Background(), h, s); e != ErrBusy {
		t.Fatal(e)
	}
	close(p.block)
}
func TestFrozenWallFreshResolveDenied(t *testing.T) {
	r, _, c, h, s := identityFixture(t)
	if _, e := r.Resolve(context.Background(), h, s); e != nil {
		t.Fatal(e)
	}
	c.mu.Lock()
	c.s.ElapsedNS += 6e9
	c.mu.Unlock()
	if _, e := r.Resolve(context.Background(), h, s); e != ErrClockUncertain {
		t.Fatal(e)
	}
	if r.Status(context.Background()).State != "unavailable" {
		t.Fatal("clock gate open")
	}
}
func TestCanonicalGranularity(t *testing.T) {
	r, _, _, _, _ := identityFixture(t)
	c := r.config
	c.Profiles[0].Granularity = "instance-required"
	if _, e := NewResolver(c); e != nil {
		t.Fatal("canonical granularity denied", e)
	}
	c.Profiles[0].Granularity = "instance"
	if _, e := NewResolver(c); e != ErrContractIncompatible {
		t.Fatal("short alias admitted", e)
	}
}
func TestProjectionChecksCurrentClock(t *testing.T) {
	r, _, c, h, s := identityFixture(t)
	actor, e := r.Resolve(context.Background(), h, s)
	if e != nil {
		t.Fatal(e)
	}
	c.mu.Lock()
	c.s.WallUnixNS += 5e9
	c.s.ElapsedNS += 5e9
	c.mu.Unlock()
	if p, e := actor.Projection(); e == nil || p.ActorID != "" {
		t.Fatal("expired handle projected", p, e)
	}
}
func TestRevisionRollbackHoldsExistingHandles(t *testing.T) {
	r, p, _, h, s := identityFixture(t)
	actor, e := r.Resolve(context.Background(), h, s)
	if e != nil {
		t.Fatal(e)
	}
	p.mu.Lock()
	p.n.Mappings[0].Revision--
	for i := range p.n.Sources {
		if p.n.Sources[i].Kind == "mapping" {
			p.n.Sources[i].Revision--
			p.n.FloorWitness.Heads[i].Revision--
		}
	}
	p.mu.Unlock()
	if _, e = r.Resolve(context.Background(), h, s); e != ErrRevisionRollback {
		t.Fatal(e)
	}
	if _, e = actor.Projection(); e == nil {
		t.Fatal("rollback gate retained authority")
	}
}
func TestStatusOwnerClose(t *testing.T) {
	r, _, _, h, s := identityFixture(t)
	if _, e := r.Resolve(context.Background(), h, s); e != nil {
		t.Fatal(e)
	}
	if r.Status(context.Background()).State != "model_only" {
		t.Fatal("missing modeled status")
	}
	r.config.Acceptor.Close()
	if r.Status(context.Background()).State != "unavailable" {
		t.Fatal("closed owner reported available")
	}
}
