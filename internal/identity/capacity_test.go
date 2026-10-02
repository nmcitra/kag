package identity

import (
	"context"
	"testing"
	"time"
)

func TestHeadCapacityNeverEvicts(t *testing.T) {
	r, _, _, h, s := identityFixture(t)
	r.config.MaxHeads = 3
	if actor, e := r.Resolve(context.Background(), h, s); e != ErrBusy || actor.state != nil {
		t.Fatal(actor, e)
	}
	if len(r.heads) != 0 {
		t.Fatal("partial head commit")
	}
}
func TestTombstoneCapacityCannotForgetKnownDeletion(t *testing.T) {
	r, p, _, h, s := identityFixture(t)
	r.config.MaxTombstones = 1
	if _, e := r.Resolve(context.Background(), h, s); e != nil {
		t.Fatal(e)
	}
	p.n.Lifecycle.Authority = "deleted"
	p.n.Lifecycle.Revision++
	bump(&p.n, "lifecycle")
	if _, e := r.Resolve(context.Background(), h, s); e != ErrActorDeleted {
		t.Fatal(e)
	}
	p.n.Mappings[0].ActorID = "a-2"
	p.n.Mappings[0].Revision++
	bump(&p.n, "mapping")
	p.n.Lifecycle.Authority = "enabled"
	for i := range p.n.FloorWitness.Heads {
		p.n.FloorWitness.Heads[i].ActorID = "a-2"
	}
	old, e := r.Resolve(context.Background(), h, s)
	if e != nil {
		t.Fatal(e)
	}
	p.n.Lifecycle.Authority = "deleted"
	p.n.Lifecycle.Revision++
	bump(&p.n, "lifecycle")
	if actor, e := r.Resolve(context.Background(), h, s); e != ErrBusy || actor.state != nil {
		t.Fatal(actor, e)
	}
	if _, e := old.Projection(); e == nil {
		t.Fatal("unretained deletion left old actor valid")
	}
	p.n.Lifecycle.Authority = "enabled"
	p.n.Lifecycle.Revision++
	bump(&p.n, "lifecycle")
	if actor, e := r.Resolve(context.Background(), h, s); e != ErrBusy || actor.state != nil {
		t.Fatal("tombstone overflow forgot deletion", actor, e)
	}
}

// The first read passes entry admission before the second read exhausts the
// permanent floor budget. Releasing it must never clear that failure latch.
func TestInFlightPositiveCannotClearHeadCapacityLatch(t *testing.T) {
	r, p, _, h, s := identityFixture(t)
	r.config.MaxHeads = 4
	initial, e := r.Resolve(context.Background(), h, s)
	if e != nil {
		t.Fatal(e)
	}
	port := &snapshotPort{n: clone(p.n), block: make(chan struct{}), entered: make(chan struct{})}
	r.config.Source = port
	r.config.Verifier = port
	type outcome struct {
		actor ActorHandle
		err   error
	}
	done := make(chan outcome, 1)
	go func() { actor, e := r.Resolve(context.Background(), h, s); done <- outcome{actor, e} }()
	<-port.entered
	release := port.block
	port.mu.Lock()
	port.block = nil
	port.entered = nil
	port.n.Mappings[0].ActorID = "a-2"
	for i := range port.n.FloorWitness.Heads {
		port.n.FloorWitness.Heads[i].ActorID = "a-2"
	}
	port.mu.Unlock()
	if actor, e := r.Resolve(context.Background(), h, s); e != ErrBusy || actor.state != nil {
		t.Fatal("capacity failure did not close authority", actor, e)
	}
	close(release)
	select {
	case got := <-done:
		if got.err != ErrBusy || got.actor.state != nil {
			t.Fatal("in-flight positive cleared permanent capacity failure", got.actor, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight read did not finish")
	}
	if _, e := initial.Projection(); e != ErrForeignHandle {
		t.Fatal("old handle survived permanent capacity failure", e)
	}
	if status := r.Status(context.Background()); status.State != "unavailable" {
		t.Fatal("permanent capacity failure became available", status)
	}
}
func TestPermanentCapacityLatchRejectsProjectionAndStatus(t *testing.T) {
	r, _, _, h, s := identityFixture(t)
	actor, e := r.Resolve(context.Background(), h, s)
	if e != nil {
		t.Fatal(e)
	}
	r.mu.Lock()
	r.capacityFailed = true
	r.held = false
	r.mu.Unlock()
	if p, e := actor.Projection(); e != ErrForeignHandle || p.ActorID != "" {
		t.Fatal("projection ignored permanent capacity latch", p, e)
	}
	if status := r.Status(context.Background()); status.State != "unavailable" {
		t.Fatal("status ignored permanent capacity latch", status)
	}
}
func TestInFlightPositiveCannotClearTombstoneCapacityLatch(t *testing.T) {
	r, p, _, h, s := identityFixture(t)
	r.config.MaxTombstones = 1
	if _, e := r.Resolve(context.Background(), h, s); e != nil {
		t.Fatal(e)
	}
	p.n.Lifecycle.Authority = "deleted"
	p.n.Lifecycle.Revision++
	bump(&p.n, "lifecycle")
	if _, e := r.Resolve(context.Background(), h, s); e != ErrActorDeleted {
		t.Fatal(e)
	}
	p.n.Mappings[0].ActorID = "a-2"
	p.n.Mappings[0].Revision++
	bump(&p.n, "mapping")
	p.n.Lifecycle.Authority = "enabled"
	for i := range p.n.FloorWitness.Heads {
		p.n.FloorWitness.Heads[i].ActorID = "a-2"
	}
	old, e := r.Resolve(context.Background(), h, s)
	if e != nil {
		t.Fatal(e)
	}
	port := &snapshotPort{n: clone(p.n), block: make(chan struct{}), entered: make(chan struct{})}
	r.config.Source = port
	r.config.Verifier = port
	type outcome struct {
		actor ActorHandle
		err   error
	}
	done := make(chan outcome, 1)
	go func() { actor, e := r.Resolve(context.Background(), h, s); done <- outcome{actor, e} }()
	<-port.entered
	release := port.block
	port.mu.Lock()
	port.block = nil
	port.entered = nil
	port.n.Lifecycle.Authority = "deleted"
	port.n.Lifecycle.Revision++
	bump(&port.n, "lifecycle")
	port.mu.Unlock()
	if actor, e := r.Resolve(context.Background(), h, s); e != ErrBusy || actor.state != nil {
		t.Fatal(actor, e)
	}
	close(release)
	select {
	case got := <-done:
		if got.err != ErrBusy || got.actor.state != nil {
			t.Fatal("in-flight positive forgot deletion capacity latch", got.actor, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight read did not finish")
	}
	if _, e := old.Projection(); e != ErrForeignHandle {
		t.Fatal(e)
	}
	if r.Status(context.Background()).State != "unavailable" {
		t.Fatal("capacity latch became available")
	}
}
