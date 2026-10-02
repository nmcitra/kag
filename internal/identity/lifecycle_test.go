package identity

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func bump(n *NormalizedSnapshot, kind string) {
	for i := range n.Sources {
		if n.Sources[i].Kind == kind {
			n.Sources[i].Revision++
			n.Sources[i].EvidenceDigest[0]++
			for j := range n.FloorWitness.Heads {
				if n.FloorWitness.Heads[j].SourceID == n.Sources[i].ID {
					n.FloorWitness.Heads[j].Revision = n.Sources[i].Revision
					n.FloorWitness.Heads[j].ContentDigest = n.Sources[i].EvidenceDigest
				}
			}
		}
	}
}
func TestCombinedDeletionKeepsTombstone(t *testing.T) {
	r, p, _, h, s := identityFixture(t)
	if _, e := r.Resolve(context.Background(), h, s); e != nil {
		t.Fatal(e)
	}
	p.mu.Lock()
	p.n.Lifecycle.Authority = "deleted"
	p.n.Lifecycle.CredentialState = "revoked"
	p.n.Lifecycle.NodeState = "removed"
	p.n.Lifecycle.Revision++
	bump(&p.n, "lifecycle")
	p.mu.Unlock()
	if actor, e := r.Resolve(context.Background(), h, s); e == nil || actor.state != nil {
		t.Fatal("combined deletion admitted")
	}
	p.mu.Lock()
	p.n.Lifecycle.Authority = "enabled"
	p.n.Lifecycle.CredentialState = "valid"
	p.n.Lifecycle.NodeState = "active"
	p.n.Lifecycle.Revision++
	bump(&p.n, "lifecycle")
	p.mu.Unlock()
	if actor, e := r.Resolve(context.Background(), h, s); e != ErrContinuityConflict || actor.state != nil {
		t.Fatal("same epoch resurrected deletion", actor, e)
	}
}
func TestTombstoneHigherEpochReenrollment(t *testing.T) {
	r, p, _, h, s := identityFixture(t)
	old, e := r.Resolve(context.Background(), h, s)
	if e != nil {
		t.Fatal(e)
	}
	p.mu.Lock()
	p.n.Lifecycle.Authority = "deleted"
	p.n.Lifecycle.Revision++
	bump(&p.n, "lifecycle")
	p.mu.Unlock()
	if _, e = r.Resolve(context.Background(), h, s); e != ErrActorDeleted {
		t.Fatal(e)
	}
	p.mu.Lock()
	p.n.Lifecycle.Authority = "enabled"
	p.n.Lifecycle.Enrollment = "reenrolled"
	p.n.Lifecycle.Revision++
	p.n.Lifecycle.ContinuityEpoch++
	p.n.Mappings[0].ContinuityEpoch++
	p.n.Mappings[0].Revision++
	bump(&p.n, "mapping")
	bump(&p.n, "lifecycle")
	for i := range p.n.FloorWitness.Heads {
		p.n.FloorWitness.Heads[i].ContinuityEpoch = p.n.Mappings[0].ContinuityEpoch
	}
	p.mu.Unlock()
	newActor, e := r.Resolve(context.Background(), h, s)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = old.Projection(); e != ErrForeignHandle {
		t.Fatal(e)
	}
	if _, e = r.Recheck(context.Background(), newActor, s); e != nil {
		t.Fatal(e)
	}
}

type snapshotPort struct {
	mu             sync.Mutex
	n              NormalizedSnapshot
	block, entered chan struct{}
}

func (p *snapshotPort) Read(ctx context.Context, q Query) ([]byte, error) {
	p.mu.Lock()
	b, e := json.Marshal(p.n)
	block, entered := p.block, p.entered
	p.mu.Unlock()
	if entered != nil {
		close(entered)
	}
	if block != nil {
		<-block
	}
	return b, e
}
func (p *snapshotPort) Normalize(ctx context.Context, b []byte, q Query) (NormalizedSnapshot, error) {
	var n NormalizedSnapshot
	e := json.Unmarshal(b, &n)
	return n, e
}
func TestOldEnabledReadCannotOverwriteNewDisable(t *testing.T) {
	r, p, _, h, s := identityFixture(t)
	old, e := r.Resolve(context.Background(), h, s)
	if e != nil {
		t.Fatal(e)
	}
	atomic := &snapshotPort{n: clone(p.n), block: make(chan struct{}), entered: make(chan struct{})}
	r.config.Source = atomic
	r.config.Verifier = atomic
	done := make(chan error, 1)
	go func() {
		actor, e := r.Resolve(context.Background(), h, s)
		if actor.state != nil {
			done <- ErrEvidenceInvalid
		} else {
			done <- e
		}
	}()
	<-atomic.entered
	release := atomic.block
	atomic.mu.Lock()
	atomic.block = nil
	atomic.entered = nil
	atomic.n.Lifecycle.Authority = "disabled"
	atomic.n.Lifecycle.Revision++
	bump(&atomic.n, "lifecycle")
	atomic.mu.Unlock()
	if _, e = r.Resolve(context.Background(), h, s); e != ErrActorDisabled {
		t.Fatal(e)
	}
	close(release)
	select {
	case e := <-done:
		if e != ErrRevisionRollback {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("old source read did not finish")
	}
	if _, e = old.Projection(); e != ErrForeignHandle {
		t.Fatal(e)
	}
}
func TestKnownDeletionSurvivesFramingOverflow(t *testing.T) {
	r, p, _, h, s := identityFixture(t)
	old, e := r.Resolve(context.Background(), h, s)
	if e != nil {
		t.Fatal(e)
	}
	p.mu.Lock()
	n := clone(p.n)
	n.Lifecycle.Authority = "deleted"
	n.Lifecycle.Revision++
	bump(&n, "lifecycle")
	kinds := []string{"mapping", "lifecycle", "origin", "profile", "context", "human", "delegation", "permission"}
	wall := r.last.WallUnixNS
	n.Sources = nil
	n.FloorWitness.Heads = nil
	contextID := ""
	for i, kind := range kinds {
		id := strings.Repeat("s", 126) + strconv.Itoa(i)
		if kind == "lifecycle" {
			id = "lifecycle"
		}
		d := sha256.Sum256([]byte(kind))
		rev := uint64(1)
		if kind == "mapping" {
			rev = n.Mappings[0].Revision
		}
		if kind == "lifecycle" {
			rev = n.Lifecycle.Revision
			d[0]++
		}
		bound := strings.Repeat("b", 126) + strconv.Itoa(i)
		n.Sources = append(n.Sources, SourceReference{ID: id, Kind: kind, BoundID: bound, ContractDigest: sha256.Sum256([]byte(kind)), EvidenceDigest: d, Revision: rev, ObservedUnixNS: wall, ValidatedUnixNS: wall, ValidFromUnixNS: wall - 1, ExpiresUnixNS: wall + 30e9})
		n.FloorWitness.Heads = append(n.FloorWitness.Heads, Head{SourceID: id, Domain: kind, TenantID: "t-a", ActorID: "a-1", Revision: rev, ContinuityEpoch: 3, ContentDigest: d})
		r.contracts[id] = SourceContract{ID: id, BoundID: bound, ContractDigest: n.Sources[i].ContractDigest, MaxAgeNS: 20e9}
		if kind == "context" {
			contextID = id
		}
	}
	for i := 0; i < 8; i++ {
		n.Context = append(n.Context, ContextEntry{Key: strings.Repeat("c", 126) + strconv.Itoa(i), Value: strings.Repeat("v", 256), SourceID: contextID, ValidFromUnixNS: wall - 1, ExpiresUnixNS: wall + 30e9})
	}
	if !bounded(n) {
		t.Fatal("fixture raw strings not within bounded normalized shape")
	}
	transport, e := r.config.Acceptor.Validate(h, time.Unix(0, wall))
	if e != nil {
		t.Fatal(e)
	}
	scope, _ := s.Projection()
	if _, e = measureSnapshot(n, transport, scope, r.profiles[scope.OperationID]); e != ErrEvidenceInvalid {
		t.Fatal("fixture did not exceed encoded limit", e)
	}
	p.n = n
	p.mu.Unlock()
	if actor, e := r.Resolve(context.Background(), h, s); e != ErrActorDeleted || actor.state != nil {
		t.Fatal("known deletion lost to framing limit", actor, e)
	}
	if _, e = old.Projection(); e != ErrForeignHandle {
		t.Fatal("known deletion left old handle alive", e)
	}
}
