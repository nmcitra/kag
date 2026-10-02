package execution

import (
	"reflect"
	"testing"
)

func topologyStep(g topology, k topologyEventKind) topologyEvent {
	return topologyEvent{kind: k, expectRevision: g.revision, expectEpoch: g.epoch, nextEpoch: g.epoch + 1, retainedHead: head{"ledger", "model-lineage", "checkpoint", 10}, independentHead: head{"ledger", "model-lineage", "checkpoint", 10}, targetHead: head{"target", "model-lineage", "target-fence", 10}, evidenceRef: "authority-ref", oldAttempts: append([]string(nil), g.oldAttempts...), rejectedNamespaces: []string{"old-ns"}, restoreID: "restore-1"}
}
func TestPromotionOrderedGates(t *testing.T) {
	g := eligibleTopology()
	var err error
	g, err = reduceTopology(g, topologyStep(g, beginPromotion))
	if err != nil || g.phase != topologyClosed {
		t.Fatal(g, err)
	}
	for _, k := range []topologyEventKind{establishHead, acquireEpoch, acknowledgeTargetFence, reconcileTopology, retainReadiness, openTopology} {
		before := cloneTopology(g)
		for _, other := range []topologyEventKind{establishHead, acquireEpoch, acknowledgeTargetFence, reconcileTopology, retainReadiness, openTopology} {
			if other == k {
				continue
			}
			n, e := reduceTopology(g, topologyStep(g, other))
			if e == nil || !reflect.DeepEqual(n, before) {
				t.Fatal("out of order gate", k, other, n, e)
			}
		}
		g, err = reduceTopology(g, topologyStep(g, k))
		if err != nil {
			t.Fatal(k, g, err)
		}
		if k != openTopology && g.phase == topologyEligible {
			t.Fatal("early opening")
		}
	}
	if g.phase != topologyEligible || g.epoch != 2 {
		t.Fatal(g)
	}
}
func TestRestoreMissingConsumedTail(t *testing.T) {
	g := eligibleTopology()
	g.oldAttempts = []string{"attempt-old"}
	g, e := reduceTopology(g, topologyStep(g, beginRestore))
	if e != nil {
		t.Fatal(e)
	}
	evt := topologyStep(g, establishHead)
	evt.retainedHead.sequence = 1
	if n, e := reduceTopology(g, evt); e != ErrEvidence || n.phase == topologyEligible {
		t.Fatal(n, e)
	}
}
func TestTopologyForkAndClone(t *testing.T) {
	g := eligibleTopology()
	g, e := reduceTopology(g, topologyStep(g, beginPromotion))
	if e != nil {
		t.Fatal(e)
	}
	evt := topologyStep(g, establishHead)
	evt.independentHead.lineage = "fork"
	n, e := reduceTopology(g, evt)
	if e != ErrEvidence || n.phase == topologyEligible {
		t.Fatal(n, e)
	}
	copy := cloneTopology(g)
	copy.oldAttempts = append(copy.oldAttempts, "other")
	if len(g.oldAttempts) != 0 {
		t.Fatal("topology aliases")
	}
}
func TestUnknownCannotGC(t *testing.T) {
	m := newModelLedger(2)
	r, e := m.reserve(inputFixture(t))
	if e != nil {
		t.Fatal(e)
	}
	if e = m.retain(r.write); e != nil {
		t.Fatal(e)
	}
	key := r.row.input.replay
	row := cloneRecord(m.retained.rows[key])
	row.state = OutcomeUnknown
	row.attempt = attempt{id: "attempt-1"}
	m.retained.rows[key] = row
	if e = m.gc(key, true, true); e != ErrTransition || len(m.retained.rows) != 1 {
		t.Fatal(e)
	}
}
func TestModelTopologyAuthorityTables(t *testing.T) {
	for _, fault := range []string{"unknown-ref", "worker-epoch", "head-id", "target-fence-ref", "unretained-readiness", "readiness-head", "readiness-positive"} {
		t.Run(fault, func(t *testing.T) {
			h := newFaultHarness(t)
			a := newModelTopologyAuthority(h.m, h.target)
			g := a.initial()
			g, e := a.transition(g, beginPromotion, true)
			if e != nil {
				t.Fatal(e)
			}
			g, e = a.transition(g, establishHead, true)
			if e != nil {
				t.Fatal(e)
			}
			evt, e := a.issue(g, acquireEpoch)
			if e != nil {
				t.Fatal(e)
			}
			a.retain(evt.evidenceRef) // forge one field of an otherwise retained grant
			switch fault {
			case "unknown-ref":
				evt.evidenceRef = "unregistered"
			case "worker-epoch":
				evt.nextEpoch++
			case "head-id":
				evt.retainedHead.id = "forged"
			}
			if fault == "unknown-ref" || fault == "worker-epoch" || fault == "head-id" {
				if _, e = a.apply(g, evt); e != ErrEvidence {
					t.Fatal("forged epoch grant admitted", e)
				}
				return
			}
			a.retain(evt.evidenceRef)
			g, e = a.apply(g, evt)
			if e != nil {
				t.Fatal(e)
			}
			evt, e = a.issue(g, acknowledgeTargetFence)
			if e != nil {
				t.Fatal(e)
			}
			a.retain(evt.evidenceRef) // retained exact fence grant before isolated corruption
			if fault == "target-fence-ref" {
				evt.targetHead.id = "forged"
				if _, e = a.apply(g, evt); e != ErrEvidence {
					t.Fatal("forged fence admitted", e)
				}
				return
			}
			a.retain(evt.evidenceRef)
			g, e = a.apply(g, evt)
			if e != nil {
				t.Fatal(e)
			}
			g, e = a.transition(g, reconcileTopology, true)
			if e != nil {
				t.Fatal(e)
			}
			evt, e = a.issue(g, retainReadiness)
			if e != nil {
				t.Fatal(e)
			}
			if fault == "unretained-readiness" {
				if _, e = a.apply(g, evt); e != ErrEvidence {
					t.Fatal("unretained readiness opened", e)
				}
				return
			}
			a.retain(evt.evidenceRef)
			if fault == "readiness-head" {
				evt.retainedHead.sequence++
				if _, e = a.apply(g, evt); e != ErrEvidence {
					t.Fatal("forged readiness head admitted", e)
				}
				return
			}
			g, e = a.apply(g, evt)
			if e != nil {
				t.Fatal(e)
			}
			g, e = a.transition(g, openTopology, true)
			if e != nil || g.phase != topologyEligible || g.epoch != 2 || h.target.epoch != 2 {
				t.Fatal("exact topology authority positive denied", g, e)
			}
		})
	}
}
