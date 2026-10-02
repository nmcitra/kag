package execution

import (
	"crypto/sha256"
	"fmt"
	"github.com/nmcitra/kag/internal/action"
	"reflect"
	"strconv"
	"testing"
)

type faultHarness struct {
	t                               testing.TB
	m                               *modelLedger
	target                          *modelTarget
	recorder                        modelRecorder
	g                               topology
	r                               record
	sent                            map[string]bool
	known                           bool
	ackAt                           int64
	tick                            int64
	trace                           []string
	writerReceipts                  map[string]deliverySummary
	auditReceipts                   map[string]evidence
	writerAvailable                 bool
	authorityAvailable              bool
	overloaded, restoring           bool
	reconcileUsed, reconcileLimit   int
	managementUsed, managementLimit int
	recoveryDeadline                int64
}

func TestD01AtomicReplayBudget(t *testing.T) {
	t.Run("same-head-CAS", TestConcurrentCASProposals)
	for _, variant := range []string{"same", "actor", "action", "target-version", "decision", "deadline", "noncanonical-replay", "last-cost-unit"} {
		t.Run(variant, func(t *testing.T) {
			if variant == "last-cost-unit" {
				TestTwoDifferentKeysFinalCostSameHead(t)
				return
			}
			h := newFaultHarness(t)
			in := h.r.input
			other := variantInput(t, in, variant)
			before := h.m.retained.budgets["global"]
			result, e := h.m.reserve(other)
			if variant == "same" {
				if e != nil || result.class != reserveJoin {
					t.Fatal(result, e)
				}
			} else if variant == "noncanonical-replay" {
				if e != ErrInvalid {
					t.Fatal(e)
				}
			} else if e != ErrConflict {
				t.Fatal(variant, e)
			}
			if h.m.retained.budgets["global"] != before {
				t.Fatal("conflict changed balance")
			}
			h.assertNoEffect()
		})
	}
	positiveControl(t)
}
func TestD02LostForgedACK(t *testing.T) {
	for _, cut := range []string{"before-reserve", "staged-row-budget", "after-local-write", "after-retain-before-ACK", "forged-store", "forged-recorder", "unavailable-ledger", "full-budget", "recorder-saturation", "absent-lookup"} {
		t.Run(cut, func(t *testing.T) {
			h := newFaultHarness(t)
			switch cut {
			case "before-reserve":
				m := newModelLedger(2)
				if len(m.local.rows) != 0 || len(m.retained.rows) != 0 || m.local.budgets["global"].held != 0 {
					t.Fatal("before-reserve not empty")
				}
				h.note("cut before reservation proposal: zero rows/holds")
			case "staged-row-budget":
				m := newModelLedger(2)
				r, proposal, e := m.previewReservation(inputFixture(t))
				if e != nil || r.state != ReservedPendingACK || len(proposal.rows) != 1 || proposal.budgets["global"].held != 1 || proposal.budgets["tenant"].held != 1 || len(m.writes) != 0 || len(m.local.rows) != 0 || len(m.retained.rows) != 0 {
					t.Fatal("pre-write row/whole-vector candidate leaked", e)
				}
				h.note("pre-write proposal only: candidate rows=1 global+tenant holds=1 local/retained rows=0 writeRefs=0")
				m.crash()
			case "after-local-write":
				m := newModelLedger(2)
				r, e := m.reserve(inputFixture(t))
				if e != nil {
					t.Fatal(e)
				}
				if len(m.retained.rows) != 0 || m.retained.budgets["global"].held != 0 || len(m.local.rows) != 1 || m.local.budgets["global"].held != 1 || m.local.budgets["tenant"].held != 1 || len(m.writes) != 1 || m.local.head != r.write.head {
					t.Fatal("local row + complete budget write not atomic")
				}
				h.note("local write head=" + r.write.head.id + " retained rows/holds=0 no ACK")
				if _, e = m.receipt(r.write); e != ErrEvidence {
					t.Fatal(e)
				}
				m.crash()
				if len(m.local.rows) != 0 || m.local.budgets["global"].held != 0 {
					t.Fatal("unretained write survived crash")
				}
			case "after-retain-before-ACK":
				h.m.crash()
				row, rc, e := h.m.lookup(h.r.input.replay)
				if e != nil || row.state != ReservedPendingACK || !h.m.validReceipt(rc) {
					t.Fatal(e)
				}
				h.note("retained reserve ACK dropped; authoritative lookup recovered exact receipt " + rc.receiptID)
			case "forged-store", "forged-recorder":
				_, rc, e := h.m.lookup(h.r.input.replay)
				if e != nil {
					t.Fatal(e)
				}
				if cut == "forged-recorder" {
					rc, e = h.recorder.append(h.r)
					if e != nil {
						t.Fatal(e)
					}
					h.m.external[rc.receiptID] = rc
				}
				rc.head.sequence++
				if h.m.validReceipt(rc) {
					t.Fatal("forged retained receipt accepted")
				}
				h.note("forged " + cut + " nonzero head rejected")
			case "unavailable-ledger":
				h.m.unavailable = true
				if _, _, e := h.m.lookup(h.r.input.replay); e != ErrClosed {
					t.Fatal(e)
				}
			case "full-budget":
				h.m.retained.budgets["global"] = account{1, 1, 0}
				h.m.local = cloneImage(h.m.retained)
				if _, e := h.m.reserve(variantInput(t, h.r.input, "last-cost-unit")); e != ErrBudget {
					t.Fatal(e)
				}
			case "recorder-saturation":
				h.recorder.max = 1
				if _, e := h.recorder.append(h.r); e != nil {
					t.Fatal(e)
				}
				other := cloneRecord(h.r)
				other.input.reservationID = "other"
				if _, e := h.recorder.append(other); e != ErrBusyModel {
					t.Fatal(e)
				}
			case "absent-lookup":
				if _, _, e := h.m.lookup(replayIdentity{"model-ns", "ffffffffffffffffffffffffffffffff"}); e != ErrEvidence {
					t.Fatal(e)
				}
			}
			if h.release(currentFor(h.r, 5), 5) {
				t.Fatal("premature release")
			}
			h.assertNoEffect()
		})
	}
	positiveControl(t)
}
func TestD03SeparateRecorderGaps(t *testing.T) {
	for _, cut := range []string{"retained-reserve", "recorder-before-receipt", "recorder-before-attachment", "attachment-before-readiness-ACK", "append-repeat", "append-conflict", "orphan-recorder"} {
		t.Run(cut, func(t *testing.T) {
			h := newFaultHarness(t)
			var rc evidence
			var e error
			if cut != "retained-reserve" {
				rc, e = h.recorder.append(h.r)
				if e != nil {
					t.Fatal(e)
				}
			}
			switch cut {
			case "retained-reserve":
				if len(h.recorder.rows) != 0 || h.r.recorderReceipt != (evidence{}) {
					t.Fatal("recorder not absent")
				}
				h.note("reserve ACK retained before any recorder append")
			case "recorder-before-receipt":
				if len(h.recorder.rows) != 1 || h.m.validReceipt(rc) {
					t.Fatal("recorder ACK not dropped")
				}
				h.note("recorder durable append; receipt delivery dropped before gateway authority table")
			case "recorder-before-attachment":
				h.m.external[rc.receiptID] = rc
				if !h.m.validReceipt(rc) || h.r.recorderReceipt != (evidence{}) {
					t.Fatal("attachment cut not pending")
				}
				h.note("recorder receipt delivered; reservation attachment not proposed")
			case "append-repeat":
				again, e := h.recorder.append(h.r)
				if e != nil || again != rc || len(h.recorder.rows) != 1 {
					t.Fatal(e)
				}
				h.note("same recorder append joined exact receipt")
			case "append-conflict":
				other := cloneRecord(h.r)
				other.input.decision.digest[0] ^= 1
				if _, e := h.recorder.append(other); e != ErrConflict {
					t.Fatal(e)
				}
				h.note("changed decision conflicts at recorder append")
			case "attachment-before-readiness-ACK":
				h.m.external[rc.receiptID] = rc
				_, reserve, _ := h.m.lookup(h.r.input.replay)
				evt := readyEvent(h.r)
				evt.reservationReceipt = reserve
				evt.recorderReceipt = rc
				w, err := h.m.propose(h.r, evt, h.g)
				if err != nil {
					t.Fatal(err)
				}
				if err = h.m.retain(w); err != nil {
					t.Fatal(err)
				}
				if h.m.retained.rows[h.r.input.replay].state != Ready || h.r.state != ReservedPendingACK {
					t.Fatal("durable readiness cut not isolated")
				}
				h.known = false
				h.note("attachment and Ready write retained; readiness ACK delivery dropped, gateway remains Pending")
			case "orphan-recorder":
				h.m = newModelLedger(2)
				if _, _, e := h.m.lookup(h.r.input.replay); e != ErrEvidence || len(h.recorder.rows) != 1 {
					t.Fatal("orphan cut not isolated", e)
				}
				h.note("recorder retained but authoritative reservation absent")
			}
			h.m.crash()
			if h.release(currentFor(h.r, 5), 5) {
				t.Fatal("gap released")
			}
			h.assertNoEffect()
		})
	}
	positiveControl(t)
}
func TestD04ReadyRecheck(t *testing.T) {
	for _, variant := range []string{"decision-expiry", "lifecycle-expiry", "permission-expiry", "inspection-expiry", "actor-revoked", "mapping-change", "catalog-change", "operation-change", "clock-forward", "clock-backward", "source-unavailable"} {
		t.Run(variant, func(t *testing.T) {
			h := newFaultHarness(t)
			h.makeReady()
			h.m.crash()
			e := consumeEvent(h.r)
			obs := freshModeledSources()
			switch variant {
			case "decision-expiry", "lifecycle-expiry", "permission-expiry", "inspection-expiry":
				name := variant[:len(variant)-len("-expiry")]
				x := obs[name]
				x.expires = e.at
				obs[name] = x
				e.check = recheckSources(h.r, obs, e.at)
				h.note(fmt.Sprintf("specific source expiry %s observations=%v", name, obs))
			case "actor-revoked":
				e.check.class = recheckRevoked
			case "mapping-change":
				e.check.actorProjectionDigest[0] ^= 1
			case "catalog-change":
				e.check.bindingDigest[0] ^= 1
			case "operation-change":
				e.check.operationDigest[0] ^= 1
			case "clock-forward":
				e.at = 1000
			case "clock-backward":
				e.check.checkedAt = -1
			case "source-unavailable":
				e.check.class = recheckUnavailable
			}
			if _, err := h.m.propose(h.r, e, h.g); err != ErrEvidence {
				t.Fatal(variant, err)
			}
			h.withhold()
			a := h.m.retained.budgets["global"]
			if a.held != 0 || a.spent != 0 || h.r.budget != budgetRefunded {
				t.Fatal(a)
			}
			h.assertNoEffect()
		})
	}
	positiveControl(t)
}
func TestD05ConsumedUncertainty(t *testing.T) {
	for _, cut := range []string{"consume-ACK-lost", "crash-after-ACK-before-send", "partial-delivery", "terminal-refusal-reply-lost", "delayed-buffered-delivery", "lookup-not-found", "lookup-stale", "lookup-unavailable", "unknown-deadline"} {
		t.Run(cut, func(t *testing.T) {
			h := newFaultHarness(t)
			h.makeReady()
			h.makeConsumed()
			switch cut {
			case "consume-ACK-lost":
				h.known = false
				h.m.crash()
				row, _, e := h.m.lookup(h.r.input.replay)
				if e != nil || row.state != AttemptConsumed || row.attempt.id != h.r.attempt.id {
					t.Fatal("consumed retained lookup failed", e)
				}
				h.note("consume retained, ACK dropped; exact historical attempt lookup, no new send knowledge")
			case "crash-after-ACK-before-send":
				if !h.m.validReceipt(h.r.consumeReceipt) {
					t.Fatal("ACK was never delivered")
				}
				h.known = false
				h.m.crash()
				h.note("delivered consume ACK then crash before any arrival")
			case "partial-delivery", "delayed-buffered-delivery", "terminal-refusal-reply-lost":
				if !h.release(currentFor(h.r, 5), 5) {
					t.Fatal("complete initial release denied")
				}
				if cut != "partial-delivery" {
					x, e := h.target.closeNoEffect(h.r.attempt.id)
					if e != nil {
						t.Fatal(e)
					}
					if _, e = h.target.commit(h.r.attempt.id, 6); e == nil {
						t.Fatal("closed delayed attempt committed")
					}
					if cut == "delayed-buffered-delivery" {
						h.confirm(x)
					}
				}
			case "lookup-not-found":
				if _, e := h.target.lookup(h.r.attempt.id); e != ErrEvidence {
					t.Fatal("not-found classification", e)
				}
				h.note("target lookup: not-found is incomplete, hold retained")
			case "lookup-stale":
				h.target.incomplete = true
				if _, e := h.target.lookup(h.r.attempt.id); e != ErrClosed {
					t.Fatal("stale lookup", e)
				}
				h.note("target lookup: stale coverage")
			case "lookup-unavailable":
				h.target.unavailable = true
				if _, e := h.target.lookup(h.r.attempt.id); e != ErrClosed {
					t.Fatal("unavailable lookup", e)
				}
				h.note("target lookup: unavailable")
			case "unknown-deadline":
				h.unknown()
				e := event{kind: quarantineDeadline, expectRevision: h.r.revision, expectEpoch: h.r.epoch, at: 950}
				h.apply(e)
			}
			if cut != "delayed-buffered-delivery" {
				h.unknown()
				if h.r.budget != budgetHeld || h.m.retained.budgets["global"].held != 1 {
					t.Fatal("uncertainty refunded")
				}
			}
			h.known = false
			if h.release(currentFor(h.r, 6), 6) {
				t.Fatal("fresh send after lost knowledge")
			}
			if h.target.commits != 0 {
				t.Fatal("unknown cut committed")
			}
		})
	}
	positiveControl(t)
}
func TestD06CommitReplyLoss(t *testing.T) {
	for _, cut := range []string{"reply-loss", "crash-before-outcome-append", "crash-before-outcome-retain", "response-inspection-failure", "duplicate-submission", "duplicate-outcome"} {
		t.Run(cut, func(t *testing.T) {
			h := newFaultHarness(t)
			h.makeReady()
			h.makeConsumed()
			if !h.release(currentFor(h.r, 5), 5) {
				t.Fatal("initial send denied")
			}
			x, e := h.target.commit(h.r.attempt.id, 6)
			if e != nil {
				t.Fatal(e)
			}
			h.m.crash()
			h.known = false
			if cut == "reply-loss" {
				recovered, e := h.target.lookup(h.r.attempt.id)
				if e != nil || recovered != x {
					t.Fatal("independent reply-loss lookup failed", e)
				}
				h.note("reply dropped; recovered independent target ledger")
			}
			if cut == "crash-before-outcome-append" {
				if h.r.state != AttemptConsumed || h.m.retained.budgets["global"].held != 1 {
					t.Fatal("pre-outcome cut misclassified")
				}
				h.note("crash before outcome proposal with committed target")
			}
			if cut == "duplicate-submission" {
				again, e := h.target.commit(h.r.attempt.id, 7)
				if e != nil || again != x {
					t.Fatal(e)
				}
			}
			if cut == "crash-before-outcome-retain" {
				h.authorizeTarget(x)
				e := outcomeEvent(h.r, confirmEffect)
				e.at = 7
				e.outcome = x
				if _, err := h.m.propose(h.r, e, h.g); err != nil {
					t.Fatal(err)
				}
				h.m.crash()
			}
			h.confirm(x)
			if cut == "response-inspection-failure" {
				h.apply(event{kind: markResponseWithheld, expectRevision: h.r.revision, expectEpoch: h.r.epoch, at: 8, annotationID: "response-denied"})
				if !h.r.responseWithheld {
					t.Fatal("response failure lost")
				}
			}
			if cut == "duplicate-outcome" {
				h.confirm(x)
			}
			if h.target.commits != 1 || h.target.version != 1 || h.m.retained.budgets["global"] != (account{2, 0, 1}) {
				t.Fatal(h.target.commits, h.m.retained.budgets)
			}
			if h.release(currentFor(h.r, 9), 9) {
				t.Fatal("effect retried")
			}
		})
	}
	positiveControl(t)
}
func TestD07OutcomeWriterGaps(t *testing.T) {
	for _, cut := range []string{"before-outcome", "before-audit", "before-writer-acceptance", "writer-unavailable", "forged-attestation", "wrong-actor", "forged-writer-receipt", "duplicate-delivery"} {
		t.Run(cut, func(t *testing.T) {
			h := newFaultHarness(t)
			h.makeReady()
			h.makeConsumed()
			if !h.release(currentFor(h.r, 5), 5) {
				t.Fatal("eligible initial release denied")
			}
			x, e := h.target.commit(h.r.attempt.id, 6)
			if e != nil {
				t.Fatal(e)
			}
			d := deliverySummary{"writer", "accept-1", "attest-1", x.receiptID, h.r.input.reservationID, h.r.attempt.id, h.r.input.decision.actorRef, h.r.input.binding.Digest(), h.r.input.decision.actorProjectionDigest}
			if cut == "before-outcome" {
				h.note("target committed; crash before outcome write, audit and writer acceptance absent")
				if h.r.state != AttemptConsumed || h.r.budget != budgetHeld || h.deliverOutcome(d) {
					t.Fatal("pre-outcome gap delivered/refunded")
				}
				h.m.crash()
				recovered, e := h.target.lookup(h.r.attempt.id)
				if e != nil || recovered != x {
					t.Fatal(e)
				}
				h.confirm(recovered)
			} else {
				h.confirm(x)
			}
			if cut != "before-outcome" && cut != "before-audit" {
				h.retainAudit()
			}
			if cut != "before-outcome" && cut != "before-audit" && cut != "before-writer-acceptance" {
				h.acceptWriter(d)
			}
			h.note("writer cut=" + cut)
			switch cut {
			case "writer-unavailable":
				h.writerAvailable = false
			case "forged-attestation":
				d.attestationID = "forged"
			case "wrong-actor":
				d.actorRef = "wrong"
			case "forged-writer-receipt":
				d.acceptanceID = "forged"
			}
			if cut == "duplicate-delivery" {
				if !h.deliverOutcome(d) {
					t.Fatal("eligible writer denied")
				}
				revision := h.r.revision
				if !h.deliverOutcome(d) || h.r.revision != revision {
					t.Fatal("duplicate delivery changed history")
				}
			} else if h.deliverOutcome(d) {
				t.Fatal("specific writer gap earned delivery")
			}
			if h.r.state != EffectConfirmed || h.target.commits != 1 || h.r.budget != budgetSpent {
				t.Fatal("writer gap changed effect")
			}
			if cut != "duplicate-delivery" {
				h.writerAvailable = true
				h.retainAudit()
				d = deliverySummary{"writer", "accept-1", "attest-1", x.receiptID, h.r.input.reservationID, h.r.attempt.id, h.r.input.decision.actorRef, h.r.input.binding.Digest(), h.r.input.decision.actorProjectionDigest}
				h.acceptWriter(d)
				if !h.deliverOutcome(d) {
					t.Fatal("restored exact audit+writer positive denied")
				}
			}
		})
	}
	positiveControl(t)
}
func TestD08TargetAtomicChecks(t *testing.T) {
	for _, variant := range []string{"two-keys-first-order", "two-keys-reverse-order", "bytes", "digest", "version", "broker", "worker", "route", "fence"} {
		t.Run(variant, func(t *testing.T) {
			h := newFaultHarness(t)
			h.makeReady()
			h.makeConsumed()
			q := targetRequest{h.r.input.binding, h.r.attempt, "executor-1", "fixed", 800}
			switch variant {
			case "broker":
				q.broker = "wrong"
			case "worker":
				q.attempt.executor = "wrong"
			case "route":
				q.route = "alternate"
			case "fence":
				q.attempt.epoch = 2
			case "digest":
				q.attempt.operationDigest[0] ^= 1
			case "version":
				h.target.version = 1
			}
			if e := h.target.enqueue(q); e != nil {
				t.Fatal(e)
			}
			if variant == "bytes" {
				wire := append([]byte(nil), h.target.finalWire[q.attempt.id]...)
				wire[len(wire)-1] ^= 1
				h.target.finalWire[q.attempt.id] = wire
				h.note("exact final wire bytes changed, binding and digests retained")
			}
			if variant == "two-keys-first-order" || variant == "two-keys-reverse-order" {
				q2 := q
				q2.binding = variantInput(t, h.r.input, "last-cost-unit").binding
				q2.attempt.id = "attempt-2"
				q2.attempt.targetKey = q2.binding.Operation().ReplayID()
				q2.attempt.operationDigest = q2.binding.Operation().Digest()
				h.target.admitBinding(q2.binding)
				if e := h.target.enqueue(q2); e != nil {
					t.Fatal(e)
				}
				ids := []string{q.attempt.id, q2.attempt.id}
				if variant == "two-keys-reverse-order" {
					ids[0], ids[1] = ids[1], ids[0]
				}
				if _, e := h.target.commit(ids[0], 5); e != nil {
					t.Fatal(e)
				}
				if _, e := h.target.commit(ids[1], 6); e == nil || h.target.commits != 1 {
					t.Fatal("same version both committed")
				}
			} else if _, e := h.target.commit(q.attempt.id, 5); e == nil || h.target.commits != 0 {
				t.Fatal("forbidden target commit", variant, e)
			}
		})
	}
	positiveControl(t)
}
func TestD09FenceOverlap(t *testing.T) {
	for _, cut := range []string{"pre-fence-commit", "post-fence-buffered", "target-partition", "store-partition", "expired-old-lease"} {
		t.Run(cut, func(t *testing.T) {
			h := newFaultHarness(t)
			h.makeReady()
			h.makeConsumed()
			if !h.release(currentFor(h.r, 5), 5) {
				t.Fatal("initial release denied")
			}
			h.g.phase = topologyClosed
			if cut == "pre-fence-commit" {
				x, e := h.target.commit(h.r.attempt.id, 6)
				if e != nil {
					t.Fatal(e)
				}
				h.target.advanceFence(2)
				h.adoptEpoch(2)
				h.confirm(x)
				if h.r.state != EffectConfirmed {
					t.Fatal("historical epoch lost")
				}
			} else {
				h.target.advanceFence(2)
				if cut == "target-partition" {
					h.target.unavailable = true
				}
				if cut == "store-partition" {
					h.m.unavailable = true
				}
				if _, e := h.target.commit(h.r.attempt.id, 6); e == nil || h.target.commits != 0 {
					t.Fatal("old buffered commit accepted")
				}
				if h.release(currentFor(h.r, 900), 900) {
					t.Fatal("lease substituted fence")
				}
			}
		})
	}
	positiveControl(t)
}
func TestD10PromotionRetainedHead(t *testing.T) {
	for _, cut := range []string{"stale-standby", "head-loss", "epoch-loss", "target-fence-loss", "reconcile-loss", "readiness-loss", "open-loss", "multiple-replica-loss"} {
		t.Run(cut, func(t *testing.T) {
			h := newFaultHarness(t)
			a := newModelTopologyAuthority(h.m, h.target)
			g := a.initial()
			if cut == "reconcile-loss" {
				g.oldAttempts = []string{"unresolved-old-attempt"}
			}
			var e error
			g, e = a.transition(g, beginPromotion, true)
			if e != nil {
				t.Fatal(e)
			}
			for _, k := range []topologyEventKind{establishHead, acquireEpoch, acknowledgeTargetFence, reconcileTopology, retainReadiness, openTopology} {
				inject := false
				switch cut {
				case "stale-standby":
					if k == establishHead {
						a.checkpoint.sequence--
						inject = true
					}
				case "head-loss":
					if k == establishHead {
						a.available = false
						inject = true
					}
				case "epoch-loss":
					if k == acquireEpoch {
						a.available = false
						inject = true
					}
				case "target-fence-loss":
					if k == acknowledgeTargetFence {
						a.target.unavailable = true
						inject = true
					}
				case "reconcile-loss":
					inject = k == reconcileTopology
				case "readiness-loss":
					inject = k == retainReadiness
				case "open-loss":
					if k == openTopology {
						a.retained[g.readinessRef] = false
						inject = true
					}
				case "multiple-replica-loss":
					if k == establishHead {
						a.ledger.unavailable = true
						a.checkpoint = head{}
						inject = true
					}
				}
				retain := !(cut == "readiness-loss" && k == retainReadiness)
				before := g
				g, e = a.transition(g, k, retain)
				h.note(fmt.Sprintf("promotion cut=%s gate=%d phase=%d revision=%d epoch=%d head=%s:%d error=%v", cut, k, g.phase, g.revision, g.epoch, g.retainedHead.id, g.retainedHead.sequence, e))
				if inject {
					if e == nil || g.phase == topologyEligible {
						t.Fatal("missing grant/fence/retained write opened", cut, k)
					}
					if g.revision != before.revision {
						t.Fatal("failed authority proposal changed topology")
					}
					break
				}
				if e != nil {
					t.Fatal(k, e)
				}
			}
			h.assertNoEffect()
		})
	}
	t.Run("intact-retained-historical-attempt", func(t *testing.T) {
		h := completedHarness(t)
		a := newModelTopologyAuthority(h.m, h.target)
		g := a.initial()
		g.oldAttempts = []string{h.r.attempt.id}
		for _, k := range []topologyEventKind{beginPromotion, establishHead, acquireEpoch, acknowledgeTargetFence, reconcileTopology, retainReadiness, openTopology} {
			var e error
			g, e = a.transition(g, k, true)
			if e != nil {
				t.Fatal(k, e)
			}
			h.note(fmt.Sprintf("intact promotion gate=%d phase=%d epoch=%d head=%s:%d", k, g.phase, g.epoch, g.retainedHead.id, g.retainedHead.sequence))
		}
		if g.phase != topologyEligible || g.epoch != 2 || h.target.epoch != 2 || h.r.attempt.epoch != 1 || h.r.input.epoch != 1 || h.target.commits != 1 || h.m.retained.budgets["global"] != (account{2, 0, 1}) {
			t.Fatal("historical lineage/accounting lost")
		}
	})
	positiveControl(t)
}
func TestD11ClosedFailureRoutes(t *testing.T) {
	for _, route := range []string{"store", "recorder", "authority", "target", "overload", "health", "maintenance", "emergency", "restore-queue-saturated"} {
		t.Run(route, func(t *testing.T) {
			h := newFaultHarness(t)
			h.makeReady()
			h.makeConsumed()
			if h.g.phase != topologyEligible {
				t.Fatal("fixture not eligible")
			}
			management := false
			switch route {
			case "store":
				h.m.unavailable = true
			case "recorder":
				h.recorder.unavailable = true
			case "authority":
				h.authorityAvailable = false
			case "target":
				h.target.unavailable = true
			case "overload":
				h.overloaded = true
			case "restore-queue-saturated":
				h.reconcileUsed = h.reconcileLimit
			case "health", "maintenance", "emergency":
				management = true
			}
			accepted := false
			if management {
				accepted = h.management(route)
				if h.managementUsed > h.managementLimit {
					t.Fatal("unbounded rejected management work")
				}
			} else {
				accepted = h.release(currentFor(h.r, 5), 5)
			}
			if accepted || h.target.arrivals != 0 || h.target.commits != 0 {
				t.Fatalf("missing %s dependency/route guard trace=%v", route, h.trace)
			}
			h.m.unavailable = false
			h.recorder.unavailable = false
			h.authorityAvailable = true
			h.target.unavailable = false
			h.overloaded = false
			h.reconcileUsed = 0
			if !h.release(currentFor(h.r, 5), 5) {
				t.Fatal("restored otherwise-complete action remains closed")
			}
			x, e := h.target.commit(h.r.attempt.id, 6)
			if e != nil {
				t.Fatal(e)
			}
			h.confirm(x)
			if h.target.commits != 1 {
				t.Fatal("restoration control failed")
			}
		})
	}
	positiveControl(t)
}
func TestD12RestoreClone(t *testing.T) {
	for _, cut := range []string{"snapshot-before-consume", "snapshot-before-effect", "old-clone", "old-replay-during-restore", "target-head-comparison", "new-fence"} {
		t.Run(cut, func(t *testing.T) {
			h := newFaultHarness(t)
			h.makeReady()
			beforeConsume := cloneImage(h.m.retained)
			h.makeConsumed()
			beforeEffect := cloneImage(h.m.retained)
			if !h.release(currentFor(h.r, 5), 5) {
				t.Fatal("initial release denied")
			}
			x, e := h.target.commit(h.r.attempt.id, 6)
			if e != nil {
				t.Fatal(e)
			}
			switch cut {
			case "snapshot-before-consume":
				if h.m.admitRestore(beforeConsume, h.target) {
					t.Fatal("missing consumed tail admitted")
				}
			case "snapshot-before-effect":
				if h.m.admitRestore(beforeEffect, h.target) {
					t.Fatal("target checkpoint tail missed")
				}
				if beforeEffect.rows[h.r.input.replay].state != AttemptConsumed {
					t.Fatal("cut not consumed")
				}
			case "old-clone":
				clone := newFaultHarness(t)
				clone.m.restore(beforeConsume)
				clone.r = cloneRecord(beforeConsume.rows[h.r.input.replay])
				clone.target = h.target
				clone.known = false
				h.target.advanceFence(2)
				if clone.release(currentFor(clone.r, 7), 7) {
					t.Fatal("old clone released")
				}
				b2 := variantInput(t, h.r.input, "next-version-key").binding
				h.target.admitBinding(b2)
				q := targetRequest{b2, h.r.attempt, "executor-1", "fixed", 800}
				q.attempt.id = "clone-attempt"
				q.attempt.targetKey = b2.Operation().ReplayID()
				q.attempt.operationDigest = b2.Operation().Digest()
				if e := h.target.enqueue(q); e != nil {
					t.Fatal(e)
				}
				if _, e := h.target.commit(q.attempt.id, 7); e == nil {
					t.Fatal("clone old epoch committed")
				}
			case "old-replay-during-restore":
				h.m.restore(beforeConsume)
				if _, e := h.m.reserve(h.r.input); e != ErrClosed {
					t.Fatal("old replay created authority during restore", e)
				}
			case "target-head-comparison":
				h.confirm(x)
				candidate := cloneImage(h.m.retained)
				h.target.head.id = "same-sequence-fork"
				if h.m.admitRestore(candidate, h.target) {
					t.Fatal("target fork accepted")
				}
			case "new-fence":
				h.target.advanceFence(2)
				b2 := variantInput(t, h.r.input, "next-version-key").binding
				h.target.admitBinding(b2)
				q := targetRequest{b2, h.r.attempt, "executor-1", "fixed", 800}
				q.attempt.id = "buffered-old"
				q.attempt.targetKey = b2.Operation().ReplayID()
				q.attempt.operationDigest = b2.Operation().Digest()
				if e := h.target.enqueue(q); e != nil {
					t.Fatal(e)
				}
				if _, e := h.target.commit(q.attempt.id, 7); e == nil {
					t.Fatal("new target fence missed")
				}
			}
			if h.target.commits != 1 || h.target.version != 1 {
				t.Fatal("restore duplicated historical effect")
			}
		})
	}
	positiveControl(t)
}
func TestD13RollbackFork(t *testing.T) {
	for _, variant := range []string{"row-tail", "budget-tail", "receipt-tail", "checkpoint-tail", "lineage", "authority", "config", "policy", "catalog", "key", "trajectory", "duplicate-outcome", "clock-jump"} {
		t.Run(variant, func(t *testing.T) {
			h := newFaultHarness(t)
			h.makeReady()
			image := cloneImage(h.m.retained)
			switch variant {
			case "row-tail":
				delete(image.rows, h.r.input.replay)
			case "budget-tail":
				image.budgets["global"] = account{2, 0, 0}
			case "receipt-tail":
				row := image.rows[h.r.input.replay]
				row.readinessReceipt = evidence{}
				image.rows[h.r.input.replay] = row
			case "checkpoint-tail":
				image.targetCheckpoint.sequence = 0
			case "lineage":
				image.head.lineage = "fork"
			case "authority":
				image.authorityVersion = "authority-old"
			case "config":
				image.configID = "config-old"
			case "policy":
				image.policyID = "policy-old"
			case "catalog":
				image.catalogID = "catalog-old"
			case "key":
				image.keyID = "key-old"
			case "trajectory":
				image.trajectoryID = "trajectory-old"
			case "clock-jump":
				image.clockFloor = 0
			case "duplicate-outcome":
				done := completedHarness(t)
				revision := done.r.revision
				x := done.r.outcome
				done.confirm(x)
				if done.r.revision != revision || done.m.retained.budgets["global"] != (account{2, 0, 1}) {
					t.Fatal("duplicate outcome changed accounting")
				}
				conflicting := x
				conflicting.afterVersion = "2"
				if done.m.validReceipt(conflicting) {
					t.Fatal("contradictory target observation accepted")
				}
				done.apply(event{kind: annotateContradiction, expectRevision: done.r.revision, expectEpoch: done.r.epoch, at: 8, annotationID: "target-fork"})
				if !done.r.quarantined || done.r.budget != budgetSpent {
					t.Fatal("terminal conflict erased history")
				}
				return
			}
			h.note(fmt.Sprintf("restore mutation %s image(head=%s:%d authority=%s config=%s policy=%s catalog=%s key=%s trajectory=%s clock=%d targethead=%s:%d rows=%d)", variant, image.head.id, image.head.sequence, image.authorityVersion, image.configID, image.policyID, image.catalogID, image.keyID, image.trajectoryID, image.clockFloor, image.targetCheckpoint.id, image.targetCheckpoint.sequence, len(image.rows)))
			if h.m.admitRestore(image, h.target) {
				t.Fatal("specific restored manifest/tail mismatch admitted", variant)
			}
			if !h.m.unavailable {
				t.Fatal("affected scope not held")
			}
			if h.release(currentFor(h.r, 5), 5) {
				t.Fatal("rollback bypass")
			}
			h.assertNoEffect()
		})
	}
	positiveControl(t)
}
func TestD14IncompleteRestoreDeadline(t *testing.T) {
	for _, missing := range []string{"backup", "target-history", "recorder-head", "checkpoint", "unknown-deadline", "recovery-deadline"} {
		t.Run(missing, func(t *testing.T) {
			h := newFaultHarness(t)
			h.makeReady()
			h.makeConsumed()
			switch missing {
			case "backup":
				candidate := cloneImage(h.m.retained)
				delete(candidate.rows, h.r.input.replay)
				if h.m.admitRestore(candidate, h.target) {
					t.Fatal("missing backup accepted")
				}
			case "target-history":
				h.target.incomplete = true
				if _, e := h.target.lookup(h.r.attempt.id); e != ErrClosed {
					t.Fatal(e)
				}
			case "recorder-head":
				h.recorder.unavailable = true
			case "checkpoint":
				candidate := cloneImage(h.m.retained)
				candidate.targetCheckpoint = head{}
				if h.m.admitRestore(candidate, h.target) {
					t.Fatal("missing checkpoint accepted")
				}
			case "unknown-deadline":
				h.unknown()
				before := h.r.revision
				h.apply(event{kind: quarantineDeadline, expectRevision: h.r.revision, expectEpoch: h.r.epoch, at: 950})
				if !h.r.quarantined || h.r.revision != before+1 || h.r.state != OutcomeUnknown {
					t.Fatal("unknown deadline did not quarantine")
				}
			case "recovery-deadline":
				h.restoring = true
				h.recoveryDeadline = 10
				h.tick = 10
				if h.finishRecovery(false) {
					t.Fatal("recovery deadline created missing evidence")
				}
				if h.g.phase == topologyEligible {
					t.Fatal("incomplete recovery opened")
				}
			}
			at := int64(5)
			if missing == "unknown-deadline" {
				at = 950
			}
			if h.release(currentFor(h.r, at), at) {
				t.Fatal("incomplete restore/deadline released")
			}
			if h.r.budget != budgetHeld || h.m.retained.budgets["global"].held != 1 {
				t.Fatal("deadline guessed refund")
			}
			h.assertNoEffect()
		})
	}
	t.Run("intact-bounded-restore", func(t *testing.T) {
		h := newFaultHarness(t)
		h.makeReady()
		h.restoring = true
		h.g.phase = topologyClosed
		h.recoveryDeadline = 10
		h.tick = 9
		if !h.finishRecovery(true) {
			t.Fatal("complete bounded recovery denied")
		}
		if h.g.phase != topologyEligible || h.g.epoch != 2 || h.target.epoch != 2 || h.m.retained.rows[h.r.input.replay].state != Ready || h.m.retained.budgets["global"].held != 1 {
			t.Fatal("bounded restore lost retained state/fence")
		}
		h.assertNoEffect()
	})
	positiveControl(t)
}
func TestD15RetentionHorizon(t *testing.T) {
	for _, edge := range []string{"delayed-arrival", "oldest-backup", "too-old-backup", "credential-rotation", "unknown-GC", "GC-replay", "GC-refund", "checkpoint-transition"} {
		t.Run(edge, func(t *testing.T) {
			h := newFaultHarness(t)
			h.makeReady()
			h.makeConsumed()
			if edge == "unknown-GC" {
				h.unknown()
				h.m.now = 1001
				if e := h.m.gc(h.r.input.replay, true, true); e != ErrTransition {
					t.Fatal(e)
				}
				if h.m.retained.budgets["global"].held != 1 {
					t.Fatal("unknown hold lost")
				}
				return
			}
			if !h.release(currentFor(h.r, 5), 5) {
				t.Fatal("initial send denied")
			}
			x, e := h.target.closeNoEffect(h.r.attempt.id)
			if e != nil {
				t.Fatal(e)
			}
			h.confirm(x)
			backup := cloneImage(h.m.retained)
			switch edge {
			case "delayed-arrival":
				h.m.now = 999
				if e = h.m.gc(h.r.input.replay, true, true); e != ErrClosed {
					t.Fatal("GC before delayed-arrival horizon", e)
				}
				if _, e = h.target.commit(h.r.attempt.id, 999); e == nil {
					t.Fatal("delayed closure reopened")
				}
			case "oldest-backup":
				h.m.oldestBackupTick = backup.createdTick
				if !h.m.admitRestore(backup, h.target) {
					t.Fatal("oldest admitted complete backup denied")
				}
			case "too-old-backup":
				h.m.oldestBackupTick = backup.createdTick + 1
				if h.m.admitRestore(backup, h.target) {
					t.Fatal("backup older than rejection coverage admitted")
				}
				h.m.unavailable = false
			case "credential-rotation":
				h.target.credentialVersion = "credential-v2"
				h.target.allowedBrokers = map[string]bool{"rotated-executor": true}
			case "checkpoint-transition":
				h.m.now = 1000
				h.prepareGC()
				if e = h.m.gc(h.r.input.replay, false, true); e != ErrClosed {
					t.Fatal("GC raced incomplete checkpoint")
				}
			case "GC-refund":
				before := h.m.retained.budgets["global"]
				h.confirm(x)
				if h.m.retained.budgets["global"] != before {
					t.Fatal("duplicate no-effect refunded twice")
				}
			}
			h.m.now = 1000
			h.prepareGC()
			if e = h.m.gc(h.r.input.replay, true, true); e != nil {
				t.Fatal(e)
			}
			h.target.rejected["model-ns"] = true
			if _, e = h.m.reserve(h.r.input); e != ErrClosed {
				t.Fatal("old namespace admitted after GC", e)
			}
			if e = h.target.enqueue(targetRequest{h.r.input.binding, h.r.attempt, "rotated-executor", "fixed", 800}); e == nil {
				t.Fatal("old target namespace admitted")
			}
			if edge == "GC-replay" {
				if _, e = h.m.reserve(h.r.input); e != ErrClosed {
					t.Fatal("concurrent replay after GC admitted")
				}
			}
			if h.m.admitRestore(backup, h.target) {
				t.Fatal("old backup resurrected collected replay")
			}
			if h.target.commits != 0 || h.m.retained.budgets["global"] != (account{2, 0, 0}) {
				t.Fatal("GC accounting mismatch")
			}
		})
	}
	positiveControl(t)
}
func variantInput(t testing.TB, in reservationInput, variant string) reservationInput {
	out := in
	out.costs = append([]budgetCost(nil), in.costs...)
	if variant == "deadline" {
		out.releaseDeadline--
		return out
	}
	if variant == "decision" {
		out.decision.digest[0] ^= 1
		return out
	}
	if variant == "noncanonical-replay" {
		out.replay.key = "INVALID"
		return out
	}
	if variant == "same" {
		return out
	}
	v, e := in.binding.View()
	if e != nil {
		t.Fatal(e)
	}
	d := sha256.Sum256([]byte("modeled"))
	gran, _ := action.NewIdentityGranularityProfile("instance-required")
	tenant, _ := action.NewTenantTargetProjection("t-a", "zone-a", "lab-fixture-01", action.TargetID)
	c := action.BindingContext{SchemaVersion: action.SchemaVersion, CatalogID: action.CatalogID, CatalogVersion: action.CatalogVersion, CatalogDigest: action.CatalogDigest(), PolicyDigest: d, GatewayBuildDigest: d, ProtectedConfigDigest: d, TargetBuildDigest: d, TargetContractDigest: d, DecisionProfileDigest: d, ActorID: "a-1", TenantID: "t-a", InstanceID: "i-1", IdentityProjectionDigest: v.IdentityProjectionDigest, IdentityGranularity: gran, ZoneID: "zone-a", AudienceID: "lab-fixture-01", TenantTarget: tenant, TargetVersion: "0", ReplayID: in.replay.key, ValidFromUnixNS: "1", ExpiresUnixNS: "1000"}
	marker := "set"
	if variant == "actor" {
		c.ActorID = "a-2"
		c.IdentityProjectionDigest = sha256.Sum256([]byte("a-2"))
		out.decision.actorProjectionDigest = c.IdentityProjectionDigest
	}
	if variant == "action" {
		marker = "clear"
	}
	if variant == "target-version" || variant == "next-version-key" {
		c.TargetVersion = "1"
	}
	if variant == "last-cost-unit" || variant == "next-version-key" {
		c.ReplayID = "1123456789abcdef0123456789abcdef"
		out.replay.key = c.ReplayID
		out.reservationID = "r-2"
	}
	a, e := action.ParseMCPArguments("lab.set_marker", []byte(fmt.Sprintf(`{"marker":%q,"expected_version":%q}`, marker, c.TargetVersion)))
	if e != nil {
		t.Fatal(e)
	}
	out.binding, e = action.Bind(a, c)
	if e != nil {
		t.Fatal(e)
	}
	return out
}

var _ = strconv.FormatUint

func newFaultHarness(t testing.TB) *faultHarness {
	t.Helper()
	m := newModelLedger(2)
	result, e := m.reserve(inputFixture(t))
	if e != nil {
		t.Fatal(e)
	}
	if e = m.retain(result.write); e != nil {
		t.Fatal(e)
	}
	h := &faultHarness{t: t, m: m, target: newModelTarget(result.row.input.binding), g: eligibleTopology(), r: result.row, sent: map[string]bool{}, tick: 2, writerReceipts: map[string]deliverySummary{}, auditReceipts: map[string]evidence{}, writerAvailable: true, authorityAvailable: true, reconcileLimit: 2, managementLimit: 2}
	h.note("retained reserve")
	t.Cleanup(func() { t.Logf("ordered model trace=%v", h.trace) })
	return h
}
func (h *faultHarness) note(s string) {
	if len(h.trace) < 64 {
		h.trace = append(h.trace, fmt.Sprintf("tick=%d %s state=%d rev=%d epoch=%d held=%d spent=%d arrivals=%d commits=%d head=%s:%d targethead=%s:%d known=%t", h.tick, s, h.r.state, h.r.revision, h.r.epoch, h.m.retained.budgets["global"].held, h.m.retained.budgets["global"].spent, h.target.arrivals, h.target.commits, h.m.retained.head.id, h.m.retained.head.sequence, h.target.head.id, h.target.head.sequence, h.known))
	}
}
func (h *faultHarness) apply(e event) {
	h.t.Helper()
	w, err := h.m.propose(h.r, e, h.g)
	if err != nil {
		h.t.Fatalf("propose %d: %v trace=%v", e.kind, err, h.trace)
	}
	if w == (writeRef{}) {
		return
	}
	if err = h.m.retain(w); err != nil {
		h.t.Fatal(err)
	}
	h.r = cloneRecord(h.m.retained.rows[h.r.input.replay])
	h.tick = e.at
	h.note(fmt.Sprintf("retained event %d", e.kind))
}
func (h *faultHarness) makeReady() {
	h.t.Helper()
	_, reserve, e := h.m.lookup(h.r.input.replay)
	if e != nil {
		h.t.Fatal(e)
	}
	recorder, e := h.recorder.append(h.r)
	if e != nil {
		h.t.Fatal(e)
	}
	h.m.external[recorder.receiptID] = recorder
	evt := readyEvent(h.r)
	evt.reservationReceipt = reserve
	evt.recorderReceipt = recorder
	h.apply(evt)
	if !h.m.validReceipt(h.r.readinessReceipt) {
		h.t.Fatal("readiness receipt not independently retained")
	}
}
func (h *faultHarness) makeConsumed() {
	h.t.Helper()
	h.apply(consumeEvent(h.r))
	if !h.m.validReceipt(h.r.consumeReceipt) {
		h.t.Fatal("consume ACK invalid")
	}
	h.known = true
	h.ackAt = 5
}
func currentFor(r record, at int64) currentCheck {
	return currentCheck{recheckCurrent, r.input.decision.id, r.input.decision.authorityVersion, r.input.binding.Digest(), r.input.binding.Operation().Digest(), r.input.decision.actorProjectionDigest, at, 800, r.input.binding.Operation().TargetVersion(), "executor-1", r.epoch}
}

// release is a test-only initial-send oracle. It authenticates model receipts
// independently, requires a post-ACK check, and never retries lost knowledge.
func (h *faultHarness) release(c currentCheck, at int64) bool {
	h.tick = at
	h.note(fmt.Sprintf("initial release check ports(store=%t recorder=%t authority=%t target=%t overload=%t restoring=%t queue=%d/%d) check=%d ack=%d", !h.m.unavailable, !h.recorder.unavailable, h.authorityAvailable, !h.target.unavailable, h.overloaded, h.restoring, h.reconcileUsed, h.reconcileLimit, c.checkedAt, h.ackAt))
	if !h.authorityAvailable || h.recorder.unavailable || h.overloaded || h.restoring || h.reconcileUsed >= h.reconcileLimit || !h.known || h.r.state != AttemptConsumed || h.r.quarantined || len(h.r.contradictionIDs) > 0 || h.m.unavailable || h.target.unavailable || h.target.incomplete || h.sent[h.r.attempt.id] || !eligible(h.g, h.r) || !h.m.validReceipt(h.r.reservationReceipt) || !h.m.validReceipt(h.r.readinessReceipt) || !h.m.validReceipt(h.r.consumeReceipt) || h.r.input.requiredRecorder != "" && !h.m.validReceipt(h.r.recorderReceipt) || c.class != recheckCurrent || c.checkedAt < h.ackAt || c.checkedAt > at || c.checkedAt < h.r.input.decision.validFrom || at >= c.expires || c.expires > h.r.input.decision.expires || at >= h.r.input.releaseDeadline || at < h.r.input.decision.validFrom || c.decisionID != h.r.input.decision.id || c.authorityVersion != h.r.input.decision.authorityVersion || c.bindingDigest != h.r.input.binding.Digest() || c.operationDigest != h.r.attempt.operationDigest || c.actorProjectionDigest != h.r.input.decision.actorProjectionDigest || c.executor != h.r.attempt.executor || c.epoch != h.r.epoch || h.target.epoch != h.r.attempt.epoch || c.targetVersion != h.r.input.binding.Operation().TargetVersion() {
		return false
	}
	h.sent[h.r.attempt.id] = true
	return h.target.enqueue(targetRequest{h.r.input.binding, h.r.attempt, c.executor, "fixed", h.r.input.releaseDeadline}) == nil
}
func (h *faultHarness) withhold() {
	h.apply(event{kind: withhold, expectRevision: h.r.revision, expectEpoch: h.r.epoch, at: 5, annotationID: "withhold-recheck"})
}
func (h *faultHarness) unknown() {
	if h.r.state == OutcomeUnknown {
		return
	}
	h.apply(event{kind: markUnknown, expectRevision: h.r.revision, expectEpoch: h.r.epoch, at: 7})
}
func (h *faultHarness) authorizeTarget(x evidence) {
	if expected, ok := h.target.receipts[x.receiptID]; !ok || expected != x {
		h.t.Fatal("unregistered target evidence")
	}
	h.m.external[x.receiptID] = x
}
func (h *faultHarness) confirm(x evidence) {
	h.authorizeTarget(x)
	k := confirmEffect
	if x.kind == targetTerminalNoEffect {
		k = confirmNoEffect
	}
	at := h.tick
	if at < 7 {
		at = 7
	}
	h.apply(event{kind: k, expectRevision: h.r.revision, expectEpoch: h.r.epoch, at: at, outcome: x})
}
func (h *faultHarness) adoptEpoch(epoch uint64) {
	h.r.epoch = epoch
	h.m.retained.rows[h.r.input.replay] = cloneRecord(h.r)
	h.m.local = cloneImage(h.m.retained)
}
func (h *faultHarness) assertNoEffect() {
	h.t.Helper()
	if h.target.commits != 0 || h.target.version != 0 {
		h.t.Fatalf("forbidden effect trace=%v", h.trace)
	}
}
func (h *faultHarness) deliverOutcome(d deliverySummary) bool {
	h.note(fmt.Sprintf("writer delivery audit=%t accepted=%t available=%t", h.auditReceipts[d.effectReceiptID] == h.r.outcome, h.writerReceipts[d.acceptanceID] == d, h.writerAvailable))
	if !h.writerAvailable || h.r.state != EffectConfirmed || h.auditReceipts[d.effectReceiptID] != h.r.outcome {
		return false
	}
	expected, ok := h.writerReceipts[d.acceptanceID]
	if !ok || expected != d || d.attestationID != "attest-1" || d.writerAuthority != "writer" {
		return false
	}
	e := event{kind: markOutcomeDelivered, expectRevision: h.r.revision, expectEpoch: h.r.epoch, at: 8, annotationID: d.acceptanceID, delivery: d}
	if _, err := reduce(h.r, e, h.g); err != nil {
		return false
	}
	h.apply(e)
	return true
}
func completedHarness(t testing.TB) *faultHarness {
	h := newFaultHarness(t)
	h.makeReady()
	h.makeConsumed()
	if !h.release(currentFor(h.r, 5), 5) {
		t.Fatal("complete positive release denied")
	}
	x, e := h.target.commit(h.r.attempt.id, 6)
	if e != nil {
		t.Fatal(e)
	}
	h.confirm(x)
	return h
}
func positiveControl(t *testing.T) {
	t.Run("positive-control", func(t *testing.T) {
		h := completedHarness(t)
		if h.target.version != 1 || h.target.commits != 1 || h.target.arrivals != 1 || h.r.state != EffectConfirmed || h.m.retained.budgets["global"] != (account{2, 0, 1}) || h.m.retained.budgets["tenant"] != (account{2, 0, 1}) {
			t.Fatalf("single-effect independent oracle failed trace=%v", h.trace)
		}
	})
}
func (m *modelLedger) admitRestore(im ledgerImage, target *modelTarget) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if im.createdTick < m.oldestBackupTick || im.clockFloor < m.retained.clockFloor || im.targetCheckpoint != target.head || !reflect.DeepEqual(im, m.retained) || target.unavailable || target.incomplete || !validHead(im.head) {
		m.unavailable = true
		return false
	}
	for _, x := range target.effects {
		found := false
		for _, r := range im.rows {
			if r.attempt.id == x.attemptID {
				found = true
			}
		}
		if !found {
			m.unavailable = true
			return false
		}
	}
	return true
}

func (h *faultHarness) management(route string) bool {
	if h.managementUsed >= h.managementLimit {
		return false
	}
	h.managementUsed++
	h.note("management route " + route)
	return false
}
func (h *faultHarness) finishRecovery(complete bool) bool {
	if !h.restoring {
		return false
	}
	if !complete || h.tick >= h.recoveryDeadline || h.target.incomplete || h.target.unavailable || h.m.unavailable || h.recorder.unavailable {
		h.g.phase = topologyQuarantined
		return false
	}
	if !h.m.admitRestore(cloneImage(h.m.retained), h.target) {
		return false
	}
	a := newModelTopologyAuthority(h.m, h.target)
	g := a.initial()
	for _, r := range h.m.retained.rows {
		if r.state == AttemptConsumed || r.state == OutcomeUnknown {
			g.oldAttempts = append(g.oldAttempts, r.attempt.id)
		}
	}
	for _, k := range []topologyEventKind{beginRestore, establishHead, acquireEpoch, acknowledgeTargetFence, reconcileTopology, retainReadiness, openTopology} {
		var e error
		g, e = a.transition(g, k, true)
		h.note(fmt.Sprintf("restore gate=%d phase=%d epoch=%d err=%v", k, g.phase, g.epoch, e))
		if e != nil {
			h.g = g
			return false
		}
	}
	h.restoring = false
	h.g = g
	return g.phase == topologyEligible
}

func (h *faultHarness) retainAudit() {
	h.t.Helper()
	if h.r.state != EffectConfirmed || h.r.budget != budgetSpent || !h.m.validReceipt(h.r.outcome) {
		h.t.Fatal("audit requires retained authenticated outcome")
	}
	h.auditReceipts[h.r.outcome.receiptID] = h.r.outcome
	h.note("retained exact audit attestation for " + h.r.outcome.receiptID)
}
func (h *faultHarness) acceptWriter(d deliverySummary) {
	h.t.Helper()
	if !h.writerAvailable || h.auditReceipts[d.effectReceiptID] != h.r.outcome || d.attestationID != "attest-1" || d.actorRef != h.r.input.decision.actorRef || d.bindingDigest != h.r.input.binding.Digest() || d.actorProjectionDigest != h.r.input.decision.actorProjectionDigest || d.writerAuthority != "writer" {
		h.t.Fatal("writer authority cannot admit unattested/mismatched delivery")
	}
	h.writerReceipts[d.acceptanceID] = d
	h.note("protected writer accepted exact receipt " + d.acceptanceID)
}
