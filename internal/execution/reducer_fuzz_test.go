package execution

import (
	"fmt"
	"reflect"
	"testing"
)

// This table is the plan's literal state/event relation, independent of the
// implementation's switch. Column zero is the invalid/zero event.
var fuzzRelation = [8][11]bool{
	{},
	{false, true, false, true, false, false, false, true, false, false, false},
	{false, false, true, true, false, false, false, true, false, false, false},
	{false, false, false, false, true, true, true, true, false, false, true},
	{false, false, false, false, true, true, true, true, false, false, true},
	{false, false, false, false, false, false, false, true, true, true, false},
	{false, false, false, false, false, false, false, true, false, false, false},
	{false, false, false, false, false, false, false, true, false, false, false},
}

func FuzzReducerSafety(f *testing.F) {
	for _, seed := range [][]byte{{1, 2, 4, 5, 9}, {1, 2, 4, 10}, {1, 3}, {1, 2, 6, 7}, {1, 2, 5, 5, 8, 9}, {0, 33, 66, 129}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 128 {
			data = data[:128]
		}
		r, e := newPending(inputFixture(t))
		if e != nil {
			t.Fatal(e)
		}
		original := cloneRecord(r)
		g := eligibleTopology()
		for i, b := range data {
			k := eventKind(b % 11)
			evt := event{kind: k, expectRevision: r.revision, expectEpoch: r.epoch, at: int64(i + 2), annotationID: fmt.Sprintf("a-%d", i)}
			switch k {
			case attachReady:
				evt = readyEvent(r)
			case consume:
				evt = consumeEvent(r)
			case confirmEffect, confirmNoEffect:
				evt = outcomeEvent(r, k)
			case markOutcomeDelivered:
				evt.delivery = deliverySummary{"writer", evt.annotationID, "attest-1", r.outcome.receiptID, r.input.reservationID, r.attempt.id, r.input.decision.actorRef, r.input.binding.Digest(), r.input.decision.actorProjectionDigest}
			}
			evt.at = int64(i + 2)
			if k == quarantineDeadline {
				evt.at = 950
			}
			staleRev, staleEpoch := b&32 != 0, b&64 != 0
			if staleRev {
				evt.expectRevision++
			}
			if staleEpoch {
				evt.expectEpoch++
			}
			localG := g
			closed := b&128 != 0
			if closed {
				localG.phase = topologyClosed
			}
			before := cloneRecord(r)
			next, err := reduce(r, evt, localG)
			if err != nil {
				if !reflect.DeepEqual(next, before) || !reflect.DeepEqual(r, before) {
					t.Fatal("denial mutated owned record")
				}
				continue
			}
			if staleRev || staleEpoch || k == 0 {
				t.Fatal("accepted stale/invalid envelope")
			}
			inert := reflect.DeepEqual(next, before)
			if !fuzzRelation[before.state][k] && !inert {
				t.Fatal("accepted illegal state/event relation", before.state, k)
			}
			if closed && (k == attachReady || k == consume) && !inert {
				t.Fatal("closed topology advanced readiness/attempt")
			}
			if !reflect.DeepEqual(next.input, original.input) {
				t.Fatal("immutable input rewritten")
			}
			if before.attempt != (attempt{}) && next.attempt != before.attempt {
				t.Fatal("second/mutated attempt")
			}
			if before.state >= EffectConfirmed && (next.state != before.state || next.budget != before.budget) {
				t.Fatal("terminal history reset")
			}
			if before.budget == budgetHeld && (k == markUnknown || k == quarantineDeadline || k == annotateContradiction) && next.budget != budgetHeld {
				t.Fatal("uncertainty refunded")
			}
			if !inert && next.revision != before.revision+1 {
				t.Fatal("transition revision not exactly once")
			}
			if inert && next.revision != before.revision {
				t.Fatal("idempotent revision changed")
			}
			r = next
		}
	})
}

func FuzzModelReplayBudget(f *testing.F) {
	for _, seed := range [][]byte{{0, 1, 0, 2, 3, 4}, {0, 1, 5, 6, 7}, {0, 1, 8, 9}, {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {0, 10, 1, 11}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64 {
			data = data[:64]
		}
		m := newModelLedger(2)
		in := inputFixture(t)
		other := variantInput(t, in, "last-cost-unit")
		var proposals []writeRef
		for _, b := range data {
			selected := in
			if b&16 != 0 {
				selected = other
			}
			r, present := m.retained.rows[selected.replay]
			switch b % 12 {
			case 0:
				result, e := m.reserve(selected)
				if e == nil && result.write != (writeRef{}) {
					proposals = append(proposals, result.write)
				}
			case 1:
				if len(proposals) > 0 {
					_ = m.retain(proposals[len(proposals)-1])
				}
			case 2:
				m.crash()
			case 3:
				changed := selected
				changed.releaseDeadline--
				_, _ = m.reserve(changed)
			case 4:
				if present && r.state == ReservedPendingACK {
					_, reserve, _ := m.lookup(selected.replay)
					rec := modelRecorder{}
					x, e := rec.append(r)
					if e == nil {
						m.external[x.receiptID] = x
						evt := readyEvent(r)
						evt.reservationReceipt = reserve
						evt.recorderReceipt = x
						if w, e := m.propose(r, evt, eligibleTopology()); e == nil {
							_ = m.retain(w)
						}
					}
				}
			case 5:
				if present && r.state == Ready {
					if w, e := m.propose(r, consumeEvent(r), eligibleTopology()); e == nil {
						_ = m.retain(w)
					}
				}
			case 6:
				if present {
					evt := event{kind: markUnknown, expectRevision: r.revision, expectEpoch: r.epoch, at: 7}
					if w, e := m.propose(r, evt, eligibleTopology()); e == nil && w != (writeRef{}) {
						_ = m.retain(w)
					}
				}
			case 7, 8:
				if present && (r.state == AttemptConsumed || r.state == OutcomeUnknown) {
					k := confirmEffect
					if b%12 == 8 {
						k = confirmNoEffect
					}
					evt := outcomeEvent(r, k)
					evt.at = 8
					evt.outcome.receiptID = fmt.Sprintf("outcome-%d-%d", b, r.revision)
					m.external[evt.outcome.receiptID] = evt.outcome
					if w, e := m.propose(r, evt, eligibleTopology()); e == nil {
						_ = m.retain(w)
					}
				}
			case 9:
				if present && (r.state == ReservedPendingACK || r.state == Ready) {
					evt := event{kind: withhold, expectRevision: r.revision, expectEpoch: r.epoch, at: 9, annotationID: "withheld"}
					if w, e := m.propose(r, evt, eligibleTopology()); e == nil {
						_ = m.retain(w)
					}
				}
			case 10:
				if present {
					m.now = 1000
					_ = m.gc(selected.replay, true, true)
				}
			case 11:
				if present {
					evt := event{kind: annotateContradiction, expectRevision: r.revision, expectEpoch: r.epoch, at: 10, annotationID: "conflict"}
					if w, e := m.propose(r, evt, eligibleTopology()); e == nil && w != (writeRef{}) {
						_ = m.retain(w)
					}
				}
			}
			// Independently derive whole-vector balances from retained slot dispositions.
			held, spent := map[string]uint64{}, map[string]uint64{}
			for key, row := range m.retained.rows {
				if row.input.replay != key {
					t.Fatal("slot key moved")
				}
				for _, cost := range row.input.costs {
					switch row.budget {
					case budgetHeld:
						held[cost.account] += cost.amount
					case budgetSpent:
						spent[cost.account] += cost.amount
					case budgetRefunded:
					default:
						t.Fatal("unknown disposition")
					}
				}
				if row.state == OutcomeUnknown && row.budget != budgetHeld {
					t.Fatal("unknown lost hold")
				}
			}
			for id, a := range m.retained.budgets {
				if a.held != held[id] || a.spent != spent[id] || a.held+a.spent > a.limit {
					t.Fatal("atomic model budget differs from independent rows", id, a, held, spent)
				}
			}
		}
	})
}
