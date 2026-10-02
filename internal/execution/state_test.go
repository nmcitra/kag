package execution

import (
	"bytes"
	"crypto/sha256"
	"github.com/nmcitra/kag/internal/action"
	"testing"
)

func bindingFixture(t testing.TB) action.Binding {
	t.Helper()
	a, e := action.ParseMCPArguments("lab.set_marker", []byte(`{"marker":"set","expected_version":"0"}`))
	if e != nil {
		t.Fatal(e)
	}
	d := sha256.Sum256([]byte("modeled"))
	gran, _ := action.NewIdentityGranularityProfile("instance-required")
	tenant, _ := action.NewTenantTargetProjection("t-a", "zone-a", "lab-fixture-01", action.TargetID)
	b, e := action.Bind(a, action.BindingContext{SchemaVersion: action.SchemaVersion, CatalogID: action.CatalogID, CatalogVersion: action.CatalogVersion, CatalogDigest: action.CatalogDigest(), PolicyDigest: d, GatewayBuildDigest: d, ProtectedConfigDigest: d, TargetBuildDigest: d, TargetContractDigest: d, DecisionProfileDigest: d, ActorID: "a-1", TenantID: "t-a", InstanceID: "i-1", IdentityProjectionDigest: d, IdentityGranularity: gran, ZoneID: "zone-a", AudienceID: "lab-fixture-01", TenantTarget: tenant, TargetVersion: "0", ReplayID: "0123456789abcdef0123456789abcdef", ValidFromUnixNS: "1", ExpiresUnixNS: "1000"})
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func inputFixture(t testing.TB) reservationInput {
	b := bindingFixture(t)
	v, e := b.View()
	if e != nil {
		t.Fatal(e)
	}
	return reservationInput{replay: replayIdentity{"model-ns", b.Operation().ReplayID()}, reservationID: "r-1", binding: b, decision: decisionSummary{id: "d-1", issuerProfile: "profile-a", actorRef: "actor-ref", permissionRef: "permission-ref", inspectionRef: "inspection-ref", digest: sha256.Sum256([]byte("decision")), actorProjectionDigest: v.IdentityProjectionDigest, validFrom: 1, expires: 1000, authorityVersion: "v-1"}, costs: []budgetCost{{"global", 1}, {"tenant", 1}}, requiredRecorder: "recorder", createdAt: 2, releaseDeadline: 900, unknownDeadline: 950, epoch: 1}
}
func TestOwnedInputAndSnapshots(t *testing.T) {
	in := inputFixture(t)
	r, e := newPending(in)
	if e != nil {
		t.Fatal(e)
	}
	in.costs[0].amount = 9
	if r.input.costs[0].amount != 1 {
		t.Fatal("input aliases")
	}
	r.contradictionIDs = []string{"c-1"}
	s := inspect(r)
	s.contradictionIDs[0] = "changed"
	if r.contradictionIDs[0] != "c-1" {
		t.Fatal("snapshot aliases")
	}
	copy := cloneRecord(r)
	copy.input.costs[0].amount = 7
	if r.input.costs[0].amount != 1 {
		t.Fatal("record aliases")
	}
	b := r.input.binding.Bytes()
	b[0] ^= 1
	if bytes.Equal(b, r.input.binding.Bytes()) {
		t.Fatal("binding accessor aliases")
	}
}
func TestInvalidZeroRecord(t *testing.T) {
	if r, e := newPending(reservationInput{}); e != ErrInvalid || r.state != Absent {
		t.Fatal(r, e)
	}
}
func TestImmutableBindingConflict(t *testing.T) {
	a := inputFixture(t)
	b := a
	b.costs = append([]budgetCost(nil), a.costs...)
	if !sameReservation(a, b) {
		t.Fatal("equal input conflict")
	}
	b.releaseDeadline--
	if sameReservation(a, b) {
		t.Fatal("changed deadline joined")
	}
	b = a
	b.decision.authorityVersion = "v-2"
	if sameReservation(a, b) {
		t.Fatal("changed decision joined")
	}
}
func eligibleTopology() topology {
	return topology{phase: topologyEligible, revision: 1, epoch: 1, retainedHead: head{"ledger", "model-lineage", "head-1", 1}, independentHead: head{"ledger", "model-lineage", "head-1", 1}, targetHead: head{"target", "model-lineage", "target-head-1", 1}}
}
func receiptFor(r record, k evidenceKind, revision uint64) evidence {
	auth := "ledger"
	if k == recorderPreAction {
		auth = r.input.requiredRecorder
	}
	if k == targetEffect || k == targetTerminalNoEffect {
		auth = "target"
	}
	return evidence{authority: auth, receiptID: "receipt-1", kind: k, reservationID: r.input.reservationID, namespace: r.input.replay.namespace, replayKey: r.input.replay.key, bindingDigest: r.input.binding.Digest(), operationDigest: r.input.binding.Operation().Digest(), decisionDigest: r.input.decision.digest, actorProjectionDigest: r.input.decision.actorProjectionDigest, revision: revision, epoch: r.epoch, head: head{auth, "model-lineage", "head-1", revision}}
}
func readyEvent(r record) event {
	return event{kind: attachReady, expectRevision: r.revision, expectEpoch: r.epoch, at: 3, reservationReceipt: receiptFor(r, storeReservation, 1), recorderReceipt: receiptFor(r, recorderPreAction, 1), readinessReceipt: receiptFor(r, storeReadiness, r.revision+1)}
}
func consumeEvent(r record) event {
	a := attempt{"attempt-1", r.input.replay.key, "executor-1", r.epoch, r.revision + 1, r.input.binding.Operation().Digest()}
	c := currentCheck{recheckCurrent, r.input.decision.id, r.input.decision.authorityVersion, r.input.binding.Digest(), a.operationDigest, r.input.decision.actorProjectionDigest, 4, 800, r.input.binding.Operation().TargetVersion(), a.executor, r.epoch}
	rc := receiptFor(r, storeConsumption, r.revision+1)
	rc.attemptID = a.id
	return event{kind: consume, expectRevision: r.revision, expectEpoch: r.epoch, at: 4, check: c, attempt: a, consumeReceipt: rc}
}
func readyFixture(t testing.TB) record {
	r, e := newPending(inputFixture(t))
	if e != nil {
		t.Fatal(e)
	}
	r, e = reduce(r, readyEvent(r), eligibleTopology())
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func consumedFixture(t testing.TB) record {
	r := readyFixture(t)
	r, e := reduce(r, consumeEvent(r), eligibleTopology())
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func outcomeEvent(r record, k eventKind) event {
	kind := targetEffect
	if k == confirmNoEffect {
		kind = targetTerminalNoEffect
	}
	rc := receiptFor(r, kind, r.attempt.consumeRevision)
	rc.attemptID = r.attempt.id
	rc.epoch = r.attempt.epoch
	rc.beforeVersion = "0"
	rc.afterVersion = "1"
	if k == confirmNoEffect {
		rc.afterVersion = "0"
		rc.terminalClosureID = "closure-1"
	}
	return event{kind: k, expectRevision: r.revision, expectEpoch: r.epoch, at: 5, outcome: rc}
}
func TestTransitionMatrix(t *testing.T) {
	allowed := [8][11]bool{ReservedPendingACK: {false, true, false, true, false, false, false, true, false, false, false}, Ready: {false, false, true, true, false, false, false, true, false, false, false}, AttemptConsumed: {false, false, false, false, true, true, true, true, false, false, true}, OutcomeUnknown: {false, false, false, false, true, true, true, true, false, false, true}, EffectConfirmed: {false, false, false, false, false, false, false, true, true, true, false}, NoEffectConfirmed: {false, false, false, false, false, false, false, true, false, false, false}, Withheld: {false, false, false, false, false, false, false, true, false, false, false}}
	for st := Absent; st <= Withheld; st++ {
		for k := eventKind(0); k <= quarantineDeadline; k++ {
			t.Run(string(rune('a'+st))+string(rune('a'+k)), func(t *testing.T) {
				r := consumedFixture(t)
				r.state = st
				r.revision = 3
				r.lastAt = 4
				if st == ReservedPendingACK || st == Ready {
					r.attempt = attempt{}
					r.consumeReceipt = evidence{}
				}
				if st == EffectConfirmed || st == NoEffectConfirmed {
					r.outcome = receiptFor(r, targetEffect, 3)
					r.outcome.receiptID = "prior"
					r.budget = budgetSpent
				}
				if st == Withheld {
					r.budget = budgetRefunded
				}
				e := outcomeEvent(r, k)
				e.at = 950
				if k != confirmEffect && k != confirmNoEffect {
					e.outcome = evidence{}
				}
				e.annotationID = "note-1"
				switch k {
				case attachReady:
					e = readyEvent(r)
					e.at = 5
				case consume:
					e = consumeEvent(r)
					e.at = 5
				case markOutcomeDelivered:
					e.delivery = deliverySummary{"writer", "accept-1", "attest-1", r.outcome.receiptID, r.input.reservationID, r.attempt.id, r.input.decision.actorRef, r.input.binding.Digest(), r.input.decision.actorProjectionDigest}
					e.annotationID = "accept-1"
				}
				if k == confirmEffect || k == confirmNoEffect {
					e.at = 5
				}
				next, err := reduce(r, e, eligibleTopology())
				if allowed[st][k] {
					if err != nil {
						t.Fatal(st, k, err)
					}
				} else {
					if err != ErrTransition {
						t.Fatal(st, k, err)
					}
					if !sameReservation(next.input, r.input) || next.state != r.state || next.revision != r.revision {
						t.Fatal("error changed row")
					}
				}
			})
		}
	}
}
func TestACKPurposeHeadRevision(t *testing.T) {
	r, _ := newPending(inputFixture(t))
	base := readyEvent(r)
	changes := []func(*evidence){func(e *evidence) { e.authority = "wrong" }, func(e *evidence) { e.kind = storeConsumption }, func(e *evidence) { e.reservationID = "wrong" }, func(e *evidence) { e.replayKey = "wrong" }, func(e *evidence) { e.bindingDigest[0] ^= 1 }, func(e *evidence) { e.operationDigest[0] ^= 1 }, func(e *evidence) { e.decisionDigest[0] ^= 1 }, func(e *evidence) { e.actorProjectionDigest[0] ^= 1 }, func(e *evidence) { e.revision++ }, func(e *evidence) { e.epoch++ }, func(e *evidence) { e.head.lineage = "wrong" }, func(e *evidence) { e.head.sequence = 0 }, func(e *evidence) { e.receiptID = "" }}
	for i, change := range changes {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			e := base
			change(&e.readinessReceipt)
			n, err := reduce(r, e, eligibleTopology())
			if err != ErrEvidence || n.revision != r.revision {
				t.Fatal(n, err)
			}
		})
	}
}
func TestConsumeDeadlineAndPostACKCheck(t *testing.T) {
	r := readyFixture(t)
	for _, at := range []int64{799, 800, 900} {
		e := consumeEvent(r)
		e.at = at
		n, err := reduce(r, e, eligibleTopology())
		if at == 799 {
			if err != nil || n.state != AttemptConsumed {
				t.Fatal(n, err)
			}
		} else if err != ErrEvidence {
			t.Fatal(at, err)
		}
	}
	e := consumeEvent(r)
	e.check.checkedAt = e.at + 1
	if _, err := reduce(r, e, eligibleTopology()); err != ErrEvidence {
		t.Fatal(err)
	}
}
func TestTerminalNoEffectClosure(t *testing.T) {
	r := consumedFixture(t)
	e := outcomeEvent(r, confirmNoEffect)
	e.outcome.terminalClosureID = ""
	if n, err := reduce(r, e, eligibleTopology()); err != ErrEvidence || n.budget != budgetHeld {
		t.Fatal(n, err)
	}
	e = outcomeEvent(r, confirmNoEffect)
	n, err := reduce(r, e, eligibleTopology())
	if err != nil || n.state != NoEffectConfirmed || n.budget != budgetRefunded {
		t.Fatal(n, err)
	}
}
func TestTerminalContradictionQuarantine(t *testing.T) {
	r := consumedFixture(t)
	r, e := reduce(r, outcomeEvent(r, confirmEffect), eligibleTopology())
	if e != nil {
		t.Fatal(e)
	}
	n, e := reduce(r, event{kind: annotateContradiction, expectRevision: r.revision, expectEpoch: r.epoch, at: 6, annotationID: "conflict-1"}, eligibleTopology())
	if e != nil || n.state != EffectConfirmed || n.budget != budgetSpent || !n.quarantined {
		t.Fatal(n, e)
	}
}
func TestIndependentReceiptLineages(t *testing.T) {
	t.Run("target", func(t *testing.T) {
		r := consumedFixture(t)
		g := eligibleTopology()
		g.targetHead.lineage = "independent-target-lineage"
		e := outcomeEvent(r, confirmEffect)
		e.outcome.head.lineage = g.targetHead.lineage
		if n, err := reduce(r, e, g); err != nil || n.state != EffectConfirmed {
			t.Fatal("independent target lineage denied", err)
		}
		e.outcome.head.lineage = "ledger-only-lineage"
		if _, err := reduce(r, e, g); err != ErrEvidence {
			t.Fatal("wrong target domain accepted", err)
		}
	})
	t.Run("recorder", func(t *testing.T) {
		r, _ := newPending(inputFixture(t))
		e := readyEvent(r)
		e.recorderReceipt.head.lineage = "independent-recorder-lineage"
		if n, err := reduce(r, e, eligibleTopology()); err != nil || n.state != Ready {
			t.Fatal("independent recorder lineage denied", err)
		}
	})
}
func TestProtectedReceiptAuthorityDomains(t *testing.T) {
	for _, which := range []string{"ledger", "target"} {
		r, _ := newPending(inputFixture(t))
		g := eligibleTopology()
		if which == "ledger" {
			g.retainedHead.authority = "other-store"
			g.independentHead.authority = "other-store"
		} else {
			g.targetHead.authority = "other-target"
		}
		if _, e := reduce(r, readyEvent(r), g); e != ErrClosed {
			t.Fatal("wrong topology authority admitted", which, e)
		}
	}
	r := consumedFixture(t)
	g := eligibleTopology()
	g.targetHead.authority = "other-target"
	if _, e := reduce(r, outcomeEvent(r, confirmEffect), g); e != ErrEvidence {
		t.Fatal("wrong target authority admitted outcome", e)
	}
}
func TestAnnotationExactIdempotence(t *testing.T) {
	r := consumedFixture(t)
	r, e := reduce(r, outcomeEvent(r, confirmEffect), eligibleTopology())
	if e != nil {
		t.Fatal(e)
	}
	evt := event{kind: markResponseWithheld, expectRevision: r.revision, expectEpoch: r.epoch, at: 6, annotationID: "response-1"}
	n, e := reduce(r, evt, eligibleTopology())
	if e != nil {
		t.Fatal(e)
	}
	evt.expectRevision = n.revision
	again, e := reduce(n, evt, eligibleTopology())
	if e != nil || again.revision != n.revision {
		t.Fatal("equal annotation not inert", e)
	}
	evt.annotationID = "response-2"
	if _, e := reduce(n, evt, eligibleTopology()); e != ErrConflict {
		t.Fatal("changed annotation silently joined", e)
	}
}
func TestInputBoundsAndCounterGuards(t *testing.T) {
	for _, field := range []string{"namespace", "replay", "reservation", "decision", "projection", "actor-ref", "permission-ref", "inspection-ref", "profile", "epoch", "created", "release", "unknown", "cost-zero", "cost-duplicate", "cost-unsorted", "cost-overflow"} {
		t.Run(field, func(t *testing.T) {
			in := inputFixture(t)
			switch field {
			case "namespace":
				in.replay.namespace = "UPPER"
			case "replay":
				in.replay.key = "bad"
			case "reservation":
				in.reservationID = ""
			case "decision":
				in.decision.digest = [32]byte{}
			case "projection":
				in.decision.actorProjectionDigest[0] ^= 1
			case "actor-ref":
				in.decision.actorRef = ""
			case "permission-ref":
				in.decision.permissionRef = ""
			case "inspection-ref":
				in.decision.inspectionRef = ""
			case "profile":
				in.decision.issuerProfile = ""
			case "epoch":
				in.epoch = 0
			case "created":
				in.createdAt = -1
			case "release":
				in.releaseDeadline = in.createdAt
			case "unknown":
				in.unknownDeadline = in.releaseDeadline - 1
			case "cost-zero":
				in.costs[0].amount = 0
			case "cost-duplicate":
				in.costs[1].account = in.costs[0].account
			case "cost-unsorted":
				in.costs[0], in.costs[1] = in.costs[1], in.costs[0]
			case "cost-overflow":
				in.costs[0].amount = ^uint64(0)
			}
			n, e := newPending(in)
			if e == nil || n.state != Absent {
				t.Fatal("invalid input creates row", field, n, e)
			}
		})
	}
	r := readyFixture(t)
	evt := consumeEvent(r)
	evt.expectRevision--
	if _, e := reduce(r, evt, eligibleTopology()); e != ErrStaleRevision {
		t.Fatal(e)
	}
	evt = consumeEvent(r)
	evt.expectEpoch++
	if _, e := reduce(r, evt, eligibleTopology()); e != ErrStaleEpoch {
		t.Fatal(e)
	}
	r.revision = ^uint64(0)
	evt = event{kind: annotateContradiction, expectRevision: r.revision, expectEpoch: r.epoch, at: 5, annotationID: "overflow"}
	if _, e := reduce(r, evt, eligibleTopology()); e != ErrOverflow {
		t.Fatal(e)
	}
}

func TestWriterAcceptanceExactIdempotence(t *testing.T) {
	r := consumedFixture(t)
	r, e := reduce(r, outcomeEvent(r, confirmEffect), eligibleTopology())
	if e != nil {
		t.Fatal(e)
	}
	d := deliverySummary{"writer", "accept-1", "attest-1", r.outcome.receiptID, r.input.reservationID, r.attempt.id, r.input.decision.actorRef, r.input.binding.Digest(), r.input.decision.actorProjectionDigest}
	evt := event{kind: markOutcomeDelivered, expectRevision: r.revision, expectEpoch: r.epoch, at: 6, annotationID: d.acceptanceID, delivery: d}
	n, e := reduce(r, evt, eligibleTopology())
	if e != nil {
		t.Fatal(e)
	}
	evt.expectRevision = n.revision
	if again, e := reduce(n, evt, eligibleTopology()); e != nil || again.revision != n.revision {
		t.Fatal("equal writer receipt not inert", e)
	}
	evt.delivery.attestationID = "attest-2"
	if _, e := reduce(n, evt, eligibleTopology()); e != ErrConflict {
		t.Fatal("changed writer receipt silently joined", e)
	}
}
