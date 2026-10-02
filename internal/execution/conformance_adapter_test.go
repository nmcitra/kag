package execution

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
)

const fixturePin = "732e293673461807d9ae491ac3d00b1c42dbb4143c5b3bf6056ab3d44993f25d"

// Only these declared fault scenarios are supported. The values select model
// operations; none is a credential or authenticated evidence. No vector IDs,
// case labels or expectations enter this adapter.
var conformanceScenarios = map[string]string{
	"baseline":      `{"authorizationCurrent":true,"bindingsCurrent":true,"reservation":"accepted","dispatchObserved":true}`,
	"expiry":        `{"proofExpiredAtQueueExit":true,"nonDispatchAuthenticated":true}`,
	"parameters":    `{"parametersMatch":false,"nonDispatchAuthenticated":true}`,
	"destination":   `{"destinationMatch":false,"nonDispatchAuthenticated":true}`,
	"version":       `{"targetVersionMatch":false,"conditionalCommitSupported":true}`,
	"replay":        `{"sameIdentity":true,"sameFingerprint":true,"priorDispatch":true}`,
	"collision":     `{"sameIdentity":true,"sameFingerprint":false}`,
	"budget":        `{"scopeLimit":10,"firstReservation":6,"secondRequestIdentity":"different","secondRequested":6,"atomicAuthority":true}`,
	"ledger":        `{"budgetStateAvailable":false,"nonDispatchAuthenticated":true}`,
	"recorder":      `{"requiredRecorderAvailable":false,"nonDispatchAuthenticated":false}`,
	"before-send":   `{"durableReservation":true,"dispatchIntent":true,"nonDispatchAuthenticated":false}`,
	"after-send":    `{"dispatchAuthenticated":true,"targetOutcomeAvailable":false}`,
	"lost-reply":    `{"responseLost":true,"targetEffectAuthenticated":true}`,
	"contradiction": `{"conflictingEvidence":true}`,
	"restore":       `{"restorationCurrent":false,"reservationPreviouslyUncertain":true}`,
	"denial":        `{"decisionDenied":true,"nonDispatchAuthenticated":false}`,
	"non-dispatch":  `{"decisionDenied":true,"nonDispatchAuthenticated":true,"coverageComplete":true,"intervalBound":true}`,
	"http":          `{"httpStatus":200,"targetEffectAuthenticated":false,"dispatchAuthenticated":false}`,
	"renewal":       `{"proofRefreshed":true,"priorEffectUncertain":true}`,
	"continuing":    `{"checkpointAuthorizationCurrent":false,"safeTransitionDeclared":true}`,
}

func selectConformanceScenario(request map[string]json.RawMessage) string {
	if len(request) == 0 || len(request) > 8 {
		return ""
	}
	// Compare exact typed JSON tokens, not coerced float/bool values.
	for name, raw := range conformanceScenarios {
		var declared map[string]json.RawMessage
		_ = json.Unmarshal([]byte(raw), &declared)
		if len(request) != len(declared) {
			continue
		}
		equal := true
		for k, v := range request {
			if len(v) > 128 {
				equal = false
				break
			}
			var compact json.RawMessage
			if err := json.Unmarshal(v, &compact); err != nil {
				equal = false
				break
			}
			// Re-encoding preserves integer lexical type and rejects null or nested data.
			var value any
			d := json.NewDecoder(bytes.NewReader(v))
			d.UseNumber()
			if err := d.Decode(&value); err != nil {
				equal = false
				break
			}
			canonical, err := json.Marshal(value)
			if err != nil || string(canonical) != string(declared[k]) {
				equal = false
				break
			}
		}
		if equal {
			return name
		}
	}
	return ""
}

func observeConformance(t *testing.T, request map[string]json.RawMessage) (map[string]any, []string, []string) {
	t.Helper()
	scenario := selectConformanceScenario(request)
	actual := map[string]any{}
	if scenario == "" {
		return actual, []string{"request rejected before model operations"}, []string{"unknown fields, types or undeclared scenario combination"}
	}
	h := newFaultHarness(t)
	var unsupported []string
	operations := []string{"initial model ledger reserve retained"}
	retained := func() bool { _, ok := h.m.retained.rows[h.r.input.replay]; return ok }
	state := func() string {
		row := h.m.retained.rows[h.r.input.replay]
		if row.state == EffectConfirmed && len(h.target.effects) > 0 && len(h.target.receipts) > 0 {
			return "effect_confirmed"
		}
		if _, ok := h.target.queue[h.r.attempt.id]; ok && !row.quarantined {
			return "dispatched"
		}
		return "unknown"
	}
	prepare := func() {
		h.makeReady()
		h.makeConsumed()
		operations = append(operations, fmt.Sprintf("model ready/consume registered receipts=%t/%t; retained state=%d", h.m.validReceipt(h.r.readinessReceipt), h.m.validReceipt(h.r.consumeReceipt), h.m.retained.rows[h.r.input.replay].state))
	}
	send := func() bool {
		before := h.target.arrivals
		accepted := h.release(currentFor(h.r, 5), 5)
		_, queued := h.target.queue[h.r.attempt.id]
		operations = append(operations, fmt.Sprintf("initial-send oracle accepted=%t queue entry=%t arrival delta=%d", accepted, queued, h.target.arrivals-before))
		return accepted && queued && h.target.arrivals == before+1
	}
	retry := func() bool {
		before := h.target.arrivals
		accepted := h.release(currentFor(h.r, 7), 7)
		operations = append(operations, fmt.Sprintf("second initial-send oracle accepted=%t arrival delta=%d", accepted, h.target.arrivals-before))
		return accepted || h.target.arrivals != before
	}
	switch scenario {
	case "baseline":
		prepare()
		actual["releaseAllowed"] = send()
		actual["evidenceState"] = state()
		actual["reservationRetained"] = retained()
	case "expiry", "parameters", "version":
		prepare()
		check := currentFor(h.r, 5)
		if scenario == "expiry" {
			check.expires = 5
		}
		if scenario == "parameters" {
			changed := variantInput(t, h.r.input, "action")
			check.bindingDigest = changed.binding.Digest()
			check.operationDigest = changed.binding.Operation().Digest()
		}
		if scenario == "version" {
			h.target.version++
			check.targetVersion = strconv.FormatUint(h.target.version, 10)
			operations = append(operations, fmt.Sprintf("actual current target version=%d; post-ACK check version=%s; bound version=%s", h.target.version, check.targetVersion, h.r.input.binding.Operation().TargetVersion()))
		}
		actual["releaseAllowed"] = h.release(check, 5)
		actual["evidenceState"] = state()
		if scenario != "version" {
			unsupported = append(unsupported, "authenticated non-dispatch coverage and interval contract absent; zero arrivals cannot establish withheld")
		}
	case "destination":
		// The imported binding builder fixes the audience. A target commit refusal
		// cannot substitute for a pre-release destination check.
		actual["evidenceState"] = state()
		unsupported = append(unsupported, "different audience binding and pre-release destination check not implemented by this adapter", "authenticated non-dispatch coverage and interval contract absent")
	case "replay":
		prepare()
		if !send() {
			t.Fatal("prior modeled enqueue failed")
		}
		joined, err := h.m.reserve(h.r.input)
		if err != nil || joined.class != reserveJoin {
			t.Fatal("same fingerprint did not join", err)
		}
		actual["additionalInvocationAllowed"] = retry()
		actual["reservationRetained"] = retained()
		operations = append(operations, "same identity and fingerprint reserveJoin; second initial-send refused with arrival delta zero")
	case "collision":
		conflict, err := h.m.reserve(variantInput(t, h.r.input, "action"))
		actual["identityCollision"] = err == ErrConflict && conflict.class == reserveConflict
		actual["additionalInvocationAllowed"] = err == nil && conflict.class == reserveNew
		operations = append(operations, fmt.Sprintf("changed canonical action reserve class=%d error=%v", conflict.class, err))
	case "budget":
		m := newModelLedger(10)
		first := inputFixture(t)
		first.costs = []budgetCost{{"global", 6}, {"tenant", 6}}
		r, err := m.reserve(first)
		if err != nil {
			t.Fatal(err)
		}
		if err = m.retain(r.write); err != nil {
			t.Fatal(err)
		}
		second := variantInput(t, first, "last-cost-unit")
		r2, err := m.reserve(second)
		if err != ErrBudget {
			t.Fatal("second reservation not refused by ledger", err)
		}
		balance := m.retained.budgets["global"]
		h.m = m
		h.r = r.row
		actual["secondReleaseAllowed"] = err == nil && r2.class == reserveNew
		actual["remainingCapacityUnits"] = balance.limit - balance.held - balance.spent
		operations = append(operations, fmt.Sprintf("atomic global and tenant accounts: limit=%d held=%d spent=%d; second reserve=%v", balance.limit, balance.held, balance.spent, err))
	case "ledger":
		prepare()
		h.m.unavailable = true
		_, err := h.m.reserve(h.r.input)
		if err != ErrClosed {
			t.Fatal("unavailable ledger admitted reserve", err)
		}
		actual["releaseAllowed"] = h.release(currentFor(h.r, 5), 5)
		actual["evidenceState"] = state()
		unsupported = append(unsupported, "authenticated non-dispatch contract absent despite ledger refusal")
	case "recorder":
		h.recorder.unavailable = true
		_, err := h.recorder.append(h.r)
		if err != ErrClosed || h.r.state != ReservedPendingACK {
			t.Fatal("recorder failure advanced readiness", err)
		}
		actual["releaseAllowed"] = h.release(currentFor(h.r, 5), 5)
		actual["evidenceState"] = state()
		operations = append(operations, "actual recorder append failed; readiness did not advance")
	case "before-send", "after-send", "restore", "renewal", "contradiction":
		stale := cloneImage(h.m.retained)
		prepare()
		if scenario == "after-send" && !send() {
			t.Fatal("enqueue failed")
		}
		h.m.crash()
		h.known = false
		h.unknown()
		if scenario == "restore" {
			if h.m.admitRestore(stale, h.target) {
				t.Fatal("stale restore admitted")
			}
			actual["releaseAllowed"] = h.release(currentFor(h.r, 7), 7)
			operations = append(operations, "stale image rejected; authoritative retained row preserved; ledger closed")
		}
		if scenario == "contradiction" {
			h.apply(event{kind: annotateContradiction, expectRevision: h.r.revision, expectEpoch: h.r.epoch, at: 8, annotationID: "adapter-conflict"})
			if !h.r.quarantined {
				t.Fatal("contradiction annotation not quarantined")
			}
			unsupported = append(unsupported, "reaction to annotation modeled; detection of authenticated contradictory evidence unsupported")
		}
		if scenario == "renewal" {
			r, err := h.m.reserve(variantInput(t, h.r.input, "decision"))
			if err != ErrConflict || r.class != reserveConflict {
				t.Fatal("changed decision did not conflict", err)
			}
			unsupported = append(unsupported, "renewed validated-decision correlation absent; changed decision reserveConflict is not successful proof refresh")
		}
		actual["retryAllowed"] = retry()
		actual["reservationRetained"] = retained()
		if scenario != "renewal" {
			actual["evidenceState"] = state()
		}
	case "lost-reply":
		prepare()
		if !send() {
			t.Fatal("enqueue failed")
		}
		if _, err := h.target.commit(h.r.attempt.id, 6); err != nil {
			t.Fatal(err)
		}
		// Discard the reply. Recover only from the registered target lookup.
		h.known = false
		h.unknown()
		x, err := h.target.lookup(h.r.attempt.id)
		if err != nil {
			t.Fatal(err)
		}
		h.confirm(x)
		actual["evidenceState"] = state()
		actual["retryAllowed"] = retry()
		operations = append(operations, "target commit reply discarded; registered lookup receipt confirmed; no additional arrival")
	case "denial", "non-dispatch":
		h.makeReady()
		check := currentFor(h.r, 5)
		check.class = recheckRevoked
		e := consumeEvent(h.r)
		e.check = check
		if _, err := h.m.propose(h.r, e, h.g); err == nil {
			t.Fatal("denied current check consumed")
		}
		if h.release(check, 5) {
			t.Fatal("denial released")
		}
		actual["evidenceState"] = state()
		if scenario == "non-dispatch" {
			unsupported = append(unsupported, "protected-path observer, complete coverage, bound interval and authentication absent; denial is not withheld evidence")
		}
	case "http":
		if _, err := h.target.lookup("transport-only"); err != ErrEvidence {
			t.Fatal("transport fabricated target receipt", err)
		}
		actual["evidenceState"] = state()
		operations = append(operations, "HTTP 200 scenario has no registered dispatch/effect receipt; transport status grants no authority")
	case "continuing":
		unsupported = append(unsupported, "continuing checkpoint and declared safe-transition execution absent")
	}
	operations = append(operations, fmt.Sprintf("component observation: retained rows=%d queue=%d receipts=%d arrivals=%d commits=%d state=%d held=%d spent=%d", len(h.m.retained.rows), len(h.target.queue), len(h.target.receipts), h.target.arrivals, h.target.commits, h.r.state, h.m.retained.budgets["global"].held, h.m.retained.budgets["global"].spent))
	return actual, operations, unsupported
}
