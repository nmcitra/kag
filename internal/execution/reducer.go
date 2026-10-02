package execution

import (
	"math"
	"reflect"
	"strconv"
)

func evidenceMatches(r record, x evidence, k evidenceKind, rev, epoch uint64, authority, attemptID string, g topology) bool {
	return x.kind == k && x.authority == authority && boundedID(x.receiptID) && x.reservationID == r.input.reservationID && x.attemptID == attemptID && x.namespace == r.input.replay.namespace && x.replayKey == r.input.replay.key && x.bindingDigest == r.input.binding.Digest() && x.operationDigest == r.input.binding.Operation().Digest() && x.decisionDigest == r.input.decision.digest && x.actorProjectionDigest == r.input.decision.actorProjectionDigest && x.revision == rev && x.epoch == epoch && validHead(x.head) && x.head.authority == authority && evidenceLineageMatches(x, k, g)
}
func eligible(g topology, r record) bool {
	if g.retainedHead.authority != "ledger" || g.independentHead.authority != "ledger" || g.targetHead.authority != "target" || g.phase != topologyEligible || g.epoch != r.epoch || !validHead(g.retainedHead) || !validHead(g.independentHead) || g.retainedHead != g.independentHead || !validHead(g.targetHead) {
		return false
	}
	for _, ns := range g.rejectedNamespaces {
		if ns == r.input.replay.namespace {
			return false
		}
	}
	return true
}
func permittedState(s State, k eventKind) bool {
	switch k {
	case attachReady:
		return s == ReservedPendingACK
	case consume:
		return s == Ready
	case withhold:
		return s == ReservedPendingACK || s == Ready
	case markUnknown, confirmEffect, confirmNoEffect, quarantineDeadline:
		return s == AttemptConsumed || s == OutcomeUnknown
	case annotateContradiction:
		return s >= ReservedPendingACK && s <= Withheld
	case markResponseWithheld, markOutcomeDelivered:
		return s == EffectConfirmed
	}
	return false
}

// reduce authenticates no observations and performs no external operation.
func reduce(old record, e event, g topology) (record, error) {
	r := cloneRecord(old)
	deny := func(err error) (record, error) { return cloneRecord(old), err }
	if old.state == Absent || old.state > Withheld || old.revision == 0 || old.epoch == 0 {
		return deny(ErrTransition)
	}
	if e.expectRevision != old.revision {
		return deny(ErrStaleRevision)
	}
	if e.expectEpoch != old.epoch {
		return deny(ErrStaleEpoch)
	}
	if e.at < old.input.createdAt || e.at < old.lastAt {
		return deny(ErrEvidence)
	}
	if _, err := ownInput(old.input); err != nil {
		return deny(ErrInvalid)
	}
	// Only exact repeated terminal evidence is inert; conflicting evidence must be annotated.
	if (e.kind == confirmEffect && r.state == EffectConfirmed || e.kind == confirmNoEffect && r.state == NoEffectConfirmed) && reflect.DeepEqual(e.outcome, r.outcome) {
		return r, nil
	}
	if e.kind == attachReady && r.state == Ready && e.reservationReceipt == r.reservationReceipt && e.recorderReceipt == r.recorderReceipt && e.readinessReceipt == r.readinessReceipt {
		return r, nil
	}
	if !permittedState(r.state, e.kind) {
		return deny(ErrTransition)
	}
	noOp := false
	switch e.kind {
	case attachReady:
		if !eligible(g, r) {
			return deny(ErrClosed)
		}
		if r.quarantined || len(r.contradictionIDs) > 0 || e.at < r.input.decision.validFrom || e.at >= r.input.releaseDeadline || e.at >= r.input.decision.expires {
			return deny(ErrEvidence)
		}
		if !evidenceMatches(r, e.reservationReceipt, storeReservation, 1, r.epoch, "ledger", "", g) || !evidenceMatches(r, e.readinessReceipt, storeReadiness, r.revision+1, r.epoch, "ledger", "", g) {
			return deny(ErrEvidence)
		}
		if r.input.requiredRecorder != "" {
			if !evidenceMatches(r, e.recorderReceipt, recorderPreAction, 1, r.epoch, r.input.requiredRecorder, "", g) {
				return deny(ErrEvidence)
			}
		} else if e.recorderReceipt != (evidence{}) {
			return deny(ErrEvidence)
		}
		r.reservationReceipt = e.reservationReceipt
		r.recorderReceipt = e.recorderReceipt
		r.readinessReceipt = e.readinessReceipt
		r.state = Ready
	case consume:
		if !eligible(g, r) {
			return deny(ErrClosed)
		}
		c := e.check
		a := e.attempt
		if r.quarantined || len(r.contradictionIDs) > 0 || r.attempt != (attempt{}) || r.consumeReceipt != (evidence{}) || !evidenceMatches(r, r.readinessReceipt, storeReadiness, r.readinessReceipt.revision, r.epoch, "ledger", "", g) || c.class != recheckCurrent || c.decisionID != r.input.decision.id || c.authorityVersion != r.input.decision.authorityVersion || c.bindingDigest != r.input.binding.Digest() || c.operationDigest != r.input.binding.Operation().Digest() || c.actorProjectionDigest != r.input.decision.actorProjectionDigest || c.checkedAt < r.input.decision.validFrom || c.checkedAt > e.at || e.at >= c.expires || c.expires > r.input.decision.expires || e.at < r.input.decision.validFrom || e.at >= r.input.releaseDeadline || e.at >= r.input.decision.expires || c.targetVersion != r.input.binding.Operation().TargetVersion() || !boundedID(a.id) || !boundedID(a.executor) || !boundedID(a.targetKey) || a.executor != c.executor || a.epoch != r.epoch || c.epoch != r.epoch || a.consumeRevision != r.revision+1 || a.operationDigest != r.input.binding.Operation().Digest() || !evidenceMatches(r, e.consumeReceipt, storeConsumption, r.revision+1, r.epoch, "ledger", a.id, g) {
			return deny(ErrEvidence)
		}
		r.state = AttemptConsumed
		r.attempt = a
		r.consumeReceipt = e.consumeReceipt
	case withhold:
		if r.attempt != (attempt{}) || r.consumeReceipt != (evidence{}) || !boundedID(e.annotationID) {
			return deny(ErrEvidence)
		}
		r.state = Withheld
		r.budget = budgetRefunded
	case markUnknown:
		if r.attempt.id == "" || r.outcome != (evidence{}) || e.outcome != (evidence{}) {
			return deny(ErrEvidence)
		}
		if r.state == OutcomeUnknown {
			noOp = true
		}
		r.state = OutcomeUnknown
	case confirmEffect, confirmNoEffect:
		if r.quarantined || len(r.contradictionIDs) > 0 || r.attempt.id == "" || r.outcome != (evidence{}) || r.budget != budgetHeld {
			return deny(ErrEvidence)
		}
		k := targetEffect
		if e.kind == confirmNoEffect {
			k = targetTerminalNoEffect
		}
		x := e.outcome
		if !evidenceMatches(r, x, k, r.attempt.consumeRevision, r.attempt.epoch, "target", r.attempt.id, g) || x.beforeVersion != r.input.binding.Operation().TargetVersion() {
			return deny(ErrEvidence)
		}
		if e.kind == confirmEffect {
			before, err := strconv.ParseUint(x.beforeVersion, 10, 64)
			if err != nil || before == math.MaxUint64 || x.afterVersion != strconv.FormatUint(before+1, 10) || x.terminalClosureID != "" {
				return deny(ErrEvidence)
			}
			r.state = EffectConfirmed
			r.budget = budgetSpent
		} else {
			if !boundedID(x.terminalClosureID) || x.afterVersion != x.beforeVersion {
				return deny(ErrEvidence)
			}
			r.state = NoEffectConfirmed
			r.budget = budgetRefunded
		}
		r.outcome = x
	case annotateContradiction:
		if !boundedID(e.annotationID) {
			return deny(ErrEvidence)
		}
		for _, id := range r.contradictionIDs {
			if id == e.annotationID {
				return r, nil
			}
		}
		if len(r.contradictionIDs) >= 32 {
			return deny(ErrOverflow)
		}
		r.contradictionIDs = append(r.contradictionIDs, e.annotationID)
		r.quarantined = true
		if r.state == AttemptConsumed || r.state == OutcomeUnknown {
			r.state = OutcomeUnknown
		}
	case markResponseWithheld:
		if !boundedID(e.annotationID) {
			return deny(ErrEvidence)
		}
		if r.responseWithheld && r.responseReference != e.annotationID {
			return deny(ErrConflict)
		}
		noOp = r.responseWithheld
		r.responseWithheld = true
		r.responseReference = e.annotationID
	case markOutcomeDelivered:
		d := e.delivery
		if r.quarantined || len(r.contradictionIDs) > 0 || d.writerAuthority != "writer" || !boundedID(d.acceptanceID) || e.annotationID != d.acceptanceID || !boundedID(d.attestationID) || d.effectReceiptID != r.outcome.receiptID || d.reservationID != r.input.reservationID || d.attemptID != r.attempt.id || d.actorRef != r.input.decision.actorRef || d.bindingDigest != r.input.binding.Digest() || d.actorProjectionDigest != r.input.decision.actorProjectionDigest {
			return deny(ErrEvidence)
		}
		if r.outcomeDelivered && r.deliveryReference != d {
			return deny(ErrConflict)
		}
		noOp = r.outcomeDelivered
		r.outcomeDelivered = true
		r.deliveryReference = d
	case quarantineDeadline:
		if r.attempt.id == "" || r.outcome != (evidence{}) || e.at < r.input.unknownDeadline {
			return deny(ErrEvidence)
		}
		noOp = r.quarantined && r.state == OutcomeUnknown
		r.quarantined = true
		r.state = OutcomeUnknown
	}
	if noOp {
		return cloneRecord(old), nil
	}
	if r.revision == math.MaxUint64 {
		return deny(ErrOverflow)
	}
	r.revision++
	r.lastAt = e.at
	return r, nil
}

func evidenceLineageMatches(x evidence, k evidenceKind, g topology) bool {
	if k == recorderPreAction {
		return true
	}
	if k == targetEffect || k == targetTerminalNoEffect {
		return g.targetHead.authority == "target" && validHead(g.targetHead) && x.head.lineage == g.targetHead.lineage
	}
	return x.head.lineage == g.retainedHead.lineage
}
