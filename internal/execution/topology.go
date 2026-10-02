package execution

import (
	"math"
	"reflect"
)

type topologyPhase uint8

const (
	topologyClosed topologyPhase = iota
	topologyHeadEstablished
	topologyEpochAcquired
	topologyTargetFenced
	topologyReconciled
	topologyReadinessRetained
	topologyEligible
	topologyQuarantined
)

type topology struct {
	phase                                     topologyPhase
	revision, epoch                           uint64
	restoreID                                 string
	retainedHead, independentHead, targetHead head
	oldAttempts, rejectedNamespaces           []string
	readinessRef                              string
}
type topologyEventKind uint8

const (
	beginPromotion topologyEventKind = iota + 1
	establishHead
	acquireEpoch
	acknowledgeTargetFence
	reconcileTopology
	retainReadiness
	openTopology
	beginRestore
	failTopology
)

type topologyEvent struct {
	kind                                      topologyEventKind
	expectRevision, expectEpoch               uint64
	nextEpoch                                 uint64
	restoreID                                 string
	retainedHead, independentHead, targetHead head
	oldAttempts, rejectedNamespaces           []string
	evidenceRef                               string
}

func cloneTopology(in topology) topology {
	in.oldAttempts = append([]string(nil), in.oldAttempts...)
	in.rejectedNamespaces = append([]string(nil), in.rejectedNamespaces...)
	return in
}
func boundedIDs(ids []string) bool {
	if len(ids) > 64 {
		return false
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if !boundedID(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

// Topology observations remain private semantic inputs; model authority tables
// in tests establish receipt eligibility. This is not a supplier verifier.
func reduceTopology(old topology, e topologyEvent) (topology, error) {
	g := cloneTopology(old)
	deny := func(err error) (topology, error) { return cloneTopology(old), err }
	if e.expectRevision != old.revision {
		return deny(ErrStaleRevision)
	}
	if e.expectEpoch != old.epoch {
		return deny(ErrStaleEpoch)
	}
	if old.revision == math.MaxUint64 {
		return deny(ErrOverflow)
	}
	if !boundedIDs(e.oldAttempts) || !boundedIDs(e.rejectedNamespaces) {
		return deny(ErrInvalid)
	}
	switch e.kind {
	case beginPromotion, beginRestore:
		if e.kind == beginRestore && (!boundedID(e.restoreID) || len(e.rejectedNamespaces) == 0) {
			return deny(ErrEvidence)
		}
		g.phase = topologyClosed
		g.readinessRef = ""
		if len(old.oldAttempts) > 0 && !reflect.DeepEqual(old.oldAttempts, e.oldAttempts) {
			return deny(ErrEvidence)
		}
		g.oldAttempts = append([]string(nil), e.oldAttempts...)
		if e.kind == beginRestore {
			g.restoreID = e.restoreID
			g.rejectedNamespaces = append([]string(nil), e.rejectedNamespaces...)
		}
	case establishHead:
		if g.phase != topologyClosed {
			return deny(ErrTransition)
		}
		if !validHead(e.retainedHead) || e.retainedHead.authority != "ledger" || e.retainedHead != e.independentHead || !boundedID(e.evidenceRef) || validHead(old.retainedHead) && (e.retainedHead.lineage != old.retainedHead.lineage || e.retainedHead.sequence < old.retainedHead.sequence || e.retainedHead.sequence == old.retainedHead.sequence && e.retainedHead.id != old.retainedHead.id) {
			return deny(ErrEvidence)
		}
		g.retainedHead = e.retainedHead
		g.independentHead = e.independentHead
		g.phase = topologyHeadEstablished
	case acquireEpoch:
		if g.phase != topologyHeadEstablished {
			return deny(ErrTransition)
		}
		if g.epoch == math.MaxUint64 {
			return deny(ErrOverflow)
		}
		if e.nextEpoch <= g.epoch || !boundedID(e.evidenceRef) {
			return deny(ErrEvidence)
		}
		g.epoch = e.nextEpoch
		g.phase = topologyEpochAcquired
	case acknowledgeTargetFence:
		if g.phase != topologyEpochAcquired {
			return deny(ErrTransition)
		}
		if !validHead(e.targetHead) || e.targetHead.authority != "target" || !boundedID(e.evidenceRef) || validHead(g.targetHead) && (e.targetHead.lineage != g.targetHead.lineage || e.targetHead.sequence < g.targetHead.sequence || e.targetHead.sequence == g.targetHead.sequence && e.targetHead.id != g.targetHead.id) {
			return deny(ErrEvidence)
		}
		g.targetHead = e.targetHead
		g.phase = topologyTargetFenced
	case reconcileTopology:
		if g.phase != topologyTargetFenced {
			return deny(ErrTransition)
		}
		if !boundedID(e.evidenceRef) || e.retainedHead != g.retainedHead || e.independentHead != g.independentHead || e.targetHead != g.targetHead || !reflect.DeepEqual(g.oldAttempts, e.oldAttempts) {
			return deny(ErrEvidence)
		}
		g.oldAttempts = nil
		g.phase = topologyReconciled
	case retainReadiness:
		if g.phase != topologyReconciled {
			return deny(ErrTransition)
		}
		if !boundedID(e.evidenceRef) || e.retainedHead != g.retainedHead || e.independentHead != g.independentHead || e.targetHead != g.targetHead {
			return deny(ErrEvidence)
		}
		g.readinessRef = e.evidenceRef
		g.phase = topologyReadinessRetained
	case openTopology:
		if g.phase != topologyReadinessRetained {
			return deny(ErrTransition)
		}
		if e.evidenceRef != g.readinessRef || g.readinessRef == "" || len(g.oldAttempts) != 0 || e.retainedHead != g.retainedHead || e.independentHead != g.independentHead || e.targetHead != g.targetHead {
			return deny(ErrEvidence)
		}
		g.phase = topologyEligible
	case failTopology:
		if !boundedID(e.evidenceRef) {
			return deny(ErrEvidence)
		}
		g.phase = topologyQuarantined
		g.readinessRef = ""
	default:
		return deny(ErrTransition)
	}
	g.revision++
	return g, nil
}
