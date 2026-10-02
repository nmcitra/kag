// Package execution contains an inert local state reducer. Proposed values do
// not persist, authenticate receipts, dispatch actions or establish durability.
package execution

import (
	"bytes"
	"github.com/gatekeeper454/KTP-Component-Dev/internal/action"
	"github.com/gatekeeper454/KTP-Component-Dev/internal/decision"
	"math"
	"reflect"
)

type State uint8

const (
	Absent State = iota
	ReservedPendingACK
	Ready
	AttemptConsumed
	OutcomeUnknown
	EffectConfirmed
	NoEffectConfirmed
	Withheld
)

type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrInvalid       Error = "invalid"
	ErrConflict      Error = "binding_conflict"
	ErrStaleRevision Error = "stale_revision"
	ErrStaleEpoch    Error = "stale_epoch"
	ErrTransition    Error = "invalid_transition"
	ErrEvidence      Error = "incomplete_or_conflicting_evidence"
	ErrClosed        Error = "topology_closed"
	ErrBudget        Error = "budget_refusal"
	ErrOverflow      Error = "counter_overflow"
)

type reserveClass uint8

const (
	reserveNew reserveClass = iota
	reserveJoin
	reserveConflict
	reserveRefused
	reserveUncertain
)

type budgetDisposition uint8

const (
	budgetHeld budgetDisposition = iota
	budgetSpent
	budgetRefunded
)

type evidenceKind uint8

const (
	storeReservation evidenceKind = iota + 1
	recorderPreAction
	storeReadiness
	storeConsumption
	targetEffect
	targetTerminalNoEffect
)

type eventKind uint8

const (
	attachReady eventKind = iota + 1
	consume
	withhold
	markUnknown
	confirmEffect
	confirmNoEffect
	annotateContradiction
	markResponseWithheld
	markOutcomeDelivered
	quarantineDeadline
)

type recheckClass uint8

const (
	recheckInvalid recheckClass = iota
	recheckCurrent
	recheckExpired
	recheckRevoked
	recheckMismatch
	recheckUnavailable
)

type head struct {
	authority, lineage, id string
	sequence               uint64
}
type replayIdentity struct{ namespace, key string }
type decisionSummary struct {
	id, issuerProfile, actorRef, permissionRef, inspectionRef string
	digest, actorProjectionDigest                             [32]byte
	validFrom, expires                                        int64
	authorityVersion                                          string
}
type budgetCost struct {
	account string
	amount  uint64
}
type reservationInput struct {
	replay                                      replayIdentity
	reservationID                               string
	binding                                     action.Binding
	decision                                    decisionSummary
	costs                                       []budgetCost
	requiredRecorder                            string
	createdAt, releaseDeadline, unknownDeadline int64
	epoch                                       uint64
}
type attempt struct {
	id, targetKey, executor string
	epoch, consumeRevision  uint64
	operationDigest         [32]byte
}
type evidence struct {
	authority, receiptID                                                  string
	kind                                                                  evidenceKind
	reservationID, attemptID, namespace, replayKey                        string
	bindingDigest, operationDigest, decisionDigest, actorProjectionDigest [32]byte
	revision, epoch                                                       uint64
	head                                                                  head
	beforeVersion, afterVersion, terminalClosureID                        string
}
type currentCheck struct {
	class                                                 recheckClass
	decisionID, authorityVersion                          string
	bindingDigest, operationDigest, actorProjectionDigest [32]byte
	checkedAt, expires                                    int64
	targetVersion, executor                               string
	epoch                                                 uint64
}
type record struct {
	input                                                                 reservationInput
	state                                                                 State
	revision, epoch                                                       uint64
	attempt                                                               attempt
	reservationReceipt, recorderReceipt, readinessReceipt, consumeReceipt evidence
	outcome                                                               evidence
	budget                                                                budgetDisposition
	contradictionIDs                                                      []string
	responseWithheld, outcomeDelivered, quarantined                       bool
	lastAt                                                                int64
	responseReference                                                     string
	deliveryReference                                                     deliverySummary
}
type deliverySummary struct {
	writerAuthority, acceptanceID, attestationID, effectReceiptID string
	reservationID, attemptID, actorRef                            string
	bindingDigest, actorProjectionDigest                          [32]byte
}
type event struct {
	kind                                                                  eventKind
	expectRevision, expectEpoch                                           uint64
	at                                                                    int64
	reservationReceipt, recorderReceipt, readinessReceipt, consumeReceipt evidence
	check                                                                 currentCheck
	attempt                                                               attempt
	outcome                                                               evidence
	delivery                                                              deliverySummary
	annotationID                                                          string
}
type snapshot struct {
	state                                                     State
	revision, epoch                                           uint64
	reservationID, namespace, replayKey, attemptID, targetKey string
	bindingDigest, operationDigest, decisionDigest            [32]byte
	budget                                                    budgetDisposition
	quarantined, responseWithheld, outcomeDelivered           bool
	contradictionIDs                                          []string
}

func boundedID(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for i, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			continue
		}
		if i > 0 && (c == '.' || c == '_' || c == ':' || c == '-') {
			continue
		}
		return false
	}
	return true
}
func validHead(h head) bool {
	return boundedID(h.authority) && boundedID(h.lineage) && boundedID(h.id) && h.sequence > 0
}
func ownInput(in reservationInput) (reservationInput, error) {
	v, e := in.binding.View()
	if e != nil || !boundedID(in.replay.namespace) || in.replay.key != v.ReplayID || !boundedID(in.reservationID) || in.epoch == 0 || len(in.costs) == 0 || len(in.costs) > 16 {
		return reservationInput{}, ErrInvalid
	}
	d := in.decision
	for _, id := range []string{d.id, d.issuerProfile, d.actorRef, d.permissionRef, d.inspectionRef, d.authorityVersion} {
		if !boundedID(id) {
			return reservationInput{}, ErrInvalid
		}
	}
	if d.digest == ([32]byte{}) || d.actorProjectionDigest != v.IdentityProjectionDigest || d.validFrom < v.ValidFromUnixNS || d.expires > v.ExpiresUnixNS || d.validFrom < 0 || d.expires <= d.validFrom || in.createdAt < d.validFrom || in.createdAt >= in.releaseDeadline || in.releaseDeadline > d.expires || in.releaseDeadline > in.unknownDeadline || in.unknownDeadline < 0 || in.requiredRecorder != "" && !boundedID(in.requiredRecorder) {
		return reservationInput{}, ErrInvalid
	}
	var sum uint64
	for i, c := range in.costs {
		if !boundedID(c.account) || c.amount == 0 || i > 0 && in.costs[i-1].account >= c.account {
			return reservationInput{}, ErrInvalid
		}
		if c.amount > math.MaxUint64-sum {
			return reservationInput{}, ErrOverflow
		}
		sum += c.amount
	}
	in.costs = append([]budgetCost(nil), in.costs...)
	return in, nil
}
func cloneRecord(in record) record {
	in.input.costs = append([]budgetCost(nil), in.input.costs...)
	in.contradictionIDs = append([]string(nil), in.contradictionIDs...)
	return in
}
func inspect(in record) snapshot {
	return snapshot{in.state, in.revision, in.epoch, in.input.reservationID, in.input.replay.namespace, in.input.replay.key, in.attempt.id, in.attempt.targetKey, in.input.binding.Digest(), in.input.binding.Operation().Digest(), in.input.decision.digest, in.budget, in.quarantined, in.responseWithheld, in.outcomeDelivered, append([]string(nil), in.contradictionIDs...)}
}
func sameReservation(a, b reservationInput) bool {
	if !bytes.Equal(a.binding.Bytes(), b.binding.Bytes()) || !bytes.Equal(a.binding.Operation().Bytes(), b.binding.Operation().Bytes()) {
		return false
	}
	a.binding = action.Binding{}
	b.binding = action.Binding{}
	return reflect.DeepEqual(a, b)
}
func newPending(in reservationInput) (record, error) {
	owned, e := ownInput(in)
	if e != nil {
		return record{}, e
	}
	if owned.binding.Operation().OperationID() != "lab.set_marker" {
		return record{}, ErrInvalid
	}
	return record{input: owned, state: ReservedPendingACK, revision: 1, epoch: owned.epoch, budget: budgetHeld, lastAt: owned.createdAt}, nil
}

// Reservation is an owned informational seed. It creates no ledger slot,
// budget hold, dispatch authority, persistence claim or readiness capability.
type Reservation struct {
	binding                                                  action.Binding
	permit                                                   decision.Permit
	namespace, evidenceScope                                 string
	bindingDigest, operationDigest, identityProjectionDigest [32]byte
	validFrom, expires                                       int64
}

func NewReservation(b action.Binding, p decision.Permit, ns string) (Reservation, error) {
	if !boundedID(ns) {
		return Reservation{}, ErrInvalid
	}
	v, err := b.View()
	if err != nil {
		return Reservation{}, ErrInvalid
	}
	q, err := p.Projection()
	if err != nil || q.EvidenceScope != "modeled" {
		return Reservation{}, ErrInvalid
	}
	if q.BindingDigest != b.Digest() || q.OperationDigest != b.Operation().Digest() || q.IdentityProjectionDigest != v.IdentityProjectionDigest || q.ReplayID != v.ReplayID || q.DecisionDigest == ([32]byte{}) || q.ValidFromUnixNS < v.ValidFromUnixNS || q.ExpiresUnixNS > v.ExpiresUnixNS || q.ValidFromUnixNS < 0 || q.ValidFromUnixNS >= q.ExpiresUnixNS {
		return Reservation{}, ErrConflict
	}
	return Reservation{binding: b, permit: p, namespace: ns, evidenceScope: "modeled", bindingDigest: q.BindingDigest, operationDigest: q.OperationDigest, identityProjectionDigest: q.IdentityProjectionDigest, validFrom: q.ValidFromUnixNS, expires: q.ExpiresUnixNS}, nil
}
func (r Reservation) State() State                       { return Absent }
func (r Reservation) EvidenceScope() string              { return r.evidenceScope }
func (r Reservation) Namespace() string                  { return r.namespace }
func (r Reservation) ReplayID() string                   { return r.binding.Operation().ReplayID() }
func (r Reservation) BindingDigest() [32]byte            { return r.bindingDigest }
func (r Reservation) OperationDigest() [32]byte          { return r.operationDigest }
func (r Reservation) IdentityProjectionDigest() [32]byte { return r.identityProjectionDigest }
func (r Reservation) ValidFromUnixNS() int64             { return r.validFrom }
func (r Reservation) ExpiresUnixNS() int64               { return r.expires }
func (r Reservation) BindingBytes() []byte               { return r.binding.Bytes() }
func (r Reservation) OperationBytes() []byte             { return r.binding.Operation().Bytes() }
