package execution

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"github.com/nmcitra/kag/internal/action"
	"math"
	"reflect"
	"strconv"
	"sync"
	"testing"
)

type writeKind uint8

const (
	writeReserve writeKind = iota + 1
	writeReady
	writeConsume
	writeOutcome
	writeWithhold
	writeTopology
)

type writeRef struct {
	id              string
	kind            writeKind
	revision, epoch uint64
	head            head
}
type account struct{ limit, held, spent uint64 }
type ledgerImage struct {
	authorityVersion, configID, policyID, catalogID, keyID, trajectoryID string
	clockFloor, createdTick                                              int64
	targetCheckpoint                                                     head
	rows                                                                 map[replayIdentity]record
	budgets                                                              map[string]account
	head                                                                 head
	quarantined                                                          map[string]bool
	rejected                                                             map[string]bool
}
type modelLedger struct {
	oldestBackupTick, latestDelayedTick, now int64
	checkpointCoverage                       map[replayIdentity]head
	rejectionCoverage                        map[string]head
	mu                                       sync.Mutex
	local, retained                          ledgerImage
	nextWrite                                uint64
	writes                                   map[string]ledgerImage
	bases                                    map[string]head
	refs                                     map[string]writeRef
	keys                                     map[string]replayIdentity
	receipts                                 map[string]evidence
	external                                 map[string]evidence
	unavailable                              bool
	maxRows                                  int
}
type reserveResult struct {
	class reserveClass
	row   record
	write writeRef
}
type modelRecorder struct {
	rows        map[string]evidence
	max         int
	unavailable bool
}
type targetRequest struct {
	binding       action.Binding
	attempt       attempt
	broker, route string
	deadline      int64
}
type modelTarget struct {
	finalWire                   map[string][]byte
	admittedBindings            map[[32]byte]action.Operation
	admittedKeys                map[string][32]byte
	allowedBrokers              map[string]bool
	credentialVersion           string
	version, epoch              uint64
	queue                       map[string]targetRequest
	bindings                    map[string][32]byte
	effects, closures           map[string]evidence
	receipts                    map[string]evidence
	rejected                    map[string]bool
	arrivals, refusals, commits uint64
	unavailable, incomplete     bool
	head                        head
	admitted                    [32]byte
}

func TestModelAtomicCASBudget(t *testing.T) {
	in := inputFixture(t)
	m := newModelLedger(1)
	a, e := m.reserve(in)
	if e != nil || a.class != reserveNew {
		t.Fatal(a, e)
	}
	if e = m.retain(a.write); e != nil {
		t.Fatal(e)
	}
	b, e := m.reserve(in)
	if e != nil || b.class != reserveJoin || len(m.retained.rows) != 1 || m.retained.budgets["global"].held != 1 {
		t.Fatal(b, e)
	}
	changed := in
	changed.releaseDeadline--
	c, e := m.reserve(changed)
	if e != ErrConflict || c.class != reserveConflict {
		t.Fatal(c, e)
	}
	different := in
	different.replay.key = "1123456789abcdef0123456789abcdef"
	if _, e = m.reserve(different); e == nil {
		t.Fatal("nonmatching action replay accepted")
	}
}
func TestModelACKKnowledge(t *testing.T) {
	m := newModelLedger(2)
	r, e := m.reserve(inputFixture(t))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.receipt(r.write); e != ErrEvidence {
		t.Fatal("local proposal has ACK", e)
	}
	m.crash()
	if len(m.retained.rows) != 0 {
		t.Fatal("local proposal retained")
	}
	r, e = m.reserve(inputFixture(t))
	if e != nil {
		t.Fatal(e)
	}
	if e = m.retain(r.write); e != nil {
		t.Fatal(e)
	}
	m.crash()
	row, receipt, e := m.lookup(inputFixture(t).replay)
	if e != nil || row.state != ReservedPendingACK || receipt.kind != storeReservation {
		t.Fatal(row, receipt, e)
	}
	receipt.head.id = "forged"
	if m.validReceipt(receipt) {
		t.Fatal("forged head authenticated")
	}
}
func TestModelTargetCommitFence(t *testing.T) {
	r := consumedFixture(t)
	target := newModelTarget(r.input.binding)
	q := targetRequest{r.input.binding, r.attempt, "executor-1", "fixed", 800}
	if e := target.enqueue(q); e != nil {
		t.Fatal(e)
	}
	target.advanceFence(2)
	if _, e := target.commit(r.attempt.id, 5); e == nil || target.commits != 0 || target.refusals != 1 {
		t.Fatal(e, target.commits, target.refusals)
	}
}
func TestModelNoEffectDelayedClosure(t *testing.T) {
	r := consumedFixture(t)
	target := newModelTarget(r.input.binding)
	q := targetRequest{r.input.binding, r.attempt, "executor-1", "fixed", 800}
	if e := target.enqueue(q); e != nil {
		t.Fatal(e)
	}
	x, e := target.closeNoEffect(r.attempt.id)
	if e != nil || x.terminalClosureID == "" {
		t.Fatal(x, e)
	}
	if _, e = target.commit(r.attempt.id, 5); e == nil || target.commits != 0 {
		t.Fatal("delayed commit survived closure")
	}
}
func cloneImage(in ledgerImage) ledgerImage {
	out := ledgerImage{authorityVersion: in.authorityVersion, configID: in.configID, policyID: in.policyID, catalogID: in.catalogID, keyID: in.keyID, trajectoryID: in.trajectoryID, clockFloor: in.clockFloor, createdTick: in.createdTick, targetCheckpoint: in.targetCheckpoint, rows: map[replayIdentity]record{}, budgets: map[string]account{}, head: in.head, quarantined: map[string]bool{}, rejected: map[string]bool{}}
	for k, r := range in.rows {
		out.rows[k] = cloneRecord(r)
	}
	for k, a := range in.budgets {
		out.budgets[k] = a
	}
	for k, v := range in.quarantined {
		out.quarantined[k] = v
	}
	for k, v := range in.rejected {
		out.rejected[k] = v
	}
	return out
}
func newModelLedger(limit uint64) *modelLedger {
	im := ledgerImage{authorityVersion: "authority-v1", configID: "config-v1", policyID: "policy-v1", catalogID: "catalog-v1", keyID: "key-v1", trajectoryID: "trajectory-v1", clockFloor: 1, createdTick: 2, targetCheckpoint: head{"target", "model-lineage", "target-initial", 1}, rows: map[replayIdentity]record{}, budgets: map[string]account{"global": {limit, 0, 0}, "tenant": {limit, 0, 0}}, head: head{"ledger", "model-lineage", "initial", 1}, quarantined: map[string]bool{}, rejected: map[string]bool{}}
	return &modelLedger{oldestBackupTick: 1, latestDelayedTick: 1000, now: 2, checkpointCoverage: map[replayIdentity]head{}, rejectionCoverage: map[string]head{}, local: cloneImage(im), retained: cloneImage(im), writes: map[string]ledgerImage{}, bases: map[string]head{}, refs: map[string]writeRef{}, keys: map[string]replayIdentity{}, receipts: map[string]evidence{}, external: map[string]evidence{}, maxRows: 64}
}
func (m *modelLedger) stage(im ledgerImage, k replayIdentity, kind writeKind) (writeRef, error) {
	if m.nextWrite == math.MaxUint64 || m.retained.head.sequence == math.MaxUint64 {
		return writeRef{}, ErrOverflow
	}
	m.nextWrite++
	id := fmt.Sprintf("write-%d", m.nextWrite)
	h := head{"ledger", "model-lineage", id, m.retained.head.sequence + 1}
	r := im.rows[k]
	w := writeRef{id, kind, r.revision, r.epoch, h}
	im.head = h
	if r.lastAt > im.createdTick {
		im.createdTick = r.lastAt
	}
	m.writes[id] = cloneImage(im)
	m.bases[id] = m.retained.head
	m.refs[id] = w
	m.keys[id] = k
	m.local = cloneImage(im)
	return w, nil
}
func (m *modelLedger) reserve(in reservationInput) (reserveResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.unavailable {
		return reserveResult{class: reserveUncertain}, ErrClosed
	}
	owned, e := ownInput(in)
	if e != nil {
		return reserveResult{class: reserveRefused}, e
	}
	if m.retained.rejected[in.replay.namespace] {
		return reserveResult{class: reserveRefused}, ErrClosed
	}
	if r, ok := m.local.rows[in.replay]; ok {
		if sameReservation(r.input, owned) {
			return reserveResult{class: reserveJoin, row: cloneRecord(r)}, nil
		}
		return reserveResult{class: reserveConflict, row: cloneRecord(r)}, ErrConflict
	}
	if len(m.retained.rows) >= m.maxRows {
		return reserveResult{class: reserveRefused}, ErrBudget
	}
	r, im, e := m.reservationProposal(owned)
	if e != nil {
		return reserveResult{class: reserveRefused}, e
	}
	w, e := m.stage(im, in.replay, writeReserve)
	if e != nil {
		return reserveResult{class: reserveRefused}, e
	}
	return reserveResult{reserveNew, cloneRecord(r), w}, nil
}
func (m *modelLedger) retain(w writeRef) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.unavailable {
		return ErrClosed
	}
	ref, ok := m.refs[w.id]
	if !ok || ref != w {
		return ErrEvidence
	}
	if m.retained.head == w.head {
		return nil
	}
	if m.retained.head != m.bases[w.id] {
		return ErrStaleRevision
	}
	im, ok := m.writes[w.id]
	if !ok {
		return ErrEvidence
	}
	m.retained = cloneImage(im)
	m.local = cloneImage(im)
	r := im.rows[m.keys[w.id]]
	kind := storeReservation
	switch w.kind {
	case writeReady:
		kind = storeReadiness
	case writeConsume:
		kind = storeConsumption
	case writeOutcome, writeWithhold:
		kind = 0
	}
	x := receiptFor(r, kind, w.revision)
	x.receiptID = w.id
	x.head = w.head
	if w.kind == writeConsume {
		x.attemptID = r.attempt.id
	}
	m.receipts[x.receiptID] = x
	return nil
}
func (m *modelLedger) receipt(w writeRef) (evidence, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	x, ok := m.receipts[w.id]
	if m.unavailable || !ok || m.refs[w.id] != w || x.head != w.head {
		return evidence{}, ErrEvidence
	}
	return x, nil
}
func (m *modelLedger) validReceipt(x evidence) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	expected, ok := m.receipts[x.receiptID]
	if !ok {
		expected, ok = m.external[x.receiptID]
	}
	return ok && expected == x
}
func (m *modelLedger) lookup(k replayIdentity) (record, evidence, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.unavailable || !validHead(m.retained.head) {
		return record{}, evidence{}, ErrClosed
	}
	r, ok := m.retained.rows[k]
	if !ok {
		return record{}, evidence{}, ErrEvidence
	}
	var x evidence
	for _, rc := range m.receipts {
		if rc.reservationID == r.input.reservationID && rc.kind == storeReservation {
			x = rc
			break
		}
	}
	if x == (evidence{}) {
		return record{}, evidence{}, ErrEvidence
	}
	return cloneRecord(r), x, nil
}
func (m *modelLedger) crash() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.local = cloneImage(m.retained)
	for id := range m.writes {
		if _, ok := m.receipts[id]; !ok {
			delete(m.writes, id)
			delete(m.bases, id)
			delete(m.refs, id)
			delete(m.keys, id)
		}
	}
}
func (m *modelLedger) restore(im ledgerImage) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.local = cloneImage(im)
	if im.head != m.retained.head {
		m.unavailable = true
	}
}
func (m *modelLedger) propose(old record, e event, g topology) (writeRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.unavailable {
		return writeRef{}, ErrClosed
	}
	stored, ok := m.retained.rows[old.input.replay]
	if !ok || !reflect.DeepEqual(stored, old) {
		return writeRef{}, ErrStaleRevision
	}
	id := fmt.Sprintf("write-%d", m.nextWrite+1)
	anticipatedHead := head{"ledger", "model-lineage", id, m.retained.head.sequence + 1}
	anticipated := func(k evidenceKind) evidence {
		x := receiptFor(old, k, old.revision+1)
		x.receiptID = id
		x.head = anticipatedHead
		return x
	}
	valid := func(x evidence) bool {
		v, ok := m.receipts[x.receiptID]
		if !ok {
			v, ok = m.external[x.receiptID]
		}
		return ok && v == x
	}
	kind := writeOutcome
	switch e.kind {
	case attachReady:
		kind = writeReady
		if !valid(e.reservationReceipt) || old.input.requiredRecorder != "" && !valid(e.recorderReceipt) {
			return writeRef{}, ErrEvidence
		}
		e.readinessReceipt = anticipated(storeReadiness)
	case consume:
		kind = writeConsume
		if !valid(old.readinessReceipt) {
			return writeRef{}, ErrEvidence
		}
		e.consumeReceipt = anticipated(storeConsumption)
		e.consumeReceipt.attemptID = e.attempt.id
	case confirmEffect, confirmNoEffect:
		if !valid(e.outcome) {
			return writeRef{}, ErrEvidence
		}
	case withhold:
		kind = writeWithhold
	}
	next, err := reduce(old, e, g)
	if err != nil {
		return writeRef{}, err
	}
	if reflect.DeepEqual(old, next) {
		return writeRef{}, nil
	}
	im := cloneImage(m.retained)
	if old.budget != next.budget {
		for _, c := range old.input.costs {
			a := im.budgets[c.account]
			if old.budget != budgetHeld || a.held < c.amount {
				return writeRef{}, ErrBudget
			}
			a.held -= c.amount
			if next.budget == budgetSpent {
				if c.amount > math.MaxUint64-a.spent {
					return writeRef{}, ErrOverflow
				}
				a.spent += c.amount
			}
			im.budgets[c.account] = a
		}
	}
	if next.quarantined && old.budget == budgetRefunded {
		for _, c := range old.input.costs {
			im.quarantined[c.account] = true
		}
	}
	if e.kind == confirmEffect || e.kind == confirmNoEffect {
		im.targetCheckpoint = e.outcome.head
	}
	im.rows[old.input.replay] = next
	return m.stage(im, old.input.replay, kind)
}
func (rec *modelRecorder) append(r record) (evidence, error) {
	if rec.unavailable {
		return evidence{}, ErrClosed
	}
	if rec.rows == nil {
		rec.rows = map[string]evidence{}
	}
	key := r.input.reservationID
	expected := receiptFor(r, recorderPreAction, 1)
	expected.receiptID = "recorder-" + key
	expected.head = head{r.input.requiredRecorder, "model-lineage", "recorder-head", 1}
	if old, ok := rec.rows[key]; ok {
		if old != expected {
			return evidence{}, ErrConflict
		}
		return old, nil
	}
	if rec.max > 0 && len(rec.rows) >= rec.max {
		return evidence{}, ErrBusyModel
	}
	rec.rows[key] = expected
	return expected, nil
}

const ErrBusyModel Error = "model_saturated"

func newModelTarget(b action.Binding) *modelTarget {
	return &modelTarget{finalWire: map[string][]byte{}, admittedBindings: map[[32]byte]action.Operation{b.Digest(): b.Operation()}, admittedKeys: map[string][32]byte{b.Operation().ReplayID(): b.Digest()}, allowedBrokers: map[string]bool{"executor-1": true}, credentialVersion: "credential-v1", epoch: 1, queue: map[string]targetRequest{}, bindings: map[string][32]byte{}, effects: map[string]evidence{}, closures: map[string]evidence{}, receipts: map[string]evidence{}, rejected: map[string]bool{}, head: head{"target", "model-lineage", "target-initial", 1}, admitted: b.Digest()}
}
func (tg *modelTarget) enqueue(q targetRequest) error {
	tg.arrivals++
	if tg.unavailable || tg.rejected["model-ns"] {
		tg.refusals++
		return ErrClosed
	}
	if _, ok := tg.closures[q.attempt.id]; ok {
		tg.refusals++
		return ErrEvidence
	}
	if prior, ok := tg.queue[q.attempt.id]; ok {
		if prior.attempt != q.attempt || prior.broker != q.broker || prior.route != q.route || prior.deadline != q.deadline || !bytes.Equal(prior.binding.Bytes(), q.binding.Bytes()) {
			tg.refusals++
			return ErrConflict
		}
		return nil
	}
	if prior, ok := tg.bindings[q.attempt.targetKey]; ok && prior != q.binding.Digest() {
		tg.refusals++
		return ErrConflict
	}
	tg.bindings[q.attempt.targetKey] = q.binding.Digest()
	tg.queue[q.attempt.id] = q
	tg.finalWire[q.attempt.id] = append([]byte(nil), q.binding.Operation().Bytes()...)
	return nil
}
func (tg *modelTarget) commit(id string, at int64) (evidence, error) {
	if x, ok := tg.effects[id]; ok {
		return x, nil
	}
	q, ok := tg.queue[id]
	if !ok || tg.closures[id] != (evidence{}) {
		tg.refusals++
		return evidence{}, ErrEvidence
	}
	v, err := q.binding.View()
	o := q.binding.Operation()
	expectedVersion := strconv.FormatUint(tg.version, 10)
	expected, admitted := tg.admittedBindings[q.binding.Digest()]
	expectedBinding, keyAdmitted := tg.admittedKeys[q.attempt.targetKey]
	if tg.unavailable || tg.rejected["model-ns"] || err != nil || tg.incomplete || !tg.allowedBrokers[q.broker] || q.route != "fixed" || q.attempt.executor != q.broker || q.attempt.epoch != tg.epoch || q.attempt.operationDigest != o.Digest() || !admitted || !keyAdmitted || expectedBinding != q.binding.Digest() || !bytes.Equal(o.Bytes(), expected.Bytes()) || !bytes.Equal(tg.finalWire[id], expected.Bytes()) || o.TargetVersion() != expectedVersion || at < v.ValidFromUnixNS || at >= v.ExpiresUnixNS || at >= q.deadline || tg.version == math.MaxUint64 {
		tg.refusals++
		return evidence{}, ErrEvidence
	}
	tg.version++
	tg.commits++
	tg.head.sequence++
	tg.head.id = fmt.Sprintf("target-%d", tg.head.sequence)
	x := evidence{authority: "target", receiptID: "effect-" + id, kind: targetEffect, reservationID: "r-1", attemptID: id, namespace: "model-ns", replayKey: v.ReplayID, bindingDigest: q.binding.Digest(), operationDigest: o.Digest(), decisionDigest: sha256.Sum256([]byte("decision")), actorProjectionDigest: v.IdentityProjectionDigest, revision: q.attempt.consumeRevision, epoch: q.attempt.epoch, head: tg.head, beforeVersion: expectedVersion, afterVersion: strconv.FormatUint(tg.version, 10)}
	tg.effects[id] = x
	tg.receipts[x.receiptID] = x
	delete(tg.queue, id)
	return x, nil
}
func (tg *modelTarget) closeNoEffect(id string) (evidence, error) {
	if tg.effects[id] != (evidence{}) || tg.unavailable || tg.incomplete {
		return evidence{}, ErrEvidence
	}
	if x, ok := tg.closures[id]; ok {
		return x, nil
	}
	q, ok := tg.queue[id]
	if !ok {
		return evidence{}, ErrEvidence
	}
	v, err := q.binding.View()
	if err != nil {
		return evidence{}, ErrEvidence
	}
	tg.head.sequence++
	tg.head.id = fmt.Sprintf("target-%d", tg.head.sequence)
	x := evidence{authority: "target", receiptID: "closure-" + id, kind: targetTerminalNoEffect, reservationID: "r-1", attemptID: id, namespace: "model-ns", replayKey: v.ReplayID, bindingDigest: q.binding.Digest(), operationDigest: q.binding.Operation().Digest(), decisionDigest: sha256.Sum256([]byte("decision")), actorProjectionDigest: v.IdentityProjectionDigest, revision: q.attempt.consumeRevision, epoch: q.attempt.epoch, head: tg.head, beforeVersion: q.binding.Operation().TargetVersion(), afterVersion: q.binding.Operation().TargetVersion(), terminalClosureID: "closed-" + id}
	tg.closures[id] = x
	tg.receipts[x.receiptID] = x
	delete(tg.queue, id)
	return x, nil
}
func (tg *modelTarget) lookup(id string) (evidence, error) {
	if tg.unavailable || tg.incomplete {
		return evidence{}, ErrClosed
	}
	if x, ok := tg.effects[id]; ok {
		return x, nil
	}
	if x, ok := tg.closures[id]; ok {
		return x, nil
	}
	return evidence{}, ErrEvidence
}
func (tg *modelTarget) advanceFence(epoch uint64) {
	if epoch > tg.epoch {
		tg.epoch = epoch
	}
}
func (tg *modelTarget) restoreTarget(other *modelTarget) {
	if other.head.lineage != tg.head.lineage || other.head.sequence < tg.head.sequence {
		tg.incomplete = true
		return
	}
	tg.version = other.version
	tg.epoch = other.epoch
}
func (m *modelLedger) gc(key replayIdentity, completeCheckpoint, rejection bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.retained.rows[key]
	if !ok {
		return ErrEvidence
	}
	if r.state != EffectConfirmed && r.state != NoEffectConfirmed && r.state != Withheld {
		return ErrTransition
	}
	if m.now < m.latestDelayedTick || !completeCheckpoint || !rejection || r.quarantined || !validHead(m.retained.head) {
		return ErrClosed
	}
	checkpoint, covered := m.checkpointCoverage[key]
	reject, closed := m.rejectionCoverage[key.namespace]
	if !covered || checkpoint != m.retained.head || !closed || !validHead(reject) || reject.authority != "target" || reject.lineage != m.retained.targetCheckpoint.lineage || reject.sequence < m.retained.targetCheckpoint.sequence {
		return ErrEvidence
	}
	m.retained.targetCheckpoint = reject
	m.retained.rejected[key.namespace] = true
	delete(m.retained.rows, key)
	m.local = cloneImage(m.retained)
	return nil
}
func TestModelTargetImmutableAttempt(t *testing.T) {
	r := consumedFixture(t)
	for _, field := range []string{"key", "epoch", "executor", "binding"} {
		t.Run(field, func(t *testing.T) {
			tg := newModelTarget(r.input.binding)
			q := targetRequest{r.input.binding, r.attempt, "executor-1", "fixed", 800}
			if e := tg.enqueue(q); e != nil {
				t.Fatal(e)
			}
			other := q
			switch field {
			case "key":
				other.attempt.targetKey = "different"
			case "epoch":
				other.attempt.epoch++
			case "executor":
				other.attempt.executor = "other"
			case "binding":
				other.binding = variantInput(t, r.input, "action").binding
			}
			if e := tg.enqueue(other); e != ErrConflict {
				t.Fatal("changed attempt was overwritten", field, e)
			}
		})
	}
}
func TestRetainedReceiptHeadsExact(t *testing.T) {
	h := completedHarness(t)
	for _, purpose := range []string{"reserve", "recorder", "ready", "consume", "outcome"} {
		base := h.r.reservationReceipt
		switch purpose {
		case "recorder":
			base = h.r.recorderReceipt
		case "ready":
			base = h.r.readinessReceipt
		case "consume":
			base = h.r.consumeReceipt
		case "outcome":
			base = h.r.outcome
		}
		for _, field := range []string{"older-nonzero", "fork", "wrong-id", "wrong-purpose", "wrong-revision", "wrong-epoch"} {
			t.Run(purpose+"/"+field, func(t *testing.T) {
				x := base
				switch field {
				case "older-nonzero":
					if x.head.sequence > 1 {
						x.head.sequence--
					} else {
						x.head.sequence = 2
					}
				case "fork":
					x.head.lineage = "fork"
				case "wrong-id":
					x.head.id = "other-head"
				case "wrong-purpose":
					x.kind = 0
				case "wrong-revision":
					x.revision++
				case "wrong-epoch":
					x.epoch++
				}
				if h.m.validReceipt(x) {
					t.Fatal("changed exact retained authority accepted")
				}
			})
		}
	}
}
func TestConcurrentCASProposals(t *testing.T) {
	m := newModelLedger(1)
	in := inputFixture(t)
	a, e := m.reserve(in)
	if e != nil {
		t.Fatal(e)
	}
	m.local = cloneImage(m.retained)
	b, e := m.reserve(in)
	if e != nil {
		t.Fatal(e)
	}
	if e = m.retain(a.write); e != nil {
		t.Fatal(e)
	}
	if e = m.retain(b.write); e != ErrStaleRevision {
		t.Fatal("same-head loser overwrote", e)
	}
	joined, e := m.reserve(in)
	if e != nil || joined.class != reserveJoin || m.retained.budgets["global"] != (account{1, 1, 0}) {
		t.Fatal(joined, e)
	}
}
func TestPostACKCurrentCheckAndReceiptGuards(t *testing.T) {
	h := newFaultHarness(t)
	h.makeReady()
	h.makeConsumed()
	for _, field := range []string{"check-before-ACK", "future-check", "expiry", "revoked", "version", "operation", "actor", "epoch", "executor", "authority"} {
		c := currentFor(h.r, 5)
		switch field {
		case "check-before-ACK":
			c.checkedAt = 4
		case "future-check":
			c.checkedAt = 6
		case "expiry":
			c.expires = 5
		case "revoked":
			c.class = recheckRevoked
		case "version":
			c.targetVersion = "1"
		case "operation":
			c.operationDigest[0] ^= 1
		case "actor":
			c.actorProjectionDigest[0] ^= 1
		case "epoch":
			c.epoch++
		case "executor":
			c.executor = "other"
		case "authority":
			c.authorityVersion = "other"
		}
		if h.release(c, 5) {
			t.Fatal("post ACK changed authority released", field)
		}
	}
	if h.target.arrivals != 0 || h.target.commits != 0 {
		t.Fatal("rejected check reached target")
	}
	if !h.release(currentFor(h.r, 5), 5) {
		t.Fatal("positive post ACK denied")
	}
}

// modelTopologyAuthority owns exact synthetic grants and retained topology
// write receipts separately from the pure proposal reducer.
type topologyGrantKey struct {
	kind topologyEventKind
	ref  string
}
type modelTopologyAuthority struct {
	ledger      *modelLedger
	target      *modelTarget
	checkpoint  head
	epochSource uint64
	counter     uint64
	grants      map[topologyGrantKey]topologyEvent
	retained    map[string]bool
	available   bool
	restoreID   string
}

func newModelTopologyAuthority(m *modelLedger, tg *modelTarget) *modelTopologyAuthority {
	return &modelTopologyAuthority{ledger: m, target: tg, checkpoint: m.retained.head, epochSource: tg.epoch, grants: map[topologyGrantKey]topologyEvent{}, retained: map[string]bool{}, available: true, restoreID: "restore-approved"}
}
func (a *modelTopologyAuthority) initial() topology {
	return topology{phase: topologyEligible, revision: 1, epoch: a.epochSource, retainedHead: a.ledger.retained.head, independentHead: a.checkpoint, targetHead: a.target.head}
}
func (a *modelTopologyAuthority) issue(g topology, k topologyEventKind) (topologyEvent, error) {
	if !a.available || a.ledger.unavailable || a.target.unavailable || a.target.incomplete {
		return topologyEvent{}, ErrClosed
	}
	a.counter++
	ref := fmt.Sprintf("topology-write-%d", a.counter)
	e := topologyEvent{kind: k, expectRevision: g.revision, expectEpoch: g.epoch, nextEpoch: a.epochSource, restoreID: a.restoreID, retainedHead: a.ledger.retained.head, independentHead: a.checkpoint, targetHead: a.target.head, oldAttempts: append([]string(nil), g.oldAttempts...), rejectedNamespaces: []string{"old-ns"}, evidenceRef: ref}
	switch k {
	case establishHead:
		if a.ledger.retained.head != a.checkpoint {
			return topologyEvent{}, ErrEvidence
		}
	case acquireEpoch:
		if a.epochSource == math.MaxUint64 {
			return topologyEvent{}, ErrOverflow
		}
		a.epochSource++
		e.nextEpoch = a.epochSource
	case acknowledgeTargetFence:
		a.target.advanceFence(g.epoch)
		if a.target.epoch != g.epoch {
			return topologyEvent{}, ErrEvidence
		}
		e.targetHead = a.target.head
	case reconcileTopology:
		for _, id := range g.oldAttempts {
			if _, err := a.target.lookup(id); err != nil {
				return topologyEvent{}, ErrEvidence
			}
			found := false
			for _, r := range a.ledger.retained.rows {
				if r.attempt.id == id && (r.state == EffectConfirmed || r.state == NoEffectConfirmed) && !r.quarantined {
					found = true
				}
			}
			if !found {
				return topologyEvent{}, ErrEvidence
			}
		}
	case retainReadiness:
		if g.retainedHead != a.ledger.retained.head || g.independentHead != a.checkpoint {
			return topologyEvent{}, ErrEvidence
		}
	case openTopology:
		e.evidenceRef = g.readinessRef
		if !a.retained[e.evidenceRef] {
			return topologyEvent{}, ErrEvidence
		}
	}
	a.grants[topologyGrantKey{k, e.evidenceRef}] = e
	return e, nil
}
func (a *modelTopologyAuthority) retain(ref string) { a.retained[ref] = true }
func (a *modelTopologyAuthority) apply(g topology, e topologyEvent) (topology, error) {
	expected, ok := a.grants[topologyGrantKey{e.kind, e.evidenceRef}]
	if !ok || !a.retained[e.evidenceRef] || !reflect.DeepEqual(expected, e) {
		return cloneTopology(g), ErrEvidence
	}
	if e.kind == acquireEpoch && e.nextEpoch != a.epochSource || e.kind == acknowledgeTargetFence && (e.targetHead != a.target.head || a.target.epoch != g.epoch) || e.kind == establishHead && (e.retainedHead != a.ledger.retained.head || e.independentHead != a.checkpoint) {
		return cloneTopology(g), ErrEvidence
	}
	return reduceTopology(g, e)
}
func (a *modelTopologyAuthority) transition(g topology, k topologyEventKind, retain bool) (topology, error) {
	e, err := a.issue(g, k)
	if err != nil {
		return cloneTopology(g), err
	}
	if retain {
		a.retain(e.evidenceRef)
	}
	return a.apply(g, e)
}
func TestModelGCCoverageCannotBeAsserted(t *testing.T) {
	h := newFaultHarness(t)
	h.makeReady()
	h.makeConsumed()
	if !h.release(currentFor(h.r, 5), 5) {
		t.Fatal("positive denied")
	}
	x, e := h.target.closeNoEffect(h.r.attempt.id)
	if e != nil {
		t.Fatal(e)
	}
	h.confirm(x)
	h.m.now = 1000
	if e = h.m.gc(h.r.input.replay, true, true); e != ErrEvidence {
		t.Fatal("bare checkpoint/rejection assertion collected slot", e)
	}
}

func (tg *modelTarget) rejectNamespace(ns string) head {
	tg.rejected[ns] = true
	tg.head.sequence++
	tg.head.id = fmt.Sprintf("rejection-%d", tg.head.sequence)
	return tg.head
}
func (h *faultHarness) prepareGC() {
	r := h.m.retained.rows[h.r.input.replay]
	if r.state != EffectConfirmed && r.state != NoEffectConfirmed && r.state != Withheld {
		h.t.Fatal("checkpoint cannot cover nonterminal slot")
	}
	if r.attempt.id != "" {
		x, e := h.target.lookup(r.attempt.id)
		if e != nil || x != r.outcome {
			h.t.Fatal("independent terminal checkpoint missing")
		}
	}
	h.m.checkpointCoverage[h.r.input.replay] = h.m.retained.head
	h.m.rejectionCoverage[h.r.input.replay.namespace] = h.target.rejectNamespace(h.r.input.replay.namespace)
	h.note("independent terminal checkpoint + permanent target namespace rejection retained")
}
func TestModelUnregisteredTargetKey(t *testing.T) {
	r := consumedFixture(t)
	tg := newModelTarget(r.input.binding)
	q := targetRequest{r.input.binding, r.attempt, "executor-1", "fixed", 800}
	q.attempt.targetKey = "unregistered-key"
	if e := tg.enqueue(q); e != nil {
		t.Fatal(e)
	}
	if _, e := tg.commit(q.attempt.id, 5); e != ErrEvidence || tg.commits != 0 {
		t.Fatal("unregistered key committed", e)
	}
}

func (tg *modelTarget) admitBinding(b action.Binding) {
	tg.admittedBindings[b.Digest()] = b.Operation()
	tg.admittedKeys[b.Operation().ReplayID()] = b.Digest()
}

func TestWriterCannotSkipRetainedAudit(t *testing.T) {
	h := completedHarness(t)
	d := deliverySummary{"writer", "accept-1", "attest-1", h.r.outcome.receiptID, h.r.input.reservationID, h.r.attempt.id, h.r.input.decision.actorRef, h.r.input.binding.Digest(), h.r.input.decision.actorProjectionDigest}
	h.writerReceipts[d.acceptanceID] = d
	if h.deliverOutcome(d) {
		t.Fatal("writer acceptance bypassed required retained audit knowledge")
	}
}

func TestModelPrewriteProposalAndSourceAges(t *testing.T) {
	m := newModelLedger(2)
	r, im, e := m.previewReservation(inputFixture(t))
	if e != nil || r.state != ReservedPendingACK || len(im.rows) != 1 || im.budgets["global"].held != 1 || im.budgets["tenant"].held != 1 || len(m.writes) != 0 || len(m.local.rows) != 0 || len(m.retained.rows) != 0 {
		t.Fatal("preview wrote local durable bytes", e)
	}
	for _, source := range []string{"decision", "lifecycle", "permission", "inspection"} {
		obs := freshModeledSources()
		x := obs[source]
		x.expires = 4
		obs[source] = x
		c := recheckSources(r, obs, 4)
		if c.class == recheckCurrent {
			t.Fatal("expired independent source admitted", source)
		}
	}
}

// reservationProposal models the atomic whole-vector proposal before a local
// write; previewReservation deliberately retains no bytes or receipt knowledge.
func (m *modelLedger) reservationProposal(owned reservationInput) (record, ledgerImage, error) {
	im := cloneImage(m.retained)
	for _, c := range owned.costs {
		a, ok := im.budgets[c.account]
		if !ok || im.quarantined[c.account] || a.spent > a.limit || a.held > a.limit-a.spent || c.amount > a.limit-a.spent-a.held {
			return record{}, ledgerImage{}, ErrBudget
		}
	}
	r, e := newPending(owned)
	if e != nil {
		return record{}, ledgerImage{}, e
	}
	im.rows[owned.replay] = r
	for _, c := range owned.costs {
		a := im.budgets[c.account]
		a.held += c.amount
		im.budgets[c.account] = a
	}
	return r, im, nil
}
func (m *modelLedger) previewReservation(in reservationInput) (record, ledgerImage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.unavailable || m.retained.rejected[in.replay.namespace] {
		return record{}, ledgerImage{}, ErrClosed
	}
	owned, e := ownInput(in)
	if e != nil {
		return record{}, ledgerImage{}, e
	}
	if _, ok := m.local.rows[owned.replay]; ok {
		return record{}, ledgerImage{}, ErrConflict
	}
	if len(m.retained.rows) >= m.maxRows {
		return record{}, ledgerImage{}, ErrBudget
	}
	return m.reservationProposal(owned)
}

type modeledSourceObservation struct {
	id                 string
	validFrom, expires int64
	available, revoked bool
}

func freshModeledSources() map[string]modeledSourceObservation {
	return map[string]modeledSourceObservation{"decision": {"decision-observation", 1, 800, true, false}, "lifecycle": {"lifecycle-observation", 1, 800, true, false}, "permission": {"permission-observation", 1, 800, true, false}, "inspection": {"inspection-observation", 1, 800, true, false}}
}
func recheckSources(r record, obs map[string]modeledSourceObservation, at int64) currentCheck {
	c := currentFor(r, at)
	for _, name := range []string{"decision", "lifecycle", "permission", "inspection"} {
		x, ok := obs[name]
		if !ok || !x.available {
			c.class = recheckUnavailable
			return c
		}
		if x.revoked || at < x.validFrom || at >= x.expires {
			c.class = recheckRevoked
			return c
		}
		if x.expires < c.expires {
			c.expires = x.expires
		}
	}
	return c
}

func TestBufferedTargetNamespaceRejection(t *testing.T) {
	r := consumedFixture(t)
	tg := newModelTarget(r.input.binding)
	q := targetRequest{r.input.binding, r.attempt, "executor-1", "fixed", 800}
	if e := tg.enqueue(q); e != nil {
		t.Fatal(e)
	}
	tg.rejectNamespace("model-ns")
	if _, e := tg.commit(r.attempt.id, 5); e == nil || tg.commits != 0 {
		t.Fatal("buffered old namespace committed after authoritative rejection", e)
	}
}
func TestRefundedContradictionClosesBudgetScopes(t *testing.T) {
	h := newFaultHarness(t)
	h.makeReady()
	h.makeConsumed()
	if !h.release(currentFor(h.r, 5), 5) {
		t.Fatal("control denied")
	}
	x, e := h.target.closeNoEffect(h.r.attempt.id)
	if e != nil {
		t.Fatal(e)
	}
	h.confirm(x)
	h.apply(event{kind: annotateContradiction, expectRevision: h.r.revision, expectEpoch: h.r.epoch, at: 8, annotationID: "late-contradiction"})
	if h.r.state != NoEffectConfirmed || h.r.budget != budgetRefunded || !h.r.quarantined || !h.m.retained.quarantined["global"] || !h.m.retained.quarantined["tenant"] {
		t.Fatal("refunded history/affected budget scope lost")
	}
	if _, e := h.m.reserve(variantInput(t, h.r.input, "last-cost-unit")); e != ErrBudget {
		t.Fatal("refunded contradiction admitted new hold", e)
	}
}

func TestTargetWireBytesIndependentOfBinding(t *testing.T) {
	r := consumedFixture(t)
	tg := newModelTarget(r.input.binding)
	q := targetRequest{r.input.binding, r.attempt, "executor-1", "fixed", 800}
	if e := tg.enqueue(q); e != nil {
		t.Fatal(e)
	}
	wire := append([]byte(nil), tg.finalWire[r.attempt.id]...)
	wire[len(wire)-1] ^= 1
	tg.finalWire[r.attempt.id] = wire
	if _, e := tg.commit(r.attempt.id, 5); e == nil || tg.commits != 0 {
		t.Fatal("changed final bytes committed with otherwise exact binding/digest", e)
	}
}

// Different keys both observe the same final-unit image. Neither caller's
// unretained candidate changes the independently retained budget snapshot.
func TestTwoDifferentKeysFinalCostSameHead(t *testing.T) {
	m := newModelLedger(1)
	first := inputFixture(t)
	second := variantInput(t, first, "last-cost-unit")
	if first.replay == second.replay || first.binding.Digest() == second.binding.Digest() {
		t.Fatal("keys/bindings not independent valid inputs")
	}
	base := m.retained.head
	a, e := m.reserve(first)
	if e != nil || a.class != reserveNew {
		t.Fatal("first eligible proposal", e)
	}
	b, e := m.reserve(second)
	if e != nil || b.class != reserveNew {
		t.Fatal("second eligible proposal", e)
	}
	if a.write == b.write || m.bases[a.write.id] != base || m.bases[b.write.id] != base {
		t.Fatal("proposals did not contend at same retained head")
	}
	for _, w := range []writeRef{a.write, b.write} {
		im := m.writes[w.id]
		if len(im.rows) != 1 || im.budgets["global"] != (account{1, 1, 0}) || im.budgets["tenant"] != (account{1, 1, 0}) {
			t.Fatal("candidate did not atomically hold final complete cost vector")
		}
	}
	if len(m.retained.rows) != 0 || m.retained.budgets["global"] != (account{1, 0, 0}) || m.retained.budgets["tenant"] != (account{1, 0, 0}) {
		t.Fatal("local proposal spent retained final unit")
	}
	t.Logf("ordered CAS trace: base=%s:%d two_keys=%s,%s staged=%s,%s retained_slots=0 held=0 cost_limit=1", base.id, base.sequence, first.replay.key, second.replay.key, a.write.id, b.write.id)
	if e = m.retain(a.write); e != nil {
		t.Fatal("winner retain", e)
	}
	if e = m.retain(b.write); e != ErrStaleRevision {
		t.Fatal("different-key same-head loser overwrote winner", e)
	}
	if _, _, e = m.lookup(second.replay); e != ErrEvidence {
		t.Fatal("loser authoritative reread unexpectedly found slot", e)
	}
	loser, e := m.reserve(second)
	if e != ErrBudget || loser.class != reserveRefused || loser.write != (writeRef{}) {
		t.Fatal("loser authoritative reread did not deny exhausted final budget", loser, e)
	}
	row, rc, e := m.lookup(first.replay)
	if e != nil || !m.validReceipt(rc) || !sameReservation(row.input, first) {
		t.Fatal("winner exact authoritative reread", e)
	}
	if len(m.retained.rows) != 1 || m.retained.budgets["global"] != (account{1, 1, 0}) || m.retained.budgets["tenant"] != (account{1, 1, 0}) {
		t.Fatal("loser allocated second slot/hold")
	}
	t.Logf("ordered CAS trace: retained_head=%s:%d winner=%s loser_CAS=stale loser_lookup=absent loser_reread=budget_denied slots=1 global_held=1 tenant_held=1", m.retained.head.id, m.retained.head.sequence, first.replay.key)
	h := &faultHarness{t: t, m: m, target: newModelTarget(row.input.binding), g: eligibleTopology(), r: row, sent: map[string]bool{}, tick: 2, writerReceipts: map[string]deliverySummary{}, auditReceipts: map[string]evidence{}, writerAvailable: true, authorityAvailable: true, reconcileLimit: 2, managementLimit: 2}
	t.Cleanup(func() { t.Logf("ordered model trace=%v", h.trace) })
	h.note("same-head two-key final-unit winner retained; loser absent and budget denied")
	h.makeReady()
	h.makeConsumed()
	if !h.release(currentFor(h.r, 5), 5) {
		t.Fatal("final-unit winner positive send denied")
	}
	x, e := h.target.commit(h.r.attempt.id, 6)
	if e != nil {
		t.Fatal("winner independent target commit", e)
	}
	h.confirm(x)
	if h.target.commits != 1 || h.target.arrivals != 1 || h.target.version != 1 || len(m.retained.rows) != 1 || m.retained.budgets["global"] != (account{1, 0, 1}) || m.retained.budgets["tenant"] != (account{1, 0, 1}) {
		t.Fatal("final-unit winner/loser oracle differs")
	}
	if _, _, e = m.lookup(second.replay); e != ErrEvidence {
		t.Fatal("loser gained slot after winner effect", e)
	}
	if loser, e = m.reserve(second); e != ErrBudget || loser.write != (writeRef{}) {
		t.Fatal("spent final unit admitted loser", e)
	}
}
