package labruntime

// OwnerLedger is a modeled owner declaration and a single-writer durable lab
// reservation authority. It is not a qualified KTP provider or KAG store.
import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strconv"
	"sync"
	"syscall"

	"github.com/nmcitra/kag/internal/action"
)

var ErrOwnerFloor = errors.New("owner_floor_withheld")
var ErrOwnerBinding = errors.New("owner_binding_invalid")

type OwnerPolicy struct {
	TargetID               string `json:"target_id"`
	OwnerDeclarationDigest string `json:"owner_declaration_digest"`
	InitialStock           uint64 `json:"initial_stock"`
	Floor                  uint64 `json:"floor"`
	EffectCost             uint64 `json:"effect_cost"`
}

type OwnerReservation struct {
	ReplayID        string `json:"replay_id"`
	BindingDigest   string `json:"binding_digest"`
	OperationDigest string `json:"operation_digest"`
	DecisionDigest  string `json:"decision_digest"`
	ActorID         string `json:"actor_id"`
	TargetID        string `json:"target_id"`
	TargetVersion   string `json:"target_version"`
}

type OwnerReceipt struct {
	ReservationID           string `json:"reservation_id"`
	OwnerPolicyDigest       string `json:"owner_policy_digest"`
	RemainingAvailableStock uint64 `json:"remaining_available_stock"`
}

type OwnerCancellation struct {
	OwnerReservation
	ReservationID string `json:"reservation_id"`
}

type OwnerState struct {
	Version string `json:"version"`
	Stock   uint64 `json:"stock"`
	Effects uint64 `json:"effects"`
}

type OwnerEffect struct {
	OwnerReservation
	ReservationID     string `json:"reservation_id"`
	OwnerPolicyDigest string `json:"owner_policy_digest"`
	Version           string `json:"version"`
	Stock             uint64 `json:"stock"`
}

type OwnerReservationRecord struct {
	OwnerReservation
	ReservationID     string `json:"reservation_id"`
	OwnerPolicyDigest string `json:"owner_policy_digest"`
	Status            string `json:"status"`
}

type ownerEntry struct {
	Kind          string           `json:"kind"`
	Policy        OwnerPolicy      `json:"policy"`
	Request       OwnerReservation `json:"request"`
	ReservationID string           `json:"reservation_id"`
	Previous      string           `json:"previous"`
	Hash          string           `json:"hash"`
}

type OwnerLedger struct {
	mu           sync.Mutex
	file         *os.File
	policy       OwnerPolicy
	policyDigest string
	head         string
	reservations map[string]ownerEntry
	ids          map[string]string
	committed    map[string]bool
	cancelled    map[string]bool
	effects      []OwnerEffect
	held         bool
}

func validOwnerPolicy(p OwnerPolicy) bool {
	return p.TargetID == action.TargetID && validDigest(p.OwnerDeclarationDigest) && p.InitialStock == 100 && p.Floor == 70 && p.EffectCost == 5
}

func (p OwnerPolicy) Digest() (string, error) {
	if !validOwnerPolicy(p) {
		return "", ErrOwnerBinding
	}
	b, _ := json.Marshal(p)
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:]), nil
}

func validOwnerRequest(q OwnerReservation, p OwnerPolicy) bool {
	if q.TargetID != p.TargetID || !validDigest(q.BindingDigest) || !validDigest(q.OperationDigest) || !validDigest(q.DecisionDigest) || len(q.ReplayID) != 32 || !validActor(q.ActorID) {
		return false
	}
	if b, err := hex.DecodeString(q.ReplayID); err != nil || len(b) != 16 || hex.EncodeToString(b) != q.ReplayID {
		return false
	}
	v, err := strconv.ParseUint(q.TargetVersion, 10, 64)
	return err == nil && strconv.FormatUint(v, 10) == q.TargetVersion
}

func ownerHash(e ownerEntry) string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

func OpenOwnerLedger(path string, policy OwnerPolicy) (*OwnerLedger, error) {
	if !validOwnerPolicy(policy) {
		return nil, ErrOwnerBinding
	}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_APPEND|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, ErrHeld
	}
	f := os.NewFile(uintptr(fd), path)
	fail := func() (*OwnerLedger, error) { f.Close(); return nil, ErrHeld }
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return fail()
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4<<20 {
		return fail()
	}
	pd, _ := policy.Digest()
	l := &OwnerLedger{file: f, policy: policy, policyDigest: pd, reservations: map[string]ownerEntry{}, ids: map[string]string{}, committed: map[string]bool{}, cancelled: map[string]bool{}}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 8192)
	count := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		var row ownerEntry
		if json.Unmarshal(line, &row) != nil || row.Hash != ownerHash(row) || row.Previous != l.head {
			return fail()
		}
		canonical, _ := json.Marshal(row)
		if string(canonical) != string(line) {
			return fail()
		}
		if count == 0 {
			if row.Kind != "policy" || row.Policy != policy {
				return fail()
			}
		} else if l.replay(row) != nil {
			return fail()
		}
		l.head = row.Hash
		count++
	}
	if scanner.Err() != nil {
		return fail()
	}
	if info.Size() > 0 {
		var tail [1]byte
		if _, err = f.ReadAt(tail[:], info.Size()-1); err != nil || tail[0] != '\n' {
			return fail()
		}
	}
	if count == 0 {
		if l.append(ownerEntry{Kind: "policy", Policy: policy}) != nil {
			return fail()
		}
		dir, err := os.Open(filepathDir(path))
		if err != nil {
			return fail()
		}
		err = dir.Sync()
		dir.Close()
		if err != nil {
			return fail()
		}
	}
	return l, nil
}

func (l *OwnerLedger) replay(row ownerEntry) error {
	switch row.Kind {
	case "reserve":
		if !validOwnerRequest(row.Request, l.policy) || len(row.ReservationID) != 32 || l.ids[row.ReservationID] != "" || l.reservations[row.Request.ReplayID].Kind != "" || l.available() < l.policy.Floor+l.policy.EffectCost {
			return ErrOwnerBinding
		}
		if b, e := hex.DecodeString(row.ReservationID); e != nil || len(b) != 16 || hex.EncodeToString(b) != row.ReservationID {
			return ErrOwnerBinding
		}
		l.reservations[row.Request.ReplayID] = row
		l.ids[row.ReservationID] = row.Request.ReplayID
	case "commit":
		old, ok := l.reservations[row.Request.ReplayID]
		if !ok || old.Request != row.Request || old.ReservationID != row.ReservationID || l.committed[row.ReservationID] || l.cancelled[row.ReservationID] || row.Request.TargetVersion != strconv.Itoa(len(l.effects)) {
			return ErrOwnerBinding
		}
		l.committed[row.ReservationID] = true
		l.effects = append(l.effects, OwnerEffect{OwnerReservation: row.Request, ReservationID: row.ReservationID, OwnerPolicyDigest: l.policyDigest, Version: strconv.Itoa(len(l.effects) + 1), Stock: l.policy.InitialStock - uint64(len(l.effects)+1)*l.policy.EffectCost})
	case "cancel":
		old, ok := l.reservations[row.Request.ReplayID]
		if !ok || old.Request != row.Request || old.ReservationID != row.ReservationID || l.committed[row.ReservationID] || l.cancelled[row.ReservationID] {
			return ErrOwnerBinding
		}
		l.cancelled[row.ReservationID] = true
	default:
		return ErrOwnerBinding
	}
	return nil
}

func (l *OwnerLedger) append(row ownerEntry) error {
	if l.held {
		return ErrHeld
	}
	row.Previous = l.head
	row.Hash = ownerHash(row)
	b, _ := json.Marshal(row)
	b = append(b, '\n')
	n, e := l.file.Write(b)
	if e != nil || n != len(b) || l.file.Sync() != nil {
		l.held = true
		return ErrHeld
	}
	l.head = row.Hash
	return nil
}

func (l *OwnerLedger) available() uint64 {
	return l.policy.InitialStock - uint64(len(l.reservations)-len(l.cancelled))*l.policy.EffectCost
}

func (l *OwnerLedger) Reserve(q OwnerReservation) (OwnerReceipt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held {
		return OwnerReceipt{}, ErrHeld
	}
	if !validOwnerRequest(q, l.policy) {
		return OwnerReceipt{}, ErrOwnerBinding
	}
	if l.reservations[q.ReplayID].Kind != "" {
		return OwnerReceipt{}, ErrReplay
	}
	if q.TargetVersion != strconv.Itoa(len(l.effects)) {
		return OwnerReceipt{}, ErrOwnerBinding
	}
	if l.available() < l.policy.Floor+l.policy.EffectCost {
		return OwnerReceipt{}, ErrOwnerFloor
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return OwnerReceipt{}, ErrHeld
	}
	id := hex.EncodeToString(raw[:])
	if l.ids[id] != "" {
		return OwnerReceipt{}, ErrHeld
	}
	row := ownerEntry{Kind: "reserve", Request: q, ReservationID: id}
	if err := l.append(row); err != nil {
		return OwnerReceipt{}, err
	}
	if err := l.replay(row); err != nil {
		l.held = true
		return OwnerReceipt{}, ErrHeld
	}
	return OwnerReceipt{ReservationID: id, OwnerPolicyDigest: l.policyDigest, RemainingAvailableStock: l.available()}, nil
}

func (l *OwnerLedger) Commit(q OwnerReservation, id string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held {
		return ErrHeld
	}
	if !validOwnerRequest(q, l.policy) {
		return ErrOwnerBinding
	}
	old, ok := l.reservations[q.ReplayID]
	if !ok || old.Request != q || old.ReservationID != id || l.committed[id] || l.cancelled[id] || q.TargetVersion != strconv.Itoa(len(l.effects)) {
		return ErrOwnerBinding
	}
	row := ownerEntry{Kind: "commit", Request: q, ReservationID: id}
	if err := l.append(row); err != nil {
		return err
	}
	if err := l.replay(row); err != nil {
		l.held = true
		return ErrHeld
	}
	return nil
}

// Cancel is allowed only before target commit. The trusted gateway calls it
// solely after it has established that no target dispatch was attempted.
// Replay identity remains consumed even though target capacity is restored.
func (l *OwnerLedger) Cancel(q OwnerReservation, id string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held {
		return ErrHeld
	}
	if !validOwnerRequest(q, l.policy) {
		return ErrOwnerBinding
	}
	old, ok := l.reservations[q.ReplayID]
	if !ok || old.Request != q || old.ReservationID != id || l.committed[id] || l.cancelled[id] {
		return ErrOwnerBinding
	}
	row := ownerEntry{Kind: "cancel", Request: q, ReservationID: id}
	if err := l.append(row); err != nil {
		return err
	}
	if err := l.replay(row); err != nil {
		l.held = true
		return ErrHeld
	}
	return nil
}

func (l *OwnerLedger) State() OwnerState {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := uint64(len(l.effects))
	return OwnerState{Version: strconv.FormatUint(n, 10), Stock: l.policy.InitialStock - n*l.policy.EffectCost, Effects: n}
}

func (l *OwnerLedger) Witness() []OwnerEffect {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]OwnerEffect{}, l.effects...)
}

func (l *OwnerLedger) Reservations() []OwnerReservationRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	rows := make([]OwnerReservationRecord, 0, len(l.reservations))
	for _, r := range l.reservations {
		status := "held"
		if l.committed[r.ReservationID] {
			status = "committed"
		} else if l.cancelled[r.ReservationID] {
			status = "cancelled"
		}
		rows = append(rows, OwnerReservationRecord{OwnerReservation: r.Request, ReservationID: r.ReservationID, OwnerPolicyDigest: l.policyDigest, Status: status})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ReplayID < rows[j].ReplayID })
	return rows
}

func (l *OwnerLedger) PolicyDigest() string { return l.policyDigest }

func (l *OwnerLedger) PolicyView() map[string]any {
	return map[string]any{"target_id": l.policy.TargetID, "owner_declaration_digest": l.policy.OwnerDeclarationDigest, "initial_stock": l.policy.InitialStock, "floor": l.policy.Floor, "effect_cost": l.policy.EffectCost, "owner_policy_digest": l.policyDigest}
}

func (l *OwnerLedger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.held = true
	return l.file.Close()
}
