// Package labruntime composes experimental modeled authority with durable lab dispatch.
// It is not a qualified KTP supplier or a production KAG release.
package labruntime

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
)

var ErrHeld = errors.New("recorder_held")
var ErrReplay = errors.New("replay_consumed")
var ErrBudget = errors.New("episode_budget_exhausted")
var ErrRate = errors.New("spacing_withheld")

type entry struct {
	Kind, ID, Binding, Outcome, Previous, Hash, ReplayID string
	UnixNS                                               int64
	Budget                                               uint64
	SpacingNS                                            int64
}
type Ledger struct {
	audit        bool
	records      []entry
	mu           sync.Mutex
	file         *os.File
	sync         func() error
	budget, used uint64
	spacing      time.Duration
	last         int64
	head         string
	seen         map[string]string
	completed    map[string]bool
	held         bool
}

func ID(i int) string { return fmt.Sprintf("%032x", i) }
func hashEntry(e entry) string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}
func OpenLedger(path string, budget uint64, spacing time.Duration) (*Ledger, error) {
	return openLedger(path, budget, spacing, false)
}
func OpenAudit(path string) (*Ledger, error) { return openLedger(path, 1000, 0, true) }
func openLedger(path string, budget uint64, spacing time.Duration, audit bool) (*Ledger, error) {
	if budget < 1 || budget > 1000 || spacing < 0 {
		return nil, ErrHeld
	}
	fd, e := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_APPEND|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, ErrHeld
	}
	f := os.NewFile(uintptr(fd), path)
	fail := func() (*Ledger, error) { f.Close(); return nil, ErrHeld }
	if e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return fail()
	}
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4<<20 {
		return fail()
	}
	l := &Ledger{audit: audit, file: f, sync: f.Sync, budget: budget, spacing: spacing, seen: map[string]string{}, completed: map[string]bool{}}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 8192)
	count := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		var r entry
		if json.Unmarshal(line, &r) != nil || r.Hash != hashEntry(r) || r.Previous != l.head {
			return fail()
		}
		canonical, _ := json.Marshal(r)
		if string(canonical) != string(line) {
			return fail()
		}
		if count == 0 {
			if r.Kind != "policy" || r.Budget != budget || r.SpacingNS != int64(spacing) || (audit && r.Binding != "audit-v1") || (!audit && r.Binding != "") {
				return fail()
			}
		} else {
			switch r.Kind {
			case "audit":
				if !audit || r.ID == "" || len(r.Outcome) > 256 || r.UnixNS <= 0 {
					return fail()
				}
				l.used++
			case "attempt":
				if r.ID == "" || r.Binding == "" || r.UnixNS <= 0 || r.UnixNS < l.last || l.used >= budget {
					return fail()
				}
				if _, ok := l.seen[r.ID]; ok {
					return fail()
				}
				l.seen[r.ID] = r.Binding
				l.used++
				l.last = r.UnixNS
			case "outcome":
				if _, ok := l.seen[r.ID]; !ok || l.completed[r.ID] || r.Outcome != "known" && r.Outcome != "unknown" {
					return fail()
				}
				l.completed[r.ID] = true
			default:
				return fail()
			}
		}
		l.head = r.Hash
		l.records = append(l.records, r)
		count++
	}
	if scanner.Err() != nil {
		return fail()
	}
	if info.Size() > 0 {
		var tail [1]byte
		if _, e = f.ReadAt(tail[:], info.Size()-1); e != nil || tail[0] != '\n' {
			return fail()
		}
	}
	if count == 0 {
		if e = l.append(entry{Kind: "policy", Budget: budget, SpacingNS: int64(spacing), Binding: func() string {
			if audit {
				return "audit-v1"
			}
			return ""
		}()}); e != nil {
			return fail()
		}
		dir, e := os.OpenFile(filepathDir(path), os.O_RDONLY, 0)
		if e != nil {
			return fail()
		}
		e = dir.Sync()
		dir.Close()
		if e != nil {
			return fail()
		}
	}
	return l, nil
}
func filepathDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			if i == 0 {
				return "/"
			}
			return path[:i]
		}
	}
	return "."
}
func (l *Ledger) append(r entry) error {
	if l.held {
		return ErrHeld
	}
	r.Previous = l.head
	r.Hash = hashEntry(r)
	b, _ := json.Marshal(r)
	b = append(b, '\n')
	n, e := l.file.Write(b)
	if e != nil || n != len(b) || l.sync() != nil {
		l.held = true
		return ErrHeld
	}
	l.head = r.Hash
	l.records = append(l.records, r)
	return nil
}

// Reserve durably consumes the effect and replay namespace before any network release.
func (l *Ledger) Reserve(id, binding string, now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held {
		return ErrHeld
	}
	if len(id) != 32 || binding == "" || len(binding) > 128 {
		return ErrHeld
	}
	if _, ok := l.seen[id]; ok {
		return ErrReplay
	}
	if l.used >= l.budget {
		return ErrBudget
	}
	n := now.UnixNano()
	if n <= 0 || n < l.last || l.last > 0 && n-l.last < int64(l.spacing) {
		return ErrRate
	}
	if e := l.append(entry{Kind: "attempt", ID: id, Binding: binding, UnixNS: n}); e != nil {
		return e
	}
	l.used++
	l.last = n
	l.seen[id] = binding
	return nil
}

// Outcome never refunds budget, including ambiguity and denied release after reservation.
func (l *Ledger) Outcome(id, outcome string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.seen[id]; !ok || l.completed[id] || outcome != "known" && outcome != "unknown" {
		return ErrHeld
	}
	if e := l.append(entry{Kind: "outcome", ID: id, Outcome: outcome}); e != nil {
		return e
	}
	l.completed[id] = true
	return nil
}
func (l *Ledger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.held = true
	return l.file.Close()
}

func (l *Ledger) Witness() []map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []map[string]any{}
	var n uint64
	for _, r := range l.records {
		if r.Kind == "attempt" {
			n++
			binding, op := r.Binding, ""
			if len(binding) == 128 {
				binding, op = binding[:64], binding[64:]
			}
			out = append(out, map[string]any{"replay_id": r.ID, "binding_digest": binding, "operation_digest": op, "version": fmt.Sprint(n), "stock": 100 - n*5, "unix_ns": r.UnixNS, "recorder_durable": true})
		}
	}
	return out
}

func (l *Ledger) Audit(id, replay, binding, decision, reason string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.audit || len(id) != 32 || len(replay) > 32 || len(binding) > 64 || len(decision)+len(reason) > 255 || l.used >= 1000 {
		return ErrHeld
	}
	if e := l.append(entry{Kind: "audit", ID: id, ReplayID: replay, Binding: binding, Outcome: decision + ":" + reason, UnixNS: time.Now().UnixNano()}); e != nil {
		return e
	}
	l.used++
	return nil
}
