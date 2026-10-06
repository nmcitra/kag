package labruntime

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestConcurrentBudgetReplayRestart(t *testing.T) {
	p := filepath.Join(t.TempDir(), "journal")
	l, e := OpenLedger(p, 4, 0)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	n := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := ID(i)
			if l.Reserve(id, "binding", time.Now()) == nil {
				mu.Lock()
				n++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if n != 4 {
		t.Fatal(n)
	}
	if l.Reserve(ID(0), "other", time.Now()) == nil {
		t.Fatal("budget/replay bypass")
	}
	l.Close()
	l, e = OpenLedger(p, 4, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	if l.Reserve(ID(99), "binding", time.Now()) == nil {
		t.Fatal("restart replenished budget")
	}
	if _, e = OpenLedger(p, 4, 0); e == nil {
		t.Fatal("second writer accepted")
	}
}
func TestRecorderFailureNoReleaseAndUnknownConsumption(t *testing.T) {
	p := filepath.Join(t.TempDir(), "journal")
	l, e := OpenLedger(p, 2, 0)
	if e != nil {
		t.Fatal(e)
	}
	l.sync = func() error { return errors.New("disk") }
	if l.Reserve(ID(1), "binding", time.Now()) == nil {
		t.Fatal("sync failure accepted")
	}
	if l.Reserve(ID(2), "binding", time.Now()) == nil {
		t.Fatal("held ledger accepted")
	}
	l.Close()
	l, e = OpenLedger(p, 2, 0)
	if e != nil {
		t.Fatal(e)
	}
	if l.Reserve(ID(2), "binding", time.Now()) != nil {
		t.Fatal("unused second slot")
	}
	if e = l.Outcome(ID(2), "unknown"); e != nil {
		t.Fatal(e)
	}
	l.Close()
	l, e = OpenLedger(p, 2, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	if l.Reserve(ID(3), "binding", time.Now()) == nil {
		t.Fatal("unknown refunded")
	}
}
func TestCorruptionAndPolicyRestart(t *testing.T) {
	p := filepath.Join(t.TempDir(), "journal")
	l, e := OpenLedger(p, 4, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	l.Close()
	if _, e = OpenLedger(p, 7, time.Second); e == nil {
		t.Fatal("policy changed on restart")
	}
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString("partial")
	f.Close()
	if _, e = OpenLedger(p, 4, time.Second); e == nil {
		t.Fatal("truncation accepted")
	}
}
func TestSpacing(t *testing.T) {
	l, e := OpenLedger(filepath.Join(t.TempDir(), "journal"), 4, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	now := time.Now()
	if e = l.Reserve(ID(1), "binding", now); e != nil {
		t.Fatal(e)
	}
	if l.Reserve(ID(2), "binding", now.Add(time.Second)) == nil {
		t.Fatal("spacing bypass")
	}
	if e = l.Reserve(ID(2), "binding", now.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
}

func TestAuditPersistsDeniedEvents(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit")
	l, e := OpenAudit(p)
	if e != nil {
		t.Fatal(e)
	}
	if e = l.Audit(ID(1), ID(2), "binding", "deny", "expired"); e != nil {
		t.Fatal(e)
	}
	l.Close()
	l, e = OpenAudit(p)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	if l.Used() != 1 {
		t.Fatal("deny evidence lost")
	}
	if _, e = OpenLedger(p, 1000, 0); e == nil {
		t.Fatal("audit opened as authority ledger")
	}
}
