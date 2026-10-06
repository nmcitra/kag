package labruntime

import (
	"encoding/json"
	"github.com/nmcitra/kag/internal/action"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
)

func ownerPolicy() OwnerPolicy {
	return OwnerPolicy{TargetID: action.TargetID, OwnerDeclarationDigest: hexDigest(digest("modeled-owner-declaration")), InitialStock: 100, Floor: 70, EffectCost: 5}
}

func ownerRequest(i int, version string) OwnerReservation {
	return OwnerReservation{ReplayID: ID(i), BindingDigest: hexDigest(digest("binding:" + strconv.Itoa(i))), OperationDigest: hexDigest(digest("operation:" + strconv.Itoa(i))), DecisionDigest: hexDigest(digest("decision:" + strconv.Itoa(i))), ActorID: "agent-one", TargetID: action.TargetID, TargetVersion: version}
}

func TestOwnerFloorHoldsDoNotReduceStockAndSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner")
	owner, err := OpenOwnerLedger(path, ownerPolicy())
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 6; i++ {
		req := ownerRequest(i, strconv.Itoa(i-1))
		if i%2 == 0 {
			req.ActorID = "agent-two"
		}
		receipt, err := owner.Reserve(req)
		if err != nil {
			t.Fatal(i, err)
		}
		if i == 1 {
			state := owner.State()
			if state.Stock != 100 || state.Effects != 0 || receipt.RemainingAvailableStock != 95 {
				t.Fatalf("hold changed target effect state: %+v %+v", state, receipt)
			}
			if rows := owner.Reservations(); len(rows) != 1 || rows[0].Status != "held" || rows[0].ReservationID != receipt.ReservationID {
				t.Fatal("hold not independently witnessed", rows)
			}
		}
		if err := owner.Commit(req, receipt.ReservationID); err != nil {
			t.Fatal(i, err)
		}
	}
	if owner.State().Stock != 70 {
		t.Fatal(owner.State())
	}
	if rows := owner.Reservations(); len(rows) != 6 || rows[0].Status != "committed" {
		t.Fatal("commit join missing", rows)
	}
	if _, err := owner.Reserve(ownerRequest(7, "6")); err != ErrOwnerFloor {
		t.Fatalf("seventh reservation: %v", err)
	}
	owner.Close()
	owner, err = OpenOwnerLedger(path, ownerPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if owner.State().Stock != 70 {
		t.Fatal(owner.State())
	}
	if _, err := owner.Reserve(ownerRequest(8, "6")); err != ErrOwnerFloor {
		t.Fatalf("restart reset floor: %v", err)
	}
	if _, err := OpenOwnerLedger(path, OwnerPolicy{TargetID: action.TargetID, OwnerDeclarationDigest: hexDigest(digest("different-owner")), InitialStock: 100, Floor: 70, EffectCost: 5}); err == nil {
		t.Fatal("policy substitution accepted")
	}
}

func TestOwnerFloorAtomicAcrossGatewayCallersAndReplay(t *testing.T) {
	owner, err := OpenOwnerLedger(filepath.Join(t.TempDir(), "owner"), ownerPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	var wg sync.WaitGroup
	var mu sync.Mutex
	approved := map[int]OwnerReceipt{}
	for i := 1; i <= 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			receipt, err := owner.Reserve(ownerRequest(i, "0"))
			if err == nil {
				mu.Lock()
				approved[i] = receipt
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if len(approved) != 6 {
		t.Fatalf("shared floor admitted %d", len(approved))
	}
	if owner.State().Stock != 100 {
		t.Fatal("holds counted as effects")
	}
	for i, receipt := range approved {
		req := ownerRequest(i, "0")
		if _, err := owner.Reserve(req); err != ErrReplay {
			t.Fatalf("same replay: %v", err)
		}
		req.OperationDigest = hexDigest(digest("altered"))
		if err := owner.Commit(req, receipt.ReservationID); err == nil {
			t.Fatal("altered operation committed")
		}
	}
}

func TestOwnerCommitRequiresExactOneTimeReservation(t *testing.T) {
	owner, err := OpenOwnerLedger(filepath.Join(t.TempDir(), "owner"), ownerPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	req := ownerRequest(1, "0")
	if err := owner.Commit(req, ID(99)); err == nil {
		t.Fatal("unreserved effect")
	}
	receipt, err := owner.Reserve(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Commit(req, receipt.ReservationID); err != nil {
		t.Fatal(err)
	}
	if err := owner.Commit(req, receipt.ReservationID); err == nil {
		t.Fatal("double effect")
	}
	if owner.State().Stock != 95 || len(owner.Witness()) != 1 {
		t.Fatal("missing effect witness")
	}
}

func TestOwnerRestartRejectsJournalThatCrossesDeclaredFloor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner")
	owner, err := OpenOwnerLedger(path, ownerPolicy())
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 6; i++ {
		if _, err = owner.Reserve(ownerRequest(i, "0")); err != nil {
			t.Fatal(err)
		}
	}
	head := owner.head
	owner.Close()
	row := ownerEntry{Kind: "reserve", Request: ownerRequest(7, "0"), ReservationID: ID(77), Previous: head}
	row.Hash = ownerHash(row)
	b, _ := json.Marshal(row)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(append(b, '\n'))
	f.Close()
	if reopened, err := OpenOwnerLedger(path, ownerPolicy()); err == nil {
		reopened.Close()
		t.Fatal("valid-chain over-floor journal reopened")
	}
}

func TestOwnerCancellationRequiresExactPreDispatchReservationAndSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner")
	owner, err := OpenOwnerLedger(path, ownerPolicy())
	if err != nil {
		t.Fatal(err)
	}
	q := ownerRequest(1, "0")
	rc, err := owner.Reserve(q)
	if err != nil {
		t.Fatal(err)
	}
	altered := q
	altered.DecisionDigest = hexDigest(digest("other"))
	if err := owner.Cancel(altered, rc.ReservationID); err == nil {
		t.Fatal("forged cancellation")
	}
	if err := owner.Cancel(q, rc.ReservationID); err != nil {
		t.Fatal(err)
	}
	if err := owner.Commit(q, rc.ReservationID); err == nil {
		t.Fatal("cancelled reservation committed")
	}
	if _, err := owner.Reserve(q); err != ErrReplay {
		t.Fatal("cancel reopened replay", err)
	}
	if rows := owner.Reservations(); len(rows) != 1 || rows[0].Status != "cancelled" {
		t.Fatal(rows)
	}
	owner.Close()
	owner, err = OpenOwnerLedger(path, ownerPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if owner.State().Stock != 100 {
		t.Fatal("cancel changed stock")
	}
	for i := 2; i <= 7; i++ {
		if _, err := owner.Reserve(ownerRequest(i, "0")); err != nil {
			t.Fatal("cancel did not restore available authority", i, err)
		}
	}
	if _, err := owner.Reserve(ownerRequest(8, "0")); err != ErrOwnerFloor {
		t.Fatal("seventh live hold admitted", err)
	}
}
