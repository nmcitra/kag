package execution

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func canonicalTemp(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// Re-exec the test binary so the deliberately fatal child does not fail CI.
// A real testing.T Fatal calls Goexit; panic recovery alone cannot handle it.
func TestConformanceFatalBoundary(t *testing.T) {
	if output := os.Getenv("KAG_CONFORMANCE_FATAL_CHILD"); output != "" {
		adapter := func(t *testing.T, r map[string]json.RawMessage) (map[string]any, []string, []string) {
			t.Fatal("intentional helper Fatal")
			return nil, nil, nil
		}
		report := runConformance(t, pinnedVectors(t), 2, adapter)
		if err := writeConformanceReport(output, report); err != nil {
			t.Fatal(err)
		}
		return
	}
	path := filepath.Join(canonicalTemp(t), "fatal.json")
	cmd := exec.Command(os.Args[0], "-test.run=^TestConformanceFatalBoundary$", "-test.count=1")
	cmd.Env = append(os.Environ(), "KAG_CONFORMANCE_FATAL_CHILD="+path)
	if raw, err := cmd.CombinedOutput(); err == nil {
		t.Fatal("fatal child unexpectedly passed", string(raw))
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("fatal lost full report", err)
	}
	var report conformanceReport
	if err = json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Cases) != 20 || report.Qualified {
		t.Fatal("fatal lost cases")
	}
	for _, c := range report.Cases {
		if c.Status != "error" || len(c.Errors) == 0 {
			t.Fatal("fatal false pass", c.ID)
		}
	}
}

func TestConformanceCLISafety(t *testing.T) {
	script, err := filepath.Abs("../../scripts/run-conformance.sh")
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := filepath.Abs("testdata/consequential-action-execution-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(canonicalTemp(t), "report.json")
	run := func(args ...string) ([]byte, error) {
		cmd := exec.Command("bash", append([]string{script}, args...)...)
		cmd.Env = os.Environ()
		return cmd.CombinedOutput()
	}
	if raw, err := run("--fixture", fixture, "--fixture-sha256", fixturePin, "--report", path); err == nil {
		t.Fatal("unsupported qualification returned success", string(raw))
	} else {
		for _, v := range pinnedVectors(t) {
			if !bytes.Contains(raw, []byte(v.ID+" expected=")) {
				t.Fatalf("CLI omitted %s: %s", v.ID, raw)
			}
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report conformanceReport
	if err = json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Cases) != 20 || report.Qualified || report.Metadata.ProfileStatus != "unverified" || report.SchemaVectorsNotExecuted != 11 {
		t.Fatal("invalid CLI report")
	}
	head, err := conformanceGit(".", "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	status, err := conformanceGit(".", "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		t.Fatal(err)
	}
	wantDirty := "clean"
	if status != "" {
		wantDirty = "dirty"
	}
	if report.Metadata.SourceHEAD != head || report.Metadata.SourceDirty != wantDirty {
		t.Fatal("CLI metadata does not match actual checkout", report.Metadata)
	}
	for _, args := range [][]string{
		{"--fixture", fixture, "--fixture-sha256", strings.Repeat("0", 64), "--report", path + ".bad"},
		{"--fixture", fixture, "--fixture-sha256", fixturePin, "--report", "relative.json"},
		{"--fixture", fixture, "--fixture", fixture, "--fixture-sha256", fixturePin, "--report", path + ".bad"},
		{"--fixture", fixture, "--fixture-sha256", fixturePin, "--report", path},
	} {
		if _, err := run(args...); err == nil {
			t.Fatal("unsafe CLI accepted", args)
		}
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, unchanged) {
		t.Fatal("overwritten existing report", err)
	}
	if _, err := os.Stat(path + ".bad"); !os.IsNotExist(err) {
		t.Fatal("bad digest created report")
	}
}

func TestConformancePinnedInputBounds(t *testing.T) {
	path := filepath.Join(canonicalTemp(t), "fixture.json")
	for _, raw := range [][]byte{[]byte("{}"), bytes.Repeat([]byte(" "), 1048577)} {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadPinnedConformance(path); err == nil {
			t.Fatal("arbitrary/oversize fixture accepted")
		}
	}
	v, err := loadPinnedConformance("testdata/consequential-action-execution-v1.json")
	if err != nil || len(v) != 20 {
		t.Fatal(err)
	}
}

func TestConformanceResultSnapshotsDetached(t *testing.T) {
	shared := map[string]any{}
	observations := []string{""}
	unsupported := []string{""}
	calls := 0
	adapter := func(t *testing.T, request map[string]json.RawMessage) (map[string]any, []string, []string) {
		calls++
		shared["releaseAllowed"] = calls%2 == 1
		observations[0] = fmt.Sprintf("observation-%d", calls)
		unsupported[0] = fmt.Sprintf("unsupported-%d", calls)
		return shared, observations, unsupported
	}
	vectors := []conformanceVector{
		{ID: "snapshot-first", Request: map[string]json.RawMessage{"scenario": json.RawMessage(`true`)}, Expect: map[string]json.RawMessage{"releaseAllowed": json.RawMessage(`true`)}},
		{ID: "snapshot-second", Request: map[string]json.RawMessage{"scenario": json.RawMessage(`false`)}, Expect: map[string]json.RawMessage{"releaseAllowed": json.RawMessage(`true`)}},
	}
	report := runConformance(t, vectors, 2, adapter)
	if len(report.Cases) != 2 || calls != 4 {
		t.Fatal("missing independent invocations")
	}
	for caseIndex, c := range report.Cases {
		if c.Actual["releaseAllowed"] != true {
			t.Errorf("case %d first result changed across repeats/cases: %v", caseIndex, c.Actual)
		}
		firstCall := caseIndex*2 + 1
		if !reflect.DeepEqual(c.Observations, []string{fmt.Sprintf("observation-%d", firstCall)}) ||
			!reflect.DeepEqual(c.Unsupported, []string{fmt.Sprintf("unsupported-%d", firstCall)}) {
			t.Errorf("case %d retained slices changed", caseIndex)
		}
		if c.Status != "error" {
			t.Errorf("case %d nondeterminism was not rejected: %s", caseIndex, c.Status)
		}
		if len(c.Attempts) != 2 {
			t.Fatal("missing attempt snapshots")
		}
		for attemptIndex, attempt := range c.Attempts {
			call := caseIndex*2 + attemptIndex + 1
			if attempt.Actual["releaseAllowed"] != (call%2 == 1) {
				t.Errorf("attempt %d result changed across calls: %v", call, attempt.Actual)
			}
			if !reflect.DeepEqual(attempt.Observations, []string{fmt.Sprintf("observation-%d", call)}) ||
				!reflect.DeepEqual(attempt.Unsupported, []string{fmt.Sprintf("unsupported-%d", call)}) {
				t.Errorf("attempt %d slices changed across calls", call)
			}
		}
	}
	before, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	shared["releaseAllowed"] = "post-report mutation"
	shared["extra"] = true
	observations[0] = "post-report observation"
	unsupported[0] = "post-report unsupported"
	after, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("adapter mutation after report changed retained actual/attempt/slice snapshots")
	}
}

func TestConformanceReportSafety(t *testing.T) {
	v := pinnedVectors(t)
	report := runConformance(t, v, 2, observeConformance)
	if len(report.Cases) != 20 || report.Qualified {
		t.Fatal("incomplete or false qualification", report)
	}
	passes := 0
	for _, c := range report.Cases {
		if c.Status == "pass" {
			passes++
		}
		if c.Expected == nil || c.Actual == nil {
			t.Fatal("lost case", c.ID)
		}
	}
	if passes != 12 {
		t.Fatal("expected twelve modeled matches and eight unsupported cases", passes)
	}
	for _, mode := range []string{"panic", "mutation", "nondeterminism", "unknown-output", "missing-observation", "wrong-number-type"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			adapter := func(t *testing.T, r map[string]json.RawMessage) (map[string]any, []string, []string) {
				calls++
				if mode == "panic" {
					panic("conformance-panic-secret-marker")
				}
				if mode == "mutation" {
					r["injected"] = json.RawMessage("true")
				}
				if mode == "unknown-output" {
					return map[string]any{"extra": true}, []string{"controlled"}, nil
				}
				if mode == "missing-observation" {
					return map[string]any{"releaseAllowed": true}, nil, nil
				}
				if mode == "wrong-number-type" {
					return map[string]any{"remainingCapacityUnits": float64(4)}, []string{"controlled"}, nil
				}
				value := true
				if mode == "nondeterminism" {
					value = calls%2 == 0
				}
				return map[string]any{"releaseAllowed": value}, []string{"controlled"}, nil
			}
			r := runConformance(t, v, 2, adapter)
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(raw, []byte("conformance-panic-secret-marker")) {
				t.Fatal("arbitrary panic payload published in report")
			}
			if len(r.Cases) != 20 {
				t.Fatal("lost cases")
			}
			for _, c := range r.Cases {
				if c.Status == "pass" || len(c.Errors) == 0 {
					t.Fatal("false pass", c)
				}
			}
		})
	}
}

func TestConformanceOutputSafety(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "new.json")
	if err := writeConformanceReport(path, conformanceReport{}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("wrong permission", info, err)
	}
	if err := writeConformanceReport(path, conformanceReport{}); err == nil {
		t.Fatal("overwrote report")
	}
	if err := os.Symlink(path, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := writeConformanceReport(filepath.Join(dir, "link"), conformanceReport{}); err == nil {
		t.Fatal("followed link")
	}
	repo := filepath.Join(dir, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeConformanceReport(filepath.Join(repo, "report.json"), conformanceReport{}); err == nil {
		t.Fatal("wrote into source repository")
	}
	if err := os.Symlink(dir, filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := writeConformanceReport(filepath.Join(dir, "alias", "new2.json"), conformanceReport{}); err == nil {
		t.Fatal("followed directory link")
	}
}

func TestConformanceMetadataClosed(t *testing.T) {
	for _, m := range []conformanceMetadata{{}, {SourceHEAD: "unknown", SourceDirty: "unknown", ProfileStatus: "unverified"}, {SourceHEAD: "72ad3dae3886ff3207610a9ce0a43afc8cb9b60f", SourceDirty: "dirty", ProfileStatus: "verified"}} {
		if metadataQualified(m) {
			t.Fatal("qualified unknown/dirty metadata", m)
		}
	}
	verified := conformanceMetadata{SourceHEAD: "72ad3dae3886ff3207610a9ce0a43afc8cb9b60f", SourceDirty: "clean", ProfileStatus: "verified", ObservedProfileHEAD: profileHEAD, Toolchain: "go1.27.1"}
	if !metadataQualified(verified) {
		t.Fatal("verified metadata rejected")
	}
	wrong := verified
	wrong.ObservedProfileHEAD = wrong.SourceHEAD
	if metadataQualified(wrong) {
		t.Fatal("arbitrary HEAD associated with fixed pin")
	}
	wrong = verified
	wrong.SourceDirty = "unknown"
	if metadataQualified(wrong) {
		t.Fatal("unknown dirty state accepted")
	}
	wrong = verified
	wrong.SourceDirty = "dirty"
	if metadataQualified(wrong) {
		t.Fatal("dirty state accepted")
	}
	m := collectConformanceMetadata(canonicalTemp(t))
	if m.ProfileStatus != "unverified" {
		t.Fatal("missing profile verified", m)
	}
	m = collectConformanceMetadata(".")
	if m.ProfileStatus != "unverified" {
		t.Fatal("arbitrary source HEAD verified as profile", m)
	}
}

func pinnedVectors(t *testing.T) []conformanceVector {
	t.Helper()
	v, err := loadConformanceFixture("testdata/consequential-action-execution-v1.json", fixturePin)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 20 {
		t.Fatal("not twenty cases")
	}
	return v
}

func TestConformanceAdapterContract(t *testing.T) {
	v := pinnedVectors(t)
	for _, x := range v {
		t.Run(x.ID, func(t *testing.T) {
			a, obs, unsupported := observeConformance(t, x.Request)
			if a == nil || len(obs) == 0 {
				t.Fatal("missing independent observations")
			}
			b, obs2, u2 := observeConformance(t, x.Request)
			if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(obs, obs2) || !reflect.DeepEqual(unsupported, u2) {
				t.Fatal("nondeterministic")
			}
			x.Expect = map[string]json.RawMessage{"releaseAllowed": json.RawMessage(`false`)}
			c, _, _ := observeConformance(t, x.Request)
			if !reflect.DeepEqual(a, c) {
				t.Fatal("expectation changed adapter")
			}
		})
	}
	a, _, _ := observeConformance(t, v[0].Request)
	if a["releaseAllowed"] != true || a["evidenceState"] != "dispatched" || a["reservationRetained"] != true {
		t.Fatal("baseline lacks actual enqueue/retain", a)
	}
	for _, raw := range []string{`{"authorizationCurrent":1}`, `{"invented":true}`, `{"sameIdentity":false,"sameFingerprint":false}`, `{"authorizationCurrent":true}`} {
		var r map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			t.Fatal(err)
		}
		a, _, u := observeConformance(t, r)
		if len(a) != 0 || len(u) == 0 {
			t.Fatal("invalid request accepted", raw, a)
		}
	}
}

func TestConformanceExactComparison(t *testing.T) {
	for _, tc := range []struct {
		expected string
		actual   map[string]any
		valid    bool
	}{
		{`{"releaseAllowed":true}`, map[string]any{"releaseAllowed": true}, true},
		{`{"remainingCapacityUnits":4}`, map[string]any{"remainingCapacityUnits": uint64(4)}, true},
		{`{"releaseAllowed":true}`, map[string]any{"releaseAllowed": 1}, false},
		{`{"releaseAllowed":false}`, map[string]any{"releaseAllowed": true}, false},
		{`{"evidenceState":"denied"}`, map[string]any{"evidenceState": "denied"}, false},
		{`{"releaseAllowed":true}`, map[string]any{"releaseAllowed": true, "extra": true}, false},
		{`{"extra":true}`, map[string]any{"extra": true}, false},
		{`{"remainingCapacityUnits":4.0}`, map[string]any{"remainingCapacityUnits": uint64(4)}, false},
		{`{"releaseAllowed":true}`, map[string]any{}, false},
	} {
		var e map[string]json.RawMessage
		if err := json.Unmarshal([]byte(tc.expected), &e); err != nil {
			t.Fatal(err)
		}
		if got := len(compareConformance(e, tc.actual)) == 0; got != tc.valid {
			t.Fatalf("%s %v accepted=%v", tc.expected, tc.actual, got)
		}
	}
}
