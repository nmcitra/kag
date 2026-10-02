package execution

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

const profileHEAD = "7855966e8c061dae165d4d66ee2527bacbb59d6c"
const specPin = "51f11db0305585efba81cd99054bd6bd0ae1b87d84cc0a7c8a844879a7e64c5d"

var requiredGaps = []string{
	"faultHarness.release is a TEST-ONLY initial-send oracle, not a production dispatcher",
	"validated-permit bridge and live current-authority integration absent",
	"model ticks versus production time units are not an integrated contract",
	"model retained images are not production persistence or restart evidence",
	"no live authority, provider actual-effect evidence or authenticated protected-path non-dispatch observer",
	"renewed decision correlation and continuing safe-transition execution absent",
	"11 schema vectors and mutation-validation vector not executed; placeholders are never authority",
}
var conformanceFields = map[string]string{
	"additionalInvocationAllowed": "bool", "continueOriginalAllowed": "bool",
	"evidenceState": "enum", "identityCollision": "bool", "releaseAllowed": "bool",
	"remainingCapacityUnits": "integer", "reservationRetained": "bool",
	"retryAllowed": "bool", "safeTransitionRequired": "bool", "secondReleaseAllowed": "bool",
}
var conformanceInteger = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
var conformanceCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)

func typedConformanceValue(key string, value any) (string, error) {
	switch conformanceFields[key] {
	case "bool":
		if b, ok := value.(bool); ok {
			return fmt.Sprint(b), nil
		}
	case "enum":
		if s, ok := value.(string); ok {
			switch s {
			case "withheld", "dispatched", "effect_confirmed", "unknown":
				return s, nil
			}
		}
	case "integer":
		if n, ok := value.(json.Number); ok {
			if conformanceInteger.MatchString(string(n)) {
				if _, err := n.Int64(); err == nil {
					return string(n), nil
				}
			}
		} else if value != nil {
			v := reflect.ValueOf(value)
			switch v.Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				if v.Int() >= 0 {
					return fmt.Sprint(v.Int()), nil
				}
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				if v.Uint() <= 1<<63-1 {
					return fmt.Sprint(v.Uint()), nil
				}
			}
		}
	}
	return "", fmt.Errorf("unknown field or invalid exact type/enum: %s", key)
}
func compareConformance(expected map[string]json.RawMessage, actual map[string]any) []string {
	var mismatches []string
	if len(expected) == 0 {
		mismatches = append(mismatches, "missing expected contract")
	}
	for k, v := range actual {
		if _, err := typedConformanceValue(k, v); err != nil {
			mismatches = append(mismatches, "actual: "+err.Error())
		}
	}
	for k, raw := range expected {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		var value any
		if len(raw) > 128 || d.Decode(&value) != nil {
			mismatches = append(mismatches, "invalid expectation: "+k)
			continue
		}
		var trailing any
		if d.Decode(&trailing) != io.EOF {
			mismatches = append(mismatches, "trailing expectation: "+k)
			continue
		}
		want, err := typedConformanceValue(k, value)
		if err != nil {
			mismatches = append(mismatches, "expected: "+err.Error())
			continue
		}
		got, ok := actual[k]
		if !ok {
			mismatches = append(mismatches, "missing actual: "+k)
			continue
		}
		normalized, err := typedConformanceValue(k, got)
		if err != nil || normalized != want {
			mismatches = append(mismatches, fmt.Sprintf("%s: expected %s actual %v", k, want, got))
		}
	}
	sort.Strings(mismatches)
	return mismatches
}

type conformanceMetadata struct {
	SourceHEAD          string `json:"sourceHEAD"`
	SourceDirty         string `json:"sourceDirtyIncludingUntracked"`
	ProfileStatus       string `json:"profileStatus"`
	ObservedProfileHEAD string `json:"observedProfileHEAD"`
	Toolchain           string `json:"toolchain"`
}
type conformanceCase struct {
	ID           string                     `json:"id"`
	Request      map[string]json.RawMessage `json:"request"`
	Expected     map[string]json.RawMessage `json:"expected"`
	Actual       map[string]any             `json:"actual"`
	Observations []string                   `json:"observations"`
	Unsupported  []string                   `json:"unsupported"`
	Mismatches   []string                   `json:"mismatches"`
	Errors       []string                   `json:"errors"`
	Status       string                     `json:"status"`
	Repeats      int                        `json:"independentRepeats"`
	Attempts     []conformanceAttempt       `json:"attempts"`
}
type conformanceAttempt struct {
	Request      map[string]json.RawMessage `json:"requestSnapshot"`
	Actual       map[string]any             `json:"actualSnapshot"`
	Observations []string                   `json:"observations"`
	Unsupported  []string                   `json:"unsupported"`
	Errors       []string                   `json:"errors"`
}
type conformanceReport struct {
	ProfileHEAD              string              `json:"fixedProfileHEAD"`
	FixtureDigest            string              `json:"fixedFixtureSHA256"`
	SpecDigest               string              `json:"fixedSpecSHA256"`
	Metadata                 conformanceMetadata `json:"metadata"`
	Lane                     string              `json:"evidenceLane"`
	Limits                   []string            `json:"requiredContractUnsupported"`
	SchemaVectorsNotExecuted int                 `json:"schemaVectorsNotExecuted"`
	Cases                    []conformanceCase   `json:"cases"`
	Qualified                bool                `json:"qualified"`
}
type conformanceAdapter func(*testing.T, map[string]json.RawMessage) (map[string]any, []string, []string)

func copyRequest(r map[string]json.RawMessage) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	for k, v := range r {
		out[k] = append(json.RawMessage(nil), v...)
	}
	return out
}

// A goroutine is the Goexit boundary. Fatal in an imported helper marks the
// subtest failed but deferred completion still runs; every vector is kept.
func invokeConformance(t *testing.T, r map[string]json.RawMessage, a conformanceAdapter) (actual map[string]any, obs, u, errors []string) {
	actual = map[string]any{}
	input := copyRequest(r)
	before := copyRequest(input)
	done := make(chan struct{})
	go func() {
		returned := false
		defer func() {
			if p := recover(); p != nil {
				errors = append(errors, "adapter panic recovered")
			}
			if !returned {
				errors = append(errors, "adapter did not return (panic or Goexit)")
			}
			if !reflect.DeepEqual(before, input) {
				errors = append(errors, "adapter mutated request")
			}
			if t.Failed() {
				errors = append(errors, "adapter subtest failed")
			}
			close(done)
		}()
		actual, obs, u = a(t, input)
		if actual == nil {
			actual = map[string]any{}
			errors = append(errors, "nil adapter result")
		}
		if len(obs) == 0 {
			errors = append(errors, "missing adapter observations")
		}
		for k, v := range actual {
			if _, err := typedConformanceValue(k, v); err != nil {
				errors = append(errors, "invalid actual output field or type")
			}
		}
		raw, err := json.Marshal(actual)
		// Discard the adapter-owned map even on snapshot failure. Decoding into
		// an existing map reuses it and leaves prior cases/attempts aliased.
		actual = map[string]any{}
		if err != nil {
			errors = append(errors, "unserializable result")
		} else {
			d := json.NewDecoder(bytes.NewReader(raw))
			d.UseNumber()
			var detached map[string]any
			if err = d.Decode(&detached); err != nil {
				errors = append(errors, "invalid result snapshot")
			} else {
				actual = detached
			}
		}
		obs = append([]string(nil), obs...)
		u = append([]string(nil), u...)
		returned = true
	}()
	<-done
	return
}
func runConformance(t *testing.T, v []conformanceVector, repeats int, a conformanceAdapter) conformanceReport {
	report := conformanceReport{ProfileHEAD: profileHEAD, FixtureDigest: fixturePin, SpecDigest: specPin,
		Lane:   "package-local imported reducer / modelLedger / modelRecorder / modelTarget / test-only initial-send oracle",
		Limits: append([]string(nil), requiredGaps...), SchemaVectorsNotExecuted: 11}
	if repeats < 2 || repeats > 10 {
		report.Limits = append(report.Limits, "independent repeats must be between 2 and 10")
		return report
	}
	for _, vector := range v {
		c := conformanceCase{ID: vector.ID, Request: copyRequest(vector.Request), Expected: copyRequest(vector.Expect), Actual: map[string]any{}, Repeats: repeats}
		var first []byte
		for i := 0; i < repeats; i++ {
			var actual map[string]any
			var obs, u, errs []string
			t.Run(fmt.Sprintf("%s-repeat-%d", vector.ID, i+1), func(t *testing.T) { actual, obs, u, errs = invokeConformance(t, vector.Request, a) })
			if actual == nil {
				actual = map[string]any{}
				errs = append(errs, "missing result")
			}
			snapshot, err := json.Marshal(struct {
				Actual                    map[string]any
				Observations, Unsupported []string
			}{actual, obs, u})
			if err != nil {
				errs = append(errs, "snapshot error")
			}
			if i == 0 {
				first = snapshot
				c.Actual = actual
				c.Observations = obs
				c.Unsupported = u
			} else if !bytes.Equal(first, snapshot) {
				errs = append(errs, "independent repeats nondeterministic")
			}
			c.Errors = append(c.Errors, errs...)
			c.Attempts = append(c.Attempts, conformanceAttempt{copyRequest(vector.Request), actual, obs, u, append([]string(nil), errs...)})
		}
		c.Mismatches = compareConformance(c.Expected, c.Actual)
		c.Status = "pass"
		if len(c.Mismatches) > 0 {
			c.Status = "fail"
		}
		if len(c.Unsupported) > 0 {
			c.Status = "unsupported"
		}
		if len(c.Errors) > 0 {
			c.Status = "error"
		}
		report.Cases = append(report.Cases, c)
	}
	// Qualification remains closed independently of modeled case matches.
	report.Qualified = false
	return report
}
func boundedFile(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("input must be a regular file, not a link or special file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(before, info) {
		return nil, fmt.Errorf("input must be regular")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 1048577))
	if err != nil {
		return nil, err
	}
	if len(raw) > 1048576 {
		return nil, fmt.Errorf("input exceeds 1 MiB")
	}
	return raw, nil
}
func loadPinnedConformance(path string) ([]conformanceVector, error) {
	raw, err := boundedFile(path)
	if err != nil {
		return nil, err
	}
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != fixturePin {
		return nil, fmt.Errorf("fixed fixture SHA-256 mismatch")
	}
	var root struct {
		Vectors []conformanceVector `json:"vectors"`
	}
	if err = json.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	if len(root.Vectors) != 20 {
		return nil, fmt.Errorf("pinned fixture must have 20 cases")
	}
	return root.Vectors, nil
}
func conformanceGit(root string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-c", "core.fsmonitor=false", "-C", root}, args...)...)
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "GIT_") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, "GIT_OPTIONAL_LOCKS=0")
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}
func metadataQualified(m conformanceMetadata) bool {
	return conformanceCommit.MatchString(m.SourceHEAD) && m.SourceDirty == "clean" && m.ProfileStatus == "verified" && m.ObservedProfileHEAD == profileHEAD && strings.HasPrefix(m.Toolchain, "go")
}
func collectConformanceMetadata(profile string) conformanceMetadata {
	m := conformanceMetadata{SourceHEAD: "unknown", SourceDirty: "unknown", ProfileStatus: "unverified", Toolchain: runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH}
	root, err := conformanceGit(".", "rev-parse", "--show-toplevel")
	if err == nil {
		if head, e := conformanceGit(root, "rev-parse", "HEAD"); e == nil {
			m.SourceHEAD = head
		}
		if status, e := conformanceGit(root, "status", "--porcelain=v1", "--untracked-files=all"); e == nil {
			m.SourceDirty = "clean"
			if status != "" {
				m.SourceDirty = "dirty"
			}
		}
	}
	if profile != "" {
		head, e := conformanceGit(profile, "rev-parse", "HEAD")
		if e == nil {
			m.ObservedProfileHEAD = head
		}
		status, e2 := conformanceGit(profile, "status", "--porcelain=v1", "--untracked-files=all")
		raw, e3 := boundedFile(filepath.Join(profile, "specifications", "consequential-action-execution-and-evidence.md"))
		fixture, e4 := boundedFile(filepath.Join(profile, "specifications", "conformance", "consequential-action-execution-v1.json"))
		if e == nil && head == profileHEAD && e2 == nil && status == "" && e3 == nil && e4 == nil && fmt.Sprintf("%x", sha256.Sum256(raw)) == specPin && fmt.Sprintf("%x", sha256.Sum256(fixture)) == fixturePin {
			m.ProfileStatus = "verified"
		}
	}
	return m
}

// Pin each directory handle and check its identity against Lstat before moving
// down the path. Refuse links, path swaps and source repository ancestry.
func writeConformanceReport(path string, report conformanceReport) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("report needs a clean absolute path")
	}
	root, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	parts := strings.Split(strings.TrimPrefix(filepath.Dir(path), string(filepath.Separator)), string(filepath.Separator))
	for _, part := range parts {
		if part == "" {
			continue
		}
		info, e := root.Lstat(part)
		if e != nil {
			return e
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("report ancestor is not a real directory")
		}
		next, e := root.OpenRoot(part)
		if e != nil {
			return e
		}
		opened, e := next.Stat(".")
		if e != nil || !os.SameFile(info, opened) {
			next.Close()
			return fmt.Errorf("report ancestor changed")
		}
		after, e := root.Lstat(part)
		if e != nil || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, after) {
			next.Close()
			return fmt.Errorf("report ancestor changed or became link")
		}
		root.Close()
		root = next
		for _, marker := range []string{".git", "go.mod", "SOURCE-IMPORT.json"} {
			if _, e := root.Lstat(marker); e == nil {
				return fmt.Errorf("reports forbidden in source repositories")
			} else if !os.IsNotExist(e) {
				return e
			}
		}
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	f, err := root.OpenFile(filepath.Base(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(append(raw, '\n')); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
func TestConformanceQualification(t *testing.T) {
	fixture := os.Getenv("KAG_CONFORMANCE_RUN_FIXTURE")
	if fixture == "" {
		t.Skip("explicit local full qualification run only")
	}
	vectors, err := loadPinnedConformance(fixture)
	if err != nil {
		t.Fatal(err)
	}
	report := runConformance(t, vectors, 2, observeConformance)
	report.Metadata = collectConformanceMetadata(os.Getenv("KAG_CONFORMANCE_PROFILE_ROOT"))
	if !metadataQualified(report.Metadata) {
		report.Limits = append(report.Limits, "source dirty/unknown or profile unverified")
	}
	for _, c := range report.Cases {
		e, _ := json.Marshal(c.Expected)
		a, _ := json.Marshal(c.Actual)
		fmt.Printf("%s expected=%s actual=%s status=%s\n", c.ID, e, a, c.Status)
	}
	if err = writeConformanceReport(os.Getenv("KAG_CONFORMANCE_REPORT"), report); err != nil {
		t.Fatal(err)
	}
	if !report.Qualified {
		t.Error("complete qualification false: required contracts unsupported; see report")
	}
}
