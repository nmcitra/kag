package execution

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestConformancePreflight(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.json")
	valid := `{"profile":"consequential-action-execution-v1","vectors":[{"id":"E01","request":{"authorizationCurrent":true},"expect":{"releaseAllowed":true}}]}`
	for _, tc := range []struct {
		name, raw string
		valid     bool
	}{
		{"valid", valid, true},
		{"empty", `{"profile":"consequential-action-execution-v1","vectors":[]}`, false},
		{"wrong profile", `{"profile":"other","vectors":[]}`, false},
		{"unknown expectation", `{"profile":"consequential-action-execution-v1","vectors":[{"id":"E01","request":{},"expect":{"invented":true}}]}`, false},
		{"missing request", `{"profile":"consequential-action-execution-v1","vectors":[{"id":"E01","expect":{"releaseAllowed":true}}]}`, false},
		{"duplicate IDs", `{"profile":"consequential-action-execution-v1","vectors":[{"id":"E01","request":{},"expect":{"releaseAllowed":true}},{"id":"E01","request":{},"expect":{"releaseAllowed":true}}]}`, false},
		{"empty ID", `{"profile":"consequential-action-execution-v1","vectors":[{"id":"","request":{},"expect":{"releaseAllowed":true}}]}`, false},
		{"empty expectation", `{"profile":"consequential-action-execution-v1","vectors":[{"id":"E01","request":{},"expect":{}}]}`, false},
		{"duplicate JSON key", `{"profile":"other","profile":"consequential-action-execution-v1","vectors":[{"id":"E01","request":{},"expect":{"releaseAllowed":true}}]}`, false},
		{"trailing JSON", valid + `{}`, false},
		{"profile alias", `{"profile":"wrong","Profile":"consequential-action-execution-v1","vectors":[{"id":"E01","request":{},"expect":{"releaseAllowed":true}}]}`, false},
		{"request alias", `{"profile":"consequential-action-execution-v1","vectors":[{"id":"E01","request":{},"Request":{"authorizationCurrent":true},"expect":{"releaseAllowed":true}}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.raw), 0600); err != nil {
				t.Fatal(err)
			}
			digest := fmt.Sprintf("%x", sha256.Sum256([]byte(tc.raw)))
			vectors, err := loadConformanceFixture(path, digest)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
			if tc.valid && len(vectors) != 1 {
				t.Fatal("missing validated vector")
			}
		})
	}
	if _, err := loadConformanceFixture(path, fmt.Sprintf("%064d", 0)); err == nil {
		t.Fatal("accepted wrong digest")
	}
	if _, err := loadConformanceFixture(path+".missing", fmt.Sprintf("%064d", 0)); err == nil {
		t.Fatal("accepted missing input")
	}
	// An explicit local fixture enables pinned-draft preflight, not an adapter run.
	if pinned := os.Getenv("KAG_CONFORMANCE_FIXTURE"); pinned != "" {
		vectors, err := loadConformanceFixture(pinned, "732e293673461807d9ae491ac3d00b1c42dbb4143c5b3bf6056ab3d44993f25d")
		if err != nil {
			t.Fatal(err)
		}
		if len(vectors) != 20 {
			t.Fatalf("expected pinned 20 vectors, got %d", len(vectors))
		}
	}
}
