package execution

// Fixture preflight is a test prerequisite, not implementation conformance.
// Nothing here grants authority or maps expected answers into runtime state.
import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

type conformanceVector struct {
	ID      string                     `json:"id"`
	Request map[string]json.RawMessage `json:"request"`
	Expect  map[string]json.RawMessage `json:"expect"`
}

func uniqueJSONValue(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, container := token.(json.Delim)
	if !container {
		return nil
	}
	if delim != '{' && delim != '[' {
		return fmt.Errorf("unexpected delimiter")
	}
	seen := map[string]bool{}
	for d.More() {
		if delim == '{' {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return fmt.Errorf("invalid or duplicate JSON key")
			}
			seen[name] = true
		}
		if err := uniqueJSONValue(d); err != nil {
			return err
		}
	}
	_, err = d.Token()
	return err
}

func loadConformanceFixture(path, digest string) ([]conformanceVector, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != digest {
		return nil, fmt.Errorf("fixture SHA-256 mismatch")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if err := uniqueJSONValue(d); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON")
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	rootFields := map[string]bool{"profile": true, "note": true, "vectors": true,
		"schemaFixture": true, "schemaFixtureNote": true, "schemaVectors": true,
		"mutationValidationVectors": true}
	for key := range root {
		if !rootFields[key] {
			return nil, fmt.Errorf("unknown root field: %s", key)
		}
	}
	var profile string
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(root["profile"], &profile); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(root["vectors"], &entries); err != nil {
		return nil, err
	}
	if profile != "consequential-action-execution-v1" || len(entries) == 0 {
		return nil, fmt.Errorf("wrong profile or empty vectors")
	}
	vectors := make([]conformanceVector, 0, len(entries))
	for _, entry := range entries {
		for key := range entry {
			if key != "id" && key != "case" && key != "note" && key != "request" && key != "expect" {
				return nil, fmt.Errorf("unknown vector field: %s", key)
			}
		}
		var v conformanceVector
		if err := json.Unmarshal(entry["id"], &v.ID); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(entry["request"], &v.Request); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(entry["expect"], &v.Expect); err != nil {
			return nil, err
		}
		vectors = append(vectors, v)
	}
	allowed := map[string]bool{
		"additionalInvocationAllowed": true, "continueOriginalAllowed": true,
		"evidenceState": true, "identityCollision": true, "releaseAllowed": true,
		"remainingCapacityUnits": true, "reservationRetained": true,
		"retryAllowed": true, "safeTransitionRequired": true, "secondReleaseAllowed": true,
	}
	seen := map[string]bool{}
	for _, v := range vectors {
		if strings.TrimSpace(v.ID) == "" || seen[v.ID] {
			return nil, fmt.Errorf("empty or duplicate vector ID")
		}
		seen[v.ID] = true
		if v.Request == nil || len(v.Expect) == 0 {
			return nil, fmt.Errorf("missing request or expectations")
		}
		for key := range v.Expect {
			if !allowed[key] {
				return nil, fmt.Errorf("unknown expectation: %s", key)
			}
		}
	}
	return vectors, nil
}
