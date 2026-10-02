package action

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

type goldenFile struct {
	CatalogHex     string         `json:"catalog_hex"`
	CatalogSHA     string         `json:"catalog_sha256"`
	BindingContext map[string]any `json:"binding_context"`
	Vectors        []goldenVector `json:"vectors"`
}
type goldenVector struct {
	Name            string `json:"name"`
	SourceKind      string `json:"source_kind"`
	SourceMethod    string `json:"source_method"`
	SourceRoute     string `json:"source_route_or_tool"`
	OperationID     string `json:"operation_id"`
	RawHex          string `json:"original_input_hex"`
	InputSHA        string `json:"input_sha256"`
	IntentHex       string `json:"intent_hex"`
	IntentSHA       string `json:"intent_sha256"`
	OperationHex    string `json:"operation_hex"`
	OperationSHA    string `json:"operation_sha256"`
	BindingHex      string `json:"binding_hex"`
	BindingSHA      string `json:"binding_sha256"`
	Marker          string `json:"marker"`
	ExpectedVersion string `json:"expected_version"`
}

func golden(t testing.TB) goldenFile {
	t.Helper()
	raw, e := os.ReadFile("testdata/independent-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var f goldenFile
	if e = json.Unmarshal(raw, &f); e != nil {
		t.Fatal(e)
	}
	return f
}
func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// refFrame is test-only framing independently transcribed from the contract.
func refFrame(fields ...[]byte) []byte {
	var out []byte
	for _, f := range fields {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(f)))
		out = append(out, n[:]...)
		out = append(out, f...)
	}
	return out
}
func refStrings(fields ...string) []byte {
	var all [][]byte
	for _, s := range fields {
		all = append(all, []byte(s))
	}
	return refFrame(all...)
}
func checkBytesSHA(t testing.TB, got []byte, wantHex, wantSHA string) {
	t.Helper()
	if !bytes.Equal(got, unhex(t, wantHex)) {
		t.Fatalf("bytes differ: got %x want %s", got, wantHex)
	}
	d := sha256.Sum256(got)
	if hex.EncodeToString(d[:]) != wantSHA {
		t.Fatalf("digest got %x want %s", d, wantSHA)
	}
}
func TestCatalog(t *testing.T) {
	want := []CatalogEntry{
		{OperationID: "lab.read_status", Method: "GET", Path: "/lab/status", Tool: "lab.read_status", TargetID: "lab-fixture-01", ResourceID: "lab-status", Risk: "20", RiskProfile: "synthetic-local-example", MinimumTier: "Observer", InstanceApplicability: "workload-or-instance", ArgumentSchema: "empty-http-exact-empty-mcp-object-v1"},
		{OperationID: "lab.set_marker", Method: "POST", Path: "/lab/marker", Tool: "lab.set_marker", TargetID: "lab-fixture-01", ResourceID: "lab-marker", Risk: "60", RiskProfile: "synthetic-local-example", MinimumTier: "Operator", InstanceApplicability: "workload-or-instance", ArgumentSchema: "marker-enum-and-canonical-uint64-string-v1", Markers: []string{"clear", "set"}},
	}
	got := CatalogEntries()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("catalog %#v", got)
	}
	f := golden(t)
	checkBytesSHA(t, CatalogBytes(), f.CatalogHex, f.CatalogSHA)
	if CatalogDigest() != sha256.Sum256(unhex(t, f.CatalogHex)) {
		t.Fatal("catalog digest")
	}
	for _, w := range want {
		v, ok := LookupOperation(w.OperationID)
		if !ok || !reflect.DeepEqual(v, w) {
			t.Fatal("lookup", w.OperationID)
		}
	}
	if _, ok := LookupOperation("LAB.read_status"); ok {
		t.Fatal("unknown operation admitted")
	}
}
func TestCatalogOwnership(t *testing.T) {
	a := CatalogEntries()
	a[1].Markers[0] = "unsafe"
	a[0].TargetID = "other"
	b := CatalogBytes()
	b[0] ^= 255
	e, _ := LookupOperation("lab.set_marker")
	e.Markers[0] = "changed"
	if CatalogEntries()[1].Markers[0] != "clear" || CatalogEntries()[0].TargetID != "lab-fixture-01" {
		t.Fatal("snapshot mutation")
	}
	f := golden(t)
	checkBytesSHA(t, CatalogBytes(), f.CatalogHex, f.CatalogSHA)
}
func TestCatalogFramingAmbiguity(t *testing.T) {
	l := refStrings("a", "bc")
	r := refStrings("ab", "c")
	if hex.EncodeToString(l) != "0000000161000000026263" || hex.EncodeToString(r) != "0000000261620000000163" || bytes.Equal(l, r) {
		t.Fatal("reference framing ambiguity")
	}
}
