// Package action implements a modeled local fixed-action byte contract. Parsing
// and binding do not establish identity, permission, freshness or eligibility.
// The package contains no transport adapter or dispatch capability.
package action

import (
	"crypto/sha256"
	"encoding/binary"
)

const (
	SchemaVersion    = "kag-local-action-v1"
	CatalogID        = "kag-local-lab"
	CatalogVersion   = "1"
	TargetID         = "lab-fixture-01"
	MaxEncodingBytes = 8192
)

// Error is a stable local category. It never includes input or credentials.
type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrUnsupportedOperation  Error = "unsupported_operation"
	ErrInvalidRequestTarget  Error = "invalid_request_target"
	ErrInvalidContent        Error = "invalid_content"
	ErrInputLimit            Error = "input_limit"
	ErrInvalidArguments      Error = "invalid_arguments"
	ErrInvalidBindingContext Error = "invalid_binding_context"
	ErrVersionMismatch       Error = "version_mismatch"
)

// CatalogEntry is an owned informational snapshot, never executable authority.
type CatalogEntry struct {
	OperationID, Method, Path, Tool, TargetID, ResourceID                 string
	Risk, RiskProfile, MinimumTier, InstanceApplicability, ArgumentSchema string
	Markers                                                               []string
}

// entry uses only privately owned scalar values; the enum is a fixed array.
type entry struct {
	operationID, method, path, tool, resourceID, risk, tier, argumentSchema string
	markerOperation                                                         bool
}

func entries() [2]entry {
	return [2]entry{
		{"lab.read_status", "GET", "/lab/status", "lab.read_status", "lab-status", "20", "Observer", "empty-http-exact-empty-mcp-object-v1", false},
		{"lab.set_marker", "POST", "/lab/marker", "lab.set_marker", "lab-marker", "60", "Operator", "marker-enum-and-canonical-uint64-string-v1", true},
	}
}
func (e entry) snapshot() CatalogEntry {
	s := CatalogEntry{OperationID: e.operationID, Method: e.method, Path: e.path, Tool: e.tool, TargetID: TargetID, ResourceID: e.resourceID, Risk: e.risk, RiskProfile: "synthetic-local-example", MinimumTier: e.tier, InstanceApplicability: "workload-or-instance", ArgumentSchema: e.argumentSchema}
	if e.markerOperation {
		s.Markers = []string{"clear", "set"}
	}
	return s
}
func CatalogEntries() []CatalogEntry {
	all := entries()
	return []CatalogEntry{all[0].snapshot(), all[1].snapshot()}
}
func lookup(id string) (entry, bool) {
	for _, e := range entries() {
		if e.operationID == id {
			return e, true
		}
	}
	return entry{}, false
}
func LookupOperation(id string) (CatalogEntry, bool) {
	e, ok := lookup(id)
	if !ok {
		return CatalogEntry{}, false
	}
	return e.snapshot(), true
}

// frame checks the entire addition before allocating retained output.
type frame struct {
	b   []byte
	err error
}

func (f *frame) raw(b []byte) {
	if f.err != nil {
		return
	}
	if len(b) > MaxEncodingBytes-len(f.b) {
		f.err = ErrInputLimit
		return
	}
	f.b = append(f.b, b...)
}
func (f *frame) u32(n uint32) { var b [4]byte; binary.BigEndian.PutUint32(b[:], n); f.raw(b[:]) }
func (f *frame) lp(b []byte) {
	if f.err != nil {
		return
	}
	if len(b) > MaxEncodingBytes-4-len(f.b) {
		f.err = ErrInputLimit
		return
	}
	f.u32(uint32(len(b)))
	f.raw(b)
}
func (f *frame) s(s string) {
	if f.err != nil {
		return
	}
	if len(s) > MaxEncodingBytes-4-len(f.b) {
		f.err = ErrInputLimit
		return
	}
	f.lp([]byte(s))
}
func (f *frame) d(d [32]byte) { f.lp(d[:]) }
func (f *frame) strings(ss ...string) {
	for _, s := range ss {
		f.s(s)
	}
}
func catalogBytes() ([]byte, error) {
	f := frame{}
	f.strings("KAG-LOCAL-CATALOG/v1", CatalogID, CatalogVersion, SchemaVersion)
	f.u32(2)
	for _, e := range entries() {
		f.strings(e.operationID, e.method, e.path, e.tool, TargetID, e.resourceID, e.risk, "synthetic-local-example", e.tier, "workload-or-instance", e.argumentSchema)
		if e.markerOperation {
			f.u32(2)
			f.strings("clear", "set")
		} else {
			f.u32(0)
		}
	}
	return f.b, f.err
}
func CatalogBytes() []byte {
	b, err := catalogBytes()
	if err != nil {
		panic("fixed catalog exceeds encoding bound")
	}
	return b
}
func CatalogDigest() [32]byte { return sha256.Sum256(CatalogBytes()) }
