package action

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math"
)

// BindingView is copied local binding metadata, never authenticated authority.
type BindingView struct {
	SchemaVersion, CatalogID, CatalogVersion                                                                                               string
	CatalogDigest, PolicyDigest, GatewayBuildDigest, ProtectedConfigDigest, TargetBuildDigest, TargetContractDigest, DecisionProfileDigest [32]byte
	ActorID, TenantID, InstanceID                                                                                                          string
	IdentityProjectionDigest                                                                                                               [32]byte
	ZoneID, AudienceID                                                                                                                     string
	IntentDigest                                                                                                                           [32]byte
	SourceKind, SourceMethod, SourceRoute                                                                                                  string
	InputDigest                                                                                                                            [32]byte
	OperationID, TargetID, ResourceID, TargetVersion, ReplayID                                                                             string
	OperationDigest                                                                                                                        [32]byte
	ValidFromUnixNS, ExpiresUnixNS                                                                                                         int64
}

func viewFields(b []byte, n int) ([][]byte, error) {
	if len(b) > MaxEncodingBytes {
		return nil, ErrInvalidBindingContext
	}
	out := make([][]byte, 0, n)
	for len(b) > 0 && len(out) < n {
		if len(b) < 4 {
			return nil, ErrInvalidBindingContext
		}
		size := binary.BigEndian.Uint32(b)
		b = b[4:]
		if uint64(size) > uint64(len(b)) {
			return nil, ErrInvalidBindingContext
		}
		out = append(out, b[:size])
		b = b[size:]
	}
	if len(out) != n || len(b) != 0 {
		return nil, ErrInvalidBindingContext
	}
	return out, nil
}

// View validates the owned frame and operation; it cannot restore arbitrary bytes.
func (b Binding) View() (BindingView, error) {
	var v BindingView
	bad := func() (BindingView, error) { return BindingView{}, ErrInvalidBindingContext }
	if len(b.encoded) == 0 || b.digest != sha256.Sum256(b.encoded) {
		return bad()
	}
	f, e := viewFields(b.encoded, 25)
	if e != nil || string(f[0]) != "KAG-LOCAL-ACTION-BINDING/v1" {
		return bad()
	}
	v.SchemaVersion = string(f[1])
	v.CatalogID = string(f[2])
	v.CatalogVersion = string(f[3])
	ds := []*[32]byte{&v.CatalogDigest, &v.PolicyDigest, &v.GatewayBuildDigest, &v.ProtectedConfigDigest, &v.TargetBuildDigest, &v.TargetContractDigest, &v.DecisionProfileDigest}
	for i, d := range ds {
		if len(f[4+i]) != 32 {
			return bad()
		}
		copy(d[:], f[4+i])
	}
	v.ActorID = string(f[11])
	v.TenantID = string(f[12])
	v.InstanceID = string(f[13])
	if len(f[14]) != 32 || len(f[17]) != 32 || len(f[21]) != 32 {
		return bad()
	}
	copy(v.IdentityProjectionDigest[:], f[14])
	v.ZoneID = string(f[15])
	v.AudienceID = string(f[16])
	copy(v.IntentDigest[:], f[17])
	v.SourceKind = string(f[18])
	v.SourceMethod = string(f[19])
	v.SourceRoute = string(f[20])
	copy(v.InputDigest[:], f[21])
	if v.IntentDigest == ([32]byte{}) || v.InputDigest == ([32]byte{}) {
		return bad()
	}
	o := b.operation
	if o.digest != sha256.Sum256(o.encoded) || !bytes.Equal(f[22], o.encoded) {
		return bad()
	}
	entry, ok := lookup(o.operationID)
	if !ok {
		return bad()
	}
	if v.SourceKind == "http" {
		if v.SourceMethod != entry.method || v.SourceRoute != entry.path {
			return bad()
		}
	} else if v.SourceKind == "mcp-arguments" {
		if v.SourceMethod != "arguments" || v.SourceRoute != entry.tool {
			return bad()
		}
	} else {
		return bad()
	}
	v.OperationID = o.operationID
	v.TargetID = TargetID
	v.ResourceID = o.resourceID
	v.TargetVersion = o.targetVersion
	v.ReplayID = o.replayID
	v.OperationDigest = o.digest
	mode := "instance-required"
	if v.InstanceID == "" {
		mode = "workload-level"
	}
	profile, _ := NewIdentityGranularityProfile(mode)
	admit, _ := NewTenantTargetProjection(v.TenantID, v.ZoneID, v.AudienceID, TargetID)
	c := BindingContext{SchemaVersion: v.SchemaVersion, CatalogID: v.CatalogID, CatalogVersion: v.CatalogVersion, CatalogDigest: v.CatalogDigest, PolicyDigest: v.PolicyDigest, GatewayBuildDigest: v.GatewayBuildDigest, ProtectedConfigDigest: v.ProtectedConfigDigest, TargetBuildDigest: v.TargetBuildDigest, TargetContractDigest: v.TargetContractDigest, DecisionProfileDigest: v.DecisionProfileDigest, ActorID: v.ActorID, TenantID: v.TenantID, InstanceID: v.InstanceID, IdentityProjectionDigest: v.IdentityProjectionDigest, IdentityGranularity: profile, ZoneID: v.ZoneID, AudienceID: v.AudienceID, TenantTarget: admit, TargetVersion: v.TargetVersion, ReplayID: v.ReplayID, ValidFromUnixNS: string(f[23]), ExpiresUnixNS: string(f[24])}
	if validateContext(c, entry) != nil {
		return bad()
	}
	start, _ := canonicalUint64(c.ValidFromUnixNS)
	expiry, _ := canonicalUint64(c.ExpiresUnixNS)
	if start > math.MaxInt64 || expiry > math.MaxInt64 {
		return bad()
	}
	v.ValidFromUnixNS = int64(start)
	v.ExpiresUnixNS = int64(expiry)
	var a ParsedAction
	if entry.markerOperation {
		a, e = ParseMCPArguments(entry.tool, o.body)
	} else {
		a, e = ParseMCPArguments(entry.tool, []byte("{}"))
	}
	if e != nil {
		return bad()
	}
	if entry.markerOperation && a.expectedVersion != c.TargetVersion {
		return bad()
	}
	// Reconstruct the preidentity intent with the retained original-input digest.
	// Marker bodies are normalized operation bytes, not the original raw input.
	if !entry.markerOperation {
		raw := []byte{}
		if v.SourceKind == "mcp-arguments" {
			raw = []byte("{}")
		}
		if v.InputDigest != sha256.Sum256(raw) {
			return bad()
		}
	}
	a.sourceKind, a.sourceMethod, a.sourceRoute = v.SourceKind, v.SourceMethod, v.SourceRoute
	a.inputDigest = v.InputDigest
	intent, err := intentBytes(a, entry)
	if err != nil || sha256.Sum256(intent) != v.IntentDigest {
		return bad()
	}
	expected, e := buildOperation(a, entry, c)
	if e != nil || expected.operationID != o.operationID || expected.resourceID != o.resourceID || expected.method != o.method || expected.path != o.path || expected.contentType != o.contentType || expected.precondition != o.precondition || expected.targetVersion != o.targetVersion || expected.replayID != o.replayID || !bytes.Equal(expected.body, o.body) || !bytes.Equal(expected.encoded, o.encoded) {
		return bad()
	}
	return v, nil
}
