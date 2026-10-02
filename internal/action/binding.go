package action

import (
	"bytes"
	"crypto/sha256"
)

// IdentityGranularityProfile is explicit modeled identity composition metadata.
// It does not verify a resolver, credentials or attribution. Its semantics are
// represented by the identity-owned IdentityProjectionDigest in a binding.
type IdentityGranularityProfile struct {
	mode  string
	valid bool
}

// NewIdentityGranularityProfile validates one explicit modeled granularity.
// Only protected composition may select this input; construction is no proof
// of identity/permission and no security boundary against gateway code/admins.
func NewIdentityGranularityProfile(mode string) (IdentityGranularityProfile, error) {
	if mode != "instance-required" && mode != "workload-level" {
		return IdentityGranularityProfile{}, ErrInvalidBindingContext
	}
	return IdentityGranularityProfile{mode: mode, valid: true}, nil
}

// TenantTargetProjection is modeled protected configuration admission metadata.
// It is not authenticated configuration or a permission outcome. The protected
// composition caller owns admission; config digest binds the actual semantics.
type TenantTargetProjection struct {
	tenant, zone, audience, target string
	valid                          bool
}

// NewTenantTargetProjection validates the exact modeled tenant/zone/audience
// admission tuple and sole fixed target. This constructor cannot authenticate
// its caller or establish that a real tenant is permitted to use that target.
func NewTenantTargetProjection(tenant, zone, audience, target string) (TenantTargetProjection, error) {
	if !contextID(tenant) || !contextID(zone) || !contextID(audience) || target != TargetID {
		return TenantTargetProjection{}, ErrInvalidBindingContext
	}
	return TenantTargetProjection{tenant: tenant, zone: zone, audience: audience, target: target, valid: true}, nil
}

// BindingContext contains complete modeled internal projection inputs supplied
// by protected composition. Presence, syntax and tuple equality validate only
// this local byte contract, never identity, authorization or freshness. Values
// are scalars/arrays; no slices, callbacks, credentials or target URLs exist.
type BindingContext struct {
	SchemaVersion, CatalogID, CatalogVersion                       string
	CatalogDigest                                                  [32]byte
	PolicyDigest, GatewayBuildDigest, ProtectedConfigDigest        [32]byte
	TargetBuildDigest, TargetContractDigest, DecisionProfileDigest [32]byte
	ActorID, TenantID, InstanceID                                  string
	IdentityProjectionDigest                                       [32]byte
	IdentityGranularity                                            IdentityGranularityProfile
	ZoneID, AudienceID                                             string
	TenantTarget                                                   TenantTargetProjection
	TargetVersion, ReplayID, ValidFromUnixNS, ExpiresUnixNS        string
}

// Operation is an immutable owned stable logical operation snapshot. It has no
// network address, callback or dispatch method; bytes are not HTTP wire bytes.
type Operation struct {
	operationID, resourceID, method, path, contentType, precondition, targetVersion, replayID string
	body, encoded                                                                             []byte
	digest                                                                                    [32]byte
}

func (o Operation) OperationID() string { return o.operationID }
func (o Operation) TargetID() string {
	if o.operationID == "" {
		return ""
	}
	return TargetID
}
func (o Operation) ResourceID() string       { return o.resourceID }
func (o Operation) Method() string           { return o.method }
func (o Operation) Path() string             { return o.path }
func (o Operation) ContentType() string      { return o.contentType }
func (o Operation) PreconditionKind() string { return o.precondition }
func (o Operation) TargetVersion() string    { return o.targetVersion }
func (o Operation) ReplayID() string         { return o.replayID }
func (o Operation) Body() []byte             { return bytes.Clone(o.body) }
func (o Operation) Bytes() []byte            { return bytes.Clone(o.encoded) }
func (o Operation) Digest() [32]byte         { return o.digest }
func (o Operation) clone() Operation {
	o.body = bytes.Clone(o.body)
	o.encoded = bytes.Clone(o.encoded)
	return o
}

// Binding owns the stable local authorization input bytes. Its existence and
// digest are not an authorization outcome and cannot release an operation.
type Binding struct {
	encoded   []byte
	digest    [32]byte
	operation Operation
}

func (b Binding) Bytes() []byte        { return bytes.Clone(b.encoded) }
func (b Binding) Digest() [32]byte     { return b.digest }
func (b Binding) Operation() Operation { return b.operation.clone() }

// Bind constructs the exact stable local byte contract from validated intent
// and complete modeled protected context. It revalidates retained intent and
// all context syntax/dependencies; target version is an independent supplied
// snapshot, not observed here. Freshness, replay reservation, permissions and
// dynamic execution fences require separate enforcement before any dispatch.
func Bind(a ParsedAction, c BindingContext) (Binding, error) {
	e, err := revalidateAction(a)
	if err != nil {
		return Binding{}, err
	}
	if err = validateContext(c, e); err != nil {
		return Binding{}, err
	}
	if e.markerOperation && a.expectedVersion != c.TargetVersion {
		return Binding{}, ErrVersionMismatch
	}
	o, err := buildOperation(a, e, c)
	if err != nil {
		return Binding{}, err
	}
	f := frame{}
	f.strings("KAG-LOCAL-ACTION-BINDING/v1", SchemaVersion, CatalogID, CatalogVersion)
	f.d(CatalogDigest())
	f.d(c.PolicyDigest)
	f.d(c.GatewayBuildDigest)
	f.d(c.ProtectedConfigDigest)
	f.d(c.TargetBuildDigest)
	f.d(c.TargetContractDigest)
	f.d(c.DecisionProfileDigest)
	f.strings(c.ActorID, c.TenantID, c.InstanceID)
	f.d(c.IdentityProjectionDigest)
	f.strings(c.ZoneID, c.AudienceID)
	f.d(a.intentDigest)
	f.strings(a.sourceKind, a.sourceMethod, a.sourceRoute)
	f.d(a.inputDigest)
	f.lp(o.encoded)
	f.strings(c.ValidFromUnixNS, c.ExpiresUnixNS)
	if f.err != nil {
		return Binding{}, f.err
	}
	return Binding{encoded: f.b, digest: sha256.Sum256(f.b), operation: o}, nil
}
func revalidateAction(a ParsedAction) (entry, error) {
	if !a.valid || len(a.input) > MaxArgumentBytes || len(a.intent) > MaxEncodingBytes {
		return entry{}, ErrInvalidArguments
	}
	e, ok := lookup(a.operationID)
	if !ok {
		return entry{}, ErrInvalidArguments
	}
	switch a.sourceKind {
	case "http":
		if a.sourceMethod != e.method || a.sourceRoute != e.path || (!e.markerOperation && len(a.input) != 0) {
			return entry{}, ErrInvalidArguments
		}
	case "mcp-arguments":
		if a.sourceMethod != "arguments" || a.sourceRoute != e.tool || (!e.markerOperation && !bytes.Equal(a.input, []byte("{}"))) {
			return entry{}, ErrInvalidArguments
		}
	default:
		return entry{}, ErrInvalidArguments
	}
	// Reparse bounded original bytes to avoid trusting typed fields or a digest.
	clean, err := makeAction(e, a.sourceKind, a.sourceMethod, a.sourceRoute, a.input)
	if err != nil || clean.marker != a.marker || clean.expectedVersion != a.expectedVersion || clean.inputDigest != a.inputDigest || clean.intentDigest != a.intentDigest || !bytes.Equal(clean.intent, a.intent) {
		return entry{}, ErrInvalidArguments
	}
	return e, nil
}
func validateContext(c BindingContext, e entry) error {
	zero := [32]byte{}
	for _, d := range [][32]byte{c.CatalogDigest, c.PolicyDigest, c.GatewayBuildDigest, c.ProtectedConfigDigest, c.TargetBuildDigest, c.TargetContractDigest, c.DecisionProfileDigest, c.IdentityProjectionDigest} {
		if d == zero {
			return ErrInvalidBindingContext
		}
	}
	if c.SchemaVersion != SchemaVersion || c.CatalogID != CatalogID || c.CatalogVersion != CatalogVersion || c.CatalogDigest != CatalogDigest() {
		return ErrVersionMismatch
	}
	if !contextID(c.ActorID) || !contextID(c.TenantID) || !contextID(c.ZoneID) || !contextID(c.AudienceID) {
		return ErrInvalidBindingContext
	}
	p := c.IdentityGranularity
	if !p.valid || (p.mode != "instance-required" && p.mode != "workload-level") {
		return ErrInvalidBindingContext
	}
	if c.InstanceID == "" {
		if p.mode != "workload-level" || e.snapshot().InstanceApplicability != "workload-or-instance" {
			return ErrInvalidBindingContext
		}
	} else if !contextID(c.InstanceID) {
		return ErrInvalidBindingContext
	}
	target := c.TenantTarget
	if !target.valid || !contextID(target.tenant) || !contextID(target.zone) || !contextID(target.audience) || target.tenant != c.TenantID || target.zone != c.ZoneID || target.audience != c.AudienceID || target.target != TargetID {
		return ErrInvalidBindingContext
	}
	if _, ok := canonicalUint64(c.TargetVersion); !ok {
		return ErrInvalidBindingContext
	}
	if !replayID(c.ReplayID) {
		return ErrInvalidBindingContext
	}
	start, ok := canonicalUint64(c.ValidFromUnixNS)
	if !ok {
		return ErrInvalidBindingContext
	}
	expiry, ok := canonicalUint64(c.ExpiresUnixNS)
	if !ok || start >= expiry {
		return ErrInvalidBindingContext
	}
	return nil
}
func contextID(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for i := range s {
		c := s[i]
		alpha := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if !alpha && (i == 0 || (c != '.' && c != '_' && c != ':' && c != '-')) {
			return false
		}
	}
	return true
}
func replayID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := range s {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
func buildOperation(a ParsedAction, e entry, c BindingContext) (Operation, error) {
	o := Operation{operationID: e.operationID, resourceID: e.resourceID, method: e.method, path: e.path, precondition: "none", targetVersion: c.TargetVersion, replayID: c.ReplayID}
	if e.markerOperation {
		o.contentType = "application/json"
		o.precondition = "match"
		o.body = []byte(`{"marker":"` + a.marker + `","expected_version":"` + a.expectedVersion + `"}`)
	}
	f := frame{}
	f.strings("KAG-LOCAL-OPERATION/v1", o.operationID, TargetID, o.resourceID, o.method, o.path, o.contentType)
	f.lp(o.body)
	f.strings(o.precondition, o.targetVersion, o.replayID)
	if f.err != nil {
		return Operation{}, f.err
	}
	o.encoded = f.b
	o.digest = sha256.Sum256(f.b)
	return o, nil
}
