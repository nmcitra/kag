// Package decision consumes authenticated normalized modeled results. It neither
// computes KTP standing nor dispatches an operation.
package decision

import (
	"bytes"
	"encoding/binary"
)

const MaxPayloadBytes = 8192
const decisionDomain = "KAG-MODELED-DECISION/v1"
const ProfileID = "kag-model-effects-v1"

type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrInvalidResult Error = "invalid_result"
	ErrInvalidConfig Error = "invalid_config"
	ErrWithheld      Error = "withheld"
	ErrExpired       Error = "expired"
	ErrClock         Error = "clock_uncertain"
	ErrBusy          Error = "busy"
	ErrCanceled      Error = "canceled"
	ErrSource        Error = "source_unavailable"
	ErrInvalidPermit Error = "invalid_permit"
)

type Claims struct {
	ProducerID, ProfileID, ResultKind, ResultID                                                                                            string
	BindingDigest, OperationDigest, IdentityProjectionDigest                                                                               [32]byte
	ActorID, TenantID, InstanceID, ZoneID, AudienceID, ReplayID                                                                            string
	CatalogDigest, PolicyDigest, GatewayBuildDigest, ProtectedConfigDigest, TargetBuildDigest, TargetContractDigest, DecisionProfileDigest [32]byte
	IssuedAtUnixNS, ExpiresUnixNS                                                                                                          int64
	Outcome                                                                                                                                string
	SoulVeto, CapacityKnown                                                                                                                bool
	AutonomyDemand, EffectiveCapacity                                                                                                      uint64
	Tier, Supervision, Magnitude, Unit                                                                                                     string
	ConstraintCeiling                                                                                                                      uint64
	AllowedMarkers                                                                                                                         uint8
}

func ascii(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for i := range s {
		if s[i] < 32 || s[i] > 126 {
			return false
		}
	}
	return true
}
func id(s string) bool {
	if !ascii(s) {
		return false
	}
	for i := range s {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			continue
		}
		if i == 0 || (c != '.' && c != '_' && c != ':' && c != '-') {
			return false
		}
	}
	return true
}
func claimSyntax(c Claims) bool {
	for _, s := range []string{c.ProducerID, c.ProfileID, c.ResultKind, c.ResultID, c.ActorID, c.TenantID, c.ZoneID, c.AudienceID, c.ReplayID} {
		if !id(s) {
			return false
		}
	}
	if c.InstanceID != "" && !id(c.InstanceID) {
		return false
	}
	for _, s := range []string{c.Outcome, c.Tier, c.Supervision, c.Magnitude, c.Unit} {
		if !ascii(s) {
			return false
		}
	}
	return c.IssuedAtUnixNS > 0 && c.ExpiresUnixNS > c.IssuedAtUnixNS
}
func n64(n uint64) []byte { var b [8]byte; binary.BigEndian.PutUint64(b[:], n); return b[:] }
func boolean(b bool) []byte {
	if b {
		return []byte{1}
	}
	return []byte{0}
}
func claimFields(c Claims) [][]byte {
	instance := []byte{0}
	if c.InstanceID != "" {
		instance = append([]byte{1}, []byte(c.InstanceID)...)
	}
	return [][]byte{[]byte(c.ProducerID), []byte(c.ProfileID), []byte(c.ResultKind), []byte(c.ResultID), c.BindingDigest[:], c.OperationDigest[:], c.IdentityProjectionDigest[:], []byte(c.ActorID), []byte(c.TenantID), instance, []byte(c.ZoneID), []byte(c.AudienceID), []byte(c.ReplayID), c.CatalogDigest[:], c.PolicyDigest[:], c.GatewayBuildDigest[:], c.ProtectedConfigDigest[:], c.TargetBuildDigest[:], c.TargetContractDigest[:], c.DecisionProfileDigest[:], n64(uint64(c.IssuedAtUnixNS)), n64(uint64(c.ExpiresUnixNS)), []byte(c.Outcome), boolean(c.SoulVeto), boolean(c.CapacityKnown), n64(c.AutonomyDemand), n64(c.EffectiveCapacity), []byte(c.Tier), []byte(c.Supervision), []byte(c.Magnitude), []byte(c.Unit), n64(c.ConstraintCeiling), []byte{c.AllowedMarkers}}
}

// EncodeClaims validates syntax only. Encoding success does not authorize.
func EncodeClaims(c Claims) ([]byte, error) {
	if !claimSyntax(c) {
		return nil, ErrInvalidResult
	}
	fields := claimFields(c)
	size := 4 + len(decisionDomain)
	for _, p := range fields {
		if len(p) > MaxPayloadBytes-6-size {
			return nil, ErrInvalidResult
		}
		size += 6 + len(p)
	}
	out := make([]byte, 0, size)
	out = binary.BigEndian.AppendUint32(out, uint32(len(decisionDomain)))
	out = append(out, decisionDomain...)
	for i, p := range fields {
		out = binary.BigEndian.AppendUint16(out, uint16(i+1))
		out = binary.BigEndian.AppendUint32(out, uint32(len(p)))
		out = append(out, p...)
	}
	return out, nil
}
func decodeClaims(p []byte) (Claims, error) {
	var c Claims
	if len(p) > MaxPayloadBytes || len(p) < 4 || binary.BigEndian.Uint32(p) != uint32(len(decisionDomain)) {
		return c, ErrInvalidResult
	}
	if len(p) < 4+len(decisionDomain) || string(p[4:4+len(decisionDomain)]) != decisionDomain {
		return c, ErrInvalidResult
	}
	p = p[4+len(decisionDomain):]
	var f [33][]byte
	for i := range f {
		if len(p) < 6 || binary.BigEndian.Uint16(p) != uint16(i+1) {
			return Claims{}, ErrInvalidResult
		}
		n := binary.BigEndian.Uint32(p[2:])
		p = p[6:]
		if uint64(n) > uint64(len(p)) {
			return Claims{}, ErrInvalidResult
		}
		f[i] = p[:n]
		p = p[n:]
	}
	if len(p) != 0 {
		return Claims{}, ErrInvalidResult
	}
	c.ProducerID = string(f[0])
	c.ProfileID = string(f[1])
	c.ResultKind = string(f[2])
	c.ResultID = string(f[3])
	for i, d := range map[int]*[32]byte{4: &c.BindingDigest, 5: &c.OperationDigest, 6: &c.IdentityProjectionDigest, 13: &c.CatalogDigest, 14: &c.PolicyDigest, 15: &c.GatewayBuildDigest, 16: &c.ProtectedConfigDigest, 17: &c.TargetBuildDigest, 18: &c.TargetContractDigest, 19: &c.DecisionProfileDigest} {
		if len(f[i]) != 32 {
			return Claims{}, ErrInvalidResult
		}
		copy(d[:], f[i])
	}
	c.ActorID = string(f[7])
	c.TenantID = string(f[8])
	if len(f[9]) == 0 || f[9][0] > 1 || f[9][0] == 0 && len(f[9]) != 1 || f[9][0] == 1 && len(f[9]) < 2 {
		return Claims{}, ErrInvalidResult
	}
	if f[9][0] == 1 {
		c.InstanceID = string(f[9][1:])
	}
	c.ZoneID = string(f[10])
	c.AudienceID = string(f[11])
	c.ReplayID = string(f[12])
	for i, d := range map[int]*uint64{25: &c.AutonomyDemand, 26: &c.EffectiveCapacity, 31: &c.ConstraintCeiling} {
		if len(f[i]) != 8 {
			return Claims{}, ErrInvalidResult
		}
		*d = binary.BigEndian.Uint64(f[i])
	}
	if len(f[20]) != 8 || len(f[21]) != 8 {
		return Claims{}, ErrInvalidResult
	}
	c.IssuedAtUnixNS = int64(binary.BigEndian.Uint64(f[20]))
	c.ExpiresUnixNS = int64(binary.BigEndian.Uint64(f[21]))
	c.Outcome = string(f[22])
	for i, d := range map[int]*bool{23: &c.SoulVeto, 24: &c.CapacityKnown} {
		if len(f[i]) != 1 || f[i][0] > 1 {
			return Claims{}, ErrInvalidResult
		}
		*d = f[i][0] == 1
	}
	c.Tier = string(f[27])
	c.Supervision = string(f[28])
	c.Magnitude = string(f[29])
	c.Unit = string(f[30])
	if len(f[32]) != 1 {
		return Claims{}, ErrInvalidResult
	}
	c.AllowedMarkers = f[32][0]
	if !claimSyntax(c) {
		return Claims{}, ErrInvalidResult
	}
	canonical, e := EncodeClaims(c)
	if e != nil || !bytes.Equal(canonical, appendDomainFields(f)) {
		return Claims{}, ErrInvalidResult
	}
	return c, nil
}
func appendDomainFields(f [33][]byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(decisionDomain)))
	out = append(out, decisionDomain...)
	for i, p := range f {
		out = binary.BigEndian.AppendUint16(out, uint16(i+1))
		out = binary.BigEndian.AppendUint32(out, uint32(len(p)))
		out = append(out, p...)
	}
	return out
}
