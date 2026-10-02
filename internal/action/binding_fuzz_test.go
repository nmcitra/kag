package action

import (
	"bytes"
	"encoding/binary"
	"regexp"
	"strconv"
	"testing"
)

var contextIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
var replayPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var uintPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,19})$`)

func oracleUint(s string) (uint64, bool) {
	if !uintPattern.MatchString(s) {
		return 0, false
	}
	n, e := strconv.ParseUint(s, 10, 64)
	return n, e == nil
}

// decodeReference bounds each frame and preserves all explicit empty fields.
func decodeReference(t testing.TB, b []byte) [][]byte {
	t.Helper()
	if len(b) > 8192 {
		t.Fatal("encoding bound")
	}
	var fields [][]byte
	for pos := 0; pos < len(b); {
		if len(b)-pos < 4 {
			t.Fatal("short prefix")
		}
		n := uint64(binary.BigEndian.Uint32(b[pos : pos+4]))
		pos += 4
		if n > uint64(len(b)-pos) {
			t.Fatal("short field")
		}
		fields = append(fields, bytes.Clone(b[pos:pos+int(n)]))
		pos += int(n)
	}
	if !bytes.Equal(refFrame(fields...), b) {
		t.Fatal("reference framing roundtrip")
	}
	return fields
}
func assertBoundOracle(t testing.TB, a ParsedAction, c BindingContext, b Binding) {
	t.Helper()
	// These are modeled completeness checks, never live authority verification.
	if c.SchemaVersion != "kag-local-action-v1" || c.CatalogID != "kag-local-lab" || c.CatalogVersion != "1" || c.CatalogDigest != digestHex(t, golden(t).CatalogSHA) {
		t.Fatal("accepted catalog/schema mismatch")
	}
	for _, d := range [][32]byte{c.CatalogDigest, c.PolicyDigest, c.GatewayBuildDigest, c.ProtectedConfigDigest, c.TargetBuildDigest, c.TargetContractDigest, c.DecisionProfileDigest, c.IdentityProjectionDigest} {
		if d == ([32]byte{}) {
			t.Fatal("accepted absent modeled digest")
		}
	}
	if !c.IdentityGranularity.valid || (c.IdentityGranularity.mode != "instance-required" && c.IdentityGranularity.mode != "workload-level") {
		t.Fatal("accepted absent/unknown granularity")
	}
	p := c.TenantTarget
	if !p.valid || p.tenant != c.TenantID || p.zone != c.ZoneID || p.audience != c.AudienceID || p.target != "lab-fixture-01" {
		t.Fatal("accepted mismatched modeled admission tuple")
	}

	for _, id := range []string{c.ActorID, c.TenantID, c.ZoneID, c.AudienceID} {
		if !contextIDPattern.MatchString(id) {
			t.Fatal("accepted invalid ID")
		}
	}
	if c.InstanceID == "" {
		if c.IdentityGranularity.mode != "workload-level" {
			t.Fatal("implicit instance absence")
		}
	} else if !contextIDPattern.MatchString(c.InstanceID) {
		t.Fatal("invalid instance")
	}
	start, ok := oracleUint(c.ValidFromUnixNS)
	if !ok {
		t.Fatal("invalid start")
	}
	end, ok := oracleUint(c.ExpiresUnixNS)
	if !ok || start >= end {
		t.Fatal("invalid interval")
	}
	if _, ok = oracleUint(c.TargetVersion); !ok || !replayPattern.MatchString(c.ReplayID) {
		t.Fatal("invalid version/replay")
	}
	m, v := a.Arguments()
	_ = m
	if a.OperationID() == "lab.set_marker" && v != c.TargetVersion {
		t.Fatal("mismatched target version bound")
	}
	if !bytes.Equal(b.Operation().Bytes(), refOperation(a, c)) || !bytes.Equal(b.Bytes(), refBinding(a, c, refOperation(a, c))) {
		t.Fatal("independent operation/binding")
	}
	fields := decodeReference(t, b.Bytes())
	if len(fields) != 25 || string(fields[0]) != "KAG-LOCAL-ACTION-BINDING/v1" || string(fields[11]) != c.ActorID || string(fields[12]) != c.TenantID || string(fields[13]) != c.InstanceID || !bytes.Equal(fields[14], c.IdentityProjectionDigest[:]) || string(fields[15]) != c.ZoneID || string(fields[16]) != c.AudienceID || !bytes.Equal(fields[22], b.Operation().Bytes()) || string(fields[23]) != c.ValidFromUnixNS || string(fields[24]) != c.ExpiresUnixNS {
		t.Fatal("decoded binding fields")
	}
	op := decodeReference(t, fields[22])
	if len(op) != 11 || string(op[0]) != "KAG-LOCAL-OPERATION/v1" || string(op[9]) != c.TargetVersion || string(op[10]) != c.ReplayID || !bytes.Equal(op[7], b.Operation().Body()) {
		t.Fatal("decoded operation fields")
	}
	d := b.Digest()
	snapshot := b.Bytes()
	snapshot[0] ^= 255
	o := b.Operation()
	body := o.Body()
	if len(body) > 0 {
		body[0] ^= 255
	}
	if b.Digest() != d || !bytes.Equal(b.Bytes(), refBinding(a, c, refOperation(a, c))) {
		t.Fatal("mutation changed binding")
	}
}
func FuzzBindingContext(f *testing.F) {
	base := fixtureContext(f)
	f.Add(uint8(0), "a-1", []byte("{}"))
	f.Add(uint8(0), "a-1", []byte(`{"marker":"set","expected_version":"7"}`))
	f.Add(uint8(5), "7", []byte(` {"expected_version":"7","marker":"clear"} `))
	f.Add(uint8(5), "8", []byte(`{"marker":"clear","expected_version":"7"}`))
	f.Add(uint8(2), "", []byte(`{"marker":"clear","expected_version":"7"}`))
	f.Add(uint8(14), "workload-level", []byte(`{"marker":"clear","expected_version":"7"}`))
	for _, v := range []string{"UPPER", "a\x00b", "", string(make([]byte, 200)), "00", "18446744073709551616", "wrong-schema"} {
		f.Add(uint8(0), v, []byte(`{"marker":"clear","expected_version":"7"}`))
	}
	for _, raw := range []string{badArguments[7], `{"marker":"clear","expected_version":"7","url":"x"}`, `{"marker":"cl\u0065ar","expected_version":"7"}`, `{"marker":"clear","expected_version":"18446744073709551616"}`, markerZero + string(make([]byte, 1025))} {
		f.Add(uint8(5), "7", []byte(raw))
	}
	f.Fuzz(func(t *testing.T, field uint8, value string, raw []byte) {
		original := bytes.Clone(raw)
		tool := "lab.set_marker"
		if bytes.Equal(raw, []byte("{}")) {
			tool = "lab.read_status"
		}
		a, e := ParseMCPArguments(tool, raw)
		if e != nil {
			assertNoAction(t, a, e)
			return
		}
		assertParsedOracle(t, a, original)
		c := base
		switch field % 17 {
		case 0:
			c.ActorID = value
		case 1:
			c.TenantID = value
			c.TenantTarget, _ = NewTenantTargetProjection(c.TenantID, c.ZoneID, c.AudienceID, "lab-fixture-01")
		case 2:
			c.InstanceID = value
		case 3:
			c.ZoneID = value
			c.TenantTarget, _ = NewTenantTargetProjection(c.TenantID, c.ZoneID, c.AudienceID, "lab-fixture-01")
		case 4:
			c.AudienceID = value
			c.TenantTarget, _ = NewTenantTargetProjection(c.TenantID, c.ZoneID, c.AudienceID, "lab-fixture-01")
		case 5:
			c.TargetVersion = value
		case 6:
			c.ReplayID = value
		case 7:
			c.ValidFromUnixNS = value
		case 8:
			c.ExpiresUnixNS = value
		case 9:
			c.IdentityProjectionDigest = [32]byte{}
			if len(value) == 32 {
				copy(c.IdentityProjectionDigest[:], value)
			}
		case 10:
			c.PolicyDigest = [32]byte{}
			if len(value) == 32 {
				copy(c.PolicyDigest[:], value)
			}
		case 11:
			c.SchemaVersion = value
		case 12:
			c.CatalogVersion = value
		case 13:
			c.IdentityGranularity = IdentityGranularityProfile{}
		case 14:
			c.InstanceID = ""
			c.IdentityGranularity, _ = NewIdentityGranularityProfile(value)
			c.IdentityProjectionDigest[0] ^= 128
		case 15:
			c.TenantTarget, _ = NewTenantTargetProjection("other-tenant", c.ZoneID, c.AudienceID, "lab-fixture-01")
		case 16:
			c.CatalogDigest = [32]byte{}
			if len(value) == 32 {
				copy(c.CatalogDigest[:], value)
			}
		}
		b, e := Bind(a, c)
		again, other := Bind(a, c)
		if (e == nil) != (other == nil) || (e != nil && e.Error() != other.Error()) || b.Digest() != again.Digest() || !bytes.Equal(b.Bytes(), again.Bytes()) {
			t.Fatal("nondeterministic bind")
		}
		if e != nil {
			assertNoBinding(t, b, e)
			return
		}
		assertBoundOracle(t, a, c, b)
		if len(raw) > 0 {
			raw[0] ^= 255
		}
		value = "mutated"
		c.ActorID = value
		c.IdentityProjectionDigest[0] ^= 255
		if !bytes.Equal(a.OriginalInput(), original) || !bytes.Equal(b.Bytes(), again.Bytes()) {
			t.Fatal("source/context mutation")
		}
	})
}
