package action

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func digestHex(t testing.TB, s string) [32]byte {
	t.Helper()
	b := unhex(t, s)
	if len(b) != 32 {
		t.Fatal("digest length")
	}
	var d [32]byte
	copy(d[:], b)
	return d
}
func fixtureContext(t testing.TB) BindingContext {
	t.Helper()
	f := golden(t)
	m := f.BindingContext
	s := func(key string) string { return m[key].(string) }
	d := func(key string) [32]byte { return digestHex(t, s(key)) }
	profile, e := NewIdentityGranularityProfile("instance-required")
	if e != nil {
		t.Fatal(e)
	}
	admission, e := NewTenantTargetProjection(s("TenantID"), s("ZoneID"), s("AudienceID"), "lab-fixture-01")
	if e != nil {
		t.Fatal(e)
	}
	return BindingContext{SchemaVersion: s("SchemaVersion"), CatalogID: s("CatalogID"), CatalogVersion: s("CatalogVersion"), CatalogDigest: d("CatalogDigest"), PolicyDigest: d("PolicyDigest"), GatewayBuildDigest: d("GatewayBuildDigest"), ProtectedConfigDigest: d("ProtectedConfigDigest"), TargetBuildDigest: d("TargetBuildDigest"), TargetContractDigest: d("TargetContractDigest"), DecisionProfileDigest: d("DecisionProfileDigest"), ActorID: s("ActorID"), TenantID: s("TenantID"), InstanceID: s("InstanceID"), IdentityProjectionDigest: d("IdentityProjectionDigest"), IdentityGranularity: profile, ZoneID: s("ZoneID"), AudienceID: s("AudienceID"), TenantTarget: admission, TargetVersion: s("TargetVersion"), ReplayID: s("ReplayID"), ValidFromUnixNS: s("ValidFromUnixNS"), ExpiresUnixNS: s("ExpiresUnixNS")}
}
func readAction(t testing.TB) ParsedAction {
	t.Helper()
	a, e := ParseMCPArguments("lab.read_status", []byte("{}"))
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func markerAction(t testing.TB, v string) ParsedAction {
	t.Helper()
	a, e := ParseMCPArguments("lab.set_marker", []byte(`{"marker":"clear","expected_version":"`+v+`"}`))
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func assertNoBinding(t testing.TB, b Binding, e error) {
	t.Helper()
	if e == nil || len(b.Bytes()) != 0 || b.Digest() != ([32]byte{}) || len(b.Operation().Bytes()) != 0 || b.Operation().OperationID() != "" {
		t.Fatal("usable failed binding", e)
	}
}

// refOperation/refBinding encode expected fields without production encoders.
func refOperation(a ParsedAction, c BindingContext) []byte {
	e, _ := LookupOperation(a.OperationID())
	m, v := a.Arguments()
	body := []byte{}
	ctype, precondition := "", "none"
	if a.OperationID() == "lab.set_marker" {
		body = []byte(`{"marker":"` + m + `","expected_version":"` + v + `"}`)
		ctype = "application/json"
		precondition = "match"
	}
	out := refStrings("KAG-LOCAL-OPERATION/v1", e.OperationID, "lab-fixture-01", e.ResourceID, e.Method, e.Path, ctype)
	out = append(out, refFrame(body)...)
	return append(out, refStrings(precondition, c.TargetVersion, c.ReplayID)...)
}
func refBinding(a ParsedAction, c BindingContext, operation []byte) []byte {
	out := refStrings("KAG-LOCAL-ACTION-BINDING/v1", c.SchemaVersion, c.CatalogID, c.CatalogVersion)
	for _, d := range [][32]byte{c.CatalogDigest, c.PolicyDigest, c.GatewayBuildDigest, c.ProtectedConfigDigest, c.TargetBuildDigest, c.TargetContractDigest, c.DecisionProfileDigest} {
		out = append(out, refFrame(d[:])...)
	}
	out = append(out, refStrings(c.ActorID, c.TenantID, c.InstanceID)...)
	out = append(out, refFrame(c.IdentityProjectionDigest[:])...)
	out = append(out, refStrings(c.ZoneID, c.AudienceID)...)
	intent, input := a.IntentDigest(), a.InputDigest()
	out = append(out, refFrame(intent[:])...)
	out = append(out, refStrings(a.SourceKind(), a.SourceMethod(), a.SourceRouteOrTool())...)
	out = append(out, refFrame(input[:], operation)...)
	return append(out, refStrings(c.ValidFromUnixNS, c.ExpiresUnixNS)...)
}
func TestOperationBindingGolden(t *testing.T) {
	c := fixtureContext(t)
	for _, v := range golden(t).Vectors {
		t.Run(v.Name, func(t *testing.T) {
			a := parseVector(t, v)
			b, e := Bind(a, c)
			if e != nil {
				t.Fatal(e)
			}
			o := b.Operation()
			checkBytesSHA(t, o.Bytes(), v.OperationHex, v.OperationSHA)
			checkBytesSHA(t, b.Bytes(), v.BindingHex, v.BindingSHA)
			if o.Digest() != sha256.Sum256(o.Bytes()) || b.Digest() != sha256.Sum256(b.Bytes()) {
				t.Fatal("digest accessors")
			}
			if !bytes.Equal(o.Bytes(), refOperation(a, c)) || !bytes.Equal(b.Bytes(), refBinding(a, c, refOperation(a, c))) {
				t.Fatal("reference bytes")
			}
			if o.OperationID() != v.OperationID || o.TargetID() != "lab-fixture-01" || o.TargetVersion() != c.TargetVersion || o.ReplayID() != c.ReplayID {
				t.Fatal("operation metadata")
			}
			if v.OperationID == "lab.read_status" {
				if len(o.Body()) != 0 || o.ContentType() != "" || o.PreconditionKind() != "none" || o.Method() != "GET" || o.Path() != "/lab/status" || o.ResourceID() != "lab-status" {
					t.Fatal("read operation")
				}
			} else {
				if string(o.Body()) != `{"marker":"set","expected_version":"7"}` || o.ContentType() != "application/json" || o.PreconditionKind() != "match" || o.Method() != "POST" || o.Path() != "/lab/marker" || o.ResourceID() != "lab-marker" {
					t.Fatal("marker operation")
				}
			}
		})
	}
}
func TestBindingPerField(t *testing.T) {
	a := readAction(t)
	original := fixtureContext(t)
	base, e := Bind(a, original)
	if e != nil {
		t.Fatal(e)
	}
	changes := map[string]func(*BindingContext){
		"actor": func(c *BindingContext) { c.ActorID = "a-2" }, "tenant": func(c *BindingContext) {
			c.TenantID = "t-b"
			c.TenantTarget, _ = NewTenantTargetProjection(c.TenantID, c.ZoneID, c.AudienceID, "lab-fixture-01")
		}, "instance": func(c *BindingContext) { c.InstanceID = "i-2" }, "identity": func(c *BindingContext) { c.IdentityProjectionDigest[0] ^= 128 }, "zone": func(c *BindingContext) {
			c.ZoneID = "z-2"
			c.TenantTarget, _ = NewTenantTargetProjection(c.TenantID, c.ZoneID, c.AudienceID, "lab-fixture-01")
		}, "audience": func(c *BindingContext) {
			c.AudienceID = "aud-2"
			c.TenantTarget, _ = NewTenantTargetProjection(c.TenantID, c.ZoneID, c.AudienceID, "lab-fixture-01")
		}, "policy": func(c *BindingContext) { c.PolicyDigest[0] ^= 128 }, "gateway": func(c *BindingContext) { c.GatewayBuildDigest[0] ^= 128 }, "config": func(c *BindingContext) { c.ProtectedConfigDigest[0] ^= 128 }, "targetbuild": func(c *BindingContext) { c.TargetBuildDigest[0] ^= 128 }, "targetcontract": func(c *BindingContext) { c.TargetContractDigest[0] ^= 128 }, "decision": func(c *BindingContext) { c.DecisionProfileDigest[0] ^= 128 }, "targetversion": func(c *BindingContext) { c.TargetVersion = "8" }, "replay": func(c *BindingContext) { c.ReplayID = "fedcba9876543210fedcba9876543210" }, "start": func(c *BindingContext) { c.ValidFromUnixNS = "1899999999999999999" }, "expiry": func(c *BindingContext) { c.ExpiresUnixNS = "1900000005000000001" },
	}
	for name, f := range changes {
		t.Run(name, func(t *testing.T) {
			c := original
			f(&c)
			b, e := Bind(a, c)
			if e != nil {
				t.Fatal(e)
			}
			wantOperation := refOperation(a, c)
			want := refBinding(a, c, wantOperation)
			if !bytes.Equal(b.Bytes(), want) || !bytes.Equal(b.Operation().Bytes(), wantOperation) || bytes.Equal(b.Bytes(), base.Bytes()) || b.Digest() == base.Digest() {
				t.Fatal("field bytes/digest")
			}
			if a.IntentDigest() != readAction(t).IntentDigest() {
				t.Fatal("identity changed pre-resolution intent")
			}
		})
	}
	for _, name := range []string{"schema", "catalogid", "catalogversion", "catalogdigest"} {
		c := original
		switch name {
		case "schema":
			c.SchemaVersion = "kag-local-action-v2"
		case "catalogid":
			c.CatalogID = "other"
		case "catalogversion":
			c.CatalogVersion = "2"
		case "catalogdigest":
			c.CatalogDigest[0] ^= 1
		}
		b, e := Bind(a, c)
		assertNoBinding(t, b, e)
		if e != ErrVersionMismatch {
			t.Fatal("dependency version category", name, e)
		}
	}
}
func TestBindingContextNegatives(t *testing.T) {
	good := fixtureContext(t)
	a := readAction(t)
	for _, field := range []string{"ActorID", "TenantID", "InstanceID", "ZoneID", "AudienceID"} {
		for _, value := range []string{"", "UPPER", "x y", "x\x00y", "é", strings.Repeat("a", 129), ".first"} {
			t.Run(field+fmt.Sprintf("-%q", value), func(t *testing.T) {
				c := good
				reflect.ValueOf(&c).Elem().FieldByName(field).SetString(value)
				b, e := Bind(a, c)
				assertNoBinding(t, b, e)
			})
		}
	}
	for _, field := range []string{"CatalogDigest", "PolicyDigest", "GatewayBuildDigest", "ProtectedConfigDigest", "TargetBuildDigest", "TargetContractDigest", "DecisionProfileDigest", "IdentityProjectionDigest"} {
		t.Run(field, func(t *testing.T) {
			c := good
			reflect.ValueOf(&c).Elem().FieldByName(field).Set(reflect.ValueOf([32]byte{}))
			b, e := Bind(a, c)
			assertNoBinding(t, b, e)
		})
	}
	changes := map[string]func(*BindingContext){"zero": func(c *BindingContext) { *c = BindingContext{} }, "profile": func(c *BindingContext) { c.IdentityGranularity = IdentityGranularityProfile{} }, "admission": func(c *BindingContext) { c.TenantTarget = TenantTargetProjection{} }, "tenantmismatch": func(c *BindingContext) { c.TenantID = "t-other" }, "zonemismatch": func(c *BindingContext) { c.ZoneID = "z-other" }, "audiencemismatch": func(c *BindingContext) { c.AudienceID = "a-other" }, "startend": func(c *BindingContext) { c.ExpiresUnixNS = c.ValidFromUnixNS }, "endbefore": func(c *BindingContext) { c.ExpiresUnixNS = "1" }}
	for name, f := range changes {
		t.Run(name, func(t *testing.T) { c := good; f(&c); b, e := Bind(a, c); assertNoBinding(t, b, e) })
	}
	for _, field := range []string{"TargetVersion", "ValidFromUnixNS", "ExpiresUnixNS"} {
		for _, value := range []string{"", "00", "-1", "+1", "1e2", "1.0", " 1", "18446744073709551616", strings.Repeat("1", 200)} {
			c := good
			reflect.ValueOf(&c).Elem().FieldByName(field).SetString(value)
			b, e := Bind(a, c)
			assertNoBinding(t, b, e)
		}
	}
	for _, value := range []string{"", strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("G", 32), strings.Repeat("A", 32), strings.Repeat("0", 31) + "\x00"} {
		c := good
		c.ReplayID = value
		b, e := Bind(a, c)
		assertNoBinding(t, b, e)
	}
}
func TestBindingProjectionConstructorsAndGranularity(t *testing.T) {
	for _, mode := range []string{"", "instance", "workload", "allow", "WORKLOAD-LEVEL"} {
		p, e := NewIdentityGranularityProfile(mode)
		if e == nil || p != (IdentityGranularityProfile{}) {
			t.Fatal("invalid profile", mode)
		}
	}
	for _, args := range [][4]string{{"", "z", "a", "lab-fixture-01"}, {"t", "Z", "a", "lab-fixture-01"}, {"t", "z", "a", "other-target"}, {"t", "z", "a", ""}, {strings.Repeat("x", 129), "z", "a", "lab-fixture-01"}} {
		p, e := NewTenantTargetProjection(args[0], args[1], args[2], args[3])
		if e == nil || p != (TenantTargetProjection{}) {
			t.Fatal("invalid projection")
		}
	}
	c := fixtureContext(t)
	c.InstanceID = ""
	a := readAction(t)
	b, e := Bind(a, c)
	assertNoBinding(t, b, e)
	c.IdentityGranularity, e = NewIdentityGranularityProfile("workload-level")
	if e != nil {
		t.Fatal(e)
	}
	c.IdentityProjectionDigest[0] ^= 128
	b, e = Bind(a, c)
	if e != nil {
		t.Fatal("explicit workload applicability", e)
	}
	if !bytes.Equal(b.Bytes(), refBinding(a, c, refOperation(a, c))) {
		t.Fatal("empty instance not explicit S empty")
	}
	a = markerAction(t, "7")
	if _, e = Bind(a, c); e != nil {
		t.Fatal("catalog allows both operations", e)
	}
	// With instance-level attribution, the largest admitted grammar field remains exact.
	c = fixtureContext(t)
	c.ActorID = strings.Repeat("a", 128)
	if _, e = Bind(readAction(t), c); e != nil {
		t.Fatal("128-byte context field", e)
	}
}
func TestBindingActionRevalidation(t *testing.T) {
	c := fixtureContext(t)
	b, e := Bind(ParsedAction{}, c)
	assertNoBinding(t, b, e)
	changes := map[string]func(*ParsedAction){"valid": func(a *ParsedAction) { a.valid = false }, "id": func(a *ParsedAction) { a.operationID = "unknown" }, "sourcekind": func(a *ParsedAction) { a.sourceKind = "http-ish" }, "sourcemethod": func(a *ParsedAction) { a.sourceMethod = "POST" }, "sourceroute": func(a *ParsedAction) { a.sourceRoute = "lab.set_marker" }, "input": func(a *ParsedAction) { a.input = []byte("{ }") }, "inputdigest": func(a *ParsedAction) { a.inputDigest[0] ^= 1 }, "intent": func(a *ParsedAction) { a.intent = []byte("different") }, "intentdigest": func(a *ParsedAction) { a.intentDigest[0] ^= 1 }, "marker": func(a *ParsedAction) { a.marker = "set" }, "version": func(a *ParsedAction) { a.expectedVersion = "7" }, "oversize": func(a *ParsedAction) { a.input = make([]byte, 1025) }, "longtyped": func(a *ParsedAction) { a.marker = strings.Repeat("x", 100000) }}
	for name, f := range changes {
		t.Run(name, func(t *testing.T) { a := readAction(t); f(&a); b, e := Bind(a, c); assertNoBinding(t, b, e) })
	}
	a := markerAction(t, "0")
	b, e = Bind(a, c)
	assertNoBinding(t, b, e)
	if e != ErrVersionMismatch {
		t.Fatal("version mismatch category", e)
	}
	c.TargetVersion = "0"
	b, e = Bind(a, c)
	if e != nil || string(b.Operation().Body()) != markerZero {
		t.Fatal("marker zero bind", e)
	}
	c.TargetVersion = "18446744073709551615"
	a = markerAction(t, c.TargetVersion)
	if _, e = Bind(a, c); e != nil {
		t.Fatal("max version bind", e)
	}
}
func TestBindingOwnershipAndByteScope(t *testing.T) {
	c := fixtureContext(t)
	a := markerAction(t, "7")
	b, e := Bind(a, c)
	if e != nil {
		t.Fatal(e)
	}
	origB, origO, origBody := b.Bytes(), b.Operation().Bytes(), b.Operation().Body()
	d := b.Digest()
	c.ActorID = "changed"
	c.PolicyDigest[0] ^= 255
	bs := b.Bytes()
	bs[0] ^= 255
	o := b.Operation()
	os := o.Bytes()
	os[0] ^= 255
	body := o.Body()
	body[0] ^= 255
	if b.Digest() != d || !bytes.Equal(b.Bytes(), origB) || !bytes.Equal(b.Operation().Bytes(), origO) || !bytes.Equal(b.Operation().Body(), origBody) {
		t.Fatal("binding ownership")
	}
	f := golden(t)
	v := f.Vectors[2]
	w := f.Vectors[3]
	x := f.Vectors[4]
	c = fixtureContext(t)
	ba, e := Bind(parseVector(t, v), c)
	if e != nil {
		t.Fatal(e)
	}
	bb, e := Bind(parseVector(t, w), c)
	if e != nil {
		t.Fatal(e)
	}
	bc, e := Bind(parseVector(t, x), c)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(ba.Operation().Bytes(), bb.Operation().Bytes()) || !bytes.Equal(bb.Operation().Bytes(), bc.Operation().Bytes()) || ba.Digest() == bb.Digest() || bb.Digest() == bc.Digest() {
		t.Fatal("input/source scope separate from operation")
	}
}
func TestBindingConcurrentReads(t *testing.T) {
	c := fixtureContext(t)
	a := markerAction(t, "7")
	want, e := Bind(a, c)
	if e != nil {
		t.Fatal(e)
	}
	wb, wd := want.Bytes(), want.Digest()
	var wg sync.WaitGroup
	errCh := make(chan string, 16)
	for j := 0; j < 16; j++ {
		wg.Go(func() {
			for i := 0; i < 40; i++ {
				b, e := Bind(a, c)
				if e != nil || b.Digest() != wd || !bytes.Equal(b.Bytes(), wb) {
					errCh <- "bind"
					return
				}
				snapshot := CatalogEntries()
				snapshot[1].Markers[0] = "mutated"
				body := b.Operation().Body()
				body[0] ^= 255
				if !bytes.Equal(b.Bytes(), wb) {
					errCh <- "ownership"
					return
				}
			}
		})
	}
	wg.Wait()
	close(errCh)
	for e := range errCh {
		t.Fatal(e)
	}
}
func TestBindingEncodingBound(t *testing.T) {
	f := frame{}
	f.lp(make([]byte, 8192))
	if f.err != ErrInputLimit || len(f.b) != 0 {
		t.Fatal("oversize addition retained")
	}
	f = frame{}
	f.lp(make([]byte, 8188))
	if f.err != nil || len(f.b) != 8192 {
		t.Fatal("exact encoding bound")
	}
	f.s("")
	if f.err != ErrInputLimit || len(f.b) != 8192 {
		t.Fatal("aggregate bound")
	}
	// The literal digest artifact is readable without any production serializer.
	if _, e := hex.DecodeString(golden(t).CatalogSHA); e != nil {
		t.Fatal(e)
	}
}
