package action

import (
	"bytes"
	"crypto/sha256"
	"strconv"
	"testing"
)

func TestBindingViewGolden(t *testing.T) {
	c := fixtureContext(t)
	for _, v := range golden(t).Vectors {
		a := parseVector(t, v)
		b, e := Bind(a, c)
		if e != nil {
			t.Fatal(e)
		}
		view, e := b.View()
		if e != nil {
			t.Fatal(e)
		}
		if view.ActorID != c.ActorID || view.TenantID != c.TenantID || view.InstanceID != c.InstanceID || view.IdentityProjectionDigest != c.IdentityProjectionDigest || view.IntentDigest != a.IntentDigest() || view.InputDigest != a.InputDigest() || view.SourceKind != a.SourceKind() || view.SourceMethod != a.SourceMethod() || view.SourceRoute != a.SourceRouteOrTool() || view.OperationDigest != b.Operation().Digest() || view.ReplayID != c.ReplayID || view.TargetVersion != c.TargetVersion || view.OperationID != a.OperationID() || view.TargetID != TargetID || view.PolicyDigest != c.PolicyDigest || view.CatalogDigest != CatalogDigest() {
			t.Fatal("copied view mismatch")
		}
		view.ActorID = "changed"
		next, _ := b.View()
		if next.ActorID != c.ActorID {
			t.Fatal("mutable projection")
		}
	}
}
func TestBindingViewRejectsCorruption(t *testing.T) {
	b, _ := Bind(markerAction(t, "7"), fixtureContext(t))
	cases := []Binding{{}, b}
	cases[1].encoded = bytes.Clone(b.encoded)
	cases[1].encoded[4] ^= 1
	for _, bad := range cases {
		if v, e := bad.View(); e == nil || v.ActorID != "" {
			t.Fatal("accepted bad binding")
		}
	}
	for _, mutate := range []func(*Binding){func(x *Binding) { x.digest[0] ^= 1 }, func(x *Binding) { x.encoded = append(bytes.Clone(x.encoded), 0); x.digest = sha256.Sum256(x.encoded) }, func(x *Binding) { x.operation.body = []byte(`{"marker":"set","expected_version":"7"}`) }, func(x *Binding) { x.operation.targetVersion = "8" }, func(x *Binding) { x.operation.digest[0] ^= 1 }} {
		bad := b
		mutate(&bad)
		if _, e := bad.View(); e == nil {
			t.Fatal("accepted inconsistent operation/frame")
		}
	}
}
func TestBindingViewRejectsExpectedVersionMismatch(t *testing.T) {
	c := fixtureContext(t)
	a := markerAction(t, "7")
	c.TargetVersion = "8"
	entry, _ := lookup(a.OperationID())
	o, e := buildOperation(a, entry, c)
	if e != nil {
		t.Fatal(e)
	}
	raw := refBinding(a, c, o.encoded)
	forged := Binding{encoded: raw, digest: sha256.Sum256(raw), operation: o}
	if _, e := forged.View(); e == nil {
		t.Fatal("accepted body version7 with operation version8")
	}
}
func TestBindingViewRejectsRehashedIntentInputCorruption(t *testing.T) {
	for _, vector := range golden(t).Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			b, e := Bind(parseVector(t, vector), fixtureContext(t))
			if e != nil {
				t.Fatal(e)
			}
			for _, field := range []int{17, 21} {
				t.Run(strconv.Itoa(field), func(t *testing.T) {
					bad := b
					bad.encoded = bytes.Clone(b.encoded)
					fields, e := viewFields(bad.encoded, 25)
					if e != nil {
						t.Fatal(e)
					}
					fields[field][0] ^= 1
					bad.digest = sha256.Sum256(bad.encoded)
					if _, e = bad.View(); e == nil {
						t.Fatalf("accepted rehashed corrupted field%d", field)
					}
				})
			}
		})
	}
}
