package decision

import (
	"github.com/gatekeeper454/KTP-Component-Dev/internal/action"
	"strconv"
	"testing"
)

func hash(b byte) (d [32]byte) {
	for i := range d {
		d[i] = b
	}
	return
}
func localBinding(t testing.TB, marker bool, identityDigest [32]byte, wall int64) (action.Binding, action.ParsedAction) {
	t.Helper()
	tool, raw := "lab.read_status", []byte("{}")
	if marker {
		tool = "lab.set_marker"
		raw = []byte(`{"marker":"set","expected_version":"7"}`)
	}
	a, e := action.ParseMCPArguments(tool, raw)
	if e != nil {
		t.Fatal(e)
	}
	g, _ := action.NewIdentityGranularityProfile("instance-required")
	target, _ := action.NewTenantTargetProjection("t-a", "z-1", action.TargetID, action.TargetID)
	b, e := action.Bind(a, action.BindingContext{SchemaVersion: action.SchemaVersion, CatalogID: action.CatalogID, CatalogVersion: action.CatalogVersion, CatalogDigest: action.CatalogDigest(), PolicyDigest: hash(1), GatewayBuildDigest: hash(2), ProtectedConfigDigest: hash(3), TargetBuildDigest: hash(4), TargetContractDigest: hash(5), DecisionProfileDigest: hash(6), ActorID: "a-1", TenantID: "t-a", InstanceID: "i-1", IdentityProjectionDigest: identityDigest, IdentityGranularity: g, ZoneID: "z-1", AudienceID: action.TargetID, TenantTarget: target, TargetVersion: "7", ReplayID: "0123456789abcdef0123456789abcdef", ValidFromUnixNS: strconv.FormatInt(wall-1e9, 10), ExpiresUnixNS: strconv.FormatInt(wall+4e9, 10)})
	if e != nil {
		t.Fatal(e)
	}
	return b, a
}
func TestSemanticIntersection(t *testing.T) {
	b, _ := localBinding(t, true, hash(7), 1900000000000000000)
	v, _ := b.View()
	base := Claims{ProfileID: ProfileID, Outcome: "allow", CapacityKnown: true, AutonomyDemand: 1, EffectiveCapacity: 1, Tier: "Operator", Supervision: "stable", Magnitude: "fixture-effects", Unit: "effects", ConstraintCeiling: 1, AllowedMarkers: 3}
	for _, tc := range []struct {
		name   string
		change func(*Claims)
		allow  bool
	}{{"equal", func(c *Claims) {}, true}, {"above", func(c *Claims) { c.EffectiveCapacity = 2 }, true}, {"below", func(c *Claims) { c.EffectiveCapacity = 0 }, false}, {"equal_veto", func(c *Claims) { c.SoulVeto = true }, false}, {"denial", func(c *Claims) { c.Outcome = "deny" }, false}, {"unknown_capacity", func(c *Claims) { c.CapacityKnown = false }, false}, {"wrong_demand", func(c *Claims) { c.AutonomyDemand = 0 }, false}, {"low_tier", func(c *Claims) { c.Tier = "Observer" }, false}, {"unknown_tier", func(c *Claims) { c.Tier = "Owner" }, false}, {"zero_constraint", func(c *Claims) { c.ConstraintCeiling = 0 }, false}, {"wide_constraint", func(c *Claims) { c.ConstraintCeiling = 2 }, false}, {"excluded", func(c *Claims) { c.AllowedMarkers = 1 }, false}, {"unknownmask", func(c *Claims) { c.AllowedMarkers = 6 }, false}, {"empty_mask", func(c *Claims) { c.AllowedMarkers = 0 }, false}, {"unknown_profile", func(c *Claims) { c.ProfileID = "other" }, false}, {"unknown_unit", func(c *Claims) { c.Unit = "score" }, false}, {"unknown_magnitude", func(c *Claims) { c.Magnitude = "posture" }, false}} {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.change(&c)
			if e := semanticGate(c, v, b.Operation()); (e == nil) != tc.allow {
				t.Fatal(e)
			}
		})
	}
	for _, s := range []string{"metacognitive", "assisted", "regulated", "silent_veto", "unknown"} {
		c := base
		c.Supervision = s
		if semanticGate(c, v, b.Operation()) == nil {
			t.Fatal("nonstable", s)
		}
	}
	read, _ := localBinding(t, false, hash(7), 1900000000000000000)
	rv, _ := read.View()
	c := base
	c.AutonomyDemand = 0
	c.Tier = "Observer"
	c.AllowedMarkers = 0
	if semanticGate(c, rv, read.Operation()) != nil {
		t.Fatal("read positive")
	}
	c.AllowedMarkers = 1
	if semanticGate(c, rv, read.Operation()) == nil {
		t.Fatal("read mask")
	}
}
