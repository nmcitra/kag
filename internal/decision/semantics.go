package decision

import (
	"bytes"
	"github.com/gatekeeper454/KTP-Component-Dev/internal/action"
)

func markerMask(o action.Operation) (uint8, error) {
	version := o.TargetVersion()
	for _, p := range []struct {
		marker string
		mask   uint8
	}{{"clear", 1}, {"set", 2}} {
		if bytes.Equal(o.Body(), []byte(`{"marker":"`+p.marker+`","expected_version":"`+version+`"}`)) {
			return p.mask, nil
		}
	}
	return 0, ErrWithheld
}
func semanticGate(c Claims, v action.BindingView, o action.Operation) error {
	if c.ProfileID != ProfileID || c.Outcome != "allow" || c.SoulVeto || !c.CapacityKnown || c.EffectiveCapacity == 0 || c.Supervision != "stable" || c.Magnitude != "fixture-effects" || c.Unit != "effects" || c.ConstraintCeiling > 1 || c.AutonomyDemand > c.EffectiveCapacity || c.AutonomyDemand > c.ConstraintCeiling || c.Tier != "Observer" && c.Tier != "Operator" {
		return ErrWithheld
	}
	switch v.OperationID {
	case "lab.read_status":
		if c.AutonomyDemand != 0 || c.AllowedMarkers != 0 {
			return ErrWithheld
		}
	case "lab.set_marker":
		m, e := markerMask(o)
		if e != nil || c.AutonomyDemand != 1 || c.Tier != "Operator" || c.AllowedMarkers == 0 || c.AllowedMarkers&^uint8(3) != 0 || c.AllowedMarkers&m == 0 {
			return ErrWithheld
		}
	default:
		return ErrWithheld
	}
	return nil
}
