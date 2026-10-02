package identity

import "github.com/gatekeeper454/KTP-Component-Dev/internal/authn"

// wireMeasure checks the entire exact encoded footprint before any retention.
type wireMeasure struct {
	n       int
	invalid bool
}

func (m *wireMeasure) add(n int) {
	if n < 0 || n > 8192-m.n {
		m.invalid = true
		return
	}
	m.n += n
}
func (m *wireMeasure) text(s ...string) {
	for _, v := range s {
		m.add(10 + len(v))
	}
}
func measureSnapshot(n NormalizedSnapshot, t authn.TransportProjection, s ScopeProjection, p OperationProfile) (int, error) {
	if len(n.Mappings) != 1 {
		return 0, ErrEvidenceInvalid
	}
	f := wireMeasure{}
	m := n.Mappings[0]
	f.text("kag.identity-projection/v1", "kag.identity-snapshot/v1", t.TrustDomain, t.CredentialProfile, t.PrincipalID)
	f.add(76 + 14 + 70)
	f.text(m.TenantID, m.ActorID, m.ActorKind, m.Granularity)
	f.add(7)
	if m.InstancePresent {
		f.text(m.InstanceID)
	}
	f.text(n.Origin.Mode, n.Origin.ID, p.HumanApplicability)
	f.add(7)
	if h := n.Human; h != nil {
		f.text(h.TenantID, h.ID, h.SourceID)
		f.add(42)
	}
	f.add(56)
	f.text(n.Lifecycle.Enrollment, n.Lifecycle.Authority, n.Lifecycle.CredentialState, n.Lifecycle.NodeState)
	f.add(44)
	f.text(s.AudienceID, s.OperationID)
	f.add(10)
	for _, h := range n.Delegation {
		f.add(6)
		f.text(h.ParentTenantID, h.ParentActorID, h.ChildTenantID, h.ChildActorID, h.AudienceID, h.ResourceID)
		f.add(10)
		f.text(h.Operations...)
		f.add(118)
		f.text(h.SourceID)
	}
	f.add(10)
	for _, c := range n.Context {
		f.add(34)
		f.text(c.Key, c.Value, c.SourceID)
	}
	f.add(10)
	for _, r := range n.Sources {
		f.add(152)
		f.text(r.ID, r.Kind, r.BoundID, "modeled")
	}
	f.add(28)
	f.text("modeled")
	if f.invalid {
		return 0, ErrEvidenceInvalid
	}
	return f.n, nil
}
