package identity

import (
	"context"
	"crypto/sha256"
	"testing"
)

func addDomain(r *Resolver, p *modelPort, kind string, revision uint64) {
	wall := r.last.WallUnixNS
	d := sha256.Sum256([]byte(kind))
	p.n.Sources = append(p.n.Sources, SourceReference{ID: kind, Kind: kind, BoundID: kind + "-age", ContractDigest: d, EvidenceDigest: d, Revision: revision, ObservedUnixNS: wall, ValidatedUnixNS: wall, ValidFromUnixNS: wall - 1, ExpiresUnixNS: wall + 30e9})
	p.n.FloorWitness.Heads = append(p.n.FloorWitness.Heads, Head{SourceID: kind, Domain: kind, TenantID: "t-a", ActorID: "a-1", Revision: revision, ContinuityEpoch: 3, ContentDigest: d})
	r.contracts[kind] = SourceContract{ID: kind, BoundID: kind + "-age", ContractDigest: d, MaxAgeNS: 20e9}
}
func terminated(r *Resolver, p *modelPort) {
	addDomain(r, p, "delegation", 1)
	wall := r.last.WallUnixNS
	p.n.Origin.Mode = "terminated"
	p.n.Origin.BrokerID = "a-1"
	p.n.DelegationRevision = 1
	p.n.Delegation = []DelegationHop{{ParentTenantID: "t-a", ParentActorID: "o-1", ChildTenantID: "t-a", ChildActorID: "a-1", AudienceID: "lab-fixture-01", ResourceID: "lab-status", Operations: []string{"lab.read_status"}, Revision: 1, ValidFromUnixNS: wall - 1, ExpiresUnixNS: wall + 30e9, SourceID: "delegation"}}
}
func TestOriginDelegationModeledPositiveAndNegatives(t *testing.T) {
	cases := []struct {
		name   string
		change func(*NormalizedSnapshot)
		want   error
	}{{"positive", func(n *NormalizedSnapshot) {}, nil}, {"cross-tenant", func(n *NormalizedSnapshot) { n.Delegation[0].ChildTenantID = "t-b" }, ErrTenantConflict}, {"missing-link", func(n *NormalizedSnapshot) { n.Delegation[0].ParentActorID = "other" }, ErrDelegationInvalid}, {"cycle", func(n *NormalizedSnapshot) { n.Delegation[0].ChildActorID = "o-1" }, ErrDelegationInvalid}, {"audience", func(n *NormalizedSnapshot) { n.Delegation[0].AudienceID = "wrong" }, ErrDelegationScope}, {"resource", func(n *NormalizedSnapshot) { n.Delegation[0].ResourceID = "wrong" }, ErrDelegationScope}, {"operation", func(n *NormalizedSnapshot) { n.Delegation[0].Operations = []string{"lab.set_marker"} }, ErrDelegationScope}, {"duplicate-op", func(n *NormalizedSnapshot) {
		n.Delegation[0].Operations = append(n.Delegation[0].Operations, "lab.read_status")
	}, ErrDelegationScope}, {"expiry", func(n *NormalizedSnapshot) { n.Delegation[0].ExpiresUnixNS = n.Sources[0].ObservedUnixNS }, ErrDelegationInvalid}, {"broker", func(n *NormalizedSnapshot) { n.Origin.BrokerID = "spoof" }, ErrOriginUnverified}, {"no-chain", func(n *NormalizedSnapshot) { n.Delegation = nil }, ErrOriginUnverified}, {"depth-nine", func(n *NormalizedSnapshot) {
		for len(n.Delegation) < 9 {
			n.Delegation = append(n.Delegation, n.Delegation[0])
		}
	}, ErrEvidenceInvalid}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, p, _, h, s := identityFixture(t)
			terminated(r, p)
			tc.change(&p.n)
			actor, e := r.Resolve(context.Background(), h, s)
			if e != tc.want || e != nil && actor.state != nil {
				t.Fatal(actor, e, tc.want)
			}
			if e == nil {
				if v, e := actor.Projection(); e != nil || v.ActorID != "a-1" || v.EvidenceLane != Modeled {
					t.Fatal(v, e)
				}
			}
		})
	}
}
func TestHumanContextIndependentRequirements(t *testing.T) {
	r, p, _, h, s := identityFixture(t)
	profile := r.profiles["lab.read_status"]
	profile.HumanApplicability = "required"
	profile.RequiredContext = []string{"inspection-label"}
	r.profiles[profile.OperationID] = profile
	if _, e := r.Resolve(context.Background(), h, s); e != ErrEvidenceInvalid {
		t.Fatal(e)
	}
	addDomain(r, p, "human", 2)
	wall := r.last.WallUnixNS
	p.n.Human = &Human{TenantID: "t-a", ID: "human-a", SourceID: "human", Revision: 2, ValidFromUnixNS: wall - 1, ExpiresUnixNS: wall + 10e9}
	if _, e := r.Resolve(context.Background(), h, s); e != ErrEvidenceInvalid {
		t.Fatal("human replaced context", e)
	}
	addDomain(r, p, "context", 1)
	p.n.Context = []ContextEntry{{Key: "inspection-label", Value: "modeled context", SourceID: "context", ValidFromUnixNS: wall - 1, ExpiresUnixNS: wall + 10e9}}
	if _, e := r.Resolve(context.Background(), h, s); e != nil {
		t.Fatal(e)
	}
	p.n.Human.TenantID = "t-b"
	if _, e := r.Resolve(context.Background(), h, s); e != ErrTenantConflict {
		t.Fatal(e)
	}
}
func TestContextOrderStableRecheck(t *testing.T) {
	r, p, _, h, s := identityFixture(t)
	addDomain(r, p, "context", 1)
	wall := r.last.WallUnixNS
	p.n.Context = []ContextEntry{{Key: "b", Value: "two", SourceID: "context", ValidFromUnixNS: wall - 1, ExpiresUnixNS: wall + 10e9}, {Key: "a", Value: "one", SourceID: "context", ValidFromUnixNS: wall - 1, ExpiresUnixNS: wall + 10e9}}
	actor, e := r.Resolve(context.Background(), h, s)
	if e != nil {
		t.Fatal(e)
	}
	p.n.Context[0], p.n.Context[1] = p.n.Context[1], p.n.Context[0]
	if _, e = r.Recheck(context.Background(), actor, s); e != nil {
		t.Fatal("canonical context ordering changed identity", e)
	}
}
