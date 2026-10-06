package labruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/nmcitra/kag/internal/action"
	"github.com/nmcitra/kag/internal/authn"
	"github.com/nmcitra/kag/internal/identity"
)

type RealClock struct{ start time.Time }

func (c RealClock) Sample() (identity.ClockSample, error) {
	now := time.Now()
	return identity.ClockSample{WallUnixNS: now.UnixNano(), ElapsedNS: now.Sub(c.start).Nanoseconds()}, nil
}
func digest(s string) [32]byte { return sha256.Sum256([]byte(s)) }

// Registry is an explicitly modeled, protected certificate-bound authority store.
// No caller-supplied actor, tenant or lifecycle state can select its mapping.
type Registry struct {
	actors   map[string]string
	from, to int64
}
type envelope struct {
	Query    identity.Query
	Snapshot identity.NormalizedSnapshot
}

func (r *Registry) Read(ctx context.Context, q identity.Query) ([]byte, error) {
	actor, ok := r.actors[q.PrincipalID]
	if !ok || ctx.Err() != nil {
		return nil, errors.New("unregistered_principal")
	}
	n := identity.NormalizedSnapshot{Mappings: []identity.Mapping{{TenantID: "lab-tenant", ActorID: actor, ActorKind: "agent", InstanceID: actor + "-instance", InstancePresent: true, Granularity: "instance-required", OriginID: actor, Revision: 1, ContinuityEpoch: 1}}, Lifecycle: identity.Lifecycle{Enrollment: "enrolled", Authority: "enabled", CredentialState: "valid", NodeState: "active", Revision: 1, ContinuityEpoch: 1}, Origin: identity.Origin{Mode: "direct", ID: actor}, FloorWitness: identity.FloorWitness{Current: true}}
	for _, kind := range []string{"mapping", "lifecycle", "origin", "profile"} {
		id := "lab-" + kind
		d := digest("experimental-modeled-" + kind + "-v1")
		ed := digest(actor + ":" + kind + ":revision1")
		n.Sources = append(n.Sources, identity.SourceReference{ID: id, Kind: kind, BoundID: id, ContractDigest: d, EvidenceDigest: ed, Revision: 1, ObservedUnixNS: r.from, ValidatedUnixNS: r.from, ValidFromUnixNS: r.from, ExpiresUnixNS: r.to})
		n.FloorWitness.Heads = append(n.FloorWitness.Heads, identity.Head{SourceID: id, Domain: kind, TenantID: "lab-tenant", ActorID: actor, Revision: 1, ContinuityEpoch: 1, ContentDigest: ed})
	}
	return json.Marshal(envelope{q, n})
}
func (r *Registry) Normalize(ctx context.Context, b []byte, q identity.Query) (identity.NormalizedSnapshot, error) {
	expected, e := r.Read(ctx, q)
	if e != nil || !bytes.Equal(expected, b) {
		return identity.NormalizedSnapshot{}, errors.New("registry_binding_invalid")
	}
	var env envelope
	e = json.Unmarshal(b, &env)
	return env.Snapshot, e
}
func newResolver(a *authn.Acceptor, actors map[string]string, c RealClock) (*identity.Resolver, error) {
	now := time.Now()
	r := &Registry{actors: actors, from: now.UnixNano(), to: now.Add(time.Hour).UnixNano()}
	contracts := []identity.SourceContract{}
	for _, kind := range []string{"mapping", "lifecycle", "origin", "profile"} {
		id := "lab-" + kind
		contracts = append(contracts, identity.SourceContract{ID: id, BoundID: id, ContractDigest: digest("experimental-modeled-" + kind + "-v1"), MaxAgeNS: int64(time.Hour)})
	}
	profiles := []identity.OperationProfile{}
	for _, entry := range action.CatalogEntries() {
		profiles = append(profiles, identity.OperationProfile{OperationID: entry.OperationID, AudienceID: action.TargetID, Granularity: "instance-required", HumanApplicability: "forbidden"})
	}
	return identity.NewResolver(identity.Config{Acceptor: a, Source: r, Verifier: r, Registration: identity.Registration{Lane: identity.Modeled, Sources: contracts, ProfileDigest: digest("experimental-modeled-profile-v1")}, Profiles: profiles, Clock: c, MaxSourceCalls: 32, MaxHandles: 4096, MaxHeads: 4096, MaxTombstones: 4096, SourceTimeout: time.Second, MaxClockDriftNS: int64(time.Second)})
}
