package identity

import (
	"crypto/sha256"
	"encoding/json"
	"github.com/nmcitra/kag/internal/action"
	"github.com/nmcitra/kag/internal/authn"
	"math"
	"unicode/utf8"
)

func (r *Resolver) validate(n NormalizedSnapshot, t authn.TransportProjection, s ScopeProjection, p OperationProfile, now, rawNow int64) (int64, int64, error, error) {
	if len(n.Mappings) == 0 {
		return 0, 0, nil, ErrMappingMissing
	}
	if len(n.Mappings) != 1 {
		return 0, 0, nil, ErrMappingAmbiguous
	}
	m := n.Mappings[0]
	if !validID(m.TenantID) || !validID(m.ActorID) || !validID(m.ActorKind) || !validID(m.OriginID) || m.Revision == 0 || m.ContinuityEpoch == 0 {
		return 0, 0, nil, ErrEvidenceInvalid
	}
	if m.Granularity != p.Granularity {
		return 0, 0, nil, ErrInstanceUnattributed
	}
	if m.InstancePresent {
		if !validID(m.InstanceID) {
			return 0, 0, nil, ErrInstanceUnattributed
		}
	} else if m.InstanceID != "" || m.Granularity != "workload-level" {
		return 0, 0, nil, ErrInstanceUnattributed
	}
	l := n.Lifecycle
	if l.Revision == 0 || l.ContinuityEpoch != m.ContinuityEpoch {
		return 0, 0, nil, ErrContinuityConflict
	}
	var eligible error
	switch l.Enrollment {
	case "enrolled", "reenrolled":
	case "pending", "unknown", "removed":
		eligible = ErrActorPending
	default:
		return 0, 0, nil, ErrEvidenceInvalid
	}
	switch l.Authority {
	case "enabled":
	case "disabled":
		eligible = ErrActorDisabled
	case "deleted":
		eligible = ErrActorDeleted
	default:
		return 0, 0, nil, ErrEvidenceInvalid
	}
	switch l.CredentialState {
	case "valid":
	case "expired", "revoked", "unknown":
		eligible = ErrCredentialExpired
	default:
		return 0, 0, nil, ErrEvidenceInvalid
	}
	switch l.NodeState {
	case "active":
	case "removed", "selector-changed", "unknown":
		eligible = ErrNodeRemoved
	default:
		return 0, 0, nil, ErrEvidenceInvalid
	}
	if l.Authority == "deleted" {
		eligible = ErrActorDeleted
	}
	if len(n.Sources) == 0 || len(n.Sources) > 8 {
		return 0, 0, nil, ErrEvidenceInvalid
	}
	from, to := t.TrustValidFromUnixNS, t.TrustExpiresUnixNS
	if t.AuthenticatedUnixNS > from {
		from = t.AuthenticatedUnixNS
	}
	for _, expiry := range []int64{t.CredentialExpiresUnixNS, t.SessionExpiresUnixNS} {
		if expiry < to {
			to = expiry
		}
	}
	bounds := func(start, end int64) bool {
		if start <= 0 || end <= start || rawNow < start || now >= end {
			return false
		}
		if start > from {
			from = start
		}
		if end < to {
			to = end
		}
		return true
	}
	refs := map[string]SourceReference{}
	kinds := map[string]SourceReference{}
	for _, ref := range n.Sources {
		if !validID(ref.ID) || !validID(ref.Kind) || !validID(ref.BoundID) || ref.Revision == 0 || !nonzero(ref.ContractDigest) || !nonzero(ref.EvidenceDigest) {
			return 0, 0, nil, ErrEvidenceInvalid
		}
		if _, dup := refs[ref.ID]; dup {
			return 0, 0, nil, ErrEvidenceInvalid
		}
		contract, ok := r.contracts[ref.ID]
		if !ok || contract.ContractDigest != ref.ContractDigest || contract.BoundID != ref.BoundID {
			return 0, 0, nil, ErrContractIncompatible
		}
		if ref.ObservedUnixNS <= 0 || ref.ValidatedUnixNS < ref.ObservedUnixNS || ref.ObservedUnixNS > math.MaxInt64-contract.MaxAgeNS {
			return 0, 0, nil, ErrSourceStale
		}
		if ref.ObservedUnixNS > rawNow && ref.ObservedUnixNS-rawNow > r.config.AllowedFutureSkewNS || ref.ValidatedUnixNS > rawNow && ref.ValidatedUnixNS-rawNow > r.config.AllowedFutureSkewNS {
			return 0, 0, nil, ErrSourceStale
		}
		if !bounds(ref.ValidFromUnixNS, ref.ExpiresUnixNS) || now >= ref.ObservedUnixNS+contract.MaxAgeNS {
			return 0, 0, nil, ErrSourceStale
		}
		if age := ref.ObservedUnixNS + contract.MaxAgeNS; age < to {
			to = age
		}
		refs[ref.ID] = ref
		if _, dup := kinds[ref.Kind]; dup {
			return 0, 0, nil, ErrEvidenceInvalid
		}
		kinds[ref.Kind] = ref
	}
	for _, kind := range []string{"mapping", "lifecycle", "origin", "profile"} {
		if _, ok := kinds[kind]; !ok {
			return 0, 0, nil, ErrEvidenceInvalid
		}
	}
	if kinds["mapping"].Revision != m.Revision || kinds["lifecycle"].Revision != l.Revision {
		return 0, 0, nil, ErrContinuityConflict
	}
	if kinds["profile"].ContractDigest != r.config.Registration.ProfileDigest {
		return 0, 0, nil, ErrContractIncompatible
	}
	if n.Human == nil {
		if p.HumanApplicability == "required" {
			return 0, 0, nil, ErrEvidenceInvalid
		}
	} else {
		h := n.Human
		if p.HumanApplicability == "forbidden" || h.TenantID != m.TenantID {
			return 0, 0, nil, ErrTenantConflict
		}
		ref, ok := refs[h.SourceID]
		if !validID(h.ID) || !validID(h.TenantID) || h.Revision == 0 || !ok || ref.Kind != "human" || ref.Revision != h.Revision || !bounds(h.ValidFromUnixNS, h.ExpiresUnixNS) {
			return 0, 0, nil, ErrEvidenceInvalid
		}
	}
	contexts := map[string]bool{}
	for _, c := range n.Context {
		ref, ok := refs[c.SourceID]
		if !validID(c.Key) || !ok || ref.Kind != "context" || len(c.Value) > 256 || !utf8.ValidString(c.Value) || contexts[c.Key] || !bounds(c.ValidFromUnixNS, c.ExpiresUnixNS) {
			return 0, 0, nil, ErrEvidenceInvalid
		}
		contexts[c.Key] = true
	}
	for _, key := range p.RequiredContext {
		if !contexts[key] {
			return 0, 0, nil, ErrEvidenceInvalid
		}
	}
	if n.Origin.ID != m.OriginID || !validID(n.Origin.ID) {
		return 0, 0, nil, ErrOriginUnverified
	}
	switch n.Origin.Mode {
	case "direct":
		if len(n.Delegation) != 0 || n.Origin.BrokerID != "" || nonzero(n.Origin.OriginalIntentDigest) || nonzero(n.Origin.BrokerConnectionDigest) {
			return 0, 0, nil, ErrOriginUnverified
		}
	case "terminated":
		if len(n.Delegation) == 0 || n.DelegationRevision == 0 || n.Origin.BrokerID != m.ActorID || n.Origin.OriginalIntentDigest != s.IntentDigest || n.Origin.BrokerConnectionDigest != t.ConnectionDigest {
			return 0, 0, nil, ErrOriginUnverified
		}
		entry, _ := action.LookupOperation(s.OperationID)
		parent := n.Origin.ID
		seen := map[string]bool{parent: true}
		var previous map[string]bool
		for _, h := range n.Delegation {
			if h.ParentTenantID != m.TenantID || h.ChildTenantID != m.TenantID {
				return 0, 0, nil, ErrTenantConflict
			}
			if !validID(h.ParentActorID) || !validID(h.ChildActorID) || h.ParentActorID != parent || seen[h.ChildActorID] || h.Revision == 0 {
				return 0, 0, nil, ErrDelegationInvalid
			}
			ref, ok := refs[h.SourceID]
			if !ok || ref.Kind != "delegation" || h.Revision != ref.Revision || !bounds(h.ValidFromUnixNS, h.ExpiresUnixNS) {
				return 0, 0, nil, ErrDelegationInvalid
			}
			if h.AudienceID != s.AudienceID || h.ResourceID != entry.ResourceID || h.OriginalIntentDigest != s.IntentDigest || h.BrokerConnectionDigest != t.ConnectionDigest || len(h.Operations) == 0 || len(h.Operations) > 16 {
				return 0, 0, nil, ErrDelegationScope
			}
			allowed := map[string]bool{}
			for _, op := range h.Operations {
				if _, ok := action.LookupOperation(op); !ok || allowed[op] || previous != nil && !previous[op] {
					return 0, 0, nil, ErrDelegationScope
				}
				allowed[op] = true
			}
			if !allowed[s.OperationID] {
				return 0, 0, nil, ErrDelegationScope
			}
			seen[h.ChildActorID] = true
			parent = h.ChildActorID
			previous = allowed
		}
		if parent != m.ActorID {
			return 0, 0, nil, ErrDelegationInvalid
		}
	default:
		return 0, 0, nil, ErrOriginUnverified
	}
	if !n.FloorWitness.Current || len(n.FloorWitness.Heads) != len(refs) {
		return 0, 0, nil, ErrRestoreUnreconciled
	}
	heads := map[string]bool{}
	for _, h := range n.FloorWitness.Heads {
		ref, ok := refs[h.SourceID]
		if !ok || heads[h.SourceID] || h.Domain != ref.Kind || h.TenantID != m.TenantID || h.ActorID != m.ActorID || h.ContinuityEpoch != m.ContinuityEpoch || h.Revision != ref.Revision || h.ContentDigest != ref.EvidenceDigest {
			return 0, 0, nil, ErrRestoreUnreconciled
		}
		heads[h.SourceID] = true
	}
	if rawNow < from || now >= to {
		return 0, 0, nil, ErrSourceStale
	}
	return from, to, eligible, nil
}
func semantic(n NormalizedSnapshot, h Head) [32]byte {
	var v any
	switch h.Domain {
	case "mapping":
		v = n.Mappings[0]
	case "lifecycle":
		v = n.Lifecycle
	case "origin":
		v = n.Origin
	case "human":
		v = n.Human
	case "delegation":
		v = n.Delegation
	case "context":
		v = n.Context
	default:
		v = h.ContentDigest
	}
	b, _ := json.Marshal(v)
	return sha256.Sum256(b)
}

// commit atomically reserves all retained keys and remembers known invalidation
// even when the well-formed observation cannot admit an actor.
func (r *Resolver) commit(n NormalizedSnapshot, eligibility error) error {
	if r.capacityFailed {
		r.holdLocked()
		return ErrBusy
	}
	m := n.Mappings[0]
	key := actorKey{m.TenantID, m.ActorID}
	newKeys := 0
	newer := false
	incoming := map[headKey]storedHead{}
	for _, h := range n.FloorWitness.Heads {
		k := headKey{h.SourceID, h.Domain, h.TenantID, h.ActorID}
		s := storedHead{h, semantic(n, h)}
		incoming[k] = s
		if old, ok := r.heads[k]; ok {
			if h.ContinuityEpoch < old.head.ContinuityEpoch || h.ContinuityEpoch == old.head.ContinuityEpoch && h.Revision < old.head.Revision {
				r.holdLocked()
				return ErrRevisionRollback
			}
			if h.ContinuityEpoch == old.head.ContinuityEpoch && h.Revision == old.head.Revision && (h.ContentDigest != old.head.ContentDigest || s.semantic != old.semantic) {
				r.holdLocked()
				return ErrContinuityConflict
			}
			if h.ContinuityEpoch > old.head.ContinuityEpoch || h.Revision > old.head.Revision {
				newer = true
			}
		} else {
			newKeys++
		}
	}
	if len(r.heads)+newKeys > r.config.MaxHeads {
		r.capacityFailed = true
		r.holdLocked()
		return ErrBusy
	}
	if old, exists := r.tombstones[key]; exists {
		if n.Lifecycle.Enrollment != "reenrolled" || m.ContinuityEpoch <= old.ContinuityEpoch || n.Lifecycle.Revision <= old.Revision {
			r.holdLocked()
			return ErrContinuityConflict
		}
	}
	if n.Lifecycle.Authority == "deleted" {
		if _, exists := r.tombstones[key]; !exists && len(r.tombstones) >= r.config.MaxTombstones {
			r.capacityFailed = true
			r.holdLocked()
			return ErrBusy
		}
	}
	for k, h := range incoming {
		r.heads[k] = h
	}
	if newer || eligibility != nil {
		r.generations[key]++
		for s := range r.handles {
			if s.key == key {
				s.valid = false
				delete(r.handles, s)
			}
		}
	}
	if n.Lifecycle.Authority == "deleted" {
		r.tombstones[key] = Head{TenantID: m.TenantID, ActorID: m.ActorID, Revision: n.Lifecycle.Revision, ContinuityEpoch: m.ContinuityEpoch}
	}
	r.restored = true
	r.held = false
	return nil
}
func (r *Resolver) holdLocked() {
	r.held = true
	for s := range r.handles {
		s.valid = false
		delete(r.handles, s)
	}
}
