// Package identity implements scope-bound modeled identity admission, not live supplier qualification.
package identity

import (
	"context"
	"crypto/sha256"
	"github.com/nmcitra/kag/internal/action"
	"github.com/nmcitra/kag/internal/authn"
	"time"
)

type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrTransportInvalid      Error = "transport_invalid"
	ErrCredentialExpired     Error = "credential_expired"
	ErrScopeInvalid          Error = "scope_invalid"
	ErrMappingMissing        Error = "mapping_missing"
	ErrMappingAmbiguous      Error = "mapping_ambiguous"
	ErrTenantConflict        Error = "tenant_conflict"
	ErrInstanceUnattributed  Error = "instance_unattributed"
	ErrOriginUnverified      Error = "origin_unverified"
	ErrActorPending          Error = "actor_pending"
	ErrActorDisabled         Error = "actor_disabled"
	ErrActorDeleted          Error = "actor_deleted"
	ErrNodeRemoved           Error = "node_removed"
	ErrDelegationInvalid     Error = "delegation_invalid"
	ErrDelegationScope       Error = "delegation_scope"
	ErrPermissionUnavailable Error = "permission_unavailable"
	ErrEvidenceInvalid       Error = "evidence_invalid"
	ErrSourceStale           Error = "source_stale"
	ErrSourceUnavailable     Error = "source_unavailable"
	ErrBusy                  Error = "busy"
	ErrCanceled              Error = "canceled"
	ErrDeadlineExceeded      Error = "deadline_exceeded"
	ErrClockUncertain        Error = "clock_uncertain"
	ErrRevisionRollback      Error = "revision_rollback"
	ErrContinuityConflict    Error = "continuity_conflict"
	ErrSnapshotChanged       Error = "snapshot_changed"
	ErrForeignHandle         Error = "foreign_handle"
	ErrContractIncompatible  Error = "contract_incompatible"
	ErrRestoreUnreconciled   Error = "restore_unreconciled"
)

type EvidenceLane uint8

const Modeled EvidenceLane = 1

type ClockSample struct{ WallUnixNS, ElapsedNS, UncertaintyNS int64 }
type Clock interface{ Sample() (ClockSample, error) }
type Query struct {
	TrustDomain, CredentialProfile, PrincipalID string
	ConnectionDigest, IntentDigest              [32]byte
	AudienceID, OperationID                     string
}
type Source interface {
	Read(context.Context, Query) ([]byte, error)
}
type Verifier interface {
	Normalize(context.Context, []byte, Query) (NormalizedSnapshot, error)
}
type SourceContract struct {
	ID, BoundID    string
	ContractDigest [32]byte
	MaxAgeNS       int64
}
type Registration struct {
	Lane          EvidenceLane
	Sources       []SourceContract
	ProfileDigest [32]byte
}
type OperationProfile struct {
	OperationID, AudienceID, Granularity, HumanApplicability string
	RequiredContext                                          []string
}
type Config struct {
	Acceptor                                                    *authn.Acceptor
	Source                                                      Source
	Verifier                                                    Verifier
	Registration                                                Registration
	Profiles                                                    []OperationProfile
	Clock                                                       Clock
	MaxSourceCalls, MaxHandles, MaxHeads, MaxTombstones         int
	SourceTimeout                                               time.Duration
	MaxClockUncertaintyNS, AllowedFutureSkewNS, MaxClockDriftNS int64
}
type ResolveScope struct {
	projection ScopeProjection
	valid      bool
}
type ScopeProjection struct {
	AudienceID, OperationID string
	IntentDigest            [32]byte
}

func NewResolveScope(a action.ParsedAction, audience string) (ResolveScope, error) {
	e, ok := action.LookupOperation(a.OperationID())
	intent, input := a.IntentBytes(), a.OriginalInput()
	if !ok || audience != action.TargetID || audience != e.TargetID || len(intent) == 0 || len(intent) > 8192 || len(input) > action.MaxArgumentBytes || a.IntentDigest() == ([32]byte{}) || a.InputDigest() == ([32]byte{}) || sha256.Sum256(intent) != a.IntentDigest() || sha256.Sum256(input) != a.InputDigest() {
		return ResolveScope{}, ErrScopeInvalid
	}
	return ResolveScope{ScopeProjection{audience, a.OperationID(), a.IntentDigest()}, true}, nil
}
func (s ResolveScope) Projection() (ScopeProjection, error) {
	if !s.valid {
		return ScopeProjection{}, ErrScopeInvalid
	}
	return s.projection, nil
}

type BindingProjection struct {
	ActorID, TenantID, InstanceID, Granularity                              string
	IdentityProjectionDigest                                                [32]byte
	ContinuityEpoch, MappingRevision, LifecycleRevision, DelegationRevision uint64
	ValidFromUnixNS, ExpiresUnixNS                                          int64
	EvidenceLane                                                            EvidenceLane
}
type DependencyStatus struct{ State, Reason, Contract string }
type ActorHandle struct{ state *actorState }

func (h ActorHandle) Projection() (BindingProjection, error) {
	if h.state == nil || h.state.owner == nil {
		return BindingProjection{}, ErrForeignHandle
	}
	r := h.state.owner
	r.mu.Lock()
	defer r.mu.Unlock()
	s := h.state
	if _, e := r.sampleLocked(); e != nil {
		return BindingProjection{}, e
	}
	if !r.actorValidLocked(s) {
		return BindingProjection{}, ErrForeignHandle
	}
	if _, e := r.config.Acceptor.Validate(s.transport, time.Unix(0, r.last.WallUnixNS)); e != nil {
		return BindingProjection{}, ErrTransportInvalid
	}
	return s.projection, nil
}
