package identity

type NormalizedSnapshot struct {
	Mappings           []Mapping
	Lifecycle          Lifecycle
	Origin             Origin
	Human              *Human
	Delegation         []DelegationHop
	Context            []ContextEntry
	Sources            []SourceReference
	DelegationRevision uint64
	FloorWitness       FloorWitness
}
type Mapping struct {
	TenantID, ActorID, ActorKind, InstanceID, Granularity, OriginID string
	InstancePresent                                                 bool
	Revision, ContinuityEpoch                                       uint64
}
type Lifecycle struct {
	Enrollment, Authority, CredentialState, NodeState string
	Revision, ContinuityEpoch                         uint64
}
type Human struct {
	TenantID, ID, SourceID         string
	Revision                       uint64
	ValidFromUnixNS, ExpiresUnixNS int64
}
type Origin struct {
	Mode, ID, BrokerID                           string
	OriginalIntentDigest, BrokerConnectionDigest [32]byte
}
type DelegationHop struct {
	ParentTenantID, ParentActorID, ChildTenantID, ChildActorID, AudienceID, ResourceID string
	Operations                                                                         []string
	Revision                                                                           uint64
	ValidFromUnixNS, ExpiresUnixNS                                                     int64
	SourceID                                                                           string
	OriginalIntentDigest, BrokerConnectionDigest                                       [32]byte
}
type ContextEntry struct {
	Key, Value, SourceID           string
	ValidFromUnixNS, ExpiresUnixNS int64
}
type SourceReference struct {
	ID                                                              string
	ContractDigest, EvidenceDigest                                  [32]byte
	Kind                                                            string
	Revision                                                        uint64
	ObservedUnixNS, ValidatedUnixNS, ValidFromUnixNS, ExpiresUnixNS int64
	BoundID                                                         string
}
type FloorWitness struct {
	Heads   []Head
	Current bool
}
type Head struct {
	SourceID, Domain, TenantID, ActorID string
	Revision, ContinuityEpoch           uint64
	ContentDigest                       [32]byte
}
