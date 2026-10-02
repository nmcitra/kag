package identity

import (
	"encoding/binary"
	"github.com/nmcitra/kag/internal/authn"
	"sort"
	"unicode/utf8"
)

const maxEncoding = 8192

type frame struct {
	b   []byte
	err error
}

func (f *frame) field(tag uint16, p []byte) {
	if f.err != nil {
		return
	}
	if len(p) > maxEncoding-6-len(f.b) {
		f.err = ErrEvidenceInvalid
		return
	}
	var b [6]byte
	binary.BigEndian.PutUint16(b[:2], tag)
	binary.BigEndian.PutUint32(b[2:], uint32(len(p)))
	f.b = append(f.b, b[:]...)
	f.b = append(f.b, p...)
}
func (f *frame) text(tag uint16, s string) {
	if len(s) > maxEncoding-10-len(f.b) || !utf8.ValidString(s) {
		f.err = ErrEvidenceInvalid
		return
	}
	b := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(b, uint32(len(s)))
	copy(b[4:], s)
	f.field(tag, b)
}
func (f *frame) number(tag uint16, n uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	f.field(tag, b[:])
}
func (f *frame) time(tag uint16, n int64) {
	if n < 0 {
		f.err = ErrEvidenceInvalid
		return
	}
	f.number(tag, uint64(n))
}
func (f *frame) nested(tag uint16, n frame) {
	if n.err != nil {
		f.err = n.err
		return
	}
	f.field(tag, n.b)
}
func count(n int) frame {
	f := frame{b: make([]byte, 4)}
	binary.BigEndian.PutUint32(f.b, uint32(n))
	return f
}
func encode(n NormalizedSnapshot, t authn.TransportProjection, s ScopeProjection, p OperationProfile, from, to int64) ([]byte, error) {
	if len(n.Mappings) != 1 || !bounded(n) || !codecUnique(n) {
		return nil, ErrEvidenceInvalid
	}
	if _, e := measureSnapshot(n, t, s, p); e != nil {
		return nil, e
	}
	f := frame{}
	f.text(1, "kag.identity-projection/v1")
	f.text(2, "kag.identity-snapshot/v1")
	f.text(3, t.TrustDomain)
	f.text(4, t.CredentialProfile)
	f.text(5, t.PrincipalID)
	f.field(6, t.CredentialDigest[:])
	f.field(7, t.ConnectionDigest[:])
	f.number(8, t.TrustRevision)
	for i, v := range []int64{t.AuthenticatedUnixNS, t.CredentialExpiresUnixNS, t.SessionExpiresUnixNS, t.TrustValidFromUnixNS, t.TrustExpiresUnixNS} {
		f.time(uint16(9+i), v)
	}
	m := n.Mappings[0]
	f.text(14, m.TenantID)
	f.text(15, m.ActorID)
	f.text(16, m.ActorKind)
	f.text(17, m.Granularity)
	opt := frame{b: []byte{0}}
	if m.InstancePresent {
		opt.b[0] = 1
		opt.text(1, m.InstanceID)
	}
	f.nested(18, opt)
	f.text(19, n.Origin.Mode)
	f.text(20, n.Origin.ID)
	f.text(21, p.HumanApplicability)
	opt = frame{b: []byte{0}}
	if n.Human != nil {
		opt.b[0] = 1
		h := n.Human
		opt.text(1, h.TenantID)
		opt.text(2, h.ID)
		opt.number(3, h.Revision)
		opt.time(4, h.ValidFromUnixNS)
		opt.time(5, h.ExpiresUnixNS)
		opt.text(6, h.SourceID)
	}
	f.nested(22, opt)
	for i, v := range []uint64{m.Revision, n.Lifecycle.Revision, m.ContinuityEpoch, n.DelegationRevision} {
		f.number(uint16(23+i), v)
	}
	for i, v := range []string{n.Lifecycle.Enrollment, n.Lifecycle.Authority, n.Lifecycle.CredentialState, n.Lifecycle.NodeState} {
		f.text(uint16(27+i), v)
	}
	scope := frame{}
	scope.text(1, s.AudienceID)
	scope.text(2, s.OperationID)
	scope.field(3, s.IntentDigest[:])
	f.nested(31, scope)
	chain := count(len(n.Delegation))
	for _, h := range n.Delegation {
		g := frame{}
		for i, v := range []string{h.ParentTenantID, h.ParentActorID, h.ChildTenantID, h.ChildActorID, h.AudienceID, h.ResourceID} {
			g.text(uint16(1+i), v)
		}
		ops := append([]string(nil), h.Operations...)
		sort.Strings(ops)
		list := count(len(ops))
		for _, op := range ops {
			list.text(1, op)
		}
		g.nested(7, list)
		g.number(8, h.Revision)
		g.time(9, h.ValidFromUnixNS)
		g.time(10, h.ExpiresUnixNS)
		g.text(11, h.SourceID)
		g.field(12, h.OriginalIntentDigest[:])
		g.field(13, h.BrokerConnectionDigest[:])
		chain.nested(1, g)
	}
	f.nested(32, chain)
	contexts := append([]ContextEntry(nil), n.Context...)
	sort.Slice(contexts, func(i, j int) bool { return contexts[i].Key < contexts[j].Key })
	list := count(len(contexts))
	for _, c := range contexts {
		g := frame{}
		g.text(1, c.Key)
		g.text(2, c.Value)
		g.text(3, c.SourceID)
		g.time(4, c.ValidFromUnixNS)
		g.time(5, c.ExpiresUnixNS)
		list.nested(1, g)
	}
	f.nested(33, list)
	sources := append([]SourceReference(nil), n.Sources...)
	sort.Slice(sources, func(i, j int) bool { return sources[i].ID < sources[j].ID })
	list = count(len(sources))
	for _, r := range sources {
		g := frame{}
		g.text(1, r.ID)
		g.field(2, r.ContractDigest[:])
		g.field(3, r.EvidenceDigest[:])
		g.text(4, r.Kind)
		g.number(5, r.Revision)
		g.time(6, r.ObservedUnixNS)
		g.time(7, r.ValidatedUnixNS)
		g.time(8, r.ValidFromUnixNS)
		g.time(9, r.ExpiresUnixNS)
		g.text(10, r.BoundID)
		g.text(11, "modeled")
		list.nested(1, g)
	}
	f.nested(34, list)
	f.time(35, from)
	f.time(36, to)
	f.text(37, "modeled")
	return f.b, f.err
}

func codecUnique(n NormalizedSnapshot) bool {
	m := n.Mappings[0]
	if !validID(m.ActorID) || !validID(m.TenantID) || !validID(m.ActorKind) || !validID(m.OriginID) || m.InstancePresent && !validID(m.InstanceID) || !m.InstancePresent && m.InstanceID != "" {
		return false
	}
	if n.Human != nil && (!validID(n.Human.ID) || !validID(n.Human.TenantID)) {
		return false
	}
	sources := map[string]bool{}
	for _, s := range n.Sources {
		if sources[s.ID] {
			return false
		}
		sources[s.ID] = true
	}
	contexts := map[string]bool{}
	for _, c := range n.Context {
		if contexts[c.Key] {
			return false
		}
		contexts[c.Key] = true
	}
	for _, h := range n.Delegation {
		ops := map[string]bool{}
		for _, o := range h.Operations {
			if ops[o] {
				return false
			}
			ops[o] = true
		}
	}
	return true
}
