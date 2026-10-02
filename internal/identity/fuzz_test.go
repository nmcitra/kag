package identity

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"unicode/utf8"
)

// Independent acceptance oracle uses literal wire lengths, never codec helpers.
func FuzzCodecText(f *testing.F) {
	f.Add("kag.identity-projection/v1")
	f.Add("")
	f.Add(string([]byte{0xff}))
	f.Fuzz(func(t *testing.T, s string) {
		got := frame{}
		got.text(1, s)
		admitted := len(s) <= 8182 && utf8.ValidString(s)
		if admitted != (got.err == nil) {
			t.Fatalf("acceptance mismatch len=%d", len(s))
		}
		if !admitted {
			if len(got.b) != 0 {
				t.Fatal("rejected text retained bytes")
			}
			return
		}
		expected := make([]byte, 10+len(s))
		binary.BigEndian.PutUint16(expected, 1)
		binary.BigEndian.PutUint32(expected[2:], uint32(4+len(s)))
		binary.BigEndian.PutUint32(expected[6:], uint32(len(s)))
		copy(expected[10:], s)
		if !bytes.Equal(got.b, expected) || len(got.b) > 8192 {
			t.Fatal("literal text framing mismatch")
		}
	})
}

// This acceptance oracle is independent of production validators/codec. The
// fixed test-only registered model supplies exactly four known kinds and a
// protected profile; mutations below cover identity, lifecycle, references and
// half-open timing. A successful resolve must satisfy every literal condition.
func FuzzResolveAcceptedOracle(f *testing.F) {
	f.Add([]byte("a-1"), byte(0))
	f.Add([]byte(""), byte(0))
	f.Add([]byte("a-1"), byte(1))
	f.Fuzz(func(t *testing.T, actorID []byte, scenario byte) {
		if len(actorID) > 8192 {
			return
		}
		r, p, c, h, s := identityFixture(t)
		id := string(actorID)
		p.n.Mappings[0].ActorID = id
		for i := range p.n.FloorWitness.Heads {
			p.n.FloorWitness.Heads[i].ActorID = id
		}
		mode := scenario % 8
		switch mode {
		case 1:
			p.n.Lifecycle.Authority = "disabled"
		case 2:
			p.n.Lifecycle.Authority = "deleted"
		case 3:
			p.n.Lifecycle.CredentialState = "revoked"
		case 4:
			p.n.Mappings[0].InstancePresent = false
			p.n.Mappings[0].InstanceID = ""
		case 5:
			p.n.Sources[0].ContractDigest[0] ^= 1
		case 6:
			p.n.Sources[0].EvidenceDigest = [32]byte{}
			p.n.FloorWitness.Heads[0].ContentDigest = [32]byte{}
		case 7:
			c.s.WallUnixNS += 5_000_000_000
			c.s.ElapsedNS += 5_000_000_000
		}
		idOK := len(actorID) >= 1 && len(actorID) <= 128
		for i, b := range actorID {
			letter := b >= 97 && b <= 122
			digit := b >= 48 && b <= 57
			punct := i > 0 && (b == 46 || b == 95 || b == 58 || b == 45)
			if !(letter || digit || punct) {
				idOK = false
			}
		}
		expected := idOK && mode == 0
		got, e := r.Resolve(context.Background(), h, s)
		if (e == nil) != expected {
			t.Fatalf("independent acceptance oracle mismatch idlen=%d scenario=%d err=%v", len(actorID), mode, e)
		}
		if !expected {
			if got.state != nil {
				t.Fatal("denial retained authority")
			}
			return
		}
		projection, e := got.Projection()
		if e != nil || projection.ActorID != id || projection.TenantID != "t-a" || projection.InstanceID != "i-1" || projection.Granularity != "instance-required" || projection.EvidenceLane != 1 || projection.ContinuityEpoch != 3 || projection.MappingRevision != 7 || projection.LifecycleRevision != 12 || projection.IdentityProjectionDigest == ([32]byte{}) || projection.ValidFromUnixNS != 1_893_456_000_000_000_000 || projection.ExpiresUnixNS != 1_893_456_005_000_000_000 {
			t.Fatal("accepted authority violates independent fixed witness", projection, e)
		}
		if p.n.Lifecycle.Enrollment != "enrolled" || p.n.Lifecycle.Authority != "enabled" || p.n.Lifecycle.CredentialState != "valid" || p.n.Lifecycle.NodeState != "active" || p.n.Origin.Mode != "direct" || p.n.Origin.ID != "o-1" || len(p.n.Delegation) != 0 || p.n.Human != nil || len(p.n.Sources) != 4 {
			t.Fatal("unexpected source facts")
		}
		known := map[string]bool{"mapping": true, "lifecycle": true, "origin": true, "profile": true}
		for _, ref := range p.n.Sources {
			if !known[ref.Kind] || ref.ObservedUnixNS != projection.ValidFromUnixNS || ref.ValidatedUnixNS != projection.ValidFromUnixNS || ref.ContractDigest == ([32]byte{}) || ref.EvidenceDigest == ([32]byte{}) || ref.ValidFromUnixNS > projection.ValidFromUnixNS || ref.ExpiresUnixNS <= projection.ExpiresUnixNS {
				t.Fatal("accepted source violates fixed kind/bounds/digest oracle")
			}
			delete(known, ref.Kind)
		}
		if len(known) != 0 {
			t.Fatal("missing source kind")
		}
	})
}
