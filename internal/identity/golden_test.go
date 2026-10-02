package identity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/nmcitra/kag/internal/authn"
	"os"
	"strings"
	"testing"
)

func filled(b byte) (d [32]byte) {
	for i := range d {
		d[i] = b
	}
	return
}
func TestCodecIndependentCompleteGolden(t *testing.T) {
	b, e := os.ReadFile("testdata/independent-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Cases []struct {
			Name string `json:"name"`
			Hex  string `json:"payload_hex"`
			SHA  string `json:"payload_sha256"`
		}
	}
	if e = json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
	wall := int64(1900000000000000000)
	transport := authn.TransportProjection{TrustDomain: "trust-a", CredentialProfile: "cert-local", PrincipalID: "cert-sha256:" + strings.Repeat("11", 32), CredentialDigest: filled(0x11), ConnectionDigest: filled(0x12), TrustRevision: 1, AuthenticatedUnixNS: wall, CredentialExpiresUnixNS: wall + 60e9, SessionExpiresUnixNS: wall + 60e9, TrustValidFromUnixNS: wall - 1e9, TrustExpiresUnixNS: wall + 60e9}
	base := NormalizedSnapshot{Mappings: []Mapping{{TenantID: "t-a", ActorID: "a-1", ActorKind: "agent", InstanceID: "i-1", InstancePresent: true, Granularity: "instance-required", OriginID: "o-1", Revision: 7, ContinuityEpoch: 3}}, Lifecycle: Lifecycle{Enrollment: "enrolled", Authority: "enabled", CredentialState: "valid", NodeState: "active", Revision: 12, ContinuityEpoch: 3}, Origin: Origin{Mode: "direct", ID: "o-1"}, DelegationRevision: 1}
	for _, s := range []struct {
		id, kind, bound    string
		rev                uint64
		contract, evidence byte
	}{{"profile-01", "profile", "age20", 1, 0x21, 0x31}, {"mapping-01", "mapping", "age20", 7, 0x22, 0x32}, {"lifecycle-01", "lifecycle", "age5", 12, 0x23, 0x33}} {
		base.Sources = append(base.Sources, SourceReference{ID: s.id, Kind: s.kind, BoundID: s.bound, Revision: s.rev, ContractDigest: filled(s.contract), EvidenceDigest: filled(s.evidence), ObservedUnixNS: wall, ValidatedUnixNS: wall, ValidFromUnixNS: wall, ExpiresUnixNS: wall + 60e9})
	}
	scope := ScopeProjection{AudienceID: "lab-fixture-01", OperationID: "lab.set_marker", IntentDigest: filled(0x13)}
	profile := OperationProfile{HumanApplicability: "forbidden"}
	for i, c := range v.Cases {
		if i > 2 {
			break
		}
		t.Run(c.Name, func(t *testing.T) {
			n := clone(base)
			switch i {
			case 1:
				n.Lifecycle.Revision = 13
				for j := range n.Sources {
					if n.Sources[j].Kind == "lifecycle" {
						n.Sources[j].Revision = 13
					}
				}
			case 2:
				n.Mappings[0].InstancePresent = false
				n.Mappings[0].InstanceID = ""
			}
			actual, e := encode(n, transport, scope, profile, wall, wall+5e9)
			if e != nil {
				t.Fatal(e)
			}
			expected, e := hex.DecodeString(c.Hex)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(actual, expected) {
				t.Fatalf("independent byte mismatch got %d bytes expected %d", len(actual), len(expected))
			}
			digest := sha256.Sum256(actual)
			if hex.EncodeToString(digest[:]) != c.SHA {
				t.Fatal("independent digest mismatch")
			}
		})
	}
}
