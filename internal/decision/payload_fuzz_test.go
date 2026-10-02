package decision

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"regexp"
	"testing"
)

// This oracle parses only the literal frozen wire grammar, independently of codec helpers.
func oracleFields(p []byte) ([][]byte, bool) {
	if len(p) > 8192 || len(p) < 27 || binary.BigEndian.Uint32(p[:4]) != 23 || string(p[4:27]) != "KAG-MODELED-DECISION/v1" {
		return nil, false
	}
	off := 27
	out := [][]byte{}
	for tag := 1; tag <= 33; tag++ {
		if len(p)-off < 6 || int(binary.BigEndian.Uint16(p[off:off+2])) != tag {
			return nil, false
		}
		n := uint64(binary.BigEndian.Uint32(p[off+2 : off+6]))
		off += 6
		if n > uint64(len(p)-off) {
			return nil, false
		}
		out = append(out, p[off:off+int(n)])
		off += int(n)
	}
	if off != len(p) {
		return nil, false
	}
	ids := regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
	for _, i := range []int{0, 1, 2, 3, 7, 8, 10, 11, 12} {
		if !ids.Match(out[i]) {
			return nil, false
		}
	}
	optional := out[9]
	if len(optional) == 0 || optional[0] > 1 || optional[0] == 0 && len(optional) != 1 || optional[0] == 1 && !ids.Match(optional[1:]) {
		return nil, false
	}
	for _, i := range []int{4, 5, 6, 13, 14, 15, 16, 17, 18, 19} {
		if len(out[i]) != 32 {
			return nil, false
		}
	}
	for _, i := range []int{20, 21, 25, 26, 31} {
		if len(out[i]) != 8 {
			return nil, false
		}
	}
	issued, expiry := int64(binary.BigEndian.Uint64(out[20])), int64(binary.BigEndian.Uint64(out[21]))
	if issued <= 0 || expiry <= issued {
		return nil, false
	}
	for _, i := range []int{23, 24} {
		if len(out[i]) != 1 || out[i][0] > 1 {
			return nil, false
		}
	}
	if len(out[32]) != 1 {
		return nil, false
	}
	for _, i := range []int{22, 27, 28, 29, 30} {
		if len(out[i]) < 1 || len(out[i]) > 128 {
			return nil, false
		}
		for _, b := range out[i] {
			if b < 32 || b > 126 {
				return nil, false
			}
		}
	}
	return out, true
}
func oracleAccept(fields, base [][]byte, wall, start, end int64) bool {
	for i := 0; i < 20; i++ {
		if i != 3 && !bytes.Equal(fields[i], base[i]) {
			return false
		}
	}
	issued := int64(binary.BigEndian.Uint64(fields[20]))
	expiry := int64(binary.BigEndian.Uint64(fields[21]))
	if issued > wall || issued < start || wall-issued >= 3e9 || expiry <= wall || expiry > end {
		return false
	}
	return string(fields[22]) == "allow" && fields[23][0] == 0 && fields[24][0] == 1 && binary.BigEndian.Uint64(fields[25]) == 1 && binary.BigEndian.Uint64(fields[26]) >= 1 && string(fields[27]) == "Operator" && string(fields[28]) == "stable" && string(fields[29]) == "fixture-effects" && string(fields[30]) == "effects" && binary.BigEndian.Uint64(fields[31]) == 1 && fields[32][0]&2 != 0 && fields[32][0]&^uint8(3) == 0
}
func FuzzDecisionPayload(f *testing.F) {
	fixture := newDecisionFixture(f, true)
	seed := fixture.signed(f).Payload
	base, _ := oracleFields(seed)
	view, _ := fixture.binding.View()
	for _, v := range vectors(f).Vectors {
		p, _ := hex.DecodeString(v.PayloadHex)
		f.Add(p, false)
	}
	f.Add(seed, false)
	f.Add(seed, true)
	f.Add([]byte{}, false)
	f.Fuzz(func(t *testing.T, payload []byte, tamper bool) {
		fields, syntax := oracleFields(payload)
		c, e := decodeClaims(payload)
		if (e == nil) != syntax {
			t.Fatalf("independent syntax disagreement %v", e)
		}
		if e == nil {
			canonical, ce := EncodeClaims(c)
			if ce != nil || !bytes.Equal(canonical, payload) {
				t.Fatal("canonical disagreement")
			}
		}
		signature := ed25519.Sign(fixture.key, payload)
		if tamper {
			signature[0] ^= 1
		}
		p, e := fixture.validator.Evaluate(context.Background(), fixture.actor, fixture.scope, fixture.binding, SignedResult{payload, signature})
		expected := syntax && !tamper && oracleAccept(fields, base, fixture.claims.IssuedAtUnixNS, view.ValidFromUnixNS, view.ExpiresUnixNS)
		if (e == nil) != expected {
			t.Fatalf("independent acceptance disagreement expected %v got %v", expected, e)
		}
		if e != nil {
			deny(t, p, e)
		}
	})
}
