package identity

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"
)

func TestCodecLiteralFraming(t *testing.T) {
	f := frame{}
	f.text(1, "kag.identity-projection/v1")
	f.field(18, []byte{0})
	f.number(23, 7)
	expected, _ := hex.DecodeString("00010000001e0000001a6b61672e6964656e746974792d70726f6a656374696f6e2f7631001200000001000017000000080000000000000007")
	if f.err != nil || !bytes.Equal(f.b, expected) {
		t.Fatalf("got %x error %v", f.b, f.err)
	}
}
func TestCodecBound(t *testing.T) {
	f := frame{}
	f.field(1, make([]byte, 8192))
	if f.err != ErrEvidenceInvalid || len(f.b) != 0 {
		t.Fatal(f.err, len(f.b))
	}
}
func TestMeasureMatchesGoldenAndBounds(t *testing.T) {
	r, p, _, h, s := identityFixture(t)
	transport, e := r.config.Acceptor.Validate(h, time.Unix(0, r.last.WallUnixNS))
	if e != nil {
		t.Fatal(e)
	}
	scope, _ := s.Projection()
	profile := r.profiles[scope.OperationID]
	size, e := measureSnapshot(p.n, transport, scope, profile)
	encoded, ee := encode(p.n, transport, scope, profile, 1, 2)
	if e != nil || ee != nil || size != len(encoded) {
		t.Fatal(size, len(encoded), e, ee)
	}
	p.n.Mappings[0].ActorID = string(make([]byte, 8192))
	if _, e = measureSnapshot(p.n, transport, scope, profile); e != ErrEvidenceInvalid {
		t.Fatal(e)
	}
}
func TestCodecRejectsShapeBeforeFraming(t *testing.T) {
	r, p, _, h, s := identityFixture(t)
	transport, _ := r.config.Acceptor.Validate(h, time.Unix(0, r.last.WallUnixNS))
	scope, _ := s.Projection()
	profile := r.profiles[scope.OperationID]
	p.n.Sources = append(p.n.Sources, p.n.Sources[0])
	if encoded, e := encode(p.n, transport, scope, profile, 1, 2); e != ErrEvidenceInvalid || len(encoded) != 0 {
		t.Fatal("duplicate source framed", len(encoded), e)
	}
}
func TestCodecPresentEmptyInstanceDenied(t *testing.T) {
	r, p, _, h, s := identityFixture(t)
	transport, _ := r.config.Acceptor.Validate(h, time.Unix(0, r.last.WallUnixNS))
	scope, _ := s.Projection()
	p.n.Mappings[0].InstanceID = ""
	if b, e := encode(p.n, transport, scope, r.profiles[scope.OperationID], 1, 2); e != ErrEvidenceInvalid || len(b) != 0 {
		t.Fatal("present empty instance framed", e)
	}
}
