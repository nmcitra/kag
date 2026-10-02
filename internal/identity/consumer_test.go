package identity_test

import (
	"encoding/json"
	"github.com/nmcitra/kag/internal/authn"
	"github.com/nmcitra/kag/internal/identity"
	"testing"
	"time"
)

func TestSerializedRecordsCannotRestoreAuthority(t *testing.T) {
	var actor identity.ActorHandle
	var transport authn.TransportHandle
	b, e := json.Marshal(actor)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &actor); e != nil {
		t.Fatal(e)
	}
	if p, e := actor.Projection(); e == nil || p.ActorID != "" {
		t.Fatal("serialized handle restored authority")
	}
	if e = json.Unmarshal([]byte(`{"Verified":true,"state":{}}`), &transport); e != nil {
		t.Fatal(e)
	}
	var acceptor authn.Acceptor
	if p, e := acceptor.Validate(transport, time.Now()); e == nil || p.PrincipalID != "" {
		t.Fatal("record restored transport")
	}
}
