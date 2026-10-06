package main

import "testing"

func TestInspectorPrincipalListAcceptsTwoDistinctFingerprints(t *testing.T) {
	var list principalList
	first := "cert-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	second := "cert-sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if list.Set(first) != nil || list.Set(second) != nil || len(list) != 2 {
		t.Fatal(list)
	}
	if list.Set(first) == nil {
		t.Fatal("duplicate inspector identity")
	}
	if list.Set("attacker") == nil {
		t.Fatal("malformed inspector identity")
	}
}
