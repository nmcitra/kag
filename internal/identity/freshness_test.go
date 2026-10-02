package identity

import (
	"context"
	"math"
	"testing"
)

func TestEachSourceHalfOpenFreshness(t *testing.T) {
	for _, kind := range []string{"mapping", "lifecycle", "origin", "profile"} {
		for _, offset := range []int64{-1, 0, 1} {
			t.Run(kind+string(rune('b'+offset)), func(t *testing.T) {
				r, p, c, h, s := identityFixture(t)
				initial := r.last.WallUnixNS
				age := r.contracts[kind].MaxAgeNS
				advance := age + offset
				c.s.WallUnixNS += advance
				c.s.ElapsedNS += advance
				for i := range p.n.Sources {
					if p.n.Sources[i].Kind != kind {
						p.n.Sources[i].ObservedUnixNS = c.s.WallUnixNS
						p.n.Sources[i].ValidatedUnixNS = c.s.WallUnixNS
					}
				}
				actor, e := r.Resolve(context.Background(), h, s)
				if offset < 0 {
					if e != nil {
						t.Fatal(initial, e)
					}
				} else if e != ErrSourceStale || actor.state != nil {
					t.Fatal(actor, e)
				}
			})
		}
	}
}
func TestClockRegressionUncertaintyAndExtremeSamples(t *testing.T) {
	changes := []func(*ClockSample){func(s *ClockSample) { s.WallUnixNS-- }, func(s *ClockSample) { s.ElapsedNS-- }, func(s *ClockSample) { s.UncertaintyNS = 1 }, func(s *ClockSample) { s.ElapsedNS = math.MaxInt64; s.WallUnixNS = math.MaxInt64 }, func(s *ClockSample) { s.WallUnixNS = -1 }, func(s *ClockSample) { s.ElapsedNS = -1 }}
	for i, change := range changes {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			r, _, c, h, s := identityFixture(t)
			change(&c.s)
			actor, e := r.Resolve(context.Background(), h, s)
			if e != ErrClockUncertain || actor.state != nil {
				t.Fatal(actor, e)
			}
			if r.Status(context.Background()).State != "unavailable" {
				t.Fatal("clock reopened")
			}
		})
	}
}
func TestConstructorLanesCapacitiesAndUnknownContext(t *testing.T) {
	r, _, _, h, s := identityFixture(t)
	for _, lane := range []EvidenceLane{0, 2, 255} {
		c := r.config
		c.Registration.Lane = lane
		if _, e := NewResolver(c); e != ErrContractIncompatible {
			t.Fatal(lane, e)
		}
	}
	if a, e := r.Resolve(nil, h, s); e != ErrCanceled || a.state != nil {
		t.Fatal(a, e)
	}
	if a, e := r.Recheck(context.Background(), ActorHandle{}, s); e != ErrForeignHandle || a.state != nil {
		t.Fatal(a, e)
	}
	r.config.MaxHandles = 1
	if _, e := r.Resolve(context.Background(), h, s); e != nil {
		t.Fatal(e)
	}
	if actor, e := r.Resolve(context.Background(), h, s); e != ErrBusy || actor.state != nil {
		t.Fatal(actor, e)
	}
}

func TestAllowedDriftSourceAgeUsesElapsedDeadline(t *testing.T) {
	for _, offset := range []int64{-1, 0, 1} {
		t.Run(string(rune('b'+offset)), func(t *testing.T) {
			r, _, c, h, s := identityFixture(t)
			r.config.MaxClockDriftNS = 1_000_000_000
			elapsed := int64(5_000_000_000) + offset
			c.s.ElapsedNS += elapsed
			c.s.WallUnixNS += elapsed - 1_000_000_000
			actor, e := r.Resolve(context.Background(), h, s)
			if offset < 0 {
				if e != nil {
					t.Fatal("allowed-drift deadline-minus-one control denied", e)
				}
				if actor.state.elapsedExpiry != 5_000_000_001 {
					t.Fatal("allowed drift extended source elapsed deadline", actor.state.elapsedExpiry)
				}
			} else if e != ErrSourceStale || actor.state != nil {
				t.Fatal("elapsed source-age equality/overflow admitted", actor, e)
			}
		})
	}
}
func TestAllowedFrozenWallFreshResolveCannotRestartEvidenceAge(t *testing.T) {
	r, _, c, h, s := identityFixture(t)
	r.config.MaxClockDriftNS = 10_000_000_000
	initial, e := r.Resolve(context.Background(), h, s)
	if e != nil {
		t.Fatal(e)
	}
	c.s.ElapsedNS += 4_000_000_000
	fresh, e := r.Resolve(context.Background(), h, s)
	if e != nil {
		t.Fatal("allowed frozen-wall before-deadline control denied", e)
	}
	if fresh.state.elapsedExpiry != initial.state.elapsedExpiry {
		t.Fatal("fresh resolve restarted unchanged source age", initial.state.elapsedExpiry, fresh.state.elapsedExpiry)
	}
	c.s.ElapsedNS += 1_000_000_000
	if actor, e := r.Resolve(context.Background(), h, s); e != ErrSourceStale || actor.state != nil {
		t.Fatal("fresh resolve bypassed unchanged source-age equality", actor, e)
	}
	if _, e = fresh.Projection(); e != ErrForeignHandle {
		t.Fatal("fresh handle bypassed original elapsed lifetime", e)
	}
}
func TestAllowedLagCannotAdmitFutureSourceOrStart(t *testing.T) {
	for _, which := range []string{"observed", "validated", "start"} {
		t.Run(which, func(t *testing.T) {
			r, p, c, h, s := identityFixture(t)
			r.config.MaxClockDriftNS = 10_000_000_000
			raw := c.s.WallUnixNS
			c.s.ElapsedNS += 4_000_000_000
			for i := range p.n.Sources {
				if p.n.Sources[i].Kind == "mapping" {
					switch which {
					case "observed":
						p.n.Sources[i].ObservedUnixNS = raw + 1
						p.n.Sources[i].ValidatedUnixNS = raw + 1
					case "validated":
						p.n.Sources[i].ValidatedUnixNS = raw + 1
					case "start":
						p.n.Sources[i].ValidFromUnixNS = raw + 1
					}
				}
			}
			if actor, e := r.Resolve(context.Background(), h, s); e != ErrSourceStale || actor.state != nil {
				t.Fatal("lagging raw clock activated future source", actor, e)
			}
		})
	}
}
func TestElapsedMappedWallCheckedLimits(t *testing.T) {
	const limit = int64(math.MaxInt64)
	base := ClockSample{WallUnixNS: limit - 2, ElapsedNS: 1}
	for _, row := range []struct {
		elapsed, raw, expected int64
		ok                     bool
	}{{2, limit - 2, limit - 1, true}, {3, limit - 2, limit, true}, {4, limit - 2, 0, false}, {2, limit, limit, true}, {0, limit - 2, 0, false}} {
		got, ok := elapsedMappedWall(ClockSample{WallUnixNS: row.raw, ElapsedNS: row.elapsed}, base)
		if ok != row.ok || got != row.expected {
			t.Fatal("checked literal elapsed mapping mismatch", got, ok, row)
		}
	}
	r, _, c, h, s := identityFixture(t)
	r.config.MaxClockDriftNS = math.MaxInt64
	c.s.ElapsedNS = math.MaxInt64
	if actor, e := r.Resolve(context.Background(), h, s); e != ErrClockUncertain || actor.state != nil {
		t.Fatal("overflowing elapsed wall mapping admitted", actor, e)
	}
}
