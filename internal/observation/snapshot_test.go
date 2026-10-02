package observation_test

import (
	"context"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/nmcitra/kag/internal/observation"
)

func validRef() observation.Ref {
	return observation.Ref{SourceID: "supplier", ObjectID: "object", PackageDigest: [32]byte{1}, ObjectDigest: [32]byte{2}}
}
func validPoints() []observation.Point {
	return []observation.Point{{SourceTime: "supplier-native-time", Metrics: []observation.Metric{{Name: "unknown", Present: false}, {Name: "count", NativeValue: "0", Present: true}}}}
}
func newValid(t *testing.T) observation.Snapshot {
	t.Helper()
	s, err := observation.NewSnapshot(validRef(), [32]byte{3}, validPoints())
	if err != nil {
		t.Fatalf("NewSnapshot valid input: %v", err)
	}
	return s
}
func TestProvenanceAndNativeValues(t *testing.T) {
	s := newValid(t)
	if got := s.Source(); got != validRef() {
		t.Fatalf("source: got %#v", got)
	}
	if got := s.ResponseDigest(); got != ([32]byte{3}) {
		t.Fatalf("response digest: got %x", got)
	}
	if got := s.Points(); !reflect.DeepEqual(got, validPoints()) {
		t.Fatalf("points: got %#v", got)
	}
}
func TestConstructorAndAccessorIsolation(t *testing.T) {
	ref, digest, points := validRef(), [32]byte{3}, validPoints()
	s, err := observation.NewSnapshot(ref, digest, points)
	if err != nil {
		t.Fatal(err)
	}
	ref.SourceID = "changed"
	ref.PackageDigest[0] = 9
	digest[0] = 9
	points[0].SourceTime = "changed"
	points[0].Metrics[1].NativeValue = "changed"
	points[0].Metrics = append(points[0].Metrics, observation.Metric{Name: "added"})
	points = append(points, observation.Point{})
	gotRef := s.Source()
	gotRef.ObjectID = "changed"
	gotRef.ObjectDigest[0] = 9
	gotDigest := s.ResponseDigest()
	gotDigest[0] = 9
	got := s.Points()
	got[0].SourceTime = "changed"
	got[0].Metrics[1].Name = "changed"
	got[0].Metrics = append(got[0].Metrics, observation.Metric{Name: "added"})
	got = append(got, observation.Point{})
	if s.Source() != validRef() || s.ResponseDigest() != ([32]byte{3}) || !reflect.DeepEqual(s.Points(), validPoints()) {
		t.Fatalf("snapshot mutated: %#v", s.Points())
	}
}
func TestEmptyRowsRemainEmpty(t *testing.T) {
	for _, points := range [][]observation.Point{nil, {}} {
		s, err := observation.NewSnapshot(validRef(), [32]byte{3}, points)
		if err != nil {
			t.Fatal(err)
		}
		if len(s.Points()) != 0 {
			t.Fatalf("empty response invented rows: %#v", s.Points())
		}
	}
}
func TestZeroSnapshotIsInert(t *testing.T) {
	var s observation.Snapshot
	if s.Source() != (observation.Ref{}) || s.ResponseDigest() != ([32]byte{}) || len(s.Points()) != 0 {
		t.Fatalf("zero snapshot has observations: %#v", s)
	}
}
func TestConcurrentAccessorCopies(t *testing.T) {
	s := newValid(t)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				points := s.Points()
				points[0].SourceTime = "local"
				points[0].Metrics[1].NativeValue = "local"
				ref := s.Source()
				ref.SourceID = "local"
				digest := s.ResponseDigest()
				digest[0] = 9
			}
		}()
	}
	wg.Wait()
	if !reflect.DeepEqual(s.Points(), validPoints()) {
		t.Fatal("concurrent copies mutated snapshot")
	}
}

type fixedSource struct{ snapshot observation.Snapshot }

func (s fixedSource) Observe(context.Context) (observation.Snapshot, error) { return s.snapshot, nil }

var _ observation.Source = fixedSource{}

func TestSourceContract(t *testing.T) {
	var source observation.Source = fixedSource{snapshot: newValid(t)}
	got, err := source.Observe(context.Background())
	if err != nil || !reflect.DeepEqual(got.Points(), validPoints()) {
		t.Fatalf("source observation: %#v, %v", got, err)
	}
}

func TestValidationConstantsAndStableError(t *testing.T) {
	if observation.MaxPoints != 64 || observation.MaxMetrics != 16 {
		t.Fatalf("limits changed: %d, %d", observation.MaxPoints, observation.MaxMetrics)
	}
	if observation.ErrInvalid.Error() != "invalid_observation" {
		t.Fatalf("stable error changed: %q", observation.ErrInvalid.Error())
	}
	if observation.Error("example").Error() != "example" {
		t.Fatal("Error must preserve its string")
	}
}

func TestScalarBoundaries(t *testing.T) {
	fields := []struct {
		name string
		max  int
		set  func(*observation.Ref, []observation.Point, string)
	}{
		{"source_id", 128, func(r *observation.Ref, p []observation.Point, v string) { r.SourceID = v }},
		{"object_id", 128, func(r *observation.Ref, p []observation.Point, v string) { r.ObjectID = v }},
		{"source_time", 128, func(r *observation.Ref, p []observation.Point, v string) { p[0].SourceTime = v }},
		{"metric_name", 64, func(r *observation.Ref, p []observation.Point, v string) { p[0].Metrics[1].Name = v }},
		{"native_value", 128, func(r *observation.Ref, p []observation.Point, v string) { p[0].Metrics[1].NativeValue = v }},
	}
	for _, f := range fields {
		t.Run(f.name, func(t *testing.T) {
			for _, size := range []int{1, f.max - 1, f.max} {
				t.Run(fmtSize(size), func(t *testing.T) {
					ref, points := validRef(), validPoints()
					f.set(&ref, points, strings.Repeat("x", size))
					s, err := observation.NewSnapshot(ref, [32]byte{3}, points)
					if err != nil {
						t.Fatalf("valid length %d: %v", size, err)
					}
					if s.Source() != ref || !reflect.DeepEqual(s.Points(), points) {
						t.Fatal("accepted scalar changed")
					}
				})
			}
			bad := []string{"", strings.Repeat("x", f.max+1), "nonASCII-\u00e9", "nonASCII-\u0080"}
			for c := 0; c < 32; c++ {
				bad = append(bad, "x"+string(byte(c))+"y")
			}
			bad = append(bad, "x\x7fy")
			for i, value := range bad {
				t.Run("invalid_"+fmtSize(i), func(t *testing.T) {
					ref, points := validRef(), validPoints()
					f.set(&ref, points, value)
					requireInvalid(t, ref, [32]byte{3}, points)
				})
			}
			// Space and tilde are the printable ASCII endpoints, preserved exactly.
			ref, points := validRef(), validPoints()
			f.set(&ref, points, " ~ ")
			s, err := observation.NewSnapshot(ref, [32]byte{3}, points)
			if err != nil || s.Source() != ref || !reflect.DeepEqual(s.Points(), points) {
				t.Fatalf("printable endpoints: %v", err)
			}
		})
	}
}
func fmtSize(i int) string { return strconv.Itoa(i) }
func requireInvalid(t *testing.T, ref observation.Ref, digest [32]byte, points []observation.Point) {
	t.Helper()
	got, err := observation.NewSnapshot(ref, digest, points)
	if err != observation.ErrInvalid {
		t.Fatalf("invalid input: got error %v, want %v", err, observation.ErrInvalid)
	}
	if !reflect.DeepEqual(got, observation.Snapshot{}) {
		t.Fatalf("error returned nonzero snapshot: %#v", got)
	}
}
func TestRejectZeroDigests(t *testing.T) {
	for _, which := range []string{"package", "object", "response"} {
		t.Run(which, func(t *testing.T) {
			ref, digest := validRef(), [32]byte{3}
			switch which {
			case "package":
				ref.PackageDigest = [32]byte{}
			case "object":
				ref.ObjectDigest = [32]byte{}
			case "response":
				digest = [32]byte{}
			}
			requireInvalid(t, ref, digest, validPoints())
		})
	}
	// A digest with a nonzero last byte is nonzero too.
	ref := validRef()
	ref.PackageDigest = [32]byte{31: 1}
	ref.ObjectDigest = [32]byte{31: 2}
	if _, err := observation.NewSnapshot(ref, [32]byte{31: 3}, nil); err != nil {
		t.Fatal(err)
	}
}
func TestPointCountBoundaries(t *testing.T) {
	for _, n := range []int{0, 1, 63, 64, 65} {
		t.Run(fmtSize(n), func(t *testing.T) {
			points := make([]observation.Point, n)
			for i := range points {
				points[i] = validPoints()[0]
			}
			if n > 64 {
				requireInvalid(t, validRef(), [32]byte{3}, points)
				return
			}
			s, err := observation.NewSnapshot(validRef(), [32]byte{3}, points)
			if err != nil || len(s.Points()) != n {
				t.Fatalf("point count %d: %v", n, err)
			}
		})
	}
}
func TestMetricCountBoundaries(t *testing.T) {
	for _, n := range []int{0, 1, 15, 16, 17} {
		t.Run(fmtSize(n), func(t *testing.T) {
			points := []observation.Point{{SourceTime: "native", Metrics: make([]observation.Metric, n)}}
			for i := range points[0].Metrics {
				points[0].Metrics[i] = observation.Metric{Name: "m" + fmtSize(i)}
			}
			if n == 0 || n > 16 {
				requireInvalid(t, validRef(), [32]byte{3}, points)
				return
			}
			s, err := observation.NewSnapshot(validRef(), [32]byte{3}, points)
			if err != nil || !reflect.DeepEqual(s.Points(), points) {
				t.Fatalf("metric count %d: %v", n, err)
			}
		})
	}
	points := validPoints()
	points[0].Metrics = nil
	requireInvalid(t, validRef(), [32]byte{3}, points)
}
func TestMetricPresenceAndDuplicates(t *testing.T) {
	t.Run("absent_must_be_empty", func(t *testing.T) {
		points := validPoints()
		points[0].Metrics[0].NativeValue = "0"
		requireInvalid(t, validRef(), [32]byte{3}, points)
	})
	t.Run("present_must_not_be_empty", func(t *testing.T) {
		points := validPoints()
		points[0].Metrics[1].NativeValue = ""
		requireInvalid(t, validRef(), [32]byte{3}, points)
	})
	t.Run("duplicate_name", func(t *testing.T) {
		points := validPoints()
		points[0].Metrics[1].Name = "unknown"
		requireInvalid(t, validRef(), [32]byte{3}, points)
	})
	t.Run("case_sensitive_and_untrimmed", func(t *testing.T) {
		points := []observation.Point{{SourceTime: "native", Metrics: []observation.Metric{{Name: "count"}, {Name: "Count"}, {Name: " count "}}}}
		s, err := observation.NewSnapshot(validRef(), [32]byte{3}, points)
		if err != nil || !reflect.DeepEqual(s.Points(), points) {
			t.Fatalf("distinct exact names changed: %v", err)
		}
	})
	t.Run("names_may_repeat_in_separate_points", func(t *testing.T) {
		points := append(validPoints(), validPoints()...)
		s, err := observation.NewSnapshot(validRef(), [32]byte{3}, points)
		if err != nil || !reflect.DeepEqual(s.Points(), points) {
			t.Fatalf("independent rows: %v", err)
		}
	})
}
