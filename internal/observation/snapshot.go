// Package observation contains descriptive supplier observations. Its values do
// not confer authority or interpret native supplier values or timestamps.
package observation

import "context"

const (
	MaxPoints  = 64
	MaxMetrics = 16
)

type Error string

func (e Error) Error() string { return string(e) }

const ErrInvalid Error = "invalid_observation"

// Ref identifies descriptive supplier provenance, not authenticated authority.
type Ref struct {
	SourceID      string
	ObjectID      string
	PackageDigest [32]byte
	ObjectDigest  [32]byte
}

type Metric struct {
	Name        string
	NativeValue string
	Present     bool
}
type Point struct {
	SourceTime string
	Metrics    []Metric
}

// Snapshot preserves supplier data without granting authority. The zero value
// contains no observations or provenance.
type Snapshot struct {
	ref            Ref
	responseDigest [32]byte
	points         []Point
}

// Source supplies observations; this interface conveys no authority.
type Source interface {
	Observe(context.Context) (Snapshot, error)
}

func NewSnapshot(ref Ref, responseDigest [32]byte, points []Point) (Snapshot, error) {
	if !validScalar(ref.SourceID, 128) || !validScalar(ref.ObjectID, 128) ||
		ref.PackageDigest == ([32]byte{}) || ref.ObjectDigest == ([32]byte{}) ||
		responseDigest == ([32]byte{}) || len(points) > MaxPoints {
		return Snapshot{}, ErrInvalid
	}
	for _, point := range points {
		if !validScalar(point.SourceTime, 128) || len(point.Metrics) == 0 || len(point.Metrics) > MaxMetrics {
			return Snapshot{}, ErrInvalid
		}
		names := make(map[string]struct{}, len(point.Metrics))
		for _, metric := range point.Metrics {
			if !validScalar(metric.Name, 64) {
				return Snapshot{}, ErrInvalid
			}
			if _, duplicate := names[metric.Name]; duplicate {
				return Snapshot{}, ErrInvalid
			}
			names[metric.Name] = struct{}{}
			if metric.Present {
				if !validScalar(metric.NativeValue, 128) {
					return Snapshot{}, ErrInvalid
				}
			} else if metric.NativeValue != "" {
				return Snapshot{}, ErrInvalid
			}
		}
	}
	return Snapshot{ref: ref, responseDigest: responseDigest, points: copyPoints(points)}, nil
}
func (s Snapshot) Source() Ref              { return s.ref }
func (s Snapshot) ResponseDigest() [32]byte { return s.responseDigest }
func (s Snapshot) Points() []Point          { return copyPoints(s.points) }
func copyPoints(points []Point) []Point {
	if points == nil {
		return nil
	}
	out := make([]Point, len(points))
	for i, p := range points {
		out[i] = p
		if p.Metrics != nil {
			out[i].Metrics = append([]Metric{}, p.Metrics...)
		}
	}
	return out
}

func validScalar(value string, max int) bool {
	if len(value) == 0 || len(value) > max {
		return false
	}
	for i := range value {
		if value[i] < 32 || value[i] > 126 {
			return false
		}
	}
	return true
}
