package decision

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"testing"
)

type independentFile struct {
	Vectors []struct {
		Name, PayloadHex, PayloadSHA string
		Fields                       map[string]any `json:"parsed_fields"`
	} `json:"cases"`
}

func vectors(t testing.TB) independentFile {
	t.Helper()
	b, e := os.ReadFile("testdata/independent-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var raw struct {
		Vectors []struct {
			Name   string         `json:"name"`
			Hex    string         `json:"payload_hex"`
			SHA    string         `json:"payload_sha256"`
			Fields map[string]any `json:"parsed_fields"`
		} `json:"cases"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e = d.Decode(&raw); e != nil {
		t.Fatal(e)
	}
	if len(raw.Vectors) == 0 {
		t.Fatal("empty independent fixtures")
	}
	var out independentFile
	for _, v := range raw.Vectors {
		out.Vectors = append(out.Vectors, struct {
			Name, PayloadHex, PayloadSHA string
			Fields                       map[string]any `json:"parsed_fields"`
		}{v.Name, v.Hex, v.SHA, v.Fields})
	}
	return out
}
func claimsFromFields(t testing.TB, m map[string]any) Claims {
	t.Helper()
	var c Claims
	v := reflect.ValueOf(&c).Elem()
	for name, x := range m {
		f := v.FieldByName(name)
		if !f.IsValid() {
			t.Fatalf("unknown %s", name)
		}
		switch f.Kind() {
		case reflect.String:
			if x != nil {
				f.SetString(x.(string))
			}
		case reflect.Array:
			b, e := hex.DecodeString(x.(string))
			if e != nil || len(b) != 32 {
				t.Fatal("digest")
			}
			reflect.Copy(f, reflect.ValueOf(b))
		case reflect.Bool:
			f.SetBool(x.(bool))
		case reflect.Int64:
			n, e := strconv.ParseInt(string(x.(json.Number)), 10, 64)
			if e != nil {
				t.Fatal(e)
			}
			f.SetInt(n)
		case reflect.Uint64, reflect.Uint8:
			n, e := strconv.ParseUint(string(x.(json.Number)), 10, 64)
			if e != nil {
				t.Fatal(e)
			}
			f.SetUint(n)
		}
	}
	return c
}
func TestCodecIndependentBytes(t *testing.T) {
	for _, v := range vectors(t).Vectors {
		t.Run(v.Name, func(t *testing.T) {
			c := claimsFromFields(t, v.Fields)
			want, _ := hex.DecodeString(v.PayloadHex)
			got, e := EncodeClaims(c)
			if e != nil || !bytes.Equal(got, want) {
				t.Fatalf("independent bytes mismatch %v", e)
			}
			h := sha256.Sum256(got)
			if hex.EncodeToString(h[:]) != v.PayloadSHA {
				t.Fatal("independent hash")
			}
			decoded, e := decodeClaims(want)
			if e != nil || decoded != c {
				t.Fatal("round trip", e)
			}
			rv := reflect.ValueOf(c)
			for i := 0; i < rv.NumField(); i++ {
				changed := c
				f := reflect.ValueOf(&changed).Elem().Field(i)
				switch f.Kind() {
				case reflect.String:
					if f.String() == "" {
						f.SetString("i-2")
					} else {
						f.SetString(f.String() + "x")
					}
				case reflect.Array:
					f.Index(0).SetUint(f.Index(0).Uint() ^ 1)
				case reflect.Bool:
					f.SetBool(!f.Bool())
				case reflect.Int64:
					f.SetInt(rv.Field(i).Int() + 1)
				default:
					f.SetUint(rv.Field(i).Uint() + 1)
				}
				enc, e := EncodeClaims(changed)
				if e == nil && bytes.Equal(got, enc) {
					t.Fatalf("field not bound %s", rv.Type().Field(i).Name)
				}
			}
		})
	}
}
func TestCodecMalformed(t *testing.T) {
	v := vectors(t).Vectors[0]
	valid, _ := hex.DecodeString(v.PayloadHex)
	mutations := map[string][]byte{"empty": {}, "trailing": append(bytes.Clone(valid), 0), "truncated": valid[:len(valid)-1], "oversize": make([]byte, 8193)}
	for name, offset := range map[string]int{"unknown": 27, "duplicate": 44, "reorder": 27} {
		b := bytes.Clone(valid)
		binary.BigEndian.PutUint16(b[offset:], 99)
		mutations[name] = b
	}
	b := bytes.Clone(valid)
	b[4] ^= 1
	mutations["domain"] = b
	for name, p := range mutations {
		if _, e := decodeClaims(p); e == nil {
			t.Fatalf("accepted %s", name)
		}
	}
	for tag := 1; tag <= 33; tag++ {
		p := bytes.Clone(valid)
		off := 27
		for n := 1; n < tag; n++ {
			off += 6 + int(binary.BigEndian.Uint32(p[off+2:]))
		}
		binary.BigEndian.PutUint32(p[off+2:], 0xffffffff)
		if _, e := decodeClaims(p); e == nil {
			t.Fatalf("length %d", tag)
		}
	}
	c := claimsFromFields(t, v.Fields)
	c.ActorID = "A-1"
	if _, e := EncodeClaims(c); e == nil {
		t.Fatal("ID case")
	}
	c = claimsFromFields(t, v.Fields)
	c.IssuedAtUnixNS = 0
	if _, e := EncodeClaims(c); e == nil {
		t.Fatal("zero time")
	}
}
func replaceField(p []byte, tag int, value []byte) []byte {
	off := 27
	for n := 1; n < tag; n++ {
		off += 6 + int(binary.BigEndian.Uint32(p[off+2:]))
	}
	old := int(binary.BigEndian.Uint32(p[off+2:]))
	out := append([]byte(nil), p[:off]...)
	out = binary.BigEndian.AppendUint16(out, uint16(tag))
	out = binary.BigEndian.AppendUint32(out, uint32(len(value)))
	out = append(out, value...)
	return append(out, p[off+6+old:]...)
}
func TestCodecExactTypeAndTagWitnesses(t *testing.T) {
	valid, _ := hex.DecodeString(vectors(t).Vectors[0].PayloadHex)
	for _, tc := range []struct {
		tag   int
		value []byte
	}{{5, make([]byte, 31)}, {21, make([]byte, 7)}, {21, make([]byte, 8)}, {24, []byte{2}}, {25, []byte{0, 1}}, {10, []byte{2}}, {10, []byte{1}}, {10, []byte{0, 'i'}}, {26, make([]byte, 7)}, {33, []byte{0, 1}}, {8, []byte("A-1")}, {28, []byte{0xff}}} {
		if _, e := decodeClaims(replaceField(valid, tc.tag, tc.value)); e == nil {
			t.Fatal("accepted wrong type", tc.tag, tc.value)
		}
	}
	duplicate := bytes.Clone(valid)
	binary.BigEndian.PutUint16(duplicate[44:], 1)
	if _, e := decodeClaims(duplicate); e == nil {
		t.Fatal("duplicate")
	}
	reordered := bytes.Clone(valid)
	binary.BigEndian.PutUint16(reordered[27:], 2)
	binary.BigEndian.PutUint16(reordered[44:], 1)
	if _, e := decodeClaims(reordered); e == nil {
		t.Fatal("reordered")
	}
	if _, e := decodeClaims(valid[:len(valid)-7]); e == nil {
		t.Fatal("missing tag")
	}
}
