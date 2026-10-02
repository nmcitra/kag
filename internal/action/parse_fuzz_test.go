package action

import (
	"bytes"
	"crypto/sha256"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var versionLiteral = `(0|[1-9][0-9]{0,19})`
var jsonWS = `[ \t\r\n]*`
var markerFirst = regexp.MustCompile(`^` + jsonWS + `\{` + jsonWS + `"marker"` + jsonWS + `:` + jsonWS + `"(clear|set)"` + jsonWS + `,` + jsonWS + `"expected_version"` + jsonWS + `:` + jsonWS + `"` + versionLiteral + `"` + jsonWS + `\}` + jsonWS + `$`)
var versionFirst = regexp.MustCompile(`^` + jsonWS + `\{` + jsonWS + `"expected_version"` + jsonWS + `:` + jsonWS + `"` + versionLiteral + `"` + jsonWS + `,` + jsonWS + `"marker"` + jsonWS + `:` + jsonWS + `"(clear|set)"` + jsonWS + `\}` + jsonWS + `$`)

// oracleMarker uses two fixed regular expressions, independent of the lexer.
func oracleMarker(raw []byte) (marker, version string, ok bool) {
	if len(raw) > 1024 {
		return "", "", false
	}
	m := markerFirst.FindSubmatch(raw)
	if m != nil {
		marker, version = string(m[1]), string(m[2])
	} else {
		m = versionFirst.FindSubmatch(raw)
		if m == nil {
			return "", "", false
		}
		marker, version = string(m[2]), string(m[1])
	}
	_, e := strconv.ParseUint(version, 10, 64)
	return marker, version, e == nil
}
func assertParsedOracle(t testing.TB, a ParsedAction, raw []byte) {
	t.Helper()
	if len(a.OriginalInput()) > 1024 || len(a.IntentBytes()) > 8192 || a.InputDigest() != sha256.Sum256(raw) || !bytes.Equal(a.OriginalInput(), raw) {
		t.Fatal("source bounds/digest")
	}
	if a.OperationID() == "lab.read_status" {
		m, v := a.Arguments()
		if m != "" || v != "" {
			t.Fatal("read args")
		}
		if a.SourceKind() == "http" {
			if len(raw) != 0 {
				t.Fatal("status HTTP bytes")
			}
		} else if string(raw) != "{}" {
			t.Fatal("MCP status bytes")
		}
	} else if a.OperationID() == "lab.set_marker" {
		m, v, ok := oracleMarker(raw)
		am, av := a.Arguments()
		if !ok || m != am || v != av {
			t.Fatal("independent schema oracle")
		}
	} else {
		t.Fatal("dynamic operation")
	}
	if !bytes.Equal(a.IntentBytes(), refIntent(t, a)) {
		t.Fatal("intent reference")
	}
	before := a.IntentDigest()
	snapshot := a.IntentBytes()
	if len(snapshot) > 0 {
		snapshot[0] ^= 255
	}
	copyInput := a.OriginalInput()
	if len(copyInput) > 0 {
		copyInput[0] ^= 255
	}
	if a.IntentDigest() != before || !bytes.Equal(a.OriginalInput(), raw) {
		t.Fatal("returned mutation")
	}
}
func FuzzParseArguments(f *testing.F) {
	f.Add("lab.read_status", []byte("{}"))
	f.Add("lab.set_marker", []byte(markerZero))
	f.Add("lab.set_marker", []byte(` {"expected_version":"18446744073709551615","marker":"set"} `))
	for _, raw := range badArguments {
		f.Add("lab.set_marker", []byte(raw))
	}
	for _, raw := range []string{`{"marker":"clear","expected_version":"0","url":"x"}`, string([]byte{0xff}), "\xef\xbb\xbf" + markerZero, markerZero + string(make([]byte, 1025))} {
		f.Add("lab.set_marker", []byte(raw))
	}
	f.Add("LAB.read_status", []byte("{}"))
	f.Add("lab.read_status", []byte("{ }"))
	f.Fuzz(func(t *testing.T, tool string, raw []byte) {
		original := bytes.Clone(raw)
		a, e := ParseMCPArguments(tool, raw)
		b, other := ParseMCPArguments(tool, raw)
		if (e == nil) != (other == nil) || (e != nil && e.Error() != other.Error()) || a.IntentDigest() != b.IntentDigest() || !bytes.Equal(a.IntentBytes(), b.IntentBytes()) {
			t.Fatal("nondeterministic parse")
		}
		if e != nil {
			assertNoAction(t, a, e)
			return
		}
		if (tool != "lab.read_status" && tool != "lab.set_marker") || a.SourceKind() != "mcp-arguments" || a.SourceMethod() != "arguments" || a.SourceRouteOrTool() != tool {
			t.Fatal("tool/source oracle")
		}
		assertParsedOracle(t, a, original)
		if len(raw) > 0 {
			raw[0] ^= 255
		}
		if !bytes.Equal(a.OriginalInput(), original) {
			t.Fatal("input mutation retained")
		}
	})
}

// oracleHTTPHeaders independently specifies accepted bounded transport metadata.
// It does not call the production validator or establish wire framing safety.
var headerNamePattern = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
var forbiddenOverridePattern = regexp.MustCompile(`^(forwarded|x-forwarded-.*|x-original-.*|x-rewrite-url|x-http-method-override|x-method-override|x-http-method|x-target(-.*)?|x-operation|x-action-id)$`)

func oracleHTTPHeaders(t testing.TB, h http.Header, method string, length int64) {
	t.Helper()
	total, count := 0, 0
	seen := map[string]bool{}
	ctype := ""
	hasType := false
	metadata := map[string]bool{"content-type": true, "content-length": true, "content-encoding": true, "transfer-encoding": true, "trailer": true, "expect": true, "upgrade": true, "host": true}
	prohibited := map[string]bool{"content-encoding": true, "transfer-encoding": true, "trailer": true, "expect": true, "upgrade": true, "host": true}
	for key, values := range h {
		if len(key) > 4096 || !headerNamePattern.MatchString(key) {
			t.Fatal("accepted header name")
		}
		total += len(key)
		count += len(values)
		name := strings.ToLower(key)
		if forbiddenOverridePattern.MatchString(name) || prohibited[name] {
			t.Fatal("accepted routing/framing override")
		}
		if metadata[name] {
			if seen[name] || len(values) != 1 {
				t.Fatal("accepted repeated metadata")
			}
			seen[name] = true
		}
		for _, value := range values {
			if len(value) > 4096 {
				t.Fatal("accepted header value bound")
			}
			total += len(value)
			for i := range value {
				if (value[i] < 32 && value[i] != '\t') || value[i] == 127 {
					t.Fatal("accepted invalid header character")
				}
			}
		}
		if name == "content-type" {
			hasType = true
			ctype = values[0]
		}
		if name == "content-length" && values[0] != strconv.FormatInt(length, 10) {
			t.Fatal("accepted inconsistent content length")
		}
	}
	if total > 16384 || count > 64 {
		t.Fatal("accepted metadata aggregate bounds")
	}
	if method == "POST" {
		if !hasType || ctype != "application/json" {
			t.Fatal("accepted nonexact marker content type")
		}
	} else if hasType {
		t.Fatal("accepted status content type")
	}
}

func FuzzParseHTTPMetadata(f *testing.F) {
	f.Add("GET", "/lab/status", authority, "X-Ordinary", "v", []byte{}, int64(0), uint8(0))
	f.Add("POST", "/lab/marker", authority, "X-Ordinary", "v", []byte(markerZero), int64(0), uint8(0))
	f.Add("GET", "/lab/status?", authority, "X-Ordinary", "v", []byte{}, int64(0), uint8(0))
	f.Add("get", "/lab/status", authority, "X-Ordinary", "v", []byte{}, int64(0), uint8(0))
	f.Add("POST", "/lab/marker", authority, "X-Target-URL", "x", []byte(markerZero), int64(0), uint8(0))
	f.Add("POST", "/lab/marker", authority, "Content-Type", "application/json", []byte(markerZero), int64(1), uint8(0))
	f.Add("POST", "/lab/marker", authority, "content-type", "application/json", []byte(markerZero), int64(0), uint8(0))
	f.Add("POST", "/lab/marker", authority, "X-Ordinary", "v", []byte(`{"marker":"clear","marker":"set","expected_version":"0"}`), int64(0), uint8(0))
	f.Add("POST", "/lab/marker", authority, "X-Ordinary", "v", []byte(`{"marker":"clear","expected_version":"18446744073709551616"}`), int64(0), uint8(0))
	f.Add("POST", "/lab/marker", authority, "X-Ordinary", "v", []byte(markerZero), int64(0), uint8(1))
	f.Add("POST", "/lab/marker", authority, "X-Ordinary", "v", []byte(`{"marker":"clear","expected_version":"0","url":"x"}`), int64(0), uint8(0))
	f.Add("POST", "/lab/marker", authority, "X-Ordinary", "v", []byte(`{"marker":"cl\u0065ar","expected_version":"0"}`), int64(0), uint8(0))
	f.Add("POST", "/lab/marker", authority, "X-Ordinary", "v", []byte(markerZero+string(make([]byte, 1025))), int64(0), uint8(0))

	f.Fuzz(func(t *testing.T, method, path, host, key, value string, raw []byte, delta int64, flag uint8) {
		r := request(method, path, raw)
		r.Host = host
		if key != "" {
			r.Header[key] = []string{value}
		}
		r.ContentLength += delta
		switch flag % 8 {
		case 1:
			r.URL.RawPath = path
		case 2:
			r.URL.RawQuery = "x"
		case 3:
			r.URL.ForceQuery = true
		case 4:
			r.TransferEncoding = []string{"chunked"}
		case 5:
			r.URL.Scheme = "http"
		case 6:
			r.Header["Content-Type"] = []string{"application/json", "application/json"}
		case 7:
			r.URL.Path = "/different"
		}
		// Create a second body reader without normalizing or mutating metadata.
		rr := r.Clone(r.Context())
		rr.Body = request(method, path, raw).Body
		original := bytes.Clone(raw)
		a, e := ParseHTTP(r, authority)
		b, other := ParseHTTP(rr, authority)
		if (e == nil) != (other == nil) || (e != nil && e.Error() != other.Error()) || a.IntentDigest() != b.IntentDigest() || !bytes.Equal(a.IntentBytes(), b.IntentBytes()) {
			t.Fatal("nondeterministic HTTP parse")
		}
		if e != nil {
			assertNoAction(t, a, e)
			return
		}
		if !((method == "GET" && path == "/lab/status") || (method == "POST" && path == "/lab/marker")) || host != authority || flag%8 != 0 || delta != 0 {
			t.Fatal("accepted metadata outside fixed request")
		}
		oracleHTTPHeaders(t, r.Header, method, r.ContentLength)
		assertParsedOracle(t, a, original)
		if len(raw) > 0 {
			raw[0] ^= 255
		}
		if !bytes.Equal(a.OriginalInput(), original) {
			t.Fatal("source alias retained")
		}
	})
}
