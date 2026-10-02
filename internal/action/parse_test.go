package action

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const authority = "kag.fixture.invalid"
const markerZero = `{"marker":"clear","expected_version":"0"}`

func request(method, path string, raw []byte) *http.Request {
	r := &http.Request{Method: method, RequestURI: path, URL: &url.URL{Path: path}, Host: authority, Header: make(http.Header), ContentLength: int64(len(raw))}
	if raw != nil {
		r.Body = io.NopCloser(bytes.NewReader(raw))
	}
	if method == "POST" {
		r.Header["Content-Type"] = []string{"application/json"}
	}
	return r
}
func assertNoAction(t testing.TB, a ParsedAction, e error) {
	t.Helper()
	if e == nil || a.OperationID() != "" || len(a.IntentBytes()) != 0 || a.InputDigest() != ([32]byte{}) || a.IntentDigest() != ([32]byte{}) {
		t.Fatalf("usable failed action: %q %v", a.OperationID(), e)
	}
}
func parseVector(t testing.TB, v goldenVector) ParsedAction {
	t.Helper()
	raw := unhex(t, v.RawHex)
	var a ParsedAction
	var e error
	if v.SourceKind == "http" {
		a, e = ParseHTTP(request(v.SourceMethod, v.SourceRoute, raw), authority)
	} else {
		a, e = ParseMCPArguments(v.SourceRoute, raw)
	}
	if e != nil {
		t.Fatalf("%s: %v", v.Name, e)
	}
	return a
}
func refIntent(t testing.TB, a ParsedAction) []byte {
	t.Helper()
	e, ok := LookupOperation(a.OperationID())
	if !ok {
		t.Fatal("unknown result")
	}
	c := sha256.Sum256(unhex(t, golden(t).CatalogHex))
	input := a.InputDigest()
	out := refStrings("KAG-LOCAL-ACTION-INTENT/v1", "kag-local-action-v1", "kag-local-lab", "1")
	out = append(out, refFrame(c[:])...)
	out = append(out, refStrings(a.SourceKind(), a.SourceMethod(), a.SourceRouteOrTool())...)
	out = append(out, refFrame(input[:])...)
	kind := "none"
	m, v := a.Arguments()
	if e.OperationID == "lab.set_marker" {
		kind = "marker-version"
	}
	return append(out, refStrings(e.OperationID, "lab-fixture-01", e.ResourceID, e.Method, e.Path, kind, m, v)...)
}
func TestParseGoldenIntent(t *testing.T) {
	f := golden(t)
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			a := parseVector(t, v)
			if a.OperationID() != v.OperationID {
				t.Fatal("operation")
			}
			checkBytesSHA(t, a.IntentBytes(), v.IntentHex, v.IntentSHA)
			if a.IntentDigest() != sha256.Sum256(unhex(t, v.IntentHex)) {
				t.Fatal("intent digest")
			}
			d := a.InputDigest()
			if hex.EncodeToString(d[:]) != v.InputSHA {
				t.Fatal("original digest")
			}
			if !bytes.Equal(refIntent(t, a), a.IntentBytes()) {
				t.Fatal("reference intent")
			}
		})
	}
}
func TestParseHTTPPositive(t *testing.T) {
	a, e := ParseHTTP(request("GET", "/lab/status", nil), authority)
	if e != nil || a.OperationID() != "lab.read_status" {
		t.Fatal(e)
	}
	for _, raw := range []string{markerZero, `{"expected_version":"18446744073709551615","marker":"set"}`, " \n { \t\"expected_version\" : \"0\" , \"marker\" : \"set\" } \r\n"} {
		a, e = ParseHTTP(request("POST", "/lab/marker", []byte(raw)), authority)
		if e != nil {
			t.Fatal(e)
		}
		if a.InputDigest() != sha256.Sum256([]byte(raw)) {
			t.Fatal("input changed")
		}
		if !bytes.Equal(a.IntentBytes(), refIntent(t, a)) {
			t.Fatal("intent")
		}
	}
	raw := markerZero + strings.Repeat(" ", 1024-len(markerZero))
	a, e = ParseHTTP(request("POST", "/lab/marker", []byte(raw)), authority)
	if e != nil || len(a.OriginalInput()) != 1024 {
		t.Fatal("1024 boundary", e)
	}
}
func TestParseHTTPRouteNegatives(t *testing.T) {
	for _, path := range []string{"/lab/status/", "/Lab/status", "/lab/./status", "/lab//status", "/lab/status;foo", "/lab/%73tatus", "/lab/%2fstatus", "/lab/%2estatus", "/lab/%252fstatus", "/lab/status?x=1", "/lab/status?", "http://kag.fixture.invalid/lab/status", "kag.fixture.invalid:443", "*"} {
		t.Run(path, func(t *testing.T) { a, e := ParseHTTP(request("GET", path, nil), authority); assertNoAction(t, a, e) })
	}
	for _, method := range []string{"get", "POST", "CONNECT", "TRACE", "OPTIONS", "HEAD", "GET "} {
		t.Run(method, func(t *testing.T) {
			a, e := ParseHTTP(request(method, "/lab/status", nil), authority)
			assertNoAction(t, a, e)
		})
	}
	changes := map[string]func(*http.Request){
		"nilURL": func(r *http.Request) { r.URL = nil }, "RequestURI": func(r *http.Request) { r.RequestURI = "/lab/marker" }, "path": func(r *http.Request) { r.URL.Path = "/lab/marker" }, "rawpath": func(r *http.Request) { r.URL.RawPath = "/lab/status" }, "query": func(r *http.Request) { r.URL.RawQuery = "x=1" }, "forcequery": func(r *http.Request) { r.URL.ForceQuery = true }, "scheme": func(r *http.Request) { r.URL.Scheme = "https" }, "urlhost": func(r *http.Request) { r.URL.Host = authority }, "opaque": func(r *http.Request) { r.URL.Opaque = "//" }, "fragment": func(r *http.Request) { r.URL.Fragment = "f" }, "rawfragment": func(r *http.Request) { r.URL.RawFragment = "f" }, "userinfo": func(r *http.Request) { r.URL.User = url.User("actor") },
	}
	for name, f := range changes {
		t.Run(name, func(t *testing.T) {
			r := request("GET", "/lab/status", nil)
			f(r)
			a, e := ParseHTTP(r, authority)
			assertNoAction(t, a, e)
		})
	}
	a, e := ParseHTTP(nil, authority)
	assertNoAction(t, a, e)
	for _, host := range []string{"", "other.invalid", "KAG.fixture.invalid", "kag.fixture.invalid:443", "user@kag.fixture.invalid", "kag.fixture.invalid/", "kag.fixture.invalid\x00", "[broken", "a b"} {
		t.Run("host"+host, func(t *testing.T) {
			r := request("GET", "/lab/status", nil)
			r.Host = host
			a, e := ParseHTTP(r, authority)
			assertNoAction(t, a, e)
		})
	}
	for _, host := range []string{"user@kag.fixture.invalid", "[broken", "a b", ""} {
		r := request("GET", "/lab/status", nil)
		r.Host = host
		a, e := ParseHTTP(r, host)
		assertNoAction(t, a, e)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("sensitive fake reader error") }
func (failingReader) Close() error             { return nil }

type ownedReader struct {
	*bytes.Reader
	closed bool
}

func (r *ownedReader) Close() error { r.closed = true; return nil }
func TestParseHTTPContentNegatives(t *testing.T) {
	tests := map[string]func(*http.Request){
		"noctype": func(r *http.Request) { r.Header.Del("Content-Type") }, "duplicatectype": func(r *http.Request) { r.Header["Content-Type"] = []string{"application/json", "application/json"} }, "mixedctype": func(r *http.Request) { r.Header["content-type"] = []string{"application/json"} }, "charset": func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-8") }, "comma": func(r *http.Request) { r.Header.Set("Content-Type", "application/json,application/json") }, "otherctype": func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, "unknownlength": func(r *http.Request) { r.ContentLength = -1 }, "zero": func(r *http.Request) { r.ContentLength = 0 }, "short": func(r *http.Request) { r.ContentLength-- }, "long": func(r *http.Request) { r.ContentLength++ }, "oversize": func(r *http.Request) { r.ContentLength = 1025 }, "nilbody": func(r *http.Request) { r.Body = nil }, "readerror": func(r *http.Request) { r.Body = failingReader{} }, "transfer": func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }, "trailer": func(r *http.Request) { r.Trailer = http.Header{"X-Trailer": []string{"x"}} }, "contentlengthduplicate": func(r *http.Request) { r.Header["Content-Length"] = []string{"39", "39"} }, "contentlengthmixed": func(r *http.Request) {
			r.Header["Content-Length"] = []string{"39"}
			r.Header["content-length"] = []string{"39"}
		}, "contentlengthlie": func(r *http.Request) { r.Header["Content-Length"] = []string{"1"} },
	}
	for name, f := range tests {
		t.Run(name, func(t *testing.T) {
			r := request("POST", "/lab/marker", []byte(markerZero))
			f(r)
			a, e := ParseHTTP(r, authority)
			assertNoAction(t, a, e)
			if e.Error() == "sensitive fake reader error" {
				t.Fatal("reader content leaked")
			}
		})
	}
	for _, key := range []string{"Content-Encoding", "Transfer-Encoding", "Trailer", "Expect", "Upgrade", "Forwarded", "X-Forwarded-Host", "X-Forwarded-For", "X-Original-URL", "X-Rewrite-URL", "X-HTTP-Method-Override", "X-Method-Override", "X-Target-URL", "X-Target-Host"} {
		t.Run(key, func(t *testing.T) {
			r := request("GET", "/lab/status", nil)
			r.Header[key] = []string{""}
			a, e := ParseHTTP(r, authority)
			assertNoAction(t, a, e)
		})
	}
	for _, raw := range [][]byte{[]byte("x"), []byte(markerZero)} {
		a, e := ParseHTTP(request("GET", "/lab/status", raw), authority)
		assertNoAction(t, a, e)
	}
	r := request("GET", "/lab/status", nil)
	r.Header.Set("Content-Type", "application/json")
	a, e := ParseHTTP(r, authority)
	assertNoAction(t, a, e)
	r = request("POST", "/lab/marker", []byte(markerZero+strings.Repeat(" ", 1025)))
	r.ContentLength = int64(len(markerZero))
	a, e = ParseHTTP(r, authority)
	assertNoAction(t, a, e)
	owner := &ownedReader{Reader: bytes.NewReader([]byte(markerZero))}
	r = request("POST", "/lab/marker", []byte(markerZero))
	r.Body = owner
	_, e = ParseHTTP(r, authority)
	if e != nil || owner.closed {
		t.Fatal("caller owns body close", e)
	}
}
func TestParseHTTPHeaderLimits(t *testing.T) {
	for name, h := range map[string]http.Header{
		"longname": {strings.Repeat("A", 4097): []string{"v"}}, "longvalue": {"X-Test": []string{strings.Repeat("a", 4097)}}, "badname": {"X Test": []string{"v"}}, "badvalue": {"X-Test": []string{"v\r\nx"}}, "nulvalue": {"X-Test": []string{"v\x00"}}, "total": {"X-1": []string{strings.Repeat("a", 4096)}, "X-2": []string{strings.Repeat("a", 4096)}, "X-3": []string{strings.Repeat("a", 4096)}, "X-4": []string{strings.Repeat("a", 4096)}}, "count": {"X-Test": make([]string, 65)},
	} {
		t.Run(name, func(t *testing.T) {
			r := request("GET", "/lab/status", nil)
			r.Header = h
			a, e := ParseHTTP(r, authority)
			assertNoAction(t, a, e)
		})
	}
	r := request("GET", "/lab/status", nil)
	r.Header["X-Ordinary"] = []string{"v", "w"}
	r.Header["X-Pad"] = []string{strings.Repeat("a", 4096)}
	a, e := ParseHTTP(r, authority)
	if e != nil || a.OperationID() == "" {
		t.Fatal("ordinary transport header", e)
	}
}

var badArguments = []string{
	``, `{}`, `[]`, `null`, `true`, `{"marker":"clear"}`, `{"expected_version":"0"}`, `{"marker":"clear","marker":"set","expected_version":"0"}`, `{"marker":"clear","expected_version":"0","expected_version":"1"}`,
	`{"Marker":"clear","expected_version":"0"}`, `{"mark\u0065r":"clear","expected_version":"0"}`, `{"marker":"cl\u0065ar","expected_version":"0"}`, `{"marker":null,"expected_version":"0"}`, `{"marker":true,"expected_version":"0"}`, `{"marker":1,"expected_version":"0"}`, `{"marker":[],"expected_version":"0"}`, `{"marker":{},"expected_version":"0"}`, `{"marker":"clear","expected_version":0}`, `{"marker":"clear","expected_version":null}`, `{"marker":"","expected_version":"0"}`, `{"marker":"other","expected_version":"0"}`, `{"marker":"https://example.invalid","expected_version":"0"}`, `{"marker":"rm -rf /","expected_version":"0"}`, `{"marker":"SELECT x","expected_version":"0"}`,
	`{"marker":"clear","expected_version":""}`, `{"marker":"clear","expected_version":"00"}`, `{"marker":"clear","expected_version":"+1"}`, `{"marker":"clear","expected_version":"-1"}`, `{"marker":"clear","expected_version":"1e2"}`, `{"marker":"clear","expected_version":"1.0"}`, `{"marker":"clear","expected_version":" 1"}`, `{"marker":"clear","expected_version":"١"}`, `{"marker":"clear","expected_version":"18446744073709551616"}`, `{"marker":"clear","expected_version":"100000000000000000000"}`, `{"marker":"clear","expected_version":"0",}`, `{"marker":"clear","expected_version":"0"} {}`, `{"marker":"clear","expected_version":"0"}x`, `{"marker":"\ud800","expected_version":"0"}`, `{"marker":"clear","expected_version":"0"`,
}

func TestArgumentNegatives(t *testing.T) {
	all := append([]string{}, badArguments...)
	for _, k := range []string{"url", "operation", "actor", "risk", "target", "headers", "nonce", "tenant", "policy", "fence", "method", "content_type"} {
		all = append(all, `{"marker":"clear","expected_version":"0","`+k+`":"x"}`)
	}
	all = append(all, string([]byte{0xff}), "\xef\xbb\xbf"+markerZero, `{"marker":`+strings.Repeat("[", 1000), markerZero+strings.Repeat(" ", 1025))
	for i, raw := range all {
		t.Run(strings.Join([]string{"case", string(rune(i + 65))}, ""), func(t *testing.T) {
			a, e := ParseMCPArguments("lab.set_marker", []byte(raw))
			assertNoAction(t, a, e)
			a, e = ParseHTTP(request("POST", "/lab/marker", []byte(raw)), authority)
			assertNoAction(t, a, e)
		})
	}
}
func TestParseMCP(t *testing.T) {
	for _, raw := range []string{markerZero, `{"marker":"set","expected_version":"18446744073709551615"}`} {
		a, e := ParseMCPArguments("lab.set_marker", []byte(raw))
		if e != nil || a.OperationID() != "lab.set_marker" {
			t.Fatal(e)
		}
	}
	for _, tool := range []string{"Lab.read_status", "lab.read_status ", "lab/set_marker", "unknown", "", "lab.set_marker\x00"} {
		a, e := ParseMCPArguments(tool, []byte("{}"))
		assertNoAction(t, a, e)
	}
	for _, raw := range []string{"", " {}", "{ }", "{} ", "[]", "null", "{}{}"} {
		a, e := ParseMCPArguments("lab.read_status", []byte(raw))
		assertNoAction(t, a, e)
	}
	a, e := ParseMCPArguments("lab.read_status", []byte("{}"))
	if e != nil || a.OperationID() != "lab.read_status" {
		t.Fatal(e)
	}
}
func TestParseOwnershipAndByteScope(t *testing.T) {
	raw := []byte(markerZero)
	a, e := ParseMCPArguments("lab.set_marker", raw)
	if e != nil {
		t.Fatal(e)
	}
	before := a.IntentDigest()
	raw[2] = 'X'
	snap := a.OriginalInput()
	snap[0] = 'X'
	intent := a.IntentBytes()
	intent[0] ^= 255
	if a.IntentDigest() != before || string(a.OriginalInput()) != markerZero || !bytes.Equal(a.IntentBytes(), refIntent(t, a)) {
		t.Fatal("owned bytes")
	}
	b, e := ParseMCPArguments("lab.set_marker", []byte(` {"expected_version":"0","marker":"clear"} `))
	if e != nil {
		t.Fatal(e)
	}
	am, av := a.Arguments()
	bm, bv := b.Arguments()
	if am != bm || av != bv || a.InputDigest() == b.InputDigest() || a.IntentDigest() == b.IntentDigest() {
		t.Fatal("semantic/source separation")
	}
	h, e := ParseHTTP(request("POST", "/lab/marker", []byte(markerZero)), authority)
	if e != nil || h.OperationID() != a.OperationID() || h.IntentDigest() == a.IntentDigest() {
		t.Fatal("HTTP MCP byte scope", e)
	}
}

func TestParseHTTPDeterministicErrorCategories(t *testing.T) {
	// Independent minimized fuzz input: duplicate content metadata and an override.
	// Refusal must have one stable category regardless of Go map iteration order.
	for i := 0; i < 1000; i++ {
		r := request("POST", "/lab/marker", []byte("27"))
		r.Header["X-Target-URL"] = []string{"9"}
		r.Header["Content-Type"] = []string{"application/json", "application/json"}
		a, e := ParseHTTP(r, authority)
		assertNoAction(t, a, e)
		if e != ErrInvalidContent {
			t.Fatalf("iteration %d: nondeterministic category %v", i, e)
		}
	}
}
