package action

import (
	"bytes"
	"crypto/sha256"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaxArgumentBytes = 1024

// ParsedAction retains only private owned bytes and validated fixed intent.
// A successful parse supplies no identity or authorization claim.
type ParsedAction struct {
	valid                                              bool
	operationID, sourceKind, sourceMethod, sourceRoute string
	marker, expectedVersion                            string
	input, intent                                      []byte
	inputDigest, intentDigest                          [32]byte
}

func (a ParsedAction) OperationID() string       { return a.operationID }
func (a ParsedAction) SourceKind() string        { return a.sourceKind }
func (a ParsedAction) SourceMethod() string      { return a.sourceMethod }
func (a ParsedAction) SourceRouteOrTool() string { return a.sourceRoute }
func (a ParsedAction) Arguments() (marker, expectedVersion string) {
	return a.marker, a.expectedVersion
}
func (a ParsedAction) OriginalInput() []byte  { return bytes.Clone(a.input) }
func (a ParsedAction) InputDigest() [32]byte  { return a.inputDigest }
func (a ParsedAction) IntentDigest() [32]byte { return a.intentDigest }
func (a ParsedAction) IntentBytes() []byte    { return bytes.Clone(a.intent) }

// ParseHTTP accepts a complete modeled HTTP request for one fixed operation.
// allowedGatewayAuthority is protected composition metadata, never request
// configuration or target selection. The caller owns closing r.Body. The
// parser reads at most 1025 bytes, retains a copy, and never retains its reader.
func ParseHTTP(r *http.Request, allowedGatewayAuthority string) (ParsedAction, error) {
	if r == nil {
		return ParsedAction{}, ErrInvalidRequestTarget
	}
	var selected entry
	found := false
	for _, e := range entries() {
		if r.Method == e.method && r.RequestURI == e.path {
			selected = e
			found = true
			break
		}
	}
	if !found {
		return ParsedAction{}, ErrUnsupportedOperation
	}
	u := r.URL
	if u == nil || u.Path != selected.path || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Scheme != "" || u.Host != "" || u.Opaque != "" || u.Fragment != "" || u.RawFragment != "" || u.User != nil {
		return ParsedAction{}, ErrInvalidRequestTarget
	}
	if len(r.Host) > 4096 || len(allowedGatewayAuthority) > 4096 {
		return ParsedAction{}, ErrInputLimit
	}
	if r.Host != allowedGatewayAuthority || !validAuthority(r.Host) {
		return ParsedAction{}, ErrInvalidRequestTarget
	}
	if err := validateHeaders(r.Header, r.ContentLength, selected.markerOperation); err != nil {
		return ParsedAction{}, err
	}
	if len(r.TransferEncoding) != 0 || r.ContentLength < 0 || len(r.Trailer) != 0 {
		return ParsedAction{}, ErrInvalidContent
	}
	if selected.markerOperation {
		if r.ContentLength > MaxArgumentBytes {
			return ParsedAction{}, ErrInputLimit
		}
		if r.ContentLength < 1 || r.Body == nil {
			return ParsedAction{}, ErrInvalidContent
		}
	} else if r.ContentLength != 0 {
		return ParsedAction{}, ErrInvalidContent
	}
	var raw []byte
	if r.Body != nil {
		var err error
		raw, err = io.ReadAll(io.LimitReader(r.Body, MaxArgumentBytes+1))
		if err != nil {
			return ParsedAction{}, ErrInvalidContent
		}
	}
	if len(raw) > MaxArgumentBytes {
		return ParsedAction{}, ErrInputLimit
	}
	if int64(len(raw)) != r.ContentLength {
		return ParsedAction{}, ErrInvalidContent
	}
	if !selected.markerOperation && len(raw) != 0 {
		return ParsedAction{}, ErrInvalidContent
	}
	return makeAction(selected, "http", selected.method, selected.path, raw)
}

// ParseMCPArguments parses only modeled local tool arguments, not an MCP
// envelope, session or transport. Exact tool names cannot select dynamic work.
func ParseMCPArguments(tool string, raw []byte) (ParsedAction, error) {
	var selected entry
	found := false
	for _, e := range entries() {
		if tool == e.tool {
			selected = e
			found = true
			break
		}
	}
	if !found {
		return ParsedAction{}, ErrUnsupportedOperation
	}
	if len(raw) > MaxArgumentBytes {
		return ParsedAction{}, ErrInputLimit
	}
	if !selected.markerOperation && !bytes.Equal(raw, []byte("{}")) {
		return ParsedAction{}, ErrInvalidArguments
	}
	return makeAction(selected, "mcp-arguments", "arguments", selected.tool, raw)
}
func makeAction(e entry, kind, method, route string, raw []byte) (ParsedAction, error) {
	var marker, version string
	if e.markerOperation {
		var err error
		marker, version, err = parseMarker(raw)
		if err != nil {
			return ParsedAction{}, err
		}
	}
	a := ParsedAction{valid: true, operationID: e.operationID, sourceKind: kind, sourceMethod: method, sourceRoute: route, marker: marker, expectedVersion: version, input: bytes.Clone(raw), inputDigest: sha256.Sum256(raw)}
	b, err := intentBytes(a, e)
	if err != nil {
		return ParsedAction{}, err
	}
	a.intent = b
	a.intentDigest = sha256.Sum256(b)
	return a, nil
}
func intentBytes(a ParsedAction, e entry) ([]byte, error) {
	f := frame{}
	f.strings("KAG-LOCAL-ACTION-INTENT/v1", SchemaVersion, CatalogID, CatalogVersion)
	f.d(CatalogDigest())
	f.strings(a.sourceKind, a.sourceMethod, a.sourceRoute)
	f.d(a.inputDigest)
	kind := "none"
	if e.markerOperation {
		kind = "marker-version"
	}
	f.strings(e.operationID, TargetID, e.resourceID, e.method, e.path, kind, a.marker, a.expectedVersion)
	return f.b, f.err
}
func validAuthority(s string) bool {
	if s == "" || strings.ContainsAny(s, "/@?#\\ \t\r\n") {
		return false
	}
	host := s
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return false
		}
		host = s[1:end]
		if net.ParseIP(host) == nil || !strings.Contains(host, ":") {
			return false
		}
		tail := s[end+1:]
		if tail == "" {
			return true
		}
		return strings.HasPrefix(tail, ":") && validPort(tail[1:])
	}
	if strings.Contains(s, ":") {
		var port string
		var err error
		host, port, err = net.SplitHostPort(s)
		if err != nil || !validPort(port) {
			return false
		}
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, part := range strings.Split(host, ".") {
		if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for i := 0; i < len(part); i++ {
			c := part[i]
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}
func validPort(s string) bool {
	if len(s) == 0 || len(s) > 5 {
		return false
	}
	for i := range s {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	n, e := strconv.ParseUint(s, 10, 16)
	return e == nil && n > 0
}
func headerToken(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := range s {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			continue
		}
		return false
	}
	return true
}
func headerValue(s string) bool {
	for i := range s {
		c := s[i]
		if (c < 32 && c != '\t') || c == 127 {
			return false
		}
	}
	return true
}
func metadataName(s string) bool {
	switch s {
	case "content-type", "content-length", "content-encoding", "transfer-encoding", "trailer", "expect", "upgrade", "host":
		return true
	}
	return false
}
func overrideName(s string) bool {
	return s == "forwarded" || strings.HasPrefix(s, "x-forwarded-") || strings.HasPrefix(s, "x-original-") || s == "x-rewrite-url" || s == "x-http-method-override" || s == "x-method-override" || s == "x-http-method" || strings.HasPrefix(s, "x-target-") || s == "x-target" || s == "x-operation" || s == "x-action-id"
}
func validateHeaders(h http.Header, length int64, marker bool) error {
	// Bound the complete metadata before allocating an ordering slice. This pass
	// only determines input_limit, so mixed invalid fields cannot alter priority.
	total, count := 0, 0
	for key, values := range h {
		if len(key) > 4096 || len(key) > 16384-total {
			return ErrInputLimit
		}
		total += len(key)
		if len(values) > 64-count {
			return ErrInputLimit
		}
		count += len(values)
		for _, value := range values {
			if len(value) > 4096 || len(value) > 16384-total {
				return ErrInputLimit
			}
			total += len(value)
		}
	}
	// Unique map keys and the byte limit bound this allocation, including the
	// sole possible empty key. Sorting makes every error category deterministic.
	keys := make([]string, 0, len(h))
	for key := range h {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	seen := make(map[string]bool)
	contentType := ""
	hasContentType := false
	for _, key := range keys {
		values := h[key]
		if !headerToken(key) {
			return ErrInvalidContent
		}
		name := strings.ToLower(key)
		if metadataName(name) {
			if seen[name] || len(values) != 1 {
				return ErrInvalidContent
			}
			seen[name] = true
		}
		if overrideName(name) {
			return ErrInvalidRequestTarget
		}
		switch name {
		case "content-encoding", "transfer-encoding", "trailer", "expect", "upgrade", "host":
			return ErrInvalidContent
		}
		for _, value := range values {
			if !headerValue(value) {
				return ErrInvalidContent
			}
		}
		if name == "content-type" {
			contentType = values[0]
			hasContentType = true
		}
		if name == "content-length" && values[0] != strconv.FormatInt(length, 10) {
			return ErrInvalidContent
		}
	}
	if marker {
		if !hasContentType || contentType != "application/json" {
			return ErrInvalidContent
		}
	} else if hasContentType {
		return ErrInvalidContent
	}
	return nil
}

// asciiLexer handles a flat narrow schema without recursion or generic maps.
// Every retained token is <=1024 bytes; nested opening tokens fail immediately.
type asciiLexer struct {
	raw []byte
	pos int
}

func (l *asciiLexer) ws() {
	for l.pos < len(l.raw) {
		switch l.raw[l.pos] {
		case ' ', '\t', '\n', '\r':
			l.pos++
		default:
			return
		}
	}
}
func (l *asciiLexer) take(c byte) bool {
	l.ws()
	if l.pos < len(l.raw) && l.raw[l.pos] == c {
		l.pos++
		return true
	}
	return false
}
func (l *asciiLexer) str() (string, bool) {
	l.ws()
	if l.pos >= len(l.raw) || l.raw[l.pos] != '"' {
		return "", false
	}
	l.pos++
	start := l.pos
	for l.pos < len(l.raw) {
		c := l.raw[l.pos]
		if c == '"' {
			s := string(l.raw[start:l.pos])
			l.pos++
			return s, true
		}
		if c == '\\' || c < 32 || c > 126 {
			return "", false
		}
		l.pos++
	}
	return "", false
}
func parseMarker(raw []byte) (string, string, error) {
	if len(raw) > MaxArgumentBytes {
		return "", "", ErrInputLimit
	}
	if !utf8.Valid(raw) || bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		return "", "", ErrInvalidArguments
	}
	l := asciiLexer{raw: raw}
	if !l.take('{') {
		return "", "", ErrInvalidArguments
	}
	var marker, version string
	seenMarker, seenVersion := false, false
	for member := 0; member < 2; member++ {
		if member > 0 && !l.take(',') {
			return "", "", ErrInvalidArguments
		}
		key, ok := l.str()
		if !ok || !l.take(':') {
			return "", "", ErrInvalidArguments
		}
		value, ok := l.str()
		if !ok {
			return "", "", ErrInvalidArguments
		}
		switch key {
		case "marker":
			if seenMarker {
				return "", "", ErrInvalidArguments
			}
			marker = value
			seenMarker = true
		case "expected_version":
			if seenVersion {
				return "", "", ErrInvalidArguments
			}
			version = value
			seenVersion = true
		default:
			return "", "", ErrInvalidArguments
		}
	}
	if !l.take('}') {
		return "", "", ErrInvalidArguments
	}
	l.ws()
	if l.pos != len(raw) || !seenMarker || !seenVersion || (marker != "clear" && marker != "set") {
		return "", "", ErrInvalidArguments
	}
	if _, ok := canonicalUint64(version); !ok {
		return "", "", ErrInvalidArguments
	}
	return marker, version, nil
}
func canonicalUint64(s string) (uint64, bool) {
	if len(s) == 0 || len(s) > 20 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	for i := range s {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, e := strconv.ParseUint(s, 10, 64)
	return n, e == nil
}
