// kag-lab is an experimental composition for synthetic pressure tests only.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/nmcitra/kag/internal/action"
	"github.com/nmcitra/kag/internal/authn"
	"github.com/nmcitra/kag/internal/ingress"
	"github.com/nmcitra/kag/internal/labruntime"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

type principalList []string

func (p *principalList) String() string { return fmt.Sprintf("%d configured", len(*p)) }
func (p *principalList) Set(s string) error {
	if len(s) != 76 || s[:12] != "cert-sha256:" || len(*p) >= 4 {
		return errors.New("principal_invalid")
	}
	b, e := hex.DecodeString(s[12:])
	if e != nil || len(b) != 32 || hex.EncodeToString(b) != s[12:] {
		return errors.New("principal_invalid")
	}
	for _, old := range *p {
		if old == s {
			return errors.New("principal_duplicate")
		}
	}
	*p = append(*p, s)
	return nil
}

type listener struct {
	a       *authn.Acceptor
	addr    net.Addr
	handles chan authn.TransportHandle
	ctx     context.Context
	cancel  context.CancelFunc
}

func (l *listener) Accept() (net.Conn, error) {
	for {
		accepted, e := l.a.Accept(l.ctx)
		if e != nil {
			if l.ctx.Err() == nil {
				continue
			}
			return nil, e
		}
		l.handles <- accepted.Handle()
		return accepted.Conn(), nil
	}
}
func (l *listener) Close() error   { l.cancel(); return l.a.Close() }
func (l *listener) Addr() net.Addr { return l.addr }
func run() error {
	mode := flag.String("mode", "gateway", "gateway or target")
	listen := flag.String("listen", ":8443", "listen address")
	authority := flag.String("authority", "", "exact request host authority")
	serverCert := flag.String("server-cert", "", "private lab certificate path")
	serverKey := flag.String("server-key", "", "private lab key path")
	caPath := flag.String("client-ca", "", "client CA path")
	journal := flag.String("journal", "", "private durable journal path")
	budget := flag.Uint64("budget", 4, "shared episode effect budget")
	spacing := flag.Duration("spacing", time.Minute, "minimum dispatch interval")
	principals := flag.String("principals", "", "protected JSON fingerprint to actor mapping")
	inspectURL := flag.String("inspect-url", "", "protected HTTPS target inspection origin")
	var inspectorPrincipals principalList
	flag.Var(&inspectorPrincipals, "inspector-principal", "target read-only gateway fingerprint; repeat for two gateways")
	ownerURL := flag.String("owner-url", "", "protected HTTPS target owner reservation origin")
	ownerDeclarationDigest := flag.String("owner-declaration-digest", "", "modeled owner declaration SHA-256 digest")
	ownerFloor := flag.Uint64("owner-floor", 70, "modeled owner target inventory floor")
	target := flag.String("target-url", "", "protected HTTPS Envoy target origin")
	bridge := flag.String("decision-url", "", "protected HTTPS KIL bridge /decision")
	clientCert := flag.String("client-cert", "", "gateway upstream certificate")
	clientKey := flag.String("client-key", "", "gateway upstream key")
	upstreamCA := flag.String("upstream-ca", "", "upstream CA roots")
	dispatchPrincipal := flag.String("dispatch-principal", "", "target accepted gateway/Envoy fingerprint")
	observerPrincipal := flag.String("observer-principal", "", "target independent observer fingerprint")
	flag.Parse()
	if *authority == "" || *journal == "" {
		return errors.New("protected_configuration_required")
	}
	cert, e := tls.LoadX509KeyPair(*serverCert, *serverKey)
	if e != nil {
		return errors.New("server_certificate_invalid")
	}
	roots, e := loadRoots(*caPath)
	if e != nil {
		return e
	}
	if *mode == "target" {
		if *dispatchPrincipal == "" || *observerPrincipal == "" || *dispatchPrincipal == *observerPrincipal || len(inspectorPrincipals) == 0 {
			return errors.New("distinct_target_identities_required")
		}
		for _, p := range inspectorPrincipals {
			if p == *dispatchPrincipal || p == *observerPrincipal {
				return errors.New("distinct_target_identities_required")
			}
		}
		var l *labruntime.Ledger
		var owner *labruntime.OwnerLedger
		if *ownerDeclarationDigest != "" {
			owner, e = labruntime.OpenOwnerLedger(*journal, labruntime.OwnerPolicy{TargetID: action.TargetID, OwnerDeclarationDigest: *ownerDeclarationDigest, InitialStock: 100, Floor: *ownerFloor, EffectCost: 5})
		} else {
			l, e = labruntime.OpenLedger(*journal, 20, 0)
		}
		if e != nil {
			return e
		}
		if owner != nil {
			defer owner.Close()
		} else {
			defer l.Close()
		}
		server, e := ingress.NewServer(*listen, cert, roots)
		if e != nil {
			return e
		}
		server.Handler = &labruntime.Target{Ledger: l, Owner: owner, Authority: *authority, DispatchPrincipal: *dispatchPrincipal, ObserverPrincipal: *observerPrincipal, InspectorPrincipals: inspectorPrincipals}
		return server.ListenAndServeTLS("", "")
	}
	if *mode != "gateway" {
		return errors.New("mode_invalid")
	}
	actors := map[string]string{}
	raw, e := os.ReadFile(*principals)
	if e != nil || len(raw) > 65536 {
		return errors.New("principal_registry_invalid")
	}
	if json.Unmarshal(raw, &actors) != nil || len(actors) < 1 || len(actors) > 32 {
		return errors.New("principal_registry_invalid")
	}
	for p, a := range actors {
		if len(p) != 76 || len(a) < 1 || len(a) > 80 {
			return errors.New("principal_registry_invalid")
		}
	}
	clientPair, e := tls.LoadX509KeyPair(*clientCert, *clientKey)
	if e != nil {
		return errors.New("dispatch_certificate_invalid")
	}
	upRoots, e := loadRoots(*upstreamCA)
	if e != nil {
		return e
	}
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect_denied") }, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: upRoots, Certificates: []tls.Certificate{clientPair}, NextProtos: []string{"http/1.1"}}, MaxConnsPerHost: 32, MaxIdleConnsPerHost: 16, ResponseHeaderTimeout: time.Second}}
	l, e := labruntime.OpenLedger(*journal, *budget, *spacing)
	if e != nil {
		return e
	}
	defer l.Close()
	rawListener, e := net.Listen("tcp", *listen)
	if e != nil {
		return e
	}
	now := time.Now()
	acceptor, e := authn.NewAcceptor(rawListener, authn.Config{ServerCertificate: cert, ClientRoots: roots, TrustDomain: "lab-domain", CredentialProfile: "lab-mtls-v1", TrustRevision: 1, TrustValidFrom: now.Add(-time.Minute), TrustExpiresAt: now.Add(time.Hour), SessionMaxAge: 20 * time.Minute, HandshakeTimeout: 2 * time.Second, MaxHandshakes: 32, MaxSessions: 4096})
	if e != nil {
		rawListener.Close()
		return e
	}
	defer acceptor.Close()
	gateway, e := labruntime.NewGateway(acceptor, l, client, actors, *authority, *target, *bridge)
	if e != nil {
		return e
	}
	if *ownerURL != "" {
		if e = gateway.EnableOwner(*ownerURL, labruntime.OwnerPolicy{TargetID: action.TargetID, OwnerDeclarationDigest: *ownerDeclarationDigest, InitialStock: 100, Floor: *ownerFloor, EffectCost: 5}); e != nil {
			return e
		}
	} else if *ownerDeclarationDigest != "" {
		return errors.New("owner_url_required")
	}
	if *inspectURL != "" {
		u, e := url.Parse(*inspectURL)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("inspection_origin_invalid")
		}
		gateway.InspectURL = *inspectURL
	}
	defer gateway.Audit.Close()
	acceptCtx, acceptCancel := context.WithCancel(context.Background())
	defer acceptCancel()
	wrapped := &listener{ctx: acceptCtx, cancel: acceptCancel, a: acceptor, addr: rawListener.Addr(), handles: make(chan authn.TransportHandle, 1)}
	server := &http.Server{Handler: gateway, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16384, ConnContext: func(ctx context.Context, c net.Conn) context.Context {
		return labruntime.WithTransport(ctx, <-wrapped.handles)
	}}
	return server.Serve(wrapped)
}
func loadRoots(path string) (*x509.CertPool, error) {
	b, e := os.ReadFile(path)
	if e != nil || len(b) > 65536 {
		return nil, errors.New("ca_invalid")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(b) {
		return nil, errors.New("ca_invalid")
	}
	return roots, nil
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "kag_lab_error:", e)
		os.Exit(2)
	}
}
