package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestProbeCollectsMetadataAndCapsBody(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "fixture")
		_, _ = w.Write([]byte("<title>Local fixture</title>body"))
	}))
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server.Listener = listener
	server.Start()
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	req := request{TimeoutSeconds: 2, MaxResponseBytes: 16, ResolvedIPs: []string{"127.0.0.1"}}
	got := probe(req, server.URL+"/")
	if got.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; error=%s", got.StatusCode, got.Error)
	}
	if got.ResponseSize != 16 {
		t.Fatalf("response size = %d, want capped size 16", got.ResponseSize)
	}
	if got.ContentType != "text/html" || got.Server != "fixture" || got.Protocol == "" {
		t.Fatalf("missing response metadata: %+v", got)
	}
	if parsed.Host == "" || got.Fingerprint == "" {
		t.Fatalf("missing target or fingerprint: %+v", got)
	}
}

func TestProbeRejectsInvalidTargets(t *testing.T) {
	got := probe(request{TimeoutSeconds: 1, MaxResponseBytes: 100}, "file:///etc/passwd")
	if !strings.Contains(got.Error, "invalid HTTP(S) target") {
		t.Fatalf("error = %q, expected invalid target", got.Error)
	}
}

func TestProbeRequiresValidatedAddresses(t *testing.T) {
	got := probe(request{TimeoutSeconds: 1, MaxResponseBytes: 100}, "https://example.com/")
	if !strings.Contains(got.Error, "scope-validated") {
		t.Fatalf("error = %q, expected missing validated IP error", got.Error)
	}
}
