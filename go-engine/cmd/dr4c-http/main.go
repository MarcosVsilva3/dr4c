package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type request struct {
	Operation        string   `json:"operation"`
	Target           string   `json:"target"`
	Targets          []string `json:"targets"`
	ResolvedIPs      []string `json:"resolved_ips"`
	TimeoutSeconds   int      `json:"timeout"`
	MaxConcurrency   int      `json:"max_concurrency"`
	MaxResponseBytes int64    `json:"max_response_bytes"`
}

type response struct {
	Target        string   `json:"target"`
	StatusCode    int      `json:"status_code,omitempty"`
	FinalURL      string   `json:"final_url,omitempty"`
	ContentType   string   `json:"content_type,omitempty"`
	ContentLength int64    `json:"content_length,omitempty"`
	Server        string   `json:"server,omitempty"`
	Protocol      string   `json:"protocol,omitempty"`
	ResponseSize  int64    `json:"response_size"`
	Redirected    bool     `json:"redirected"`
	DurationMS    int64    `json:"duration_ms"`
	Title         string   `json:"title,omitempty"`
	Fingerprint   string   `json:"fingerprint,omitempty"`
	TLSSubject    string   `json:"tls_subject,omitempty"`
	TLSIssuer     string   `json:"tls_issuer,omitempty"`
	TLSNotAfter   string   `json:"tls_not_after,omitempty"`
	TLSVersion    string   `json:"tls_version,omitempty"`
	TLSSANs       []string `json:"tls_sans,omitempty"`
	Error         string   `json:"error,omitempty"`
}

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 2*1024*1024)
	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()
	for scanner.Scan() {
		var req request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			writeJSON(writer, map[string]any{"error": "malformed JSON request"})
			continue
		}
		if req.TimeoutSeconds <= 0 || req.TimeoutSeconds > 120 {
			req.TimeoutSeconds = 10
		}
		if req.MaxResponseBytes <= 0 || req.MaxResponseBytes > 16*1024*1024 {
			req.MaxResponseBytes = 1024 * 1024
		}
		if req.MaxConcurrency <= 0 || req.MaxConcurrency > 100 {
			req.MaxConcurrency = 10
		}
		switch req.Operation {
		case "probe":
			writeJSON(writer, probe(req, req.Target))
		case "probe_batch":
			results := probeBatch(req)
			writeJSON(writer, map[string]any{"results": results})
		default:
			writeJSON(writer, map[string]any{"error": "unsupported operation"})
		}
	}
}

func writeJSON(writer *bufio.Writer, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		data = []byte(`{"error":"response serialization failed"}`)
	}
	_, _ = writer.Write(append(data, '\n'))
	_ = writer.Flush()
}

func probeBatch(req request) []response {
	targets := req.Targets
	if len(targets) == 0 && req.Target != "" {
		targets = []string{req.Target}
	}
	results := make([]response, len(targets))
	sem := make(chan struct{}, req.MaxConcurrency)
	var wg sync.WaitGroup
	for i, target := range targets {
		wg.Add(1)
		go func(i int, target string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = probe(req, target)
		}(i, target)
	}
	wg.Wait()
	return results
}

func probe(req request, target string) response {
	result := response{Target: target, FinalURL: target}
	parsed, err := url.ParseRequestURI(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		result.Error = "invalid HTTP(S) target"
		return result
	}
	if len(req.ResolvedIPs) == 0 {
		result.Error = "no scope-validated destination IPs provided"
		return result
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.TimeoutSeconds)*time.Second)
	defer cancel()
	transport := &http.Transport{DisableKeepAlives: true, Proxy: nil}
	if len(req.ResolvedIPs) > 0 {
		port := parsed.Port()
		if port == "" {
			if parsed.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		validated := make(map[string]bool, len(req.ResolvedIPs))
		for _, raw := range req.ResolvedIPs {
			if ip := net.ParseIP(raw); ip != nil {
				validated[ip.String()] = true
			}
		}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			var lastErr error
			for ip := range validated {
				conn, dialErr := (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip, port))
				if dialErr == nil {
					return conn, nil
				}
				lastErr = dialErr
			}
			if lastErr == nil {
				lastErr = fmt.Errorf("no validated destination IPs")
			}
			return nil, lastErr
		}
	}
	client := &http.Client{Transport: transport, Timeout: time.Duration(req.TimeoutSeconds) * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		result.Error = "invalid request"
		return result
	}
	request.Header.Set("User-Agent", "DR4C/0.1.0 (authorized security assessment)")
	resp, err := client.Do(request)
	result.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()
	result.StatusCode = resp.StatusCode
	result.ContentType = resp.Header.Get("Content-Type")
	result.ContentLength = resp.ContentLength
	result.Server = resp.Header.Get("Server")
	result.Protocol = resp.Proto
	result.Redirected = resp.StatusCode >= 300 && resp.StatusCode < 400
	if result.Redirected {
		result.FinalURL = resp.Header.Get("Location")
	}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		result.TLSSubject = cert.Subject.String()
		result.TLSIssuer = cert.Issuer.String()
		result.TLSNotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
		result.TLSSANs = cert.DNSNames
		result.TLSVersion = tlsVersion(resp.TLS.Version)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, req.MaxResponseBytes+1))
	if readErr != nil {
		result.Error = "response body read failed"
		return result
	}
	if int64(len(body)) > req.MaxResponseBytes {
		body = body[:req.MaxResponseBytes]
	}
	result.ResponseSize = int64(len(body))
	sum := sha256.Sum256(body)
	result.Fingerprint = hex.EncodeToString(sum[:])
	if match := titlePattern.FindSubmatch(body); len(match) > 1 {
		result.Title = strings.TrimSpace(strings.Join(strings.Fields(string(match[1])), " "))
	}
	return result
}

func tlsVersion(version uint16) string {
	switch version {
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}
