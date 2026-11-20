# roxina
roxina phishing tool

## Supported Upstream Schemes

| Scheme | Example | Typical use |
|---|---|---|
| `http` | `-upstream http://127.0.0.1:8081` | Burp Suite / mitmproxy (CONNECT) |
| `https` | `-upstream https://user:pass@proxy:8443` | HTTPS-to-proxy (basic auth via URL userinfo) |
| `socks5` | `-upstream socks5://127.0.0.1:9050` | Tor, `ssh -D` |
| `socks5h` | `-upstream socks5h://127.0.0.1:9050` | SOCKS5 with remote DNS |

Credentials are passed via URL userinfo: `socks5://user:pass@127.0.0.1:9050`.

## Usage Examples

```bash
# Chain through Burp (HTTP CONNECT, default 8081)
go run roxina.go -t https://example.com -l :8080 \
  -upstream http://127.0.0.1:8081 -v

# Chain through Burp with credentials
go run roxina.go -t https://example.com -l :8080 \
  -upstream http://user:pass@127.0.0.1:8081

# Chain through Tor (SOCKS5, remote DNS)
go run roxina.go -t https://example.com -l :8080 \
  -upstream socks5h://127.0.0.1:9050

# Full stack: HTTPS listener + Burp upstream + verbose + header inject
go run roxina.go -t https://example.com -l :443 \
  -scheme https -cert cert.pem -key key.pem \
  -upstream http://127.0.0.1:8081 \
  -H "X-Test: 1" -v

# Verify active upstream
curl -s http://127.0.0.1:8080/__status | jq
```

## Example Startup Output

```
  Target      : https://example.com
  Listen      : :8080
  Proxy scheme: http
  Upstream    : http://127.0.0.1:8081
  Body rewrite: true
  Strip cookie: false

  [upstream] HTTP proxy -> http://127.0.0.1:8081
  [*] HTTP listening on :8080
```

## Verify It's Chaining

With `-v`, every proxied request is logged:

```
[proxy] GET /login -> example.com/login
[redirect] https://example.com/account -> /account
[proxy] GET /account -> example.com/account
```

And in **Burp** → *Proxy → HTTP history* you'll see the requests arriving from Roxina — confirming the chain is live.

`/__status`:
```json
{"status":"ok","target":"https://example.com","listen":":8080","upstream":"http://127.0.0.1:8081","time":"2026-11-20T15:04:05Z"}
```

> **Notes:**
> - `socks5h` and `socks5` behave identically in `golang.org/x/net/proxy` — both use the SOCKS server's resolver. Use `socks5h://` for clarity in logs.
> - HTTPS-to-proxy (`https://proxy:8443`) is supported but rare; most Burp setups use plain `http://`.
> - The transport is **shared** across all requests, so keep-alive connections to the upstream proxy are reused — good for throughput.
> - If the upstream is down, all requests return `502 Bad Gateway` with a `[proxy] upstream error` log line.
