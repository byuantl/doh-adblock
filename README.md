# DoH Adblock Resolver

A DNS-over-HTTPS server that blocks ad/tracker domains using a StevenBlack blocklist, with caching, live stats, and AI-assisted blocklist enrichment.

## Quick Start

```bash
# 1. TLS certs (required for HTTPS)
brew install mkcert
mkcert -install
mkcert -cert-file certs/cert.pem -key-file certs/key.pem localhost 127.0.0.1

# 2. Blocklist
curl -o blocklist.txt https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts

# 3. Run
go run ./cmd/server/
```

## Test

```bash
pip3 install dnspython

# Query an allowed domain
python3 -c "import dns.message; open('query.bin','wb').write(dns.message.make_query('example.com','A').to_wire())"
curl -k -X POST https://localhost:8443/dns-query \
  --header "content-type: application/dns-message" \
  --data-binary @query.bin -o response.bin
python3 -c "import dns.message; print(dns.message.from_wire(open('response.bin','rb').read()))"

# Query a blocked domain
python3 -c "import dns.message; open('query.bin','wb').write(dns.message.make_query('doubleclick.net','A').to_wire())"
curl -k -X POST https://localhost:8443/dns-query \
  --header "content-type: application/dns-message" \
  --data-binary @query.bin -o response.bin
python3 -c "import dns.message; print(dns.message.from_wire(open('response.bin','rb').read()))"
```

The blocked domain returns `0.0.0.0` instead of a real IP.

<!-- screenshot: curl response showing a blocked domain returning 0.0.0.0 -->

## Dashboard

Open [https://localhost:8443/dashboard/dashboard.html](https://localhost:8443/dashboard/dashboard.html) in your browser.

- **Stats tab** — live counters for total queries, blocked, cache hits, and top blocked/unblocked domains
- **Analysis tab** — run heuristic or LLM analysis on frequently-seen unblocked domains, then approve candidates to the blocklist

<!-- screenshot: stats tab showing live counters and top blocked/unblocked tables -->
<!-- screenshot: analysis tab showing verdicts table and approve buttons -->

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/dns-query` | DoH query (RFC 8484 POST, `application/dns-message`) |
| `GET` | `/stats` | JSON stats snapshot |
| `POST` | `/analyze` | Run domain analysis `{"count":20, "backend":"local"}` |
| `POST` | `/blocklist/approve` | Approve domains `{"domains":["ads.example.com"]}` |

## Analysis Backends

Set the env var and use the corresponding `backend` value in `/analyze`:

| Backend | Env | Notes |
|---------|-----|-------|
| `local` | none | Heuristic keyword/suffix matching, no API key needed |
| `anthropic` | `ANTHROPIC_API_KEY` | Calls Claude via Anthropic Messages API |
| `openai` | `OPENAI_API_KEY` + `OPENAI_BASE_URL` (optional) | OpenAI-compatible; works with Ollama, llama.cpp, vLLM, etc. |

```bash
# Example: analyze with a local model via Ollama
export OPENAI_API_KEY=ollama
export OPENAI_BASE_URL=http://localhost:11434/v1
go run ./cmd/server/

curl -k -X POST https://localhost:8443/analyze \
  -H "content-type: application/json" \
  -d '{"count": 20, "backend": "openai"}'
```

## Project Layout

```
cmd/server/main.go          # entrypoint
internal/analyzer/          # analyzer Backend interface + backends
internal/blocklist/         # blocklist loader + map lookup
internal/cache/             # TTL-aware response cache
internal/stats/             # atomic counters
web/dashboard.html          # live dashboard
certs/                      # TLS certs (generated at setup)
blocklist.txt               # StevenBlack hosts file (downloaded at setup)
```


