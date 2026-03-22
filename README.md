# TruthLens custom MCP backend

This directory contains the dedicated backend brain for TruthLens.

## What it does

- `analyze_claim` — runs the Railway backend analysis directly, with cache-first fallback if needed
- `search_evidence` — web search cascade with cache-first, free-first fallback order
- `factcheck_claim` — Google Fact Check lookup when available
- `get_context` — Wikipedia context lookup
- `score_sources` — trust / recency / relevance scoring for arbitrary source lists
- `build_plan` — tells the model which sub-agents should run
- `get_history` — recent MCP analyses from this backend
- `get_metrics` — live backend metrics snapshot

## Transport

The same server supports:

- `stdio` for local tools and debugging
- `http` (Streamable HTTP) for Railway and other remote deployments

The official MCP transport spec defines stdio and Streamable HTTP as the two standard transport mechanisms, and Streamable HTTP is the remote transport used for web-based deployments.

## Deploy on Railway

Use this folder as a **separate Railway service** with the root directory set to `/mcp`.
Railway supports monorepo root directories, configurable build/start commands, and config-as-code via `railway.toml` / `railway.json` if you want to lock settings in the repo.

Recommended service settings:

- **Root directory:** `/mcp`
- **Build command:** `npm install`
- **Start command:** `npm start`
- **Health check path:** `/health`

## Required variables

- `MCP_AUTH_TOKEN` — bearer token for remote MCP access
- `MCP_ALLOWED_ORIGINS` — comma-separated allowlist
- `MCP_ANALYZE_PATH` — default `/analyze`
- `MCP_METRICS_PATH` — default `/metrics`
- `MCP_TIMEOUT_MS` — request timeout for the Vercel client
- `MCP_MAX_RETRIES` — retry count for the Vercel client

Optional provider variables:

- `GOOGLE_SEARCH_API_KEY`
- `GOOGLE_SEARCH_ENGINE_ID`
- `GOOGLE_FACT_CHECK_API_KEY`
- `BRAVE_SEARCH_API_KEY`
- `SEARXNG_URL`
- `REDIS_URL` — optional, but the backend works without Redis

## Local use

```bash
cd mcp
npm install
npm start
```

or for stdio mode:

```bash
cd mcp
npm run stdio
```

## Notes

- The Next.js app remains separate so you can redesign the frontend later in Claude Sonnet without touching backend contracts.
- The Vercel API route should call the Railway `/analyze` endpoint first, then fall back locally if needed.
- If Redis is not configured, the MCP server uses in-memory cache/history so the backend still stays functional.
