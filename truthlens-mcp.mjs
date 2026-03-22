#!/usr/bin/env node
import crypto from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const APP_NAME = process.env.MCP_SERVER_NAME || "truthlens-mcp-server";
const ANALYZE_ENDPOINT = String(process.env.MCP_ANALYZE_PATH || "/analyze");
const HTTP_METRICS_PATH = String(process.env.MCP_METRICS_PATH || "/metrics");
const TRANSPORT = String(process.env.TRANSPORT || "stdio").toLowerCase();
const PORT = parseInt(process.env.PORT || "3000", 10);
const AUTH_TOKEN = String(process.env.MCP_AUTH_TOKEN || "").trim();
const ALLOWED_ORIGINS = parseCsv(
  process.env.MCP_ALLOWED_ORIGINS || process.env.NEXT_PUBLIC_APP_URL || ""
);
const FACTCHECK_KEY = process.env.GOOGLE_FACT_CHECK_API_KEY || "";
const GOOGLE_SEARCH_KEY = process.env.GOOGLE_SEARCH_API_KEY || "";
const GOOGLE_SEARCH_ENGINE_ID = process.env.GOOGLE_SEARCH_ENGINE_ID || "";
const BRAVE_SEARCH_KEY = process.env.BRAVE_SEARCH_API_KEY || "";
const SEARXNG_URL = process.env.SEARXNG_URL || "";
const CACHE_TTL_SECONDS = parseInt(process.env.MCP_CACHE_TTL_SECONDS || "3600", 10);
const HISTORY_LIMIT = parseInt(process.env.MCP_HISTORY_LIMIT || "50", 10);
const USER_AGENT = `${APP_NAME}/1.0`;
const TIMEOUT_MS = 10000;

const cache = new Map();
const recentAnalyses = [];
const metrics = {
  startedAt: Date.now(),
  analyses: 0,
  localAnalyses: 0,
  appAnalyses: 0,
  cacheHits: 0,
  searchCalls: 0,
  factCheckCalls: 0,
  contextCalls: 0,
  fallbackAnalyses: 0,
  failures: 0,
  totalLatencyMs: 0,
};

function normalizeBaseUrl(url) {
  return String(url || "").replace(/\/$/, "");
}

function parseCsv(value) {
  return String(value || "")
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
}

function makeHash(value) {
  return crypto.createHash("sha256").update(String(value).toLowerCase().trim()).digest("hex").slice(0, 16);
}

function extractDomain(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return "unknown";
  }
}

function confidenceFromText(text) {
  const lower = String(text || "").toLowerCase();
  if (/(breaking|exclusive|shocking|anonymous)/.test(lower)) return 2;
  if (/(official|study|report|journal|published|reviewed)/.test(lower)) return 4;
  return 3;
}

function recencyScore(dateLike) {
  if (!dateLike) return 50;
  const stamp = Date.parse(dateLike);
  if (Number.isNaN(stamp)) return 50;
  const days = Math.max(0, (Date.now() - stamp) / 86400000);
  if (days < 3) return 100;
  if (days < 30) return 85;
  if (days < 180) return 70;
  if (days < 365) return 55;
  return 35;
}

function cacheGet(key) {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    cache.delete(key);
    return null;
  }
  entry.lastAccessed = Date.now();
  return entry.value;
}

function cacheSet(key, value, ttlSeconds = CACHE_TTL_SECONDS) {
  if (cache.size > 1000) {
    let oldestKey = null;
    let oldestAccess = Infinity;
    for (const [k, entry] of cache.entries()) {
      if (entry.lastAccessed < oldestAccess) {
        oldestAccess = entry.lastAccessed;
        oldestKey = k;
      }
    }
    if (oldestKey) cache.delete(oldestKey);
  }
  cache.set(key, {
    value,
    expiresAt: Date.now() + ttlSeconds * 1000,
    lastAccessed: Date.now(),
  });
}

async function withTimeout(url, init = {}, timeoutMs = TIMEOUT_MS) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error("timeout")), timeoutMs);
  try {
    return await fetch(url, {
      ...init,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchJson(url, init = {}, timeoutMs = TIMEOUT_MS) {
  const res = await withTimeout(url, init, timeoutMs);
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { ok: res.ok, status: res.status, text, json };
}

function textToolOutput(payload) {
  return {
    content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
    structuredContent: payload,
  };
}

function applyAuth(req, res) {
  if (!AUTH_TOKEN) return true;
  const header = req.headers.authorization || "";
  if (header === `Bearer ${AUTH_TOKEN}`) return true;
  res.status(401).json({
    jsonrpc: "2.0",
    error: {
      code: -32001,
      message: "Unauthorized",
    },
    id: null,
  });
  return false;
}

function applyOriginCheck(req, res) {
  const origin = req.headers.origin;
  if (!origin) return true;
  if (ALLOWED_ORIGINS.length === 0) return true;
  if (ALLOWED_ORIGINS.includes("*")) return true;
  if (ALLOWED_ORIGINS.some((allowed) => origin.startsWith(allowed))) return true;
  res.status(403).json({
    jsonrpc: "2.0",
    error: {
      code: -32002,
      message: "Forbidden origin",
    },
    id: null,
  });
  return false;
}

async function searchGoogle(query, limit) {
  if (!GOOGLE_SEARCH_KEY || !GOOGLE_SEARCH_ENGINE_ID) return [];
  const cacheKey = `search:google:${makeHash(query)}`;
  const cached = cacheGet(cacheKey);
  if (cached) return cached;

  const url = new URL("https://www.googleapis.com/customsearch/v1");
  url.searchParams.set("key", GOOGLE_SEARCH_KEY);
  url.searchParams.set("cx", GOOGLE_SEARCH_ENGINE_ID);
  url.searchParams.set("q", query);
  url.searchParams.set("num", String(Math.min(limit, 10)));
  url.searchParams.set("safe", "active");
  const { ok, status, json } = await fetchJson(url.toString(), { headers: { Accept: "application/json" } });
  if (!ok) throw new Error(`Google CSE error: ${status}`);
  const out = (json?.items || []).map((item) => ({
    title: item.title || "Untitled",
    url: item.link || "",
    snippet: item.snippet || "",
    domain: extractDomain(item.link || ""),
    sourceType: "secondary",
    publishedAt: item?.pagemap?.metatags?.[0]?.["article:published_time"],
  })).filter((item) => item.url && item.title).slice(0, limit);
  cacheSet(cacheKey, out, 1800);
  return out;
}

async function searchBrave(query, limit) {
  if (!BRAVE_SEARCH_KEY) return [];
  const cacheKey = `search:brave:${makeHash(query)}`;
  const cached = cacheGet(cacheKey);
  if (cached) return cached;

  const url = new URL("https://api.search.brave.com/res/v1/web/search");
  url.searchParams.set("q", query);
  url.searchParams.set("count", String(Math.min(limit, 10)));
  url.searchParams.set("safesearch", "moderate");
  const { ok, status, json } = await fetchJson(url.toString(), {
    headers: {
      Accept: "application/json",
      "Accept-Encoding": "gzip",
      "X-Subscription-Token": BRAVE_SEARCH_KEY,
    },
  });
  if (!ok) throw new Error(`Brave error: ${status}`);
  const out = (json?.web?.results || []).map((item) => ({
    title: item.title || "Untitled",
    url: item.url || "",
    snippet: item.description || "",
    domain: extractDomain(item.url || ""),
    sourceType: "secondary",
    publishedAt: item.age,
  })).filter((item) => item.url && item.title).slice(0, limit);
  cacheSet(cacheKey, out, 1800);
  return out;
}

async function searchSearxng(query, limit) {
  if (!SEARXNG_URL) return [];
  const cacheKey = `search:searxng:${makeHash(query)}`;
  const cached = cacheGet(cacheKey);
  if (cached) return cached;

  const base = SEARXNG_URL.replace(/\/$/, "");
  const url = new URL(`${base}/search`);
  url.searchParams.set("q", query);
  url.searchParams.set("format", "json");
  url.searchParams.set("categories", "general");
  url.searchParams.set("language", "en");
  url.searchParams.set("safesearch", "1");
  const { ok, status, json } = await fetchJson(url.toString(), { headers: { Accept: "application/json" } });
  if (!ok) throw new Error(`SearXNG error: ${status}`);
  const out = (json?.results || []).slice(0, limit).map((item) => ({
    title: item.title || "Untitled",
    url: item.url || "",
    snippet: item.content || "",
    domain: extractDomain(item.url || ""),
    sourceType: "secondary",
    publishedAt: item.publishedDate,
  })).filter((item) => item.url && item.title);
  cacheSet(cacheKey, out, 1800);
  return out;
}

async function searchDuckDuckGo(query, limit) {
  const cacheKey = `search:ddg:${makeHash(query)}`;
  const cached = cacheGet(cacheKey);
  if (cached) return cached;

  const url = new URL("https://api.duckduckgo.com/");
  url.searchParams.set("q", query);
  url.searchParams.set("format", "json");
  url.searchParams.set("no_html", "1");
  url.searchParams.set("skip_disambig", "1");
  const { ok, status, json } = await fetchJson(url.toString(), { headers: { Accept: "application/json" } }, 8000);
  if (!ok) throw new Error(`DDG error: ${status}`);
  const out = [];
  if (json?.AbstractText && json?.AbstractURL) {
    out.push({
      title: json.AbstractSource || "DuckDuckGo Abstract",
      url: json.AbstractURL,
      snippet: json.AbstractText.slice(0, 400),
      domain: extractDomain(json.AbstractURL),
      sourceType: "encyclopedia",
    });
  }
  for (const topic of (json?.RelatedTopics || []).slice(0, 3)) {
    if (topic.Text && topic.FirstURL) {
      out.push({
        title: topic.Text.slice(0, 80),
        url: topic.FirstURL,
        snippet: topic.Text.slice(0, 300),
        domain: extractDomain(topic.FirstURL),
        sourceType: "secondary",
      });
    }
  }
  const sliced = out.slice(0, limit);
  cacheSet(cacheKey, sliced, 3600);
  return sliced;
}

async function searchEvidence(query, limit = 5) {
  metrics.searchCalls += 1;
  const providers = [
    { name: "searxng", fn: searchSearxng },
    { name: "google-cse", fn: searchGoogle },
    { name: "brave", fn: searchBrave },
    { name: "duckduckgo", fn: searchDuckDuckGo },
  ];
  for (const provider of providers) {
    try {
      const results = await provider.fn(query, limit);
      if (results.length) return { provider: provider.name, results };
    } catch {
      continue;
    }
  }
  return { provider: "none", results: [] };
}

async function factcheckClaim(claim) {
  metrics.factCheckCalls += 1;
  if (!FACTCHECK_KEY) return { available: false, results: [] };
  const cacheKey = `factcheck:${makeHash(claim)}`;
  const cached = cacheGet(cacheKey);
  if (cached) return cached;

  const url = new URL("https://factchecktools.googleapis.com/v1alpha1/claims:search");
  url.searchParams.set("query", claim);
  url.searchParams.set("pageSize", "10");
  url.searchParams.set("key", FACTCHECK_KEY);
  const { ok, status, json } = await fetchJson(url.toString(), { headers: { Accept: "application/json" } });
  if (!ok) throw new Error(`Google Fact Check error: ${status}`);
  const results = (json?.claims || []).map((item) => ({
    claimText: item.text || claim,
    rating: item.claimReview?.[0]?.textualRating || item.claimReview?.[0]?.title || "unknown",
    publisher: item.claimReview?.[0]?.publisher?.name || "Google Fact Check",
    url: item.claimReview?.[0]?.url || "",
    reviewDate: item.claimReview?.[0]?.reviewDate,
  }));
  const payload = { available: true, results };
  cacheSet(cacheKey, payload, 7200);
  return payload;
}

async function getContext(query) {
  metrics.contextCalls += 1;
  const cacheKey = `context:${makeHash(query)}`;
  const cached = cacheGet(cacheKey);
  if (cached) return cached;

  const searchUrl = new URL("https://en.wikipedia.org/w/api.php");
  searchUrl.searchParams.set("action", "opensearch");
  searchUrl.searchParams.set("search", query);
  searchUrl.searchParams.set("limit", "1");
  searchUrl.searchParams.set("namespace", "0");
  searchUrl.searchParams.set("format", "json");
  const { ok, status, json } = await fetchJson(searchUrl.toString(), { headers: { Accept: "application/json" } });
  if (!ok) throw new Error(`Wikipedia search error: ${status}`);
  const title = json?.[1]?.[0];
  const url = json?.[3]?.[0];
  if (!title || !url) return { available: false, context: null };
  const summaryUrl = `https://en.wikipedia.org/api/rest_v1/page/summary/${encodeURIComponent(title)}`;
  const summaryRes = await fetchJson(summaryUrl, { headers: { Accept: "application/json" } }, 8000);
  const context = {
    title,
    extract: summaryRes.json?.extract || null,
    url,
    thumbnailUrl: summaryRes.json?.thumbnail?.source,
    lastModified: summaryRes.json?.timestamp,
  };
  const payload = { available: true, context };
  cacheSet(cacheKey, payload, 43200);
  return payload;
}

function scoreSources(sources, claim = "") {
  const lowerClaim = String(claim).toLowerCase();
  return sources.map((source) => {
    const domain = extractDomain(source.url || source.domain || "");
    const domainTrust = (() => {
      const trusted = [
        "reuters.com", "apnews.com", "bbc.com", "who.int", "cdc.gov", "nih.gov", "nature.com",
        "sciencemag.org", "statnews.com", "factcheck.org", "politifact.com", "snopes.com",
        "wikipedia.org", "nytimes.com", "washingtonpost.com", "theguardian.com"
      ];
      if (trusted.some((d) => domain.endsWith(d))) return 5;
      if (/(\.gov|\.edu)$/.test(domain)) return 5;
      if (/youtube\.com|reddit\.com|facebook\.com|x\.com|tiktok\.com/.test(domain)) return 2;
      return 3;
    })();

    const relevance = Math.max(
      20,
      Math.min(
        100,
        40 +
          (source.snippet || source.title || "")
            .toLowerCase()
            .split(/\s+/)
            .filter((w) => w && lowerClaim.includes(w)).length * 12
      )
    );
    const recency = recencyScore(source.publishedAt);
    const credibility = Math.max(1, Math.min(5, Math.round((domainTrust + confidenceFromText(source.snippet || source.title || "")) / 2)));
    const stance = /false|misleading|debunk|no evidence|hoax/i.test(`${source.title} ${source.snippet}`)
      ? "opposes"
      : /true|confirmed|supports|evidence|study|report/i.test(`${source.title} ${source.snippet}`)
        ? "supports"
        : "neutral";
    return {
      title: source.title || "Untitled",
      url: source.url,
      domain,
      snippet: source.snippet || "",
      stance,
      credibility,
      sourceType: source.sourceType || "secondary",
      recencyScore: recency,
      relevanceScore: relevance,
      publishedAt: source.publishedAt,
    };
  });
}

function buildPlan(claim) {
  const lower = String(claim).toLowerCase();
  const checkable = !/\b(opinion|i think|i feel|satire|parody|joke|meme)\b/.test(lower);
  const categories = [];
  if (/\b(health|medical|doctor|vaccine|covid|cancer|disease)\b/.test(lower)) categories.push("health");
  if (/\b(election|government|minister|president|congress|policy|politic)\b/.test(lower)) categories.push("political");
  if (/\b(stock|crypto|price|investment|profit|loss|market)\b/.test(lower)) categories.push("financial");
  if (/\b(science|study|research|paper|journal)\b/.test(lower)) categories.push("scientific");

  const steps = [
    { agent: "planner", action: "normalize", reason: "Classify the claim and decide which tools to invoke." },
  ];

  if (checkable) {
    steps.push({ agent: "search", action: "search_evidence", reason: "Gather public web evidence." });
    steps.push({ agent: "factcheck", action: "factcheck_claim", reason: "Check professional fact-check databases if available." });
    steps.push({ agent: "context", action: "get_context", reason: "Pull encyclopedic background context." });
    steps.push({ agent: "scoring", action: "score_sources", reason: "Rank sources by credibility, recency, and relevance." });
  }

  steps.push({ agent: "synthesis", action: "analyze_claim", reason: "Synthesize the evidence into a conservative verdict." });
  steps.push({ agent: "memory", action: "get_history", reason: "Reuse prior analyses when available." });

  return { checkable, categories, steps };
}

function normalizeClaimText(claim) {
  return String(claim || "")
    .replace(/\s+/g, " ")
    .trim();
}

function localSynthesis(claim, scoredSources, factCheckResults, context) {
  const support = scoredSources.filter((s) => s.stance === "supports");
  const oppose = scoredSources.filter((s) => s.stance === "opposes");
  const neutral = scoredSources.filter((s) => s.stance === "neutral");

  const supportWeight = support.reduce((sum, s) => sum + s.credibility * 0.45 + s.relevanceScore / 100 + s.recencyScore / 100, 0);
  const opposeWeight = oppose.reduce((sum, s) => sum + s.credibility * 0.45 + s.relevanceScore / 100 + s.recencyScore / 100, 0);

  const factCheckSupport = factCheckResults.filter((fc) => /\b(true|accurate|correct|supported|mostly true|verified)\b/i.test(fc.rating)).length;
  const factCheckOppose = factCheckResults.filter((fc) => /\b(false|falsehood|misleading|incorrect|mostly false|pants on fire|unsupported|unproven)\b/i.test(fc.rating)).length;

  const totalSignal = supportWeight + opposeWeight + factCheckSupport + factCheckOppose;
  let verdict = "UNVERIFIED";
  if (totalSignal > 0 && supportWeight + factCheckSupport >= (opposeWeight + factCheckOppose) * 1.3 && supportWeight + factCheckSupport >= 2) {
    verdict = "TRUE";
  } else if (totalSignal > 0 && opposeWeight + factCheckOppose >= (supportWeight + factCheckSupport) * 1.3 && opposeWeight + factCheckOppose >= 2) {
    verdict = "FALSE";
  } else if (supportWeight > 0 && opposeWeight > 0) {
    verdict = "MIXED";
  }

  const confidenceBase = Math.min(100, Math.round(Math.max(supportWeight, opposeWeight) * 18 + factCheckResults.length * 8 + (context ? 8 : 0)));
  const confidence = verdict === "UNVERIFIED"
    ? Math.min(60, Math.max(28, confidenceBase))
    : verdict === "MIXED"
      ? Math.min(72, Math.max(45, confidenceBase))
      : Math.min(92, Math.max(55, confidenceBase + 8));

  const headline = verdict === "TRUE"
    ? "Evidence leans in favor."
    : verdict === "FALSE"
      ? "Evidence contradicts the claim."
      : verdict === "MIXED"
        ? "Evidence is divided or context-dependent."
        : "Evidence is insufficient for a firm verdict.";

  const summaryParts = [];
  if (support.length || oppose.length) {
    summaryParts.push(`TruthLens found ${support.length} supporting and ${oppose.length} opposing web sources.`);
  }
  if (factCheckResults.length) {
    summaryParts.push(`Fact-check databases returned ${factCheckResults.length} result(s).`);
  }
  if (context?.extract) {
    summaryParts.push(`Background context from Wikipedia: ${String(context.extract).slice(0, 180)}${String(context.extract).length > 180 ? "..." : ""}`);
  }
  if (!summaryParts.length) {
    summaryParts.push("No strong public evidence was found, so the safe result is UNVERIFIED.");
  }

  const warnings = [];
  if (!scoredSources.length) warnings.push("No strong search results were available from the configured providers.");
  if (factCheckResults.length === 0) warnings.push("No direct fact-check matches were found.");
  if (!context?.extract) warnings.push("No encyclopedia context was available for this claim.");

  const reasoning = [
    {
      step: "Evidence balance",
      icon: "⚖️",
      color: "#6B8AFD",
      text: `Support score ${supportWeight.toFixed(1)} vs opposition score ${opposeWeight.toFixed(1)} after credibility and recency weighting.`,
    },
    {
      step: "Fact-check review",
      icon: "🧾",
      color: "#F4B961",
      text: factCheckResults.length
        ? `${factCheckResults.length} fact-check result(s) were reviewed for corroboration.`
        : "No direct fact-check entries were found, so the analysis relied on public web evidence.",
    },
    {
      step: "Context layer",
      icon: "📚",
      color: "#F5F1EA",
      text: context?.title
        ? `Wikipedia context was added for ${context.title}.`
        : "No encyclopedic context could be attached for this claim.",
    },
  ];

  return {
    verdict,
    confidence,
    headline,
    summary: summaryParts.join(" "),
    category: /\b(health|medical|vaccine|covid|doctor|cancer|disease)\b/i.test(claim)
      ? "health"
      : /\b(election|government|minister|president|congress|policy|politic)\b/i.test(claim)
        ? "political"
        : /\b(stock|crypto|price|investment|profit|loss|market)\b/i.test(claim)
          ? "financial"
          : /\b(science|study|research|paper|journal)\b/i.test(claim)
            ? "scientific"
            : "other",
    reasoning,
    sources: scoredSources.slice(0, 8),
    factChecks: factCheckResults,
    evidenceBreakdown: {
      supporting: support.length ? Math.min(100, Math.round((supportWeight / (supportWeight + opposeWeight + 0.001)) * 100)) : 50,
      opposing: oppose.length ? Math.min(100, Math.round((opposeWeight / (supportWeight + opposeWeight + 0.001)) * 100)) : 50,
      consensus: verdict === "UNVERIFIED" ? 35 : verdict === "MIXED" ? 55 : 72,
      quality: Math.min(100, Math.round((scoredSources.reduce((n, s) => n + s.credibility, 0) / Math.max(1, scoredSources.length)) * 18 + factCheckResults.length * 5)),
    },
    radar: {
      accuracy: confidence,
      diversity: Math.min(100, new Set(scoredSources.map((s) => s.domain)).size * 18),
      consensus: verdict === "MIXED" ? 55 : verdict === "UNVERIFIED" ? 32 : 72,
      recency: scoredSources.length ? Math.min(100, Math.round(scoredSources.reduce((n, s) => n + s.recencyScore, 0) / scoredSources.length)) : 40,
      verifiability: factCheckResults.length ? 85 : 52,
    },
    warnings,
  };
}

async function retryOperation(fn, { attempts = 2, baseDelayMs = 250, label = "operation" } = {}) {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await fn(attempt);
    } catch (error) {
      lastError = error;
      if (attempt < attempts) {
        const delay = baseDelayMs * attempt;
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
  }
  throw new Error(
    `${label} failed after ${attempts} attempt${attempts > 1 ? "s" : ""}: ${lastError instanceof Error ? lastError.message : String(lastError || "unknown error")}`
  );
}

async function runBackendAnalysis(claim, { routeSource = "mcp" } = {}) {
  const cleanClaim = normalizeClaimText(claim);
  const cacheKey = `analysis:${makeHash(cleanClaim)}`;
  const start = Date.now();
  const plan = buildPlan(cleanClaim);
  const trace = [
    {
      stage: "normalize",
      agent: "planner",
      status: "done",
      message: "Claim normalized and MCP analysis plan created.",
      count: plan.categories.length,
    },
  ];

  const cached = cacheGet(cacheKey);
  if (cached) {
    metrics.cacheHits += 1;
    metrics.analyses += 1;
    if (routeSource === "http") metrics.appAnalyses += 1;
    else metrics.localAnalyses += 1;
    metrics.totalLatencyMs += Date.now() - start;
    const cachedResult = {
      ...cached,
      cacheStatus: "hit",
      latencyMs: Date.now() - start,
      pipelineTrace: [
        ...trace,
        {
          stage: "cache",
          agent: "cache",
          status: "hit",
          message: "Returned cached analysis result from the MCP backend.",
          latencyMs: Date.now() - start,
        },
      ],
    };

    recordHistory({
      id: makeHash(`${cleanClaim}:${Date.now()}`),
      claimPreview: cleanClaim.slice(0, 120),
      verdict: cachedResult.verdict,
      confidence: cachedResult.confidence,
      source: "cache",
      createdAt: new Date().toISOString(),
    });

    return {
      ok: true,
      source: "cache",
      routeSource,
      plan,
      data: cachedResult,
    };
  }

  let search = { provider: "none", results: [] };
  let fact = { available: false, results: [] };
  let context = { available: false, context: null };
  const warnings = [];

  if (plan.checkable) {
    trace.push({
      stage: "retrieval",
      agent: "search",
      status: "running",
      message: "Gathering public evidence, fact-check data, and encyclopedic context.",
    });

    try {
      [search, fact, context] = await Promise.all([
        retryOperation(() => searchEvidence(cleanClaim, 6), { attempts: 2, baseDelayMs: 300, label: "search" }),
        retryOperation(() => factcheckClaim(cleanClaim), { attempts: 2, baseDelayMs: 300, label: "fact-check" }),
        retryOperation(() => getContext(cleanClaim), { attempts: 2, baseDelayMs: 300, label: "context" }),
      ]);
      trace.push({
        stage: "retrieval",
        agent: "search",
        status: "done",
        message: `Retrieved ${search.results.length} sources, ${fact.results.length} fact-checks, and ${context.context ? 1 : 0} context item(s).`,
        count: search.results.length,
      });
    } catch (error) {
      warnings.push(
        `Evidence retrieval partially failed; the backend fell back to conservative synthesis. ${error instanceof Error ? error.message : String(error || "")}`.slice(0, 240)
      );
      trace.push({
        stage: "retrieval",
        agent: "search",
        status: "fallback",
        message: "Evidence retrieval partially failed; continuing with whatever evidence is available.",
      });
    }
  } else {
    trace.push({
      stage: "retrieval",
      agent: "search",
      status: "skipped",
      message: "Claim is not checkable, so evidence retrieval was skipped.",
    });
  }

  const scored = scoreSources(search.results || [], cleanClaim);
  trace.push({
    stage: "scoring",
    agent: "scoring",
    status: "done",
    message: `Scored ${scored.length} sources for credibility, relevance, and recency.`,
    count: scored.length,
  });

  const result = localSynthesis(cleanClaim, scored, fact.results || [], context.context || null);
  const analysis = {
    ...result,
    factChecks: fact.results || [],
    warnings: [
      ...(result.warnings || []),
      ...warnings,
    ].slice(0, 5),
    cacheStatus: "miss",
    latencyMs: Date.now() - start,
    synthesisMode: "rules",
    pipelineTrace: [
      ...trace,
      {
        stage: "synthesis",
        agent: "synthesis",
        status: "done",
        message: "Rules-based synthesis produced the final verdict.",
      },
      {
        stage: "memory",
        agent: "memory",
        status: "done",
        message: "Result will be written into the backend cache and history log.",
      },
    ],
  };

  trace.push({
    stage: "cache",
    agent: "cache",
    status: "running",
    message: "Writing MCP analysis into cache.",
  });
  cacheSet(cacheKey, analysis, CACHE_TTL_SECONDS);
  trace.push({
    stage: "cache",
    agent: "cache",
    status: "done",
    message: "MCP analysis cached for fast reuse.",
  });
  analysis.pipelineTrace = trace;

  recordHistory({
    id: makeHash(`${cleanClaim}:${Date.now()}`),
    claimPreview: cleanClaim.slice(0, 120),
    verdict: analysis.verdict,
    confidence: analysis.confidence,
    source: routeSource,
    createdAt: new Date().toISOString(),
  });

  metrics.analyses += 1;
  if (routeSource === "http") metrics.appAnalyses += 1;
  else metrics.localAnalyses += 1;
  metrics.totalLatencyMs += Date.now() - start;

  return {
    ok: true,
    source: "mcp",
    routeSource,
    plan,
    data: analysis,
  };
}
function recordHistory(entry) {
  recentAnalyses.unshift(entry);
  if (recentAnalyses.length > HISTORY_LIMIT) recentAnalyses.length = HISTORY_LIMIT;
}

function getMetricsSnapshot() {
  const elapsedMs = Math.max(1, Date.now() - metrics.startedAt);
  return {
    totals: {
      analyses: metrics.analyses,
      appAnalyses: metrics.appAnalyses,
      localAnalyses: metrics.localAnalyses,
      cacheHits: metrics.cacheHits,
      searchCalls: metrics.searchCalls,
      factCheckCalls: metrics.factCheckCalls,
      contextCalls: metrics.contextCalls,
      fallbackAnalyses: metrics.fallbackAnalyses,
      failures: metrics.failures,
    },
    performance: {
      avgLatencyMs: metrics.analyses ? Math.round(metrics.totalLatencyMs / metrics.analyses) : 0,
      uptimeSeconds: Math.floor(elapsedMs / 1000),
    },
    cache: {
      entries: cache.size,
      ttlSeconds: CACHE_TTL_SECONDS,
    },
    backend: {
      transport: TRANSPORT,
      analyzeEndpoint: ANALYZE_ENDPOINT,
      metricsEndpoint: HTTP_METRICS_PATH,
      freeTierSafe: true,
      redisConfigured: !!process.env.REDIS_URL,
    },
    history: recentAnalyses.slice(0, 10),
  };
}

const server = new McpServer(
  { name: APP_NAME, version: "1.0.0" },
  { capabilities: { logging: {} } }
);

server.registerTool(
  "analyze_claim",
  {
    title: "Analyze Claim",
    description: "Run the complete TruthLens backend pipeline through the Railway MCP service, with conservative local cache-first fallback if required.",
    inputSchema: z.object({
      claim: z.string().min(3).max(4000),
    }),
  },
  async ({ claim }) => {
    const cleanClaim = normalizeClaimText(claim);
    const cacheKey = `analysis:${makeHash(cleanClaim)}`;
    const start = Date.now();
    const cached = cacheGet(cacheKey);
    if (cached) {
      metrics.cacheHits += 1;
      metrics.analyses += 1;
      metrics.totalLatencyMs += Date.now() - start;
      const payload = {
        ok: true,
        source: "cache",
        routeSource: "tool",
        plan: buildPlan(cleanClaim),
        result: {
          ...cached,
          cacheStatus: "hit",
          latencyMs: Date.now() - start,
        },
      };
      return textToolOutput(payload);
    }

    try {
      const payload = await runBackendAnalysis(cleanClaim, { routeSource: "tool" });
      return textToolOutput(payload);
    } catch (error) {
      metrics.failures += 1;
      const fallbackPlan = buildPlan(cleanClaim);
      const search = fallbackPlan.checkable
        ? await retryOperation(() => searchEvidence(cleanClaim, 6), { attempts: 2, baseDelayMs: 300, label: "search" }).catch(() => ({ provider: "none", results: [] }))
        : { provider: "none", results: [] };
      const fact = fallbackPlan.checkable
        ? await retryOperation(() => factcheckClaim(cleanClaim), { attempts: 2, baseDelayMs: 300, label: "fact-check" }).catch(() => ({ available: false, results: [] }))
        : { available: false, results: [] };
      const context = fallbackPlan.checkable
        ? await retryOperation(() => getContext(cleanClaim), { attempts: 2, baseDelayMs: 300, label: "context" }).catch(() => ({ available: false, context: null }))
        : { available: false, context: null };
      const scored = scoreSources(search.results || [], cleanClaim);
      const result = {
        ...localSynthesis(cleanClaim, scored, fact.results || [], context.context || null),
        warnings: [
          "The Railway MCP route was unavailable or failed, so the backend used its local free-first fallback.",
          error instanceof Error ? error.message : String(error || "Unknown error"),
        ].slice(0, 3),
        cacheStatus: "miss",
        latencyMs: Date.now() - start,
        synthesisMode: "rules",
        pipelineTrace: [
          {
            stage: "normalize",
            agent: "planner",
            status: "done",
            message: "Claim normalized for fallback analysis.",
          },
          {
            stage: "retrieval",
            agent: "search",
            status: "fallback",
            message: "Remote MCP analysis failed; a local free-first retrieval fallback was used.",
          },
          {
            stage: "synthesis",
            agent: "synthesis",
            status: "done",
            message: "Rules engine produced the conservative fallback verdict.",
          },
        ],
      };

      const payload = {
        ok: true,
        source: "local-fallback",
        routeSource: "tool",
        plan: fallbackPlan,
        result,
      };

      recordHistory({
        id: makeHash(`${cleanClaim}:${Date.now()}`),
        claimPreview: cleanClaim.slice(0, 120),
        verdict: result.verdict,
        confidence: result.confidence,
        source: "local-fallback",
        createdAt: new Date().toISOString(),
      });

      cacheSet(cacheKey, result, CACHE_TTL_SECONDS);
      metrics.fallbackAnalyses += 1;
      metrics.analyses += 1;
      metrics.localAnalyses += 1;
      metrics.totalLatencyMs += Date.now() - start;
      return textToolOutput(payload);
    }
  }
);

server.registerTool(
  "search_evidence",
  {
    title: "Search Evidence",
    description: "Collect public web evidence using the free-first search cascade.",
    inputSchema: z.object({
      query: z.string().min(2).max(500),
      limit: z.number().int().min(1).max(10).default(5),
    }),
  },
  async ({ query, limit }) => {
    const cleanQuery = normalizeClaimText(query);
    const cacheKey = `search:${makeHash(`${cleanQuery}:${limit}`)}`;
    const cached = cacheGet(cacheKey);
    if (cached) {
      metrics.cacheHits += 1;
      return textToolOutput({ ...cached, source: "cache" });
    }
    const result = await searchEvidence(cleanQuery, limit);
    cacheSet(cacheKey, result, 1800);
    return textToolOutput(result);
  }
);

server.registerTool(
  "factcheck_claim",
  {
    title: "Fact Check Claim",
    description: "Query Google Fact Check Tools API when available.",
    inputSchema: z.object({
      claim: z.string().min(2).max(4000),
    }),
  },
  async ({ claim }) => {
    const cleanClaim = normalizeClaimText(claim);
    const cacheKey = `factcheck:${makeHash(cleanClaim)}`;
    const cached = cacheGet(cacheKey);
    if (cached) {
      metrics.cacheHits += 1;
      return textToolOutput({ ...cached, source: "cache" });
    }
    const result = await factcheckClaim(cleanClaim);
    cacheSet(cacheKey, result, 7200);
    return textToolOutput(result);
  }
);

server.registerTool(
  "get_context",
  {
    title: "Get Context",
    description: "Retrieve encyclopedic background from Wikipedia.",
    inputSchema: z.object({
      query: z.string().min(2).max(500),
    }),
  },
  async ({ query }) => {
    const cleanQuery = normalizeClaimText(query);
    const cacheKey = `context:${makeHash(cleanQuery)}`;
    const cached = cacheGet(cacheKey);
    if (cached) {
      metrics.cacheHits += 1;
      return textToolOutput({ ...cached, source: "cache" });
    }
    const result = await getContext(cleanQuery);
    cacheSet(cacheKey, result, 43200);
    return textToolOutput(result);
  }
);

server.registerTool(
  "score_sources",
  {
    title: "Score Sources",
    description: "Score raw sources for credibility, recency, relevance, and stance.",
    inputSchema: z.object({
      claim: z.string().optional().default(""),
      sources: z.array(
        z.object({
          title: z.string(),
          url: z.string(),
          snippet: z.string().optional().default(""),
          publishedAt: z.string().optional(),
          domain: z.string().optional(),
          sourceType: z.enum(["primary", "secondary", "fact-check", "encyclopedia", "news"]).optional(),
        })
      ).min(1).max(25),
    }),
  },
  async ({ claim, sources }) => {
    const result = { scored: scoreSources(sources, claim) };
    return textToolOutput(result);
  }
);

server.registerTool(
  "build_plan",
  {
    title: "Build Plan",
    description: "Explain which TruthLens sub-agents should run for a claim.",
    inputSchema: z.object({
      claim: z.string().min(2).max(4000),
    }),
  },
  async ({ claim }) => {
    const result = buildPlan(claim);
    return textToolOutput(result);
  }
);

server.registerTool(
  "get_history",
  {
    title: "Get History",
    description: "Return the recent analyses performed by this MCP backend.",
    inputSchema: z.object({}),
  },
  async () => {
    return textToolOutput({
      ok: true,
      history: recentAnalyses,
      count: recentAnalyses.length,
    });
  }
);

server.registerTool(
  "get_metrics",
  {
    title: "Get Metrics",
    description: "Return a lightweight metrics snapshot for the TruthLens backend.",
    inputSchema: z.object({}),
  },
  async () => {
    return textToolOutput({ ok: true, ...getMetricsSnapshot() });
  }
);

async function runStdio() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`[${APP_NAME}] running via stdio`);
}

async function runHttp() {
  const express = (await import("express")).default;
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "1mb" }));

  app.use((req, res, next) => {
    const origin = req.headers.origin || "";
    const normalizedAllowed = ALLOWED_ORIGINS.map((allowedOrigin) => allowedOrigin.replace(/\/$/, ""));
    const allowed =
      !origin ||
      normalizedAllowed.length === 0 ||
      normalizedAllowed.includes("*") ||
      normalizedAllowed.some((allowedOrigin) => origin === allowedOrigin || origin.startsWith(allowedOrigin));

    if (allowed) {
      res.setHeader("Access-Control-Allow-Origin", origin || "*");
      res.setHeader("Vary", "Origin");
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept");
      res.setHeader("Access-Control-Max-Age", "86400");
    }

    if (req.method === "OPTIONS") {
      res.status(204).end();
      return;
    }

    next();
  });

  app.get("/health", (_req, res) => {
    res.json({
      ok: true,
      app: APP_NAME,
      transport: "http",
      uptimeSeconds: Math.floor((Date.now() - metrics.startedAt) / 1000),
    });
  });

  app.get(HTTP_METRICS_PATH, (req, res) => {
    if (!applyAuth(req, res) || !applyOriginCheck(req, res)) return;
    res.json({ ok: true, ...getMetricsSnapshot() });
  });

  app.all("/mcp", async (req, res) => {
    if (!applyAuth(req, res) || !applyOriginCheck(req, res)) return;

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });

    res.on("close", () => transport.close());

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  app.post(ANALYZE_ENDPOINT, async (req, res) => {
    if (!applyAuth(req, res) || !applyOriginCheck(req, res)) return;

    const claim = normalizeClaimText(req.body?.claim || req.body?.query || "");
    if (claim.length < 3) {
      res.status(400).json({
        ok: false,
        error: { code: "INVALID_INPUT", message: "Claim must be at least 3 characters." },
      });
      return;
    }

    try {
      const payload = await runBackendAnalysis(claim, { routeSource: "http" });
      res.status(200).json(payload);
    } catch (error) {
      metrics.failures += 1;
      res.status(500).json({
        ok: false,
        error: {
          code: "INTERNAL_ERROR",
          message: error instanceof Error ? error.message.slice(0, 180) : "MCP analysis failed.",
        },
      });
    }
  });

  app.listen(PORT, "0.0.0.0", () => {
    console.error(`[${APP_NAME}] running on http://0.0.0.0:${PORT}${ANALYZE_ENDPOINT}`);
  });
}

async function main() {
  if (TRANSPORT === "http") {
    await runHttp();
    return;
  }
  await runStdio();
}

main().catch((error) => {
  metrics.failures += 1;
  console.error(`[${APP_NAME}] MCP server crashed:`, error);
  process.exit(1);
});
