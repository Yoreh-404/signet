#!/usr/bin/env node

import { performance } from "node:perf_hooks";

const baseUrl = new URL(
  process.env.SIGNET_PERF_BASE_URL ?? process.env.APP_URL ?? "http://127.0.0.1:8080",
);
const requestCount = positiveInteger(process.env.SIGNET_PERF_REQUESTS, 500);
const concurrency = positiveInteger(process.env.SIGNET_PERF_CONCURRENCY, 16);
const warmupCount = nonNegativeInteger(
  process.env.SIGNET_PERF_WARMUP_REQUESTS,
  Math.min(64, requestCount),
);
const timeoutMs = positiveInteger(process.env.SIGNET_PERF_TIMEOUT_MS, 5000);
const strict = process.env.SIGNET_PERF_STRICT === "1";

const sessionCookie = process.env.SIGNET_PERF_COOKIE?.trim() || null;
const forwardAuthTarget = process.env.SIGNET_PERF_FORWARD_AUTH_TARGET?.trim() || null;

function positiveInteger(raw, fallback) {
  const value = Number.parseInt(raw ?? "", 10);
  return Number.isInteger(value) && value > 0 ? value : fallback;
}

function nonNegativeInteger(raw, fallback) {
  const value = Number.parseInt(raw ?? "", 10);
  return Number.isInteger(value) && value >= 0 ? value : fallback;
}

function percentile(sorted, fraction) {
  if (sorted.length === 0) return 0;
  const index = Math.min(sorted.length - 1, Math.ceil(sorted.length * fraction) - 1);
  return sorted[index];
}

function formatMs(value) {
  return `${value.toFixed(2)}ms`;
}

function resolve(path) {
  return new URL(path, baseUrl).toString();
}

async function oneRequest(scenario) {
  const started = performance.now();
  try {
    const response = await fetch(resolve(scenario.path), {
      method: scenario.method ?? "GET",
      headers: scenario.headers,
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
    });
    // Consume the body so the connection can be returned to the fetch pool.
    const body = await response.arrayBuffer();
    return {
      status: response.status,
      bytes: body.byteLength,
      latencyMs: performance.now() - started,
      ok: scenario.expectedStatuses.has(response.status),
    };
  } catch (error) {
    return {
      status: "ERR",
      bytes: 0,
      latencyMs: performance.now() - started,
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

async function runRequests(scenario, total) {
  let nextIndex = 0;
  const results = new Array(total);
  const workers = Array.from({ length: Math.min(concurrency, Math.max(total, 1)) }, async () => {
    while (true) {
      const index = nextIndex++;
      if (index >= total) return;
      results[index] = await oneRequest(scenario);
    }
  });
  await Promise.all(workers);
  return results;
}

async function benchmark(scenario) {
  if (warmupCount > 0) {
    await runRequests(scenario, warmupCount);
  }
  const started = performance.now();
  const results = await runRequests(scenario, requestCount);
  const wallMs = performance.now() - started;
  const latencies = results.map((result) => result.latencyMs).sort((a, b) => a - b);
  const failures = results.filter((result) => !result.ok);
  const statuses = new Map();
  for (const result of results) {
    statuses.set(result.status, (statuses.get(result.status) ?? 0) + 1);
  }
  const totalBytes = results.reduce((sum, result) => sum + result.bytes, 0);
  return {
    name: scenario.name,
    requests: requestCount,
    concurrency,
    rps: requestCount / (wallMs / 1000),
    meanMs: latencies.reduce((sum, value) => sum + value, 0) / Math.max(latencies.length, 1),
    p50Ms: percentile(latencies, 0.5),
    p95Ms: percentile(latencies, 0.95),
    p99Ms: percentile(latencies, 0.99),
    maxMs: latencies.at(-1) ?? 0,
    failures: failures.length,
    statuses: Object.fromEntries(statuses),
    responseBytes: totalBytes,
    firstError: failures.find((result) => result.error)?.error ?? null,
  };
}

async function jwksConditionalScenario() {
  const response = await fetch(resolve("/oauth2/jwks"), {
    signal: AbortSignal.timeout(timeoutMs),
  });
  await response.arrayBuffer();
  if (!response.ok) {
    throw new Error(`JWKS bootstrap returned HTTP ${response.status}`);
  }
  const etag = response.headers.get("etag");
  if (!etag) return null;
  return {
    name: "jwks-304",
    path: "/oauth2/jwks",
    headers: { "if-none-match": etag },
    expectedStatuses: new Set([304]),
  };
}

function printSummary(result) {
  const statuses = Object.entries(result.statuses)
    .map(([status, count]) => `${status}:${count}`)
    .join(",");
  console.log(
    [
      result.name.padEnd(16),
      `rps=${result.rps.toFixed(1).padStart(8)}`,
      `p50=${formatMs(result.p50Ms).padStart(10)}`,
      `p95=${formatMs(result.p95Ms).padStart(10)}`,
      `p99=${formatMs(result.p99Ms).padStart(10)}`,
      `max=${formatMs(result.maxMs).padStart(10)}`,
      `fail=${String(result.failures).padStart(4)}`,
      `status=[${statuses}]`,
    ].join("  "),
  );
}

async function main() {
  console.log(
    `Signet perf smoke: base=${baseUrl.origin} requests=${requestCount} concurrency=${concurrency} warmup=${warmupCount}`,
  );

  const scenarios = [
    {
      name: "health-ready",
      path: "/api/health/ready",
      expectedStatuses: new Set([200]),
    },
    {
      name: "oidc-discovery",
      path: "/.well-known/openid-configuration",
      expectedStatuses: new Set([200]),
    },
    {
      name: "jwks-200",
      path: "/oauth2/jwks",
      expectedStatuses: new Set([200]),
    },
  ];

  const conditional = await jwksConditionalScenario();
  if (conditional) scenarios.push(conditional);
  else console.log("jwks-304         skipped: endpoint does not publish ETag");

  if (sessionCookie && forwardAuthTarget) {
    scenarios.push({
      name: "forward-auth",
      path: `/api/iap/forward-auth?target=${encodeURIComponent(forwardAuthTarget)}`,
      headers: { cookie: sessionCookie },
      expectedStatuses: new Set([204]),
    });
  } else {
    console.log(
      "forward-auth     skipped: set SIGNET_PERF_COOKIE and SIGNET_PERF_FORWARD_AUTH_TARGET",
    );
  }

  const results = [];
  for (const scenario of scenarios) {
    const result = await benchmark(scenario);
    results.push(result);
    printSummary(result);
  }

  if (process.env.SIGNET_PERF_JSON === "1") {
    console.log(JSON.stringify({ baseUrl: baseUrl.origin, results }, null, 2));
  }

  const failures = results.reduce((sum, result) => sum + result.failures, 0);
  if (strict && failures > 0) process.exitCode = 1;
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack : error);
  process.exitCode = 1;
});
