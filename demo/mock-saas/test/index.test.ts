import { SELF } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index";

const INGEST_URL = "https://saas.example.invalid/ingest";
const CONTROLLED_ENDPOINT_TOKEN = `ce_${"t".repeat(43)}`;
const RATE_LIMIT_KEY = "demo-agent-synthetic-actor";

type TestEnv = {
  CONTROLLED_ENDPOINT_TOKEN?: string;
  CONTROLLED_ENDPOINT_RATE_LIMITER?: RateLimit;
};

const invokeWorker = worker.fetch as (
  request: Request,
  env: TestEnv,
  context: ExecutionContext,
) => Promise<Response>;
const testContext = {} as ExecutionContext;

class TestRateLimiter implements RateLimit {
  readonly keys: string[] = [];

  constructor(private readonly success: boolean) {}

  async limit(options: RateLimitOptions): Promise<RateLimitOutcome> {
    this.keys.push(options.key);
    return { success: this.success };
  }
}

function testEnv(options?: {
  token?: string;
  limiter?: TestRateLimiter;
}): TestEnv {
  return {
    CONTROLLED_ENDPOINT_TOKEN:
      options && "token" in options
        ? options.token
        : CONTROLLED_ENDPOINT_TOKEN,
    CONTROLLED_ENDPOINT_RATE_LIMITER:
      options && "limiter" in options
        ? options.limiter
        : new TestRateLimiter(true),
  };
}

function ingestRequest(authorization?: string): Request {
  const headers = new Headers({ "content-type": "application/json" });
  if (authorization !== undefined) headers.set("authorization", authorization);
  return new Request(INGEST_URL, {
    method: "POST",
    headers,
    body: JSON.stringify({ asset: "demo-laptop-042", owner: "example-user" }),
  });
}

function fetchWorker(url = INGEST_URL, init?: RequestInit): Promise<Response> {
  const headers = new Headers(init?.headers);
  if (init?.method === "POST" && !headers.has("authorization")) {
    headers.set("authorization", `Bearer ${CONTROLLED_ENDPOINT_TOKEN}`);
  }
  return SELF.fetch(url, { ...init, headers });
}

describe("controlled external endpoint", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("echoes a bounded safe JSON body", async () => {
    const body = { asset: "demo-laptop-042", owner: "example-user" };
    const response = await fetchWorker(INGEST_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toMatch(/^application\/json/);
    expect(await response.json()).toEqual({ received: body });
  });

  it("rejects non-POST requests", async () => {
    const response = await fetchWorker();

    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("POST");
    expect(await response.json()).toEqual({ error: "Method not allowed" });
  });

  it("returns not found for paths other than the exact ingest path", async () => {
    const response = await fetchWorker(
      "https://saas.example.invalid/ingest/",
      { method: "POST", body: "{}" },
    );

    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: "Not found" });
  });

  it("rejects invalid JSON", async () => {
    const response = await fetchWorker(INGEST_URL, {
      method: "POST",
      body: "not-json",
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "Invalid JSON" });
  });

  it("accepts a body of exactly 4096 bytes", async () => {
    const value = "x".repeat(4084);
    const body = JSON.stringify({ value });
    expect(new TextEncoder().encode(body).byteLength).toBe(4096);

    const response = await fetchWorker(INGEST_URL, {
      method: "POST",
      body,
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ received: { value } });
  });

  it("rejects a body one byte over the 4096-byte limit", async () => {
    const body = JSON.stringify({ value: "x".repeat(4085) });
    expect(new TextEncoder().encode(body).byteLength).toBe(4097);

    const response = await fetchWorker(INGEST_URL, {
      method: "POST",
      body,
    });

    expect(response.status).toBe(413);
    expect(await response.json()).toEqual({ error: "Payload too large" });
  });

  it("rejects an absent body as invalid JSON", async () => {
    const response = await fetchWorker(INGEST_URL, {
      method: "POST",
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "Invalid JSON" });
  });

  it("rejects a zero-byte body as invalid JSON", async () => {
    const response = await fetchWorker(INGEST_URL, {
      method: "POST",
      body: "",
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "Invalid JSON" });
  });

  it("decodes UTF-8 JSON content", async () => {
    const response = await fetchWorker(INGEST_URL, {
      method: "POST",
      headers: { "content-type": "application/json; charset=utf-8" },
      body: JSON.stringify({ owner: "Jos\u00e9", status: "\u2713" }),
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      received: { owner: "Jos\u00e9", status: "\u2713" },
    });
  });

  it("rejects invalid UTF-8 JSON content", async () => {
    const invalidUtf8Json = new Uint8Array([
      0x7b, 0x22, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x22, 0x3a, 0x22, 0xc3,
      0x28, 0x22, 0x7d,
    ]);
    const response = await fetchWorker(INGEST_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: invalidUtf8Json,
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "Invalid JSON" });
  });

  it("preserves a numeric exponent that overflows JavaScript numbers", async () => {
    const response = await fetchWorker(INGEST_URL, {
      method: "POST",
      body: "1e400",
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toMatch(/^application\/json/);
    expect(await response.text()).toBe('{"received":1e400}');
  });

  it("preserves an integer beyond JavaScript's safe range", async () => {
    const response = await fetchWorker(INGEST_URL, {
      method: "POST",
      body: "9007199254740993",
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toMatch(/^application\/json/);
    expect(await response.text()).toBe('{"received":9007199254740993}');
  });

  it("does not carry payload data into a later request", async () => {
    const firstResponse = await fetchWorker(INGEST_URL, {
      method: "POST",
      body: JSON.stringify({ request: "first-request-only" }),
    });
    expect(firstResponse.status).toBe(200);

    const secondResponse = await fetchWorker(INGEST_URL, {
      method: "POST",
      body: JSON.stringify({ request: "second" }),
    });

    expect(secondResponse.status).toBe(200);
    expect(await secondResponse.json()).toEqual({
      received: { request: "second" },
    });
  });

  it("logs only sanitized acceptance metadata", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const secret = "must-not-be-logged";

    const response = await fetchWorker(INGEST_URL, {
      method: "POST",
      headers: {
        authorization: `Bearer ${CONTROLLED_ENDPOINT_TOKEN}`,
        "x-unused-secret": secret,
      },
      body: JSON.stringify({ secret }),
    });

    expect(response.status).toBe(200);
    expect(log).toHaveBeenCalledOnce();
    expect(JSON.parse(String(log.mock.calls[0]?.[0]))).toEqual({
      message: "controlled endpoint request accepted",
      method: "POST",
      path: "/ingest",
      bodyBytes: 31,
    });
    expect(String(log.mock.calls[0]?.[0])).not.toContain(secret);
  });

  it.each([
    ["missing", undefined],
    ["wrong scheme", `Basic ${CONTROLLED_ENDPOINT_TOKEN}`],
    ["lowercase scheme", `bearer ${CONTROLLED_ENDPOINT_TOKEN}`],
    ["extra spacing", `Bearer  ${CONTROLLED_ENDPOINT_TOKEN}`],
    ["multiple values", `Bearer ${CONTROLLED_ENDPOINT_TOKEN}, Bearer other`],
    ["wrong token", `Bearer ce_${"w".repeat(43)}`],
    ["arbitrary bearer", "Bearer arbitrary-value"],
  ])("rejects %s authorization without reading the body", async (_case, authorization) => {
    const request = ingestRequest(authorization);
    const limiter = new TestRateLimiter(true);

    const response = await invokeWorker(
      request,
      testEnv({ limiter }),
      testContext,
    );

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "Unauthorized" });
    expect(request.bodyUsed).toBe(false);
    expect(limiter.keys).toEqual([]);
  });

  it("fails closed when the secret binding is unavailable", async () => {
    const request = ingestRequest(`Bearer ${CONTROLLED_ENDPOINT_TOKEN}`);
    const limiter = new TestRateLimiter(true);

    const response = await invokeWorker(
      request,
      testEnv({ token: undefined, limiter }),
      testContext,
    );

    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "Service unavailable" });
    expect(request.bodyUsed).toBe(false);
    expect(limiter.keys).toEqual([]);
  });

  it("fails closed when the rate-limit binding is unavailable", async () => {
    const request = ingestRequest(`Bearer ${CONTROLLED_ENDPOINT_TOKEN}`);

    const response = await invokeWorker(
      request,
      testEnv({ limiter: undefined }),
      testContext,
    );

    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "Service unavailable" });
    expect(request.bodyUsed).toBe(false);
  });

  it("rejects a rate-limited request without reading the body", async () => {
    const request = ingestRequest(`Bearer ${CONTROLLED_ENDPOINT_TOKEN}`);
    const limiter = new TestRateLimiter(false);

    const response = await invokeWorker(
      request,
      testEnv({ limiter }),
      testContext,
    );

    expect(response.status).toBe(429);
    expect(await response.json()).toEqual({ error: "Too many requests" });
    expect(request.bodyUsed).toBe(false);
    expect(limiter.keys).toEqual([RATE_LIMIT_KEY]);
  });

  it("authenticates and rate-limits before accepting an exact safe request", async () => {
    const request = ingestRequest(`Bearer ${CONTROLLED_ENDPOINT_TOKEN}`);
    const limiter = new TestRateLimiter(true);

    const response = await invokeWorker(
      request,
      testEnv({ limiter }),
      testContext,
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      received: { asset: "demo-laptop-042", owner: "example-user" },
    });
    expect(request.bodyUsed).toBe(true);
    expect(limiter.keys).toEqual([RATE_LIMIT_KEY]);
  });
});
