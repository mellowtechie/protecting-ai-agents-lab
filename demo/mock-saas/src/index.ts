const MAX_BODY_BYTES = 4096;
const RATE_LIMIT_KEY = "demo-agent-synthetic-actor";
const TOKEN_PATTERN = /^ce_[A-Za-z0-9_-]{43}$/;

type ControlledEndpointEnv = Env & {
  readonly CONTROLLED_ENDPOINT_TOKEN: string;
};

class PayloadTooLargeError extends Error {}

class InvalidJsonError extends Error {}

type BoundedJson = {
  size: number;
  text: string;
};

async function tokensMatch(provided: string, expected: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const [providedDigest, expectedDigest] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(provided)),
    crypto.subtle.digest("SHA-256", encoder.encode(expected)),
  ]);
  return crypto.subtle.timingSafeEqual(providedDigest, expectedDigest);
}

async function readBoundedJson(request: Request): Promise<BoundedJson> {
  if (!request.body) throw new InvalidJsonError();

  const declaredSize = Number(request.headers.get("content-length"));
  if (declaredSize > MAX_BODY_BYTES) {
    await request.body.cancel();
    throw new PayloadTooLargeError();
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    size += value.byteLength;
    if (size > MAX_BODY_BYTES) {
      await reader.cancel();
      throw new PayloadTooLargeError();
    }
    chunks.push(value);
  }

  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    const text = new TextDecoder("utf-8", {
      fatal: true,
      ignoreBOM: false,
    }).decode(body);
    JSON.parse(text);
    return { size, text };
  } catch (error) {
    if (error instanceof SyntaxError || error instanceof TypeError) {
      throw new InvalidJsonError();
    }
    throw error;
  }
}

export default {
  async fetch(request: Request, env: ControlledEndpointEnv): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname !== "/ingest") {
      return Response.json({ error: "Not found" }, { status: 404 });
    }
    if (request.method !== "POST") {
      return Response.json(
        { error: "Method not allowed" },
        { headers: { Allow: "POST" }, status: 405 },
      );
    }

    const expectedToken = env.CONTROLLED_ENDPOINT_TOKEN;
    if (typeof expectedToken !== "string" || !TOKEN_PATTERN.test(expectedToken)) {
      return Response.json({ error: "Service unavailable" }, { status: 503 });
    }
    const authorization = request.headers.get("authorization");
    const presented = authorization?.match(/^Bearer ([^\s,]+)$/)?.[1];
    if (!presented || !(await tokensMatch(presented, expectedToken))) {
      return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    const rateLimiter = env.CONTROLLED_ENDPOINT_RATE_LIMITER;
    if (!rateLimiter || typeof rateLimiter.limit !== "function") {
      return Response.json({ error: "Service unavailable" }, { status: 503 });
    }
    try {
      const { success } = await rateLimiter.limit({ key: RATE_LIMIT_KEY });
      if (!success) {
        return Response.json({ error: "Too many requests" }, { status: 429 });
      }
    } catch {
      return Response.json({ error: "Service unavailable" }, { status: 503 });
    }

    try {
      const { size, text } = await readBoundedJson(request);
      console.log(
        JSON.stringify({
          message: "controlled endpoint request accepted",
          method: request.method,
          path: url.pathname,
          bodyBytes: size,
        }),
      );
      return new Response(`{"received":${text}}`, {
        headers: { "content-type": "application/json; charset=utf-8" },
      });
    } catch (error) {
      if (error instanceof PayloadTooLargeError) {
        return Response.json({ error: "Payload too large" }, { status: 413 });
      }
      if (error instanceof InvalidJsonError) {
        return Response.json({ error: "Invalid JSON" }, { status: 400 });
      }
      throw error;
    }
  },
} satisfies ExportedHandler<ControlledEndpointEnv>;
