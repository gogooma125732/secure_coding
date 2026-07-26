/** Cloudflare Worker entry point for the vinext-starter template. */
import { handleImageOptimization, DEFAULT_DEVICE_SIZES, DEFAULT_IMAGE_SIZES } from "vinext/server/image-optimization";
import handler from "vinext/server/app-router-entry";

interface Env {
  ASSETS: Fetcher;
  DB: D1Database;
  UPLOADS: R2Bucket;
  ADMIN_BOOTSTRAP_TOKEN?: string;
  BOT_PROTECTION_MODE?: string;
  BOT_PROTECTION_SECRET?: string;
  PLATFORM_IDENTITY_SECRET?: string;
  PASSKEY_RP_ID?: string;
  PASSKEY_ORIGIN?: string;
  WEB3_CHAIN_ID?: string;
  WEB3_RPC_URL?: string;
  WEB3_RPC_HOST_ALLOWLIST?: string;
  WEB3_ESCROW_ADDRESS?: string;
  WEB3_PAYMENT_TOKEN_ADDRESS?: string;
  WEB3_CONFIRMATIONS?: string;
  IMAGES: {
    input(stream: ReadableStream): {
      transform(options: Record<string, unknown>): {
        output(options: { format: string; quality: number }): Promise<{ response(): Response }>;
      };
    };
  };
}

interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

// Image security config. SVG sources with .svg extension auto-skip the
// optimization endpoint on the client side (served directly, no proxy).
// To route SVGs through the optimizer (with security headers), set
// dangerouslyAllowSVG: true in next.config.js and uncomment below:
// const imageConfig: ImageConfig = { dangerouslyAllowSVG: true };

const worker = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const nonce = createNonce();
    const allowDevelopmentWebSockets =
      url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1");
    const contentSecurityPolicy = buildContentSecurityPolicy(nonce, false, allowDevelopmentWebSockets);
    const reportOnlyPolicy = buildContentSecurityPolicy(nonce, true, allowDevelopmentWebSockets);
    const requestHeaders = new Headers(request.headers);
    // Next/Vinext reads the request CSP and propagates its nonce to framework
    // bootstrap scripts. A fresh nonce is generated for every request.
    requestHeaders.set("content-security-policy", contentSecurityPolicy);
    requestHeaders.set("x-nonce", nonce);
    const securedRequest = new Request(request, { headers: requestHeaders });
    let response: Response;

    if (url.pathname === "/_vinext/image") {
      const allowedWidths = [...DEFAULT_DEVICE_SIZES, ...DEFAULT_IMAGE_SIZES];
      response = await handleImageOptimization(securedRequest, {
        fetchAsset: (path) => env.ASSETS.fetch(new Request(new URL(path, request.url))),
        transformImage: async (body, { width, format, quality }) => {
          const result = await env.IMAGES.input(body).transform(width > 0 ? { width } : {}).output({ format, quality });
          return result.response();
        },
      }, allowedWidths);
    } else {
      response = await handler.fetch(securedRequest, env, ctx);
    }

    const headers = new Headers(response.headers);
    headers.set("x-content-type-options", "nosniff");
    headers.set("referrer-policy", "no-referrer");
    headers.set("x-frame-options", "DENY");
    headers.set("cross-origin-opener-policy", "same-origin");
    headers.set("cross-origin-resource-policy", "same-origin");
    headers.set("x-permitted-cross-domain-policies", "none");
    headers.set("permissions-policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
    headers.delete("server");
    headers.delete("x-powered-by");
    headers.set("content-security-policy", contentSecurityPolicy);
    headers.set("content-security-policy-report-only", reportOnlyPolicy);
    headers.set("reporting-endpoints", `csp-endpoint="${url.origin}/api/security/csp-report"`);
    // A response containing a per-request nonce must never be shared from a
    // cache, otherwise a previously issued nonce could be replayed.
    if (headers.get("content-type")?.includes("text/html")) {
      headers.set("cache-control", "private, no-store");
    }
    if (url.pathname.startsWith("/api/")) {
      headers.set("cache-control", "no-store");
      headers.set("x-api-version", "1");
    }
    if (url.protocol === "https:") {
      headers.set("strict-transport-security", "max-age=31536000; includeSubDomains");
    }
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  },
};

function buildContentSecurityPolicy(nonce: string, reportOnly: boolean, allowDevelopmentWebSockets: boolean): string {
  const directives = [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "img-src 'self' blob: data:",
    "frame-src 'none'",
    allowDevelopmentWebSockets ? "connect-src 'self' ws: wss:" : "connect-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
    "script-src-attr 'none'",
    `style-src 'self' 'nonce-${nonce}'`,
    // React's streaming renderer may emit narrowly scoped style attributes for
    // hidden transport nodes. Keep attributes compatible while requiring a
    // request nonce for every inline <style> block.
    "style-src-attr 'unsafe-inline'",
    "font-src 'self' data:",
    "manifest-src 'self'",
    "worker-src 'self' blob:",
  ];
  if (reportOnly) {
    directives.push("require-trusted-types-for 'script'", "report-uri /api/security/csp-report", "report-to csp-endpoint");
  }
  return `${directives.join("; ")};`;
}

function createNonce(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export default worker;
