import { NextRequest, NextResponse } from "next/server";

const API_URL = process.env.API_URL ?? "http://backend:8000";
// The key this console uses for browser-originated calls. Prefer a dedicated,
// least-privilege FRONTEND_API_KEY; fall back to the legacy single API_KEY.
const API_KEY = process.env.FRONTEND_API_KEY || process.env.API_KEY;

export const dynamic = "force-dynamic";

async function proxy(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const { path } = await context.params;
  // Never let a decoded dot-segment walk outside the API root.
  if (path.some((segment) => segment === "." || segment === ".." || segment.includes("/") || segment.includes("\\"))) {
    return NextResponse.json({ detail: "invalid path" }, { status: 400 });
  }
  const upstream = new URL(`${API_URL}/${path.join("/")}`);
  upstream.search = request.nextUrl.search;
  const headers: Record<string, string> = { "content-type": request.headers.get("content-type") ?? "application/json" };
  if (API_KEY) headers["x-api-key"] = API_KEY;
  const accept = request.headers.get("accept");
  if (accept) headers.accept = accept;
  const response = await fetch(upstream, {
    method: request.method,
    headers,
    body: request.method === "GET" ? undefined : await request.text(),
    cache: "no-store",
    signal: request.signal,
  });
  const contentType = response.headers.get("content-type") ?? "application/json";
  const outHeaders: Record<string, string> = { "content-type": contentType };
  if (contentType.startsWith("text/event-stream")) {
    // Live stream: pass bytes through unbuffered.
    outHeaders["cache-control"] = "no-store";
    outHeaders["x-accel-buffering"] = "no";
  }
  return new NextResponse(response.body, { status: response.status, headers: outHeaders });
}

export const GET = proxy;
export const POST = proxy;
export const PUT = proxy;
