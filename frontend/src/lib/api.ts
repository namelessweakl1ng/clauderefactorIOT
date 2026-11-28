const API = typeof window === "undefined" ? (process.env.API_URL ?? "http://backend:8000") : "/api";
export type RecordValue = Record<string, unknown>;

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

// Server-side requests attach the optional shared-secret API key when configured;
// browser requests go through the Next proxy route, which attaches it instead.
const serverApiKey = typeof window === "undefined" ? process.env.FRONTEND_API_KEY || process.env.API_KEY : undefined;

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(serverApiKey ? { "X-API-Key": serverApiKey } : {}),
      ...init?.headers,
    },
    cache: "no-store",
  });
  if (!response.ok) {
    const body = await response.text();
    let detail = body;
    try {
      const parsed = JSON.parse(body) as { detail?: unknown };
      if (typeof parsed.detail === "string") detail = parsed.detail;
    } catch {
      // Upstream did not return JSON; retain its readable response text.
    }
    throw new ApiError(response.status, detail || `Request failed with status ${response.status}`);
  }
  return response.json() as Promise<T>;
}

/** Settle several independent requests; each panel renders its own error state. */
export async function load<T>(path: string): Promise<{ data: T | null; error: string | null }> {
  try {
    return { data: await api<T>(path), error: null };
  } catch (caught) {
    return { data: null, error: errorMessage(caught, path) };
  }
}

export function pct(value: unknown, digits = 0): string {
  return typeof value === "number" && Number.isFinite(value) ? `${(value * 100).toFixed(digits)}%` : "—";
}

export function num(value: unknown, digits = 3): string {
  return typeof value === "number" && Number.isFinite(value) ? value.toFixed(digits) : "—";
}

export function secondsSince(timestamp?: string | null): number | null {
  if (!timestamp) return null;
  const value = (Date.now() - new Date(timestamp).getTime()) / 1000;
  return Number.isFinite(value) ? value : null;
}

export function ago(timestamp?: string | null): string {
  if (!timestamp) return "never";
  const seconds = Math.round((Date.now() - new Date(timestamp).getTime()) / 1000);
  if (!Number.isFinite(seconds)) return "unknown";
  if (seconds < 90) return `${Math.max(0, seconds)}s ago`;
  if (seconds < 5400) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 172800) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

export function errorMessage(error: unknown, context: string): string {
  if (error instanceof ApiError) return `${context}: ${error.message}`;
  if (error instanceof Error) return `${context}: ${error.message}`;
  return context;
}

export function displayValue(value: unknown, fallback = "Unknown"): string {
  if (value === null || value === undefined || value === "") return fallback;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return value.length ? value.map((item) => displayValue(item)).join(", ") : "None";
  return fallback;
}
