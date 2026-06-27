/**
 * CyberGuard API client.
 *
 * Expects a FastAPI backend (the user's uploaded Python code) hosted at
 * VITE_CYBERGUARD_API_URL with the routes documented in API_ROUTES below.
 * CORS must allow the app origin.
 */

export const API_BASE: string =
  (import.meta.env.VITE_CYBERGUARD_API_URL as string | undefined)?.replace(/\/$/, "") ?? "";

export const API_ROUTES = {
  url: "/api/url/analyze",
  password: "/api/password/analyze",
  headers: "/api/headers/check",
  phishing: "/api/phishing/analyze",
  report: "/api/report/generate",
} as const;

export class ApiError extends Error {
  constructor(message: string, public status?: number) {
    super(message);
  }
}

async function post<T>(path: string, body: unknown): Promise<T> {
  if (!API_BASE) {
    throw new ApiError(
      "Backend URL not configured. Set VITE_CYBERGUARD_API_URL in Settings.",
    );
  }
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (e) {
    throw new ApiError(
      `Network error reaching backend at ${API_BASE}. Is it running and CORS enabled?`,
    );
  }
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new ApiError(text || `Request failed (${res.status})`, res.status);
  }
  return res.json() as Promise<T>;
}

/* ---------- Types matching the Python services ---------- */

export interface UrlAnalysisResult {
  url: string;
  is_https: boolean;
  ssl?: { valid: boolean; issuer?: string; expires?: string; days_remaining?: number };
  dns?: { a?: string[]; mx?: string[]; ns?: string[] };
  whois?: { registrar?: string; created?: string; expires?: string; country?: string };
  redirects?: string[];
  risk_score: number;
  findings: { severity: "low" | "medium" | "high" | "info"; message: string }[];
  recommendations: string[];
}

export interface PasswordAnalysisResult {
  length: number;
  entropy: number;
  charset_size: number;
  has_uppercase: boolean;
  has_lowercase: boolean;
  has_digits: boolean;
  has_special: boolean;
  has_repeated_chars: boolean;
  has_sequential_chars: boolean;
  is_common_password: boolean;
  score: number;
  strength: string;
  crack_time_estimate: string;
  crack_seconds: number;
  suggestions: string[];
}

export interface HeadersResult {
  url: string;
  score: number;
  grade: string;
  headers: Record<string, string | null>;
  present: string[];
  missing: string[];
  recommendations: { header: string; message: string }[];
}

export interface PhishingResult {
  url: string;
  risk_score: number;
  verdict: string;
  indicators: { name: string; triggered: boolean; weight: number; description: string }[];
  findings: string[];
  recommendations: string[];
}

export const api = {
  analyzeUrl: (url: string) => post<UrlAnalysisResult>(API_ROUTES.url, { url }),
  analyzePassword: (password: string) =>
    post<PasswordAnalysisResult>(API_ROUTES.password, { password }),
  checkHeaders: (url: string) => post<HeadersResult>(API_ROUTES.headers, { url }),
  analyzePhishing: (url: string) => post<PhishingResult>(API_ROUTES.phishing, { url }),
  generateReport: async (payload: unknown): Promise<Blob> => {
    if (!API_BASE) throw new ApiError("Backend URL not configured.");
    const res = await fetch(`${API_BASE}${API_ROUTES.report}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new ApiError(`Report failed (${res.status})`, res.status);
    return res.blob();
  },
};

/* ---------- Settings persistence ---------- */

const SETTINGS_KEY = "cyberguard:settings";
export interface AppSettings {
  apiUrl: string;
  profileName: string;
  profileEmail: string;
}
export function loadSettings(): AppSettings {
  if (typeof window === "undefined") return { apiUrl: "", profileName: "", profileEmail: "" };
  try {
    const raw = window.localStorage.getItem(SETTINGS_KEY);
    if (raw) return JSON.parse(raw) as AppSettings;
  } catch {}
  return {
    apiUrl: (import.meta.env.VITE_CYBERGUARD_API_URL as string | undefined) ?? "",
    profileName: "Security Analyst",
    profileEmail: "",
  };
}
export function saveSettings(s: AppSettings) {
  if (typeof window !== "undefined") {
    window.localStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
  }
}