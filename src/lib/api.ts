/**
 * CyberGuard API client.
 *
 * Expects a FastAPI backend (the user's uploaded Python code) hosted at
 * VITE_CYBERGUARD_API_URL with the routes documented in API_ROUTES below.
 * CORS must allow the app origin.
 */

const DEFAULT_BASE = "https://cyberguard-api-y49i.onrender.com";

const BUILD_TIME_BASE: string =
  (import.meta.env.VITE_CYBERGUARD_API_URL as string | undefined)?.replace(/\/$/, "") ||
  DEFAULT_BASE;

const RUNTIME_KEY = "cyberguard:api-url";

/** Resolved base URL: runtime override (Settings) wins over build-time env. */
export function getApiBase(): string {
  if (typeof window !== "undefined") {
    try {
      const override = window.localStorage.getItem(RUNTIME_KEY);
      if (override) return override.replace(/\/$/, "");
    } catch {}
  }
  return BUILD_TIME_BASE;
}

/** Back-compat export — prefer `getApiBase()` for fresh reads. */
export const API_BASE: string = BUILD_TIME_BASE;

export const API_ROUTES = {
  url: "/api/url-check",
  password: "/api/password-strength",
  headers: "/api/security-headers",
  phishing: "/api/phishing-detect",
  report: "/api/report",
  health: "/api/health",
} as const;

export class ApiError extends Error {
  constructor(message: string, public status?: number) {
    super(message);
  }
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const base = getApiBase();
  if (!base) {
    throw new ApiError(
      "Backend URL not configured. Paste your Render URL in Settings → Backend API.",
    );
  }
  let res: Response;
  try {
    res = await fetch(`${base}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (e) {
    throw new ApiError(
      `Network error reaching backend at ${base}. Is it running and CORS enabled?`,
    );
  }
  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    try {
      const txt = await res.text();
      try {
        const j = JSON.parse(txt);
        msg = j?.detail || j?.message || txt || msg;
      } catch {
        if (txt) msg = txt;
      }
    } catch {}
    throw new ApiError(msg, res.status);
  }
  return res.json() as Promise<T>;
}

/* ---------- Types matching the live FastAPI backend ---------- */

export interface Finding {
  label?: string;
  description?: string;
  score?: number;
  severity?: string;
}

export interface SSLInfo {
  valid?: boolean;
  issuer?: { commonName?: string; organizationName?: string; countryName?: string } | null;
  subject?: { commonName?: string } | null;
  not_before?: string | null;
  not_after?: string | null;
  days_remaining?: number | null;
  expiry_status?: string | null;
  tls_version?: string | null;
  tls_trusted?: boolean | null;
  san?: string[] | null;
  error?: string | null;
}

export interface WhoisInfo {
  domain?: string | null;
  registrar?: string | null;
  creation_date?: string | null;
  expiry_date?: string | null;
  updated_date?: string | null;
  organization?: string | null;
  country?: string | null;
  name_servers?: string[] | null;
  age_days?: number | null;
  days_until_expiry?: number | null;
  newly_registered?: boolean | null;
  expiring_soon?: boolean | null;
  found?: boolean;
  error?: string | null;
}

export interface DnsRecordSet {
  hostname?: string;
  record_type?: string;
  records?: Array<Record<string, unknown>>;
  found?: boolean;
  error?: string | null;
}

export interface DnsInfo {
  hostname?: string;
  results?: Record<string, DnsRecordSet>;
}

export interface UrlAnalysisResult {
  url: string;
  valid?: boolean;
  https?: boolean;
  ssl?: SSLInfo | null;
  dns?: DnsInfo | null;
  whois?: WhoisInfo | null;
  redirects?: string[];
  final_url?: string;
  url_length?: number;
  subdomain_count?: number;
  hyphen_count?: number;
  dot_count?: number;
  is_ip_url?: boolean;
  is_shortener?: boolean;
  has_punycode?: boolean;
  has_unicode?: boolean;
  has_at_symbol?: boolean;
  has_hex_encoding?: boolean;
  suspicious_tld?: boolean;
  tld?: string;
  suspicious_keywords?: string[];
  risk?: {
    score?: number;
    raw_score?: number;
    risk_level?: string;
    findings?: Finding[];
    recommendations?: string[];
  };
  error?: string | null;
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

export interface HeaderFinding {
  header: string;
  present: boolean;
  value?: string | null;
  score?: number;
  max_score?: number;
  status?: "good" | "weak" | "missing" | string;
  note?: string;
  description?: string;
  recommended?: string;
}

export interface HeadersResult {
  url: string;
  score: number;
  grade?: string;
  risk_level?: string;
  headers_found?: Record<string, string>;
  findings?: HeaderFinding[];
  recommendations?: string[];
  error?: string | null;
}

export interface PhishingResult {
  url: string;
  valid?: boolean;
  score: number;
  risk_level?: string;
  is_phishing?: boolean;
  confidence?: string;
  findings?: Finding[];
  explanation?: string;
  recommendations?: string[];
  checks_performed?: string[];
  error?: string | null;
}

export const api = {
  analyzeUrl: (url: string) => post<UrlAnalysisResult>(API_ROUTES.url, { url }),
  analyzePassword: (password: string) =>
    post<PasswordAnalysisResult>(API_ROUTES.password, { password }),
  checkHeaders: (url: string) => post<HeadersResult>(API_ROUTES.headers, { url }),
  analyzePhishing: (url: string) => post<PhishingResult>(API_ROUTES.phishing, { url }),
  generateReport: async (payload: unknown): Promise<Blob> => {
    const base = getApiBase();
    if (!base) throw new ApiError("Backend URL not configured.");
    const res = await fetch(`${base}${API_ROUTES.report}`, {
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
    apiUrl:
      (typeof window !== "undefined" && window.localStorage.getItem(RUNTIME_KEY)) ||
      (import.meta.env.VITE_CYBERGUARD_API_URL as string | undefined) ||
      "",
    profileName: "Security Analyst",
    profileEmail: "",
  };
}
export function saveSettings(s: AppSettings) {
  if (typeof window !== "undefined") {
    window.localStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
    const trimmed = s.apiUrl.trim().replace(/\/$/, "");
    if (trimmed) window.localStorage.setItem(RUNTIME_KEY, trimmed);
    else window.localStorage.removeItem(RUNTIME_KEY);
  }
}