/**
 * AI Markets SSO ticket (ai-marketplace-api `POST /v1/paperclip/launch`).
 *
 * The marketplace sends the buyer to
 * `https://{userId}.paperclip.aimarkets.vn/api/auth/aimarkets/sso?ticket=...` where
 *   ticket  = base64url(JSON payload) + "." + base64url(HMAC-SHA256(secret, "aimr.v1.paperclip." + payload))
 *   payload = { v: 1, rt: "paperclip", uid, name, email, exp (ms), jti }
 * and `secret` is PAPERCLIP_SSO_SECRET (or AIMARKETS_RUNTIME_SSO_SECRET), identical on both sides.
 */

import { createHmac, timingSafeEqual } from "node:crypto";

export const AIMARKETS_SSO_RUNTIME = "paperclip";
export const AIMARKETS_SSO_PATH = "/aimarkets/sso";
export const AIMARKETS_SSO_TICKET_QUERY_PARAM = "ticket";

const USER_ID_RE = /^[a-f0-9]{24}$/;
const MAX_TICKET_LENGTH = 4096;

export type AimarketsSsoPayload = {
  v: 1;
  rt: typeof AIMARKETS_SSO_RUNTIME;
  uid: string;
  name: string;
  email: string;
  /** Milliseconds since epoch. */
  exp: number;
  jti: string;
};

export function resolveAimarketsSsoSecret(env: NodeJS.ProcessEnv = process.env): string | null {
  return env.PAPERCLIP_SSO_SECRET?.trim() || env.AIMARKETS_RUNTIME_SSO_SECRET?.trim() || null;
}

/** Email domain of the synthetic per-buyer account (real buyer emails are never shown to other tenants). */
export function aimarketsSsoEmail(uid: string, env: NodeJS.ProcessEnv = process.env): string {
  const domain = env.AIMARKETS_SSO_EMAIL_DOMAIN?.trim() || "users.aimarkets.vn";
  return `${uid}@${domain}`;
}

function base64UrlDecode(value: string): Buffer | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const decoded = Buffer.from(value, "base64url");
  return decoded.length > 0 ? decoded : null;
}

export function cleanAimarketsSsoName(value: unknown, uid: string): string {
  const name = String(value ?? "")
    .replace(/[\u0000-\u001f<>]/g, "")
    .trim()
    .slice(0, 80);
  return name || `AI Markets ${uid.slice(-6)}`;
}

export function verifyAimarketsSsoTicket(input: {
  ticket: string | null | undefined;
  secret: string | null | undefined;
  now?: number;
}): AimarketsSsoPayload | null {
  const secret = input.secret?.trim();
  const raw = input.ticket?.trim();
  if (!secret || !raw || raw.length > MAX_TICKET_LENGTH) return null;
  const segments = raw.split(".");
  if (segments.length !== 2) return null;
  const [encodedPayload, encodedSignature] = segments as [string, string];

  const provided = base64UrlDecode(encodedSignature);
  if (!provided) return null;
  const expected = createHmac("sha256", secret)
    .update(`aimr.v1.${AIMARKETS_SSO_RUNTIME}.${encodedPayload}`)
    .digest();
  // Signature first: never parse attacker-controlled JSON we have not authenticated.
  if (expected.length !== provided.length || !timingSafeEqual(expected, provided)) return null;

  const decoded = base64UrlDecode(encodedPayload);
  if (!decoded) return null;
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(decoded.toString("utf8")) as Record<string, unknown>;
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;
  if (parsed.v !== 1 || parsed.rt !== AIMARKETS_SSO_RUNTIME) return null;
  const uid = String(parsed.uid ?? "").toLowerCase();
  if (!USER_ID_RE.test(uid)) return null;
  const exp = parsed.exp;
  if (typeof exp !== "number" || !Number.isFinite(exp) || exp < (input.now ?? Date.now())) return null;
  const jti = typeof parsed.jti === "string" ? parsed.jti : "";
  if (!jti) return null;

  return {
    v: 1,
    rt: AIMARKETS_SSO_RUNTIME,
    uid,
    name: cleanAimarketsSsoName(parsed.name, uid),
    email: typeof parsed.email === "string" ? parsed.email : "",
    exp,
    jti,
  };
}

/**
 * First DNS label of the request host when it is a buyer host (`{userId}.paperclip...`).
 * Defense in depth only: the ticket is already bound to one buyer; this just stops a
 * ticket from signing the buyer in on somebody else's hostname.
 */
export function aimarketsHostUserId(host: string | null | undefined): string | null {
  const label = String(host ?? "")
    .split(",")[0]!
    .trim()
    .toLowerCase()
    .split(":")[0]!
    .split(".")[0]!;
  return USER_ID_RE.test(label) ? label : null;
}
