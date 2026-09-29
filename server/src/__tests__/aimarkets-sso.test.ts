import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  aimarketsHostUserId,
  aimarketsSsoEmail,
  resolveAimarketsSsoSecret,
  verifyAimarketsSsoTicket,
} from "../auth/aimarkets-sso.js";

const SECRET = "test-paperclip-sso-secret-0123456789";
const UID = "6a69f224e6032a3f00de977f";

/** Same construction as ai-marketplace-api `src/utils/runtime-sso-ticket.js`. */
function issue(payload: Record<string, unknown>, secret = SECRET, runtime = "paperclip"): string {
  const encoded = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const sig = createHmac("sha256", secret).update(`aimr.v1.${runtime}.${encoded}`).digest("base64url");
  return `${encoded}.${sig}`;
}

function payload(overrides: Record<string, unknown> = {}) {
  return { v: 1, rt: "paperclip", uid: UID, name: "Hoàng", email: "b@x.vn", exp: Date.now() + 60_000, jti: "n1", ...overrides };
}

describe("aimarkets sso ticket", () => {
  it("accepts a ticket signed by the marketplace", () => {
    const result = verifyAimarketsSsoTicket({ ticket: issue(payload()), secret: SECRET });
    expect(result?.uid).toBe(UID);
    expect(result?.name).toBe("Hoàng");
    expect(result?.jti).toBe("n1");
  });

  it("rejects other runtimes, secrets, expiry and tampering", () => {
    expect(verifyAimarketsSsoTicket({ ticket: issue(payload(), SECRET, "openwebui"), secret: SECRET })).toBeNull();
    expect(verifyAimarketsSsoTicket({ ticket: issue(payload(), "other-secret"), secret: SECRET })).toBeNull();
    expect(verifyAimarketsSsoTicket({ ticket: issue(payload({ exp: Date.now() - 1 })), secret: SECRET })).toBeNull();
    expect(verifyAimarketsSsoTicket({ ticket: issue(payload({ jti: "" })), secret: SECRET })).toBeNull();
    expect(verifyAimarketsSsoTicket({ ticket: issue(payload({ uid: "nope" })), secret: SECRET })).toBeNull();

    const [, sig] = issue(payload()).split(".");
    const forged = Buffer.from(JSON.stringify(payload({ uid: "a".repeat(24) }))).toString("base64url");
    expect(verifyAimarketsSsoTicket({ ticket: `${forged}.${sig}`, secret: SECRET })).toBeNull();
    expect(verifyAimarketsSsoTicket({ ticket: issue(payload()), secret: "" })).toBeNull();
  });

  it("strips markup from the display name and falls back when empty", () => {
    expect(verifyAimarketsSsoTicket({ ticket: issue(payload({ name: "<b>x</b>" })), secret: SECRET })?.name).toBe("bx/b");
    expect(verifyAimarketsSsoTicket({ ticket: issue(payload({ name: "" })), secret: SECRET })?.name).toBe(
      `AI Markets ${UID.slice(-6)}`,
    );
  });

  it("reads the buyer id from the host label only", () => {
    expect(aimarketsHostUserId(`${UID}.paperclip.aimarkets.vn`)).toBe(UID);
    expect(aimarketsHostUserId(`${UID.toUpperCase()}.paperclip.aimarkets.vn:443`)).toBe(UID);
    expect(aimarketsHostUserId("paperclip.aimarkets.vn")).toBeNull();
    expect(aimarketsHostUserId(undefined)).toBeNull();
  });

  it("resolves the secret and synthetic email from env", () => {
    expect(resolveAimarketsSsoSecret({ AIMARKETS_RUNTIME_SSO_SECRET: " s " } as NodeJS.ProcessEnv)).toBe("s");
    expect(resolveAimarketsSsoSecret({ PAPERCLIP_SSO_SECRET: "p", AIMARKETS_RUNTIME_SSO_SECRET: "s" } as NodeJS.ProcessEnv)).toBe("p");
    expect(resolveAimarketsSsoSecret({} as NodeJS.ProcessEnv)).toBeNull();
    expect(aimarketsSsoEmail(UID, {} as NodeJS.ProcessEnv)).toBe(`${UID}@users.aimarkets.vn`);
  });
});
