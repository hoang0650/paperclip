/**
 * Better Auth plugin: exchange an AI Markets SSO ticket for a Paperclip session.
 *
 * Mirrors `workspace-login-handoff-plugin.ts` so session creation and cookie
 * signing stay on Better Auth's supported path. Each marketplace buyer gets one
 * synthetic account (`<uid>@users.aimarkets.vn`) and, on first launch, one company
 * they own. Buyers are never instance admins, so they cannot see other companies.
 *
 * Only registered when PAPERCLIP_SSO_SECRET / AIMARKETS_RUNTIME_SSO_SECRET is set.
 */

import { and, eq } from "drizzle-orm";
import { setSessionCookie } from "better-auth/cookies";
import { createAuthEndpoint } from "better-auth/api";
import type { Session, User } from "better-auth/types";
import type { Db } from "@paperclipai/db";
import { companyMemberships } from "@paperclipai/db";
import { logger } from "../middleware/logger.js";
import { accessService, companyService, logActivity } from "../services/index.js";
import {
  AIMARKETS_SSO_PATH,
  AIMARKETS_SSO_TICKET_QUERY_PARAM,
  aimarketsHostUserId,
  aimarketsSsoEmail,
  resolveAimarketsSsoSecret,
  verifyAimarketsSsoTicket,
} from "./aimarkets-sso.js";

type AimarketsSsoEndpointContext = {
  query?: Record<string, unknown>;
  headers?: Headers;
  setHeader: (name: string, value: string) => void;
  redirect: (url: string) => unknown;
  error: (status: string, body?: Record<string, unknown>) => unknown;
  context: {
    internalAdapter: {
      findUserByEmail: (email: string) => Promise<{ user: User } | null>;
      createUser: (user: { email: string; name: string; emailVerified: boolean }) => Promise<User | null>;
      createSession: (userId: string) => Promise<Session | null>;
      findVerificationValue: (identifier: string) => Promise<{ identifier: string } | null>;
      reserveVerificationValue: (data: { identifier: string; value: string; expiresAt: Date }) => Promise<boolean>;
    };
  };
};

async function ensureBuyerCompany(db: Db, userId: string, name: string): Promise<void> {
  const hasMembership = await db
    .select({ id: companyMemberships.id })
    .from(companyMemberships)
    .where(
      and(
        eq(companyMemberships.principalType, "user"),
        eq(companyMemberships.principalId, userId),
        eq(companyMemberships.status, "active"),
      ),
    )
    .limit(1)
    .then((rows) => rows.length > 0);
  if (hasMembership) return;

  const access = accessService(db);
  const company = await companyService(db).create({
    name: `${name}'s company`,
    budgetMonthlyCents: 0,
    defaultResponsibleUserId: userId,
  } as Parameters<ReturnType<typeof companyService>["create"]>[0]);
  await access.ensureMembership(company.id, "user", userId, "owner", "active");
  await access.ensureRoleDefaultGrants(company.id, userId, "owner", userId);
  await logActivity(db, {
    companyId: company.id,
    actorType: "user",
    actorId: userId,
    action: "company.created",
    entityType: "company",
    entityId: company.id,
    details: { name: company.name, source: "aimarkets-sso" },
  });
}

export function aimarketsSsoPlugin(deps: { db: Db }) {
  return {
    id: "aimarkets-sso",
    endpoints: {
      exchangeAimarketsSso: createAuthEndpoint(
        AIMARKETS_SSO_PATH,
        { method: "GET", requireHeaders: true },
        async (endpointContext) => {
          const ctx = endpointContext as unknown as AimarketsSsoEndpointContext;
          ctx.setHeader("Cache-Control", "no-store");
          ctx.setHeader("Referrer-Policy", "no-referrer");

          const secret = resolveAimarketsSsoSecret();
          if (!secret) {
            throw ctx.error("SERVICE_UNAVAILABLE", { message: "AI Markets SSO is not configured", code: "not_configured" });
          }

          const rawTicket = ctx.query?.[AIMARKETS_SSO_TICKET_QUERY_PARAM];
          const payload = verifyAimarketsSsoTicket({
            ticket: typeof rawTicket === "string" ? rawTicket : null,
            secret,
          });
          if (!payload) {
            logger.warn("aimarkets sso rejected: invalid or expired ticket");
            throw ctx.error("UNAUTHORIZED", {
              message: "Invalid or expired AI Markets ticket. Launch Paperclip again from aimarkets.vn.",
              code: "invalid_ticket",
            });
          }

          const hostUid = aimarketsHostUserId(ctx.headers?.get("x-forwarded-host") || ctx.headers?.get("host"));
          if (hostUid && hostUid !== payload.uid) {
            logger.warn({ nonce: payload.jti }, "aimarkets sso rejected: host mismatch");
            throw ctx.error("FORBIDDEN", { message: "This AI Markets ticket belongs to another workspace.", code: "host_mismatch" });
          }

          const identifier = `aimarkets-sso:${payload.jti}`;
          const fresh =
            !(await ctx.context.internalAdapter.findVerificationValue(identifier)) &&
            (await ctx.context.internalAdapter.reserveVerificationValue({
              identifier,
              value: "consumed",
              expiresAt: new Date(payload.exp + 60_000),
            }));
          if (!fresh) {
            logger.warn({ nonce: payload.jti }, "aimarkets sso rejected: replay");
            throw ctx.error("UNAUTHORIZED", {
              message: "This AI Markets ticket was already used. Launch Paperclip again.",
              code: "ticket_used",
            });
          }

          const email = aimarketsSsoEmail(payload.uid);
          let user = (await ctx.context.internalAdapter.findUserByEmail(email))?.user ?? null;
          if (!user) {
            user = await ctx.context.internalAdapter.createUser({ email, name: payload.name, emailVerified: true });
          }
          if (!user) {
            throw ctx.error("INTERNAL_SERVER_ERROR", { message: "Could not create the Paperclip account", code: "user_failed" });
          }

          await ensureBuyerCompany(deps.db, user.id, user.name || payload.name);

          const session = await ctx.context.internalAdapter.createSession(user.id);
          if (!session) {
            throw ctx.error("INTERNAL_SERVER_ERROR", { message: "Could not create the Paperclip session", code: "session_failed" });
          }
          await setSessionCookie(ctx as never, { session, user });

          logger.info({ nonce: payload.jti, userId: user.id }, "aimarkets sso accepted");
          // Relative redirect keeps the buyer on their own {userId}.paperclip host.
          throw ctx.redirect("/");
        },
      ),
    },
  };
}
