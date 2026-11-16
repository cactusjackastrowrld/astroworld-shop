import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";

const siteOrigin = Deno.env.get("SITE_ORIGIN") || "https://cactusjackastrowrld.github.io";
const botToken = Deno.env.get("SHOP_BOT_TOKEN") ?? "";
const ownerId = Deno.env.get("SHOP_OWNER_ID") ?? "";
const adminJwtSecret = Deno.env.get("ADMIN_JWT_SECRET") ?? "";
const webhookSecret = Deno.env.get("SHOP_WEBHOOK_SECRET") ?? "";
const TOKEN_TTL_SECONDS = 12 * 60 * 60; // 12 hours
const LEGACY_SALT = "astro-world-salt-2026";
const PBKDF2_ITERATIONS = 600_000;
const MIN_PASSWORD_LEN = 12;
const LEAKED_SEED_HASH = "db812db08007152375fbf084d0664856b2633f7d0594fa2599a31edae8dbf393";

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.length % 2 === 0 ? hex : "0" + hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16) || 0;
  }
  return out;
}

// Constant-time string comparison (never short-circuits on content)
function constantTimeEqual(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const ba = enc.encode(a);
  const bb = enc.encode(b);
  const len = Math.max(ba.length, bb.length);
  let diff = ba.length ^ bb.length;
  for (let i = 0; i < len; i++) {
    diff |= (ba[i] ?? 0) ^ (bb[i] ?? 0);
  }
  return diff === 0;
}

async function hashIp(ip: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(ip));
  return bytesToHex(new Uint8Array(buf));
}

function getClientIp(req: Request): string {
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    req.headers.get("cf-connecting-ip") || "127.0.0.1";
}

async function isRateLimited(db: any, ipHash: string, maxAttempts: number, windowMinutes = 10): Promise<boolean> {
  const since = new Date(Date.now() - windowMinutes * 60 * 1000).toISOString();
  const { count } = await db.from("rate_limits")
    .select("id", { count: "exact", head: true })
    .eq("ip_hash", ipHash)
    .gte("created_at", since);
  return count !== null && count >= maxAttempts;
}

function isAllowedOrigin(o: string | null) {
  if (!o || o === "null") return true;
  return [siteOrigin, "https://cactusjackastrowrld.github.io", "https://cactusastrowrld.github.io"].includes(o);
}

function getCorsHeaders(origin: string | null) {
  const allowed = isAllowedOrigin(origin) && origin && origin !== "null" ? origin : siteOrigin;
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-admin-token, x-session-id",
    "Vary": "Origin",
  };
}

async function pbkdf2Hex(password: string, saltBytes: Uint8Array, iterations = PBKDF2_ITERATIONS): Promise<string> {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations },
    baseKey,
    256
  );
  return bytesToHex(new Uint8Array(bits));
}

async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const derived = await pbkdf2Hex(password, salt, PBKDF2_ITERATIONS);
  return `pbkdf2$${PBKDF2_ITERATIONS}$${bytesToHex(salt)}$${derived}`;
}

async function hashLegacySha256(password: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(LEGACY_SALT + password));
  return bytesToHex(new Uint8Array(buf));
}

async function verifyPassword(
  password: string,
  storedHash: string | null | undefined
): Promise<{ valid: boolean; needsRehash: boolean }> {
  const dummySalt = new Uint8Array(16);
  const legacyCandidate = await hashLegacySha256(password);
  const isSubmittedSeedPassword = constantTimeEqual(legacyCandidate, LEAKED_SEED_HASH);

  if (!storedHash) {
    await pbkdf2Hex(password, dummySalt, PBKDF2_ITERATIONS);
    return { valid: false, needsRehash: false };
  }

  // Refuse any account whose stored hash equals the leaked seed hash
  if (constantTimeEqual(storedHash, LEAKED_SEED_HASH)) {
    await pbkdf2Hex(password, dummySalt, PBKDF2_ITERATIONS);
    return { valid: false, needsRehash: false };
  }

  if (storedHash.startsWith("pbkdf2$")) {
    const parts = storedHash.split("$");
    const iter = parseInt(parts[1] || "", 10) || PBKDF2_ITERATIONS;
    const saltHex = parts[2] || "";
    const expectedHex = parts[3] || "";
    const derivedHex = await pbkdf2Hex(password, hexToBytes(saltHex), iter);
    const match = constantTimeEqual(derivedHex, expectedHex) && !isSubmittedSeedPassword;
    return { valid: match, needsRehash: match && iter < PBKDF2_ITERATIONS };
  }

  // Legacy non-seed SHA-256 hash: run dummy PBKDF2 for uniform timing, upgrade on match
  await pbkdf2Hex(password, dummySalt, PBKDF2_ITERATIONS);
  const match = constantTimeEqual(legacyCandidate, storedHash) && !isSubmittedSeedPassword;
  return { valid: match, needsRehash: match };
}

async function createToken(payload: { id: string; username: string; role: string; iat: number }) {
  if (!adminJwtSecret || adminJwtSecret.length < 64) {
    throw new Error("Server misconfigured: missing or short ADMIN_JWT_SECRET");
  }
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const exp = Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS;
  const body = btoa(JSON.stringify({ ...payload, exp }));
  const unsigned = `${header}.${body}`;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(adminJwtSecret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(unsigned));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${unsigned}.${sigB64}`;
}

async function verifyToken(token: string): Promise<any | null> {
  try {
    if (!adminJwtSecret || adminJwtSecret.length < 64) return null;
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const unsigned = `${parts[0]}.${parts[1]}`;
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(adminJwtSecret),
      { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const sigStr = atob(parts[2].replace(/-/g, "+").replace(/_/g, "/"));
    const sigBytes = new Uint8Array(sigStr.split("").map(c => c.charCodeAt(0)));
    const valid = await crypto.subtle.verify("HMAC", key, sigBytes, new TextEncoder().encode(unsigned));
    if (!valid) return null;
    const payload = JSON.parse(atob(parts[1]));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

async function tgMessage(text: string) {
  if (!botToken || !ownerId) return;
  await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: ownerId, text, parse_mode: "HTML" }),
  });
}
async function tgPhoto(photo: string, caption: string) {
  if (!botToken || !ownerId) return;
  await fetch(`https://api.telegram.org/bot${botToken}/sendPhoto`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: ownerId, photo, caption, parse_mode: "HTML" }),
  });
}

// Run a task after the response is sent (so users don't wait for it)
function background(p: Promise<unknown>) {
  const safe = p.catch(() => {});
  // deno-lint-ignore no-explicit-any
  const rt = (globalThis as any).EdgeRuntime;
  if (rt?.waitUntil) rt.waitUntil(safe);
}

// Escape text for Telegram HTML messages
function escTg(s: string) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// Only accept real timestamps for "since" filters (keep full microsecond precision)
function safeIso(v: string | null) {
  if (!v) return new Date(0).toISOString();
  const d = new Date(v);
  return isNaN(d.getTime()) ? new Date(0).toISOString() : v.trim();
}

serve(async (req) => {
  const origin = req.headers.get("origin");
  if (req.method === "OPTIONS") return new Response("ok", { headers: getCorsHeaders(origin) });

  const cors = getCorsHeaders(origin);
  const json = (data: any, status = 200) =>
    new Response(JSON.stringify(data), { status, headers: { ...cors, "Content-Type": "application/json" } });

  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/shop-admin/, "").replace(/\/$/, "");

  const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
  const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
  const db = createClient(supabaseUrl, supabaseKey);

  // ─── PUBLIC: Chat widget endpoints (no auth) ───────────────────────────────

  // Customer starts a NEW chat session (every page load = fresh chat)
  if (path === "/chat/open" && req.method === "POST") {
    const clientIp = getClientIp(req);
    const openRateKey = await hashIp("chat:open:" + clientIp);
    const ipHash = await hashIp("chat:ip:" + clientIp);

    const [rateLimited, { count: openSessions }] = await Promise.all([
      isRateLimited(db, openRateKey, 5, 10),
      db.from("conversations")
        .select("id", { count: "exact", head: true })
        .eq("ip_hash", ipHash)
        .eq("status", "open"),
    ]);

    if (rateLimited) {
      return json({ ok: false, error: "Too many chat sessions opened. Please wait a few minutes." }, 429);
    }
    if ((openSessions ?? 0) >= 3) {
      return json({ ok: false, error: "Maximum number of open chat sessions (3) reached for your connection." }, 429);
    }

    background(Promise.resolve(db.from("rate_limits").insert({ ip_hash: openRateKey })));
    const body = await req.json().catch(() => ({}));
    const name = String(body.name || "Customer").replace(/[\x00-\x1F\x7F]/g, "").trim().slice(0, 40) || "Customer";
    const sessionId = crypto.randomUUID();
    const { data: conv, error } = await db.from("conversations")
      .insert({ session_id: sessionId, customer_name: name, status: "open", ip_hash: ipHash })
      .select("id").single();
    if (error || !conv) return json({ ok: false, error: "Could not start chat" }, 500);
    return json({ ok: true, session_id: sessionId });
  }

  // Customer sends a message
  if (path === "/chat/message" && req.method === "POST") {
    const body = await req.json().catch(() => ({}));
    const sessionId = String(body.session_id || "").trim();
    const rawText = String(body.text || "").replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").trim();
    if (!sessionId || !rawText) return json({ ok: false, error: "Missing session_id or text" }, 400);
    if (rawText.length > 500) {
      return json({ ok: false, error: "Message too long (maximum 500 characters)" }, 400);
    }

    const msgRateKey = await hashIp("chat:msg:" + getClientIp(req));
    if (await isRateLimited(db, msgRateKey, 15, 1)) {
      return json({ ok: false, error: "Sending messages too fast. Please wait a moment." }, 429);
    }

    const { data: conv } = await db.from("conversations").select("id, customer_name, status").eq("session_id", sessionId).maybeSingle();
    if (!conv) return json({ ok: false, error: "Session not found" }, 404);
    if (conv.status === "closed") return json({ ok: false, closed: true, error: "This chat was closed" }, 409);

    const { count: sessMsgCount } = await db.from("messages")
      .select("id", { count: "exact", head: true })
      .eq("conversation_id", conv.id)
      .eq("sender", "customer");
    if ((sessMsgCount ?? 0) >= 50) {
      return json({ ok: false, error: "Maximum messages per chat session (50) reached." }, 429);
    }

    const now = new Date().toISOString();
    const [{ data: msg }] = await Promise.all([
      db.from("messages").insert({ conversation_id: conv.id, sender: "customer", sender_name: conv.customer_name, text: rawText })
        .select("id, sender, sender_name, text, created_at").single(),
      db.from("conversations").update({ updated_at: now }).eq("id", conv.id),
      db.from("rate_limits").insert({ ip_hash: msgRateKey }),
    ]);

    // Cap Telegram alerts: at most 1 per 2 mins per conversation, and 5 per 5 mins globally
    const tgConvKey = await hashIp("chat:tg:conv:" + conv.id);
    const tgGlobalKey = await hashIp("chat:tg:global");
    const [convAlerted, globalAlerted] = await Promise.all([
      isRateLimited(db, tgConvKey, 1, 2),
      isRateLimited(db, tgGlobalKey, 5, 5),
    ]);
    if (!convAlerted && !globalAlerted) {
      background(
        Promise.all([
          db.from("rate_limits").insert([{ ip_hash: tgConvKey }, { ip_hash: tgGlobalKey }]),
          tgMessage(`💬 <b>New Chat Message</b>\n<b>${escTg(conv.customer_name)}:</b> ${escTg(rawText)}\n\n<i>Reply in Admin Dashboard → Live Chat</i>`),
        ])
      );
    }
    return json({ ok: true, message: msg });
  }

  // Customer polls for new messages (since a given ISO timestamp)
  if (path === "/chat/poll" && req.method === "GET") {
    const sessionId = url.searchParams.get("session_id");
    if (!sessionId) return json({ ok: false, error: "Missing session_id" }, 400);
    const since = safeIso(url.searchParams.get("since"));

    const { data: conv } = await db.from("conversations").select("id, status").eq("session_id", sessionId).maybeSingle();
    if (!conv) return json({ ok: true, messages: [], status: "gone" });

    const { data: msgs } = await db.from("messages")
      .select("id, sender, sender_name, text, created_at")
      .eq("conversation_id", conv.id)
      .gt("created_at", since)
      .order("created_at", { ascending: true });

    return json({ ok: true, messages: msgs || [], status: conv.status });
  }

  // Customer leaves the page / ends chat (sent with navigator.sendBeacon as text/plain)
  if (path === "/chat/end" && req.method === "POST") {
    let sessionId = "";
    try { sessionId = JSON.parse(await req.text()).session_id || ""; } catch { /* ignore */ }
    if (sessionId) {
      await db.from("conversations").update({ status: "closed" }).eq("session_id", sessionId).eq("status", "open");
    }
    return json({ ok: true });
  }

  // ─── ALL OTHER ROUTES REQUIRE ADMIN LOGIN ─────────────────────────────────

  // Public login
  if (path === "/login" && req.method === "POST") {
    const body = await req.json().catch(() => ({}));
    const username = (body.username || "").trim().toLowerCase();
    const password = String(body.password || "");
    if (!username || !password) return json({ ok: false, error: "Username and password required" }, 400);

    const ipHash = await hashIp("login:ip:" + getClientIp(req));
    const userHash = await hashIp("login:user:" + username);
    const [ipLimited, userLimited] = await Promise.all([
      isRateLimited(db, ipHash, 10, 15),
      isRateLimited(db, userHash, 5, 15),
    ]);
    if (ipLimited || userLimited) {
      return json({ ok: false, error: "Too many failed login attempts. Try again in 15 minutes." }, 429);
    }

    const { data: admin } = await db.from("admins")
      .select("id, username, password_hash, display_name, role, blocked, must_change_password")
      .eq("username", username).maybeSingle();

    const { valid, needsRehash } = await verifyPassword(password, admin?.password_hash);

    if (!admin || !valid) {
      await db.from("rate_limits").insert([{ ip_hash: ipHash }, { ip_hash: userHash }]);
      return json({ ok: false, error: "Invalid username or password" }, 401);
    }
    if (admin.blocked) return json({ ok: false, error: "This account has been suspended. Contact the shop owner." }, 403);

    const updates: Record<string, unknown> = { last_seen: new Date().toISOString() };
    if (needsRehash) {
      updates.password_hash = await hashPassword(password);
    }
    await db.from("admins").update(updates).eq("id", admin.id);

    const iat = Math.floor(Date.now() / 1000);
    const token = await createToken({ id: admin.id, username: admin.username, role: admin.role, iat });

    return json({
      ok: true,
      token,
      admin: {
        id: admin.id,
        username: admin.username,
        display_name: admin.display_name,
        role: admin.role,
        must_change_password: Boolean(admin.must_change_password),
      },
    });
  }

  // Auth check
  const authHeader = req.headers.get("authorization") || req.headers.get("x-admin-token") || "";
  const rawToken = authHeader.replace(/^Bearer\s+/i, "").trim();

  // Internal/Owner endpoint to sync Telegram webhook with rotated SHOP_WEBHOOK_SECRET
  if (path === "/bot/sync-webhook" && req.method === "POST") {
    const isAdminSecret = Boolean(adminJwtSecret && rawToken && constantTimeEqual(rawToken, adminJwtSecret));
    const ownerSession = !isAdminSecret ? await verifyToken(rawToken) : null;
    if (!isAdminSecret && ownerSession?.role !== "Owner") {
      return json({ ok: false, error: "Forbidden" }, 403);
    }
    if (!botToken || !webhookSecret) {
      return json({ ok: false, error: "Missing SHOP_BOT_TOKEN or SHOP_WEBHOOK_SECRET" }, 500);
    }
    const targetUrl = `${supabaseUrl}/functions/v1/shop-bot`;
    const setRes = await fetch(`https://api.telegram.org/bot${botToken}/setWebhook`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: targetUrl, secret_token: webhookSecret }),
    }).then(r => r.json());
    const infoRes = await fetch(`https://api.telegram.org/bot${botToken}/getWebhookInfo`).then(r => r.json());
    return json({
      ok: Boolean(setRes?.ok),
      description: setRes?.description || "",
      webhook_url: infoRes?.result?.url || "",
      pending_update_count: infoRes?.result?.pending_update_count ?? 0,
    });
  }

  const session = await verifyToken(rawToken);
  if (!session) return json({ ok: false, error: "Unauthorized" }, 401);

  // Check if account is blocked or token was issued before invalidation
  const { data: selfAdmin } = await db.from("admins")
    .select("id, display_name, role, blocked, session_invalidated_at, last_seen, must_change_password")
    .eq("id", session.id).maybeSingle();

  if (!selfAdmin || selfAdmin.blocked) return json({ ok: false, error: "Account suspended" }, 403);
  const isOwner = selfAdmin.role === "Owner";
  if (selfAdmin.session_invalidated_at) {
    const invalidatedAt = Math.floor(new Date(selfAdmin.session_invalidated_at).getTime() / 1000);
    if (session.iat && session.iat < invalidatedAt) {
      return json({ ok: false, error: "Session expired. Please log in again." }, 401);
    }
  }
  if (selfAdmin.must_change_password && path !== "/change-password") {
    return json({
      ok: false,
      must_change_password: true,
      error: `You must set a new password (at least ${MIN_PASSWORD_LEN} characters) before continuing.`,
    }, 403);
  }

  // Update last_seen heartbeat (at most once a minute, in the background)
  const lastSeenMs = selfAdmin.last_seen ? new Date(selfAdmin.last_seen).getTime() : 0;
  if (Date.now() - lastSeenMs > 60_000) {
    background(Promise.resolve(db.from("admins").update({ last_seen: new Date().toISOString() }).eq("id", session.id)));
  }

  try {

    // ── STATS ────────────────────────────────────────────────────────────────
    if (path === "/stats" && req.method === "GET") {
      const [
        { count: catCount }, { count: bkTotal }, { count: bkPending },
        { count: reqTotal }, { count: reqNew }, { count: rvTotal }, { count: rvPending },
        { count: chatOpen },
      ] = await Promise.all([
        db.from("catalog").select("id", { count: "exact", head: true }).eq("active", true),
        db.from("bookings").select("id", { count: "exact", head: true }),
        db.from("bookings").select("id", { count: "exact", head: true }).eq("status", "new"),
        db.from("requests").select("id", { count: "exact", head: true }),
        db.from("requests").select("id", { count: "exact", head: true }).eq("status", "new"),
        db.from("reviews").select("id", { count: "exact", head: true }),
        db.from("reviews").select("id", { count: "exact", head: true }).eq("status", "pending"),
        db.from("conversations").select("id", { count: "exact", head: true }).eq("status", "open"),
      ]);
      return json({ ok: true, stats: {
        catalog: catCount ?? 0, bookingsTotal: bkTotal ?? 0, bookingsPending: bkPending ?? 0,
        requestsTotal: reqTotal ?? 0, requestsNew: reqNew ?? 0,
        reviewsTotal: rvTotal ?? 0, reviewsPending: rvPending ?? 0, chatOpen: chatOpen ?? 0,
      }});
    }

    // ── BOOKINGS ─────────────────────────────────────────────────────────────
    if (path === "/bookings") {
      if (req.method === "GET") {
        const { data, error } = await db.from("bookings").select("*").order("created_at", { ascending: false }).limit(200);
        if (error) throw error;
        return json({ ok: true, data });
      }
      if (req.method === "PATCH") {
        const { id, status } = await req.json();
        const { error } = await db.from("bookings").update({ status }).eq("id", id);
        if (error) throw error;
        return json({ ok: true });
      }
      if (req.method === "DELETE") {
        if (!isOwner) return json({ ok: false, error: "Only the shop Owner can delete records" }, 403);
        const { id } = await req.json();
        const { error } = await db.from("bookings").delete().eq("id", id);
        if (error) throw error;
        return json({ ok: true });
      }
    }

    // ── REQUESTS ─────────────────────────────────────────────────────────────
    if (path === "/requests") {
      if (req.method === "GET") {
        const { data, error } = await db.from("requests").select("*").order("created_at", { ascending: false }).limit(200);
        if (error) throw error;
        return json({ ok: true, data });
      }
      if (req.method === "PATCH") {
        const { id, status } = await req.json();
        const { error } = await db.from("requests").update({ status }).eq("id", id);
        if (error) throw error;
        return json({ ok: true });
      }
      if (req.method === "DELETE") {
        if (!isOwner) return json({ ok: false, error: "Only the shop Owner can delete records" }, 403);
        const { id } = await req.json();
        const { error } = await db.from("requests").delete().eq("id", id);
        if (error) throw error;
        return json({ ok: true });
      }
    }

    // ── REVIEWS ──────────────────────────────────────────────────────────────
    if (path === "/reviews") {
      if (req.method === "GET") {
        const { data, error } = await db.from("reviews").select("*").order("created_at", { ascending: false }).limit(200);
        if (error) throw error;
        const rows = (data || []).map((r: any) => ({ ...r, approved: r.status === "approved" }));
        return json({ ok: true, data: rows });
      }
      if (req.method === "PATCH") {
        const body = await req.json();
        const { id, approved, status } = body;
        const nextStatus = status || (approved ? "approved" : "pending");
        const { error } = await db.from("reviews").update({ status: nextStatus }).eq("id", id);
        if (error) throw error;
        return json({ ok: true });
      }
      if (req.method === "DELETE") {
        if (!isOwner) return json({ ok: false, error: "Only the shop Owner can delete records" }, 403);
        const { id } = await req.json();
        const { error } = await db.from("reviews").delete().eq("id", id);
        if (error) throw error;
        return json({ ok: true });
      }
    }

    // ── CATALOG ──────────────────────────────────────────────────────────────
    if (path === "/catalog") {
      if (req.method === "GET") {
        const { data, error } = await db.from("catalog").select("*").order("created_at", { ascending: false });
        if (error) throw error;
        const items = (data || []).map((row: any) => ({
          ...row,
          img: row.image_path
            ? (row.image_path.startsWith("http") ? row.image_path : `${supabaseUrl}/storage/v1/object/public/posters/${row.image_path}`)
            : "",
        }));
        return json({ ok: true, data: items });
      }
      if (req.method === "POST") {
        const body = await req.json();
        const { title, subtitle, category, sub, genres, description, image_url, trending, announce_telegram } = body;
        if (!title || !category) return json({ ok: false, error: "Title and Category required" }, 400);
        const genresList = Array.isArray(genres) ? genres : (genres || "").split(",").map((g: string) => g.trim()).filter(Boolean);
        const { data, error } = await db.from("catalog").insert({
          title: title.trim(), subtitle: (subtitle || "").trim() || null,
          category: category.toLowerCase().trim(), sub: sub ? sub.toLowerCase().trim() : null,
          genres: genresList.length ? genresList : ["Action"],
          description: (description || "").trim(),
          image_path: (image_url || "").trim() || null,
          trending: trending ? 1 : 0, active: true,
        }).select().single();
        if (error) throw error;
        if (announce_telegram && botToken && ownerId) {
          const cap = `🔥 <b>New Title Added!</b>\n🎬 <b>${escTg(data.title)}</b>\n` +
            (data.subtitle ? `📌 <i>${escTg(data.subtitle)}</i>\n` : "") +
            `📂 ${escTg(data.category.toUpperCase())}` + (data.sub ? ` (${escTg(data.sub)})` : "") + `\n` +
            `🏷️ ${escTg(data.genres.join(", "))}\n\n📝 ${escTg(data.description || "Available now at Astro World Cyber!")}`;
          if (data.image_path?.startsWith("http")) await tgPhoto(data.image_path, cap);
          else await tgMessage(cap);
        }
        return json({ ok: true, data });
      }
      if (req.method === "PATCH") {
        const { id, trending, active } = await req.json();
        const updates: any = {};
        if (trending !== undefined) updates.trending = trending ? 1 : 0;
        if (active !== undefined) updates.active = active;
        const { error } = await db.from("catalog").update(updates).eq("id", id);
        if (error) throw error;
        return json({ ok: true });
      }
      if (req.method === "DELETE") {
        if (!isOwner) return json({ ok: false, error: "Only the shop Owner can delete records" }, 403);
        const { id } = await req.json();
        const { error } = await db.from("catalog").delete().eq("id", id);
        if (error) throw error;
        return json({ ok: true });
      }
    }

    // ── BOT SEND (OWNER ONLY) ────────────────────────────────────────────────
    if (path === "/bot/send" && req.method === "POST") {
      if (!isOwner) return json({ ok: false, error: "Only the shop Owner can send Telegram bot messages" }, 403);
      const body = await req.json().catch(() => ({}));
      if (body.chat_id !== undefined) {
        return json({ ok: false, error: "Custom chat_id is not allowed" }, 400);
      }
      const message = String(body.message || "").trim();
      const photoUrl = String(body.photo_url || "").trim();
      if (!message && !photoUrl) return json({ ok: false, error: "Message or photo URL required" }, 400);
      if (message.length > 1000) return json({ ok: false, error: "Message too long (max 1000 characters)" }, 400);

      if (photoUrl) {
        if (photoUrl.length > 500) return json({ ok: false, error: "Photo URL too long" }, 400);
        let parsed: URL;
        try {
          parsed = new URL(photoUrl);
        } catch {
          return json({ ok: false, error: "Invalid photo URL" }, 400);
        }
        const host = parsed.hostname.toLowerCase();
        if (
          parsed.protocol !== "https:" ||
          host === "localhost" ||
          host.startsWith("127.") ||
          host.startsWith("10.") ||
          host.startsWith("192.168.") ||
          host.startsWith("169.254.") ||
          host.endsWith(".local")
        ) {
          return json({ ok: false, error: "Photo URL must be a valid public https:// URL" }, 400);
        }
        try {
          const headRes = await fetch(parsed.toString(), { method: "HEAD" });
          if (!headRes.ok) return json({ ok: false, error: "Photo URL is not reachable" }, 400);
          const cType = (headRes.headers.get("content-type") || "").toLowerCase();
          const cLen = parseInt(headRes.headers.get("content-length") || "0", 10);
          if (cType && !cType.startsWith("image/")) {
            return json({ ok: false, error: "Photo URL must point to an image" }, 400);
          }
          if (cLen > 5 * 1024 * 1024) {
            return json({ ok: false, error: "Photo exceeds 5 MB size limit" }, 400);
          }
        } catch {
          return json({ ok: false, error: "Could not verify photo URL" }, 400);
        }
        await tgPhoto(parsed.toString(), escTg(message));
      } else {
        await tgMessage(escTg(message));
      }
      return json({ ok: true });
    }

    // ── LIVE CHAT (ADMIN SIDE) ────────────────────────────────────────────────
    if (path === "/chat/conversations" && req.method === "GET") {
      const { data: convs } = await db.from("conversations")
        .select("id, customer_name, status, created_at, updated_at")
        .order("updated_at", { ascending: false }).limit(100);
      const list = convs || [];
      // Attach last message preview + whether the customer is waiting for a reply
      const last: Record<string, any> = {};
      const counts: Record<string, number> = {};
      if (list.length) {
        const { data: msgs } = await db.from("messages")
          .select("conversation_id, sender, text, created_at")
          .in("conversation_id", list.map(c => c.id))
          .order("created_at", { ascending: false }).limit(2000);
        for (const m of msgs || []) {
          counts[m.conversation_id] = (counts[m.conversation_id] || 0) + 1;
          if (!last[m.conversation_id]) last[m.conversation_id] = m;
        }
      }
      const data = list.map(c => ({
        ...c,
        last_text: last[c.id]?.text || "",
        last_sender: last[c.id]?.sender || "",
        needs_reply: c.status === "open" && last[c.id]?.sender === "customer",
        message_count: counts[c.id] || 0,
      }));
      return json({ ok: true, data });
    }

    if (path === "/chat/messages" && req.method === "GET") {
      const convId = url.searchParams.get("conversation_id");
      const since = safeIso(url.searchParams.get("since"));
      if (!convId) return json({ ok: false, error: "Missing conversation_id" }, 400);
      const [{ data }, { data: conv }] = await Promise.all([
        db.from("messages")
          .select("id, sender, sender_name, text, created_at")
          .eq("conversation_id", convId)
          .gt("created_at", since)
          .order("created_at", { ascending: true }),
        db.from("conversations").select("status").eq("id", convId).maybeSingle(),
      ]);
      return json({ ok: true, messages: data || [], status: conv?.status || "gone" });
    }

    if (path === "/chat/reply" && req.method === "POST") {
      const body = await req.json();
      const { conversation_id, text } = body;
      if (!conversation_id || !text?.trim()) return json({ ok: false, error: "Missing fields" }, 400);
      const [{ data: msg, error }] = await Promise.all([
        db.from("messages").insert({
          conversation_id,
          sender: "admin",
          sender_name: selfAdmin.display_name || session.username || "Astro World",
          text: String(text).trim().slice(0, 1000),
        }).select("id, sender, sender_name, text, created_at").single(),
        db.from("conversations").update({ updated_at: new Date().toISOString() }).eq("id", conversation_id),
      ]);
      if (error) return json({ ok: false, error: "Could not send" }, 500);
      return json({ ok: true, message: msg });
    }

    if (path === "/chat/close" && req.method === "POST") {
      const { conversation_id } = await req.json();
      await db.from("conversations").update({ status: "closed" }).eq("id", conversation_id);
      return json({ ok: true });
    }

    // Delete one conversation, or all closed ones (Owner only)
    if (path === "/chat/delete" && req.method === "POST") {
      if (!isOwner) return json({ ok: false, error: "Only the shop Owner can delete chats" }, 403);
      const { conversation_id, all_closed } = await req.json();
      if (all_closed) {
        const { data } = await db.from("conversations").delete().eq("status", "closed").select("id");
        return json({ ok: true, deleted: data?.length || 0 });
      }
      if (!conversation_id) return json({ ok: false, error: "Missing conversation_id" }, 400);
      await db.from("conversations").delete().eq("id", conversation_id);
      return json({ ok: true, deleted: 1 });
    }

    // ── ADMINS (Owner sees all; Staff sees only own account) ────────────────
    if (path === "/admins" && req.method === "GET") {
      let query = db.from("admins")
        .select("id, username, display_name, role, blocked, must_change_password, last_seen, created_at")
        .order("created_at", { ascending: true });
      if (!isOwner) {
        query = query.eq("id", session.id);
      }
      const { data } = await query;
      return json({ ok: true, data: data || [] });
    }

    if (path === "/change-password" && req.method === "POST") {
      const { current_password, new_password } = await req.json();
      const curPwd = String(current_password || "");
      const nextPwd = String(new_password || "");
      if (!curPwd || !nextPwd || nextPwd.length < MIN_PASSWORD_LEN) {
        return json({ ok: false, error: `New password must be at least ${MIN_PASSWORD_LEN} characters` }, 400);
      }
      if (constantTimeEqual(await hashLegacySha256(nextPwd), LEAKED_SEED_HASH)) {
        return json({ ok: false, error: "Cannot use the old default password. Choose a unique password." }, 400);
      }
      if (constantTimeEqual(curPwd, nextPwd)) {
        return json({ ok: false, error: "New password must be different from your current password." }, 400);
      }
      const { data: admin } = await db.from("admins").select("password_hash, username, display_name, role").eq("id", session.id).single();
      const { valid } = await verifyPassword(curPwd, admin?.password_hash);
      if (!admin || !valid) return json({ ok: false, error: "Current password incorrect" }, 400);
      const nowIso = new Date().toISOString();
      const { error } = await db.from("admins").update({
        password_hash: await hashPassword(nextPwd),
        must_change_password: false,
        session_invalidated_at: nowIso,
      }).eq("id", session.id);
      if (error) throw error;
      const iat = Math.floor(new Date(nowIso).getTime() / 1000) + 1;
      const newToken = await createToken({ id: session.id, username: admin.username, role: admin.role, iat });
      return json({
        ok: true,
        token: newToken,
        admin: {
          id: session.id,
          username: admin.username,
          display_name: admin.display_name,
          role: admin.role,
          must_change_password: false,
        },
      });
    }

    if (path === "/update-profile" && req.method === "POST") {
      const { display_name, username } = await req.json();
      const newU = (username || "").trim().toLowerCase();
      if (!newU || newU.length < 3) return json({ ok: false, error: "Username must be at least 3 characters" }, 400);
      const { data: existing } = await db.from("admins").select("id").eq("username", newU).neq("id", session.id).maybeSingle();
      if (existing) return json({ ok: false, error: "Username already taken" }, 400);
      const updates: any = { username: newU };
      if (display_name) updates.display_name = display_name.trim();
      const { data: updated, error } = await db.from("admins").update(updates).eq("id", session.id)
        .select("id, username, display_name, role, must_change_password").single();
      if (error) throw error;
      const newToken = await createToken({ id: updated.id, username: updated.username, role: updated.role, iat: Math.floor(Date.now() / 1000) });
      return json({ ok: true, admin: updated, token: newToken });
    }

    // ── OWNER-ONLY: ADMIN MANAGEMENT ─────────────────────────────────────────
    if (!isOwner) {
      if (["/admin/add", "/admin/delete", "/admin/block", "/admin/unblock", "/admin/force-logout", "/admin/reset-password"].includes(path))
        return json({ ok: false, error: "Only the shop Owner can manage admin accounts" }, 403);
    }

    if (path === "/admin/add" && req.method === "POST") {
      const { username, display_name, role, password } = await req.json();
      const u = (username || "").trim().toLowerCase();
      const pwd = String(password || "");
      if (!u || u.length < 3 || !pwd || pwd.length < MIN_PASSWORD_LEN) {
        return json({ ok: false, error: `Username (3+ chars) and password (${MIN_PASSWORD_LEN}+ chars) required` }, 400);
      }
      if (constantTimeEqual(await hashLegacySha256(pwd), LEAKED_SEED_HASH)) {
        return json({ ok: false, error: "Cannot use the old default password." }, 400);
      }
      const hash = await hashPassword(pwd);
      const { data, error } = await db.from("admins").insert({
        username: u,
        display_name: (display_name || u).trim(),
        role: role || "Staff",
        password_hash: hash,
        must_change_password: true,
      }).select("id, username, display_name, role, must_change_password").single();
      if (error) return json({ ok: false, error: error.message.includes("unique") ? "Username already exists" : error.message }, 400);
      return json({ ok: true, data });
    }

    if (path === "/admin/reset-password" && req.method === "POST") {
      const { id, new_password } = await req.json();
      const nextPwd = String(new_password || "");
      if (!id || !nextPwd || nextPwd.length < MIN_PASSWORD_LEN) {
        return json({ ok: false, error: `Password must be at least ${MIN_PASSWORD_LEN} characters` }, 400);
      }
      if (constantTimeEqual(await hashLegacySha256(nextPwd), LEAKED_SEED_HASH)) {
        return json({ ok: false, error: "Cannot use the old default password." }, 400);
      }
      const nowIso = new Date().toISOString();
      const { error } = await db.from("admins").update({
        password_hash: await hashPassword(nextPwd),
        must_change_password: id !== session.id,
        session_invalidated_at: nowIso,
      }).eq("id", id);
      if (error) throw error;
      return json({ ok: true });
    }

    if (path === "/admin/delete" && req.method === "POST") {
      const { id } = await req.json();
      if (id === session.id) return json({ ok: false, error: "You cannot delete your own account" }, 400);
      const { error } = await db.from("admins").delete().eq("id", id);
      if (error) throw error;
      return json({ ok: true });
    }

    if (path === "/admin/block" && req.method === "POST") {
      const { id } = await req.json();
      if (id === session.id) return json({ ok: false, error: "You cannot block yourself" }, 400);
      await db.from("admins").update({ blocked: true, session_invalidated_at: new Date().toISOString() }).eq("id", id);
      return json({ ok: true });
    }

    if (path === "/admin/unblock" && req.method === "POST") {
      const { id } = await req.json();
      await db.from("admins").update({ blocked: false }).eq("id", id);
      return json({ ok: true });
    }

    if (path === "/admin/force-logout" && req.method === "POST") {
      const { id, all } = await req.json();
      const nowIso = new Date().toISOString();
      if (all) {
        await db.from("admins").update({ session_invalidated_at: nowIso }).neq("id", session.id);
        return json({ ok: true });
      }
      if (id === session.id) return json({ ok: false, error: "Cannot force-logout yourself" }, 400);
      await db.from("admins").update({ session_invalidated_at: nowIso }).eq("id", id);
      return json({ ok: true });
    }

    return json({ error: "Endpoint not found" }, 404);
  } catch (err: any) {
    return json({ ok: false, error: err.message }, 500);
  }
});
