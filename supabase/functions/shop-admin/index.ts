import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";

const siteOrigin = Deno.env.get("SITE_ORIGIN") || "https://cactusjackastrowrld.github.io";
const botToken = Deno.env.get("SHOP_BOT_TOKEN") ?? "";
const ownerId = Deno.env.get("SHOP_OWNER_ID") ?? "";
const webhookSecret = Deno.env.get("SHOP_WEBHOOK_SECRET") || "astro-secret-key-2026";
const SALT = "astro-world-salt-2026";

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

async function hashPassword(p: string) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(SALT + p));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function createToken(payload: { id: string; username: string; role: string; iat: number }) {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const exp = Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60;
  const body = btoa(JSON.stringify({ ...payload, exp }));
  const unsigned = `${header}.${body}`;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(webhookSecret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(unsigned));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${unsigned}.${sigB64}`;
}

async function verifyToken(token: string): Promise<any | null> {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const unsigned = `${parts[0]}.${parts[1]}`;
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(webhookSecret),
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

  // Customer starts or continues a chat session
  if (path === "/chat/open" && req.method === "POST") {
    const body = await req.json();
    const name = (body.name || "Customer").trim().slice(0, 80);
    const sessionId = body.session_id || crypto.randomUUID();

    // Find or create conversation
    let { data: conv } = await db.from("conversations").select("*").eq("session_id", sessionId).maybeSingle();
    if (!conv) {
      const { data: newConv } = await db.from("conversations")
        .insert({ session_id: sessionId, customer_name: name, status: "open" })
        .select().single();
      conv = newConv;
    }
    return json({ ok: true, session_id: sessionId, conversation_id: conv.id });
  }

  // Customer sends a message
  if (path === "/chat/message" && req.method === "POST") {
    const body = await req.json();
    const sessionId = body.session_id;
    const text = (body.text || "").trim().slice(0, 1000);
    if (!sessionId || !text) return json({ ok: false, error: "Missing session_id or text" }, 400);

    const { data: conv } = await db.from("conversations").select("id, customer_name").eq("session_id", sessionId).maybeSingle();
    if (!conv) return json({ ok: false, error: "Session not found" }, 404);

    await db.from("messages").insert({ conversation_id: conv.id, sender: "customer", sender_name: conv.customer_name, text });
    await db.from("conversations").update({ updated_at: new Date().toISOString(), status: "open" }).eq("id", conv.id);

    // Alert Telegram
    await tgMessage(`💬 <b>New Chat Message</b>\n<b>${conv.customer_name}:</b> ${text}\n\n<i>Reply in Admin Dashboard → Live Chat</i>`);
    return json({ ok: true });
  }

  // Customer polls for new messages (since a given timestamp)
  if (path === "/chat/poll" && req.method === "GET") {
    const sessionId = url.searchParams.get("session_id");
    const since = url.searchParams.get("since") || new Date(0).toISOString();
    if (!sessionId) return json({ ok: false, error: "Missing session_id" }, 400);

    const { data: conv } = await db.from("conversations").select("id").eq("session_id", sessionId).maybeSingle();
    if (!conv) return json({ ok: true, messages: [] });

    const { data: msgs } = await db.from("messages")
      .select("id, sender, sender_name, text, created_at")
      .eq("conversation_id", conv.id)
      .gt("created_at", since)
      .order("created_at", { ascending: true });

    return json({ ok: true, messages: msgs || [] });
  }

  // ─── ALL OTHER ROUTES REQUIRE ADMIN LOGIN ─────────────────────────────────

  // Public login
  if (path === "/login" && req.method === "POST") {
    const body = await req.json();
    const username = (body.username || "").trim().toLowerCase();
    const password = body.password || "";
    if (!username || !password) return json({ ok: false, error: "Username and password required" }, 400);

    const hash = await hashPassword(password);
    const { data: admin } = await db.from("admins")
      .select("id, username, password_hash, display_name, role, blocked")
      .eq("username", username).maybeSingle();

    if (!admin || admin.password_hash !== hash) return json({ ok: false, error: "Invalid username or password" }, 401);
    if (admin.blocked) return json({ ok: false, error: "This account has been suspended. Contact the shop owner." }, 403);

    const iat = Math.floor(Date.now() / 1000);
    const token = await createToken({ id: admin.id, username: admin.username, role: admin.role, iat });

    // Update last_seen
    await db.from("admins").update({ last_seen: new Date().toISOString() }).eq("id", admin.id);

    return json({ ok: true, token, admin: { id: admin.id, username: admin.username, display_name: admin.display_name, role: admin.role } });
  }

  // Auth check
  const authHeader = req.headers.get("authorization") || req.headers.get("x-admin-token") || "";
  const rawToken = authHeader.replace(/^Bearer\s+/i, "").trim();
  const session = await verifyToken(rawToken);
  if (!session) return json({ ok: false, error: "Unauthorized" }, 401);

  // Check if account is blocked or token was issued before invalidation
  const { data: selfAdmin } = await db.from("admins")
    .select("id, blocked, session_invalidated_at")
    .eq("id", session.id).maybeSingle();

  if (!selfAdmin || selfAdmin.blocked) return json({ ok: false, error: "Account suspended" }, 403);
  if (selfAdmin.session_invalidated_at) {
    const invalidatedAt = Math.floor(new Date(selfAdmin.session_invalidated_at).getTime() / 1000);
    if (session.iat && session.iat < invalidatedAt) {
      return json({ ok: false, error: "Session expired. Please log in again." }, 401);
    }
  }

  // Update last_seen heartbeat
  await db.from("admins").update({ last_seen: new Date().toISOString() }).eq("id", session.id);

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
        db.from("reviews").select("id", { count: "exact", head: true }).eq("approved", false),
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
        return json({ ok: true, data });
      }
      if (req.method === "PATCH") {
        const { id, approved } = await req.json();
        const { error } = await db.from("reviews").update({ approved }).eq("id", id);
        if (error) throw error;
        return json({ ok: true });
      }
      if (req.method === "DELETE") {
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
          const cap = `🔥 <b>New Title Added!</b>\n🎬 <b>${data.title}</b>\n` +
            (data.subtitle ? `📌 <i>${data.subtitle}</i>\n` : "") +
            `📂 ${data.category.toUpperCase()}` + (data.sub ? ` (${data.sub})` : "") + `\n` +
            `🏷️ ${data.genres.join(", ")}\n\n📝 ${data.description || "Available now at Astro World Cyber!"}`;
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
        const { id } = await req.json();
        const { error } = await db.from("catalog").delete().eq("id", id);
        if (error) throw error;
        return json({ ok: true });
      }
    }

    // ── BOT SEND ─────────────────────────────────────────────────────────────
    if (path === "/bot/send" && req.method === "POST") {
      const body = await req.json();
      const message = (body.message || "").trim();
      const photoUrl = (body.photo_url || "").trim();
      if (!message && !photoUrl) return json({ ok: false, error: "Message or photo URL required" }, 400);
      if (photoUrl) await tgPhoto(photoUrl, message);
      else await tgMessage(message);
      return json({ ok: true });
    }

    // ── LIVE CHAT (ADMIN SIDE) ────────────────────────────────────────────────
    if (path === "/chat/conversations" && req.method === "GET") {
      const { data } = await db.from("conversations")
        .select("id, session_id, customer_name, status, created_at, updated_at")
        .order("updated_at", { ascending: false }).limit(100);
      return json({ ok: true, data: data || [] });
    }

    if (path === "/chat/messages" && req.method === "GET") {
      const convId = url.searchParams.get("conversation_id");
      const since = url.searchParams.get("since") || new Date(0).toISOString();
      if (!convId) return json({ ok: false, error: "Missing conversation_id" }, 400);
      const { data } = await db.from("messages")
        .select("id, sender, sender_name, text, created_at")
        .eq("conversation_id", convId)
        .gt("created_at", since)
        .order("created_at", { ascending: true });
      return json({ ok: true, messages: data || [] });
    }

    if (path === "/chat/reply" && req.method === "POST") {
      const body = await req.json();
      const { conversation_id, text } = body;
      if (!conversation_id || !text?.trim()) return json({ ok: false, error: "Missing fields" }, 400);
      await db.from("messages").insert({
        conversation_id,
        sender: "admin",
        sender_name: (selfAdmin as any)?.display_name || session.username || "Astro World",
        text: text.trim().slice(0, 1000),
      });
      await db.from("conversations").update({ updated_at: new Date().toISOString() }).eq("id", conversation_id);
      return json({ ok: true });
    }

    if (path === "/chat/close" && req.method === "POST") {
      const { conversation_id } = await req.json();
      await db.from("conversations").update({ status: "closed" }).eq("id", conversation_id);
      return json({ ok: true });
    }

    // ── ADMINS (read + profile self-edit) ────────────────────────────────────
    if (path === "/admins" && req.method === "GET") {
      const { data } = await db.from("admins")
        .select("id, username, display_name, role, blocked, last_seen, created_at")
        .order("created_at", { ascending: true });
      return json({ ok: true, data: data || [] });
    }

    if (path === "/change-password" && req.method === "POST") {
      const { current_password, new_password } = await req.json();
      if (!current_password || !new_password || new_password.length < 6)
        return json({ ok: false, error: "New password must be at least 6 characters" }, 400);
      const curHash = await hashPassword(current_password);
      const { data: admin } = await db.from("admins").select("password_hash").eq("id", session.id).single();
      if (!admin || admin.password_hash !== curHash) return json({ ok: false, error: "Current password incorrect" }, 400);
      const { error } = await db.from("admins").update({ password_hash: await hashPassword(new_password) }).eq("id", session.id);
      if (error) throw error;
      return json({ ok: true });
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
        .select("id, username, display_name, role").single();
      if (error) throw error;
      const newToken = await createToken({ id: updated.id, username: updated.username, role: updated.role, iat: Math.floor(Date.now() / 1000) });
      return json({ ok: true, admin: updated, token: newToken });
    }

    // ── OWNER-ONLY: ADMIN MANAGEMENT ─────────────────────────────────────────
    if (session.role !== "Owner") {
      if (["/admin/add", "/admin/delete", "/admin/block", "/admin/unblock", "/admin/force-logout"].includes(path))
        return json({ ok: false, error: "Only the shop Owner can manage admin accounts" }, 403);
    }

    if (path === "/admin/add" && req.method === "POST") {
      const { username, display_name, role, password } = await req.json();
      const u = (username || "").trim().toLowerCase();
      if (!u || u.length < 3 || !password || password.length < 6)
        return json({ ok: false, error: "Username (3+ chars) and password (6+ chars) required" }, 400);
      const hash = await hashPassword(password);
      const { data, error } = await db.from("admins").insert({
        username: u, display_name: (display_name || u).trim(),
        role: role || "Staff", password_hash: hash,
      }).select("id, username, display_name, role").single();
      if (error) return json({ ok: false, error: error.message.includes("unique") ? "Username already exists" : error.message }, 400);
      return json({ ok: true, data });
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
      const { id } = await req.json();
      if (id === session.id) return json({ ok: false, error: "Cannot force-logout yourself" }, 400);
      await db.from("admins").update({ session_invalidated_at: new Date().toISOString() }).eq("id", id);
      return json({ ok: true });
    }

    return json({ error: "Endpoint not found" }, 404);
  } catch (err: any) {
    return json({ ok: false, error: err.message }, 500);
  }
});
