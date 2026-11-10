import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";

const siteOrigin = Deno.env.get("SITE_ORIGIN") || "https://cactusjackastrowrld.github.io";
const botToken = Deno.env.get("SHOP_BOT_TOKEN") ?? "";
const ownerId = Deno.env.get("SHOP_OWNER_ID") ?? "";
const webhookSecret = Deno.env.get("SHOP_WEBHOOK_SECRET") || "astro-secret-key-2026";
const SALT = "astro-world-salt-2026";

function isAllowedOrigin(origin: string | null): boolean {
  if (!origin || origin === "null") return true;
  if (origin === siteOrigin) return true;
  if (origin === "https://cactusjackastrowrld.github.io") return true;
  if (origin === "https://cactusastrowrld.github.io") return true;
  return false;
}

function getCorsHeaders(origin: string | null) {
  const allowed = isAllowedOrigin(origin) && origin && origin !== "null" ? origin : siteOrigin;
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-admin-token",
    "Vary": "Origin",
  };
}

async function hashPassword(password: string): Promise<string> {
  const data = new TextEncoder().encode(SALT + password);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Simple signed session token using Web Crypto HMAC-SHA256
async function createToken(payload: { id: string; username: string; role: string }): Promise<string> {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const exp = Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60; // 7 days
  const body = btoa(JSON.stringify({ ...payload, exp }));
  const unsigned = `${header}.${body}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(webhookSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(unsigned));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `${unsigned}.${sigB64}`;
}

async function verifyToken(token: string): Promise<any | null> {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const unsigned = `${parts[0]}.${parts[1]}`;
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(webhookSecret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const sigStr = atob(parts[2].replace(/-/g, "+").replace(/_/g, "/"));
    const sigBytes = new Uint8Array(sigStr.split("").map((c) => c.charCodeAt(0)));
    const valid = await crypto.subtle.verify("HMAC", key, sigBytes, new TextEncoder().encode(unsigned));
    if (!valid) return null;
    const payload = JSON.parse(atob(parts[1]));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

// Telegram messaging helpers
async function sendTelegramMessage(text: string) {
  if (!botToken || !ownerId) return { ok: false, error: "Bot token or Owner ID not configured" };
  const res = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: ownerId, text, parse_mode: "HTML" }),
  });
  return await res.json();
}

async function sendTelegramPhoto(photoUrl: string, caption: string) {
  if (!botToken || !ownerId) return { ok: false, error: "Bot token or Owner ID not configured" };
  const res = await fetch(`https://api.telegram.org/bot${botToken}/sendPhoto`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: ownerId, photo: photoUrl, caption, parse_mode: "HTML" }),
  });
  return await res.json();
}

serve(async (req) => {
  const origin = req.headers.get("origin");

  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: getCorsHeaders(origin) });
  }

  const corsHeaders = getCorsHeaders(origin);
  const jsonResponse = (data: any, status = 200) =>
    new Response(JSON.stringify(data), {
      status,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/shop-admin/, "").replace(/\/$/, "");

  const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
  const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
  const supabase = createClient(supabaseUrl, supabaseServiceKey);

  // 1. PUBLIC ENDPOINT: Login
  if (path === "/login" && req.method === "POST") {
    try {
      const body = await req.json();
      const username = (body.username || "").trim().toLowerCase();
      const password = body.password || "";

      if (!username || !password) {
        return jsonResponse({ ok: false, error: "Username and password required" }, 400);
      }

      const inputHash = await hashPassword(password);

      const { data: admin, error } = await supabase
        .from("admins")
        .select("id, username, password_hash, display_name, role")
        .eq("username", username)
        .single();

      if (error || !admin || admin.password_hash !== inputHash) {
        return jsonResponse({ ok: false, error: "Invalid username or password" }, 401);
      }

      const token = await createToken({
        id: admin.id,
        username: admin.username,
        role: admin.role,
      });

      return jsonResponse({
        ok: true,
        token,
        admin: {
          id: admin.id,
          username: admin.username,
          display_name: admin.display_name,
          role: admin.role,
        },
      });
    } catch (err: any) {
      return jsonResponse({ ok: false, error: err.message }, 500);
    }
  }

  // 2. AUTHENTICATION CHECK FOR ALL OTHER ENDPOINTS
  const authHeader = req.headers.get("authorization") || req.headers.get("x-admin-token") || "";
  const token = authHeader.replace(/^Bearer\s+/i, "").trim();
  const session = await verifyToken(token);

  if (!session) {
    return jsonResponse({ ok: false, error: "Unauthorized: session invalid or expired" }, 401);
  }

  try {
    // 3. STATS
    if (path === "/stats" && req.method === "GET") {
      const [
        { count: catCount },
        { count: bkTotal },
        { count: bkPending },
        { count: reqTotal },
        { count: reqNew },
        { count: rvTotal },
        { count: rvPending },
      ] = await Promise.all([
        supabase.from("catalog").select("id", { count: "exact", head: true }).eq("active", true),
        supabase.from("bookings").select("id", { count: "exact", head: true }),
        supabase.from("bookings").select("id", { count: "exact", head: true }).eq("status", "new"),
        supabase.from("requests").select("id", { count: "exact", head: true }),
        supabase.from("requests").select("id", { count: "exact", head: true }).eq("status", "new"),
        supabase.from("reviews").select("id", { count: "exact", head: true }),
        supabase.from("reviews").select("id", { count: "exact", head: true }).eq("approved", false),
      ]);

      return jsonResponse({
        ok: true,
        stats: {
          catalog: catCount ?? 0,
          bookingsTotal: bkTotal ?? 0,
          bookingsPending: bkPending ?? 0,
          requestsTotal: reqTotal ?? 0,
          requestsNew: reqNew ?? 0,
          reviewsTotal: rvTotal ?? 0,
          reviewsPending: rvPending ?? 0,
        },
      });
    }

    // 4. BOOKINGS
    if (path === "/bookings") {
      if (req.method === "GET") {
        const { data, error } = await supabase
          .from("bookings")
          .select("*")
          .order("created_at", { ascending: false })
          .limit(100);
        if (error) throw error;
        return jsonResponse({ ok: true, data });
      }
      if (req.method === "PATCH") {
        const body = await req.json();
        const { id, status } = body;
        const { error } = await supabase.from("bookings").update({ status }).eq("id", id);
        if (error) throw error;
        return jsonResponse({ ok: true });
      }
      if (req.method === "DELETE") {
        const body = await req.json();
        const { id } = body;
        const { error } = await supabase.from("bookings").delete().eq("id", id);
        if (error) throw error;
        return jsonResponse({ ok: true });
      }
    }

    // 5. REQUESTS
    if (path === "/requests") {
      if (req.method === "GET") {
        const { data, error } = await supabase
          .from("requests")
          .select("*")
          .order("created_at", { ascending: false })
          .limit(100);
        if (error) throw error;
        return jsonResponse({ ok: true, data });
      }
      if (req.method === "PATCH") {
        const body = await req.json();
        const { id, status } = body;
        const { error } = await supabase.from("requests").update({ status }).eq("id", id);
        if (error) throw error;
        return jsonResponse({ ok: true });
      }
      if (req.method === "DELETE") {
        const body = await req.json();
        const { id } = body;
        const { error } = await supabase.from("requests").delete().eq("id", id);
        if (error) throw error;
        return jsonResponse({ ok: true });
      }
    }

    // 6. REVIEWS
    if (path === "/reviews") {
      if (req.method === "GET") {
        const { data, error } = await supabase
          .from("reviews")
          .select("*")
          .order("created_at", { ascending: false })
          .limit(100);
        if (error) throw error;
        return jsonResponse({ ok: true, data });
      }
      if (req.method === "PATCH") {
        const body = await req.json();
        const { id, approved } = body;
        const { error } = await supabase.from("reviews").update({ approved }).eq("id", id);
        if (error) throw error;
        return jsonResponse({ ok: true });
      }
      if (req.method === "DELETE") {
        const body = await req.json();
        const { id } = body;
        const { error } = await supabase.from("reviews").delete().eq("id", id);
        if (error) throw error;
        return jsonResponse({ ok: true });
      }
    }

    // 7. CATALOG / POSTERS
    if (path === "/catalog") {
      if (req.method === "GET") {
        const { data, error } = await supabase
          .from("catalog")
          .select("*")
          .order("created_at", { ascending: false });
        if (error) throw error;

        // Generate public image URLs
        const items = (data || []).map((row: any) => {
          let img = "";
          if (row.image_path) {
            img = row.image_path.startsWith("http")
              ? row.image_path
              : `${supabaseUrl}/storage/v1/object/public/posters/${row.image_path}`;
          }
          return { ...row, img };
        });

        return jsonResponse({ ok: true, data: items });
      }

      if (req.method === "POST") {
        const body = await req.json();
        const { title, subtitle, category, sub, genres, description, image_url, trending, announce_telegram } = body;

        if (!title || !category) {
          return jsonResponse({ ok: false, error: "Title and Category required" }, 400);
        }

        const genresList = Array.isArray(genres)
          ? genres
          : (genres || "").split(",").map((g: string) => g.trim()).filter(Boolean);

        const { data, error } = await supabase
          .from("catalog")
          .insert({
            title: title.trim(),
            subtitle: (subtitle || "").trim() || null,
            category: category.toLowerCase().trim(),
            sub: sub ? sub.toLowerCase().trim() : null,
            genres: genresList.length ? genresList : ["Action"],
            description: (description || "").trim(),
            image_path: (image_url || "").trim() || null,
            trending: trending ? 1 : 0,
            active: true,
          })
          .select()
          .single();

        if (error) throw error;

        // Broadcast to Telegram if requested
        if (announce_telegram && botToken && ownerId) {
          const caption = `🔥 <b>New Title Added to Astro World!</b>\n\n` +
            `🎬 <b>${data.title}</b>\n` +
            (data.subtitle ? `📌 <i>${data.subtitle}</i>\n` : "") +
            `📂 <b>Category:</b> ${data.category.toUpperCase()}` + (data.sub ? ` (${data.sub})` : "") + `\n` +
            `🏷️ <b>Genres:</b> ${data.genres.join(", ")}\n\n` +
            `📝 ${data.description || "Available now at Astro World Cyber!"}`;

          if (data.image_path && data.image_path.startsWith("http")) {
            await sendTelegramPhoto(data.image_path, caption);
          } else {
            await sendTelegramMessage(caption);
          }
        }

        return jsonResponse({ ok: true, data });
      }

      if (req.method === "PATCH") {
        const body = await req.json();
        const { id, trending, active } = body;
        const updates: any = {};
        if (trending !== undefined) updates.trending = trending ? 1 : 0;
        if (active !== undefined) updates.active = active;

        const { error } = await supabase.from("catalog").update(updates).eq("id", id);
        if (error) throw error;
        return jsonResponse({ ok: true });
      }

      if (req.method === "DELETE") {
        const body = await req.json();
        const { id } = body;
        const { error } = await supabase.from("catalog").delete().eq("id", id);
        if (error) throw error;
        return jsonResponse({ ok: true });
      }
    }

    // 8. COMMUNICATE WITH TELEGRAM BOT
    if (path === "/bot/send" && req.method === "POST") {
      const body = await req.json();
      const message = (body.message || "").trim();
      const photoUrl = (body.photo_url || "").trim();

      if (!message && !photoUrl) {
        return jsonResponse({ ok: false, error: "Message or photo URL required" }, 400);
      }

      let resTelegram;
      if (photoUrl) {
        resTelegram = await sendTelegramPhoto(photoUrl, message);
      } else {
        resTelegram = await sendTelegramMessage(message);
      }

      return jsonResponse({ ok: true, result: resTelegram });
    }

    // 9. ADMINS LIST & PASSWORD CHANGE
    if (path === "/admins" && req.method === "GET") {
      const { data, error } = await supabase
        .from("admins")
        .select("id, username, display_name, role, created_at")
        .order("created_at", { ascending: true });
      if (error) throw error;
      return jsonResponse({ ok: true, data });
    }

    if (path === "/change-password" && req.method === "POST") {
      const body = await req.json();
      const currentPassword = body.current_password || "";
      const newPassword = body.new_password || "";

      if (!currentPassword || !newPassword || newPassword.length < 6) {
        return jsonResponse({ ok: false, error: "New password must be at least 6 characters" }, 400);
      }

      const currentHash = await hashPassword(currentPassword);
      const newHash = await hashPassword(newPassword);

      const { data: admin, error } = await supabase
        .from("admins")
        .select("password_hash")
        .eq("id", session.id)
        .single();

      if (error || !admin || admin.password_hash !== currentHash) {
        return jsonResponse({ ok: false, error: "Current password incorrect" }, 400);
      }

      const { error: updateError } = await supabase
        .from("admins")
        .update({ password_hash: newHash })
        .eq("id", session.id);

      if (updateError) throw updateError;
      return jsonResponse({ ok: true });
    }

    if (path === "/update-profile" && req.method === "POST") {
      const body = await req.json();
      const newUsername = (body.username || "").trim().toLowerCase();
      const newDisplayName = (body.display_name || "").trim();

      if (!newUsername || newUsername.length < 3) {
        return jsonResponse({ ok: false, error: "Username must be at least 3 characters" }, 400);
      }

      // Check if username is already taken by another admin
      const { data: existing } = await supabase
        .from("admins")
        .select("id")
        .eq("username", newUsername)
        .neq("id", session.id)
        .maybeSingle();

      if (existing) {
        return jsonResponse({ ok: false, error: "Username is already in use by another admin" }, 400);
      }

      const updates: any = { username: newUsername };
      if (newDisplayName) updates.display_name = newDisplayName;

      const { data: updated, error: updateError } = await supabase
        .from("admins")
        .update(updates)
        .eq("id", session.id)
        .select("id, username, display_name, role")
        .single();

      if (updateError) throw updateError;

      const newToken = await createToken({
        id: updated.id,
        username: updated.username,
        role: updated.role,
      });

      return jsonResponse({ ok: true, admin: updated, token: newToken });
    }

    return jsonResponse({ error: "Endpoint not found" }, 404);
  } catch (err: any) {
    return jsonResponse({ ok: false, error: err.message }, 500);
  }
});
