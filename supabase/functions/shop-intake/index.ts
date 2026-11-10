import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";

const siteOrigin = Deno.env.get("SITE_ORIGIN") || "https://cactusastrowrld.github.io";

function getCorsHeaders(origin: string | null) {
  const allowed = origin === siteOrigin ? siteOrigin : siteOrigin;
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Vary": "Origin",
  };
}

// Escape customer input for safe Telegram HTML formatting
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// Strip control characters (ASCII 0-31 and 127) and trim
function sanitize(val: unknown, maxLen = 500): string {
  if (typeof val !== "string") return "";
  return val.replace(/[\x00-\x1F\x7F]/g, "").trim().slice(0, maxLen);
}

// Send alert to the shop owner on Telegram
async function notifyOwner(text: string, inlineKeyboard?: any[][]) {
  const token = Deno.env.get("SHOP_BOT_TOKEN");
  const ownerId = Deno.env.get("SHOP_OWNER_ID");
  if (!token || !ownerId) return;

  const url = `https://api.telegram.org/bot${token}/sendMessage`;
  const payload: any = {
    chat_id: ownerId,
    text,
    parse_mode: "HTML",
  };
  if (inlineKeyboard) {
    payload.reply_markup = { inline_keyboard: inlineKeyboard };
  }

  try {
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    console.error("Telegram notification error:", err);
  }
}

// Compute SHA-256 hash of IP address
async function hashIp(ip: string): Promise<string> {
  const data = new TextEncoder().encode(ip);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

serve(async (req) => {
  const origin = req.headers.get("origin");

  // Handle CORS Preflight
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: getCorsHeaders(origin) });
  }

  if (req.method !== "POST") {
    return new Response(JSON.stringify({ ok: false, error: "Method not allowed" }), {
      status: 405,
      headers: { ...getCorsHeaders(origin), "Content-Type": "application/json" },
    });
  }

  // 1. Origin verification
  if (origin && origin !== siteOrigin) {
    return new Response(JSON.stringify({ ok: false, error: "Forbidden: invalid origin" }), {
      status: 403,
      headers: { ...getCorsHeaders(origin), "Content-Type": "application/json" },
    });
  }

  try {
    let body: any;
    try {
      body = await req.json();
    } catch {
      return new Response(JSON.stringify({ ok: false, error: "Invalid JSON body" }), {
        status: 400,
        headers: { ...getCorsHeaders(origin), "Content-Type": "application/json" },
      });
    }

    // 2. Honeypot check: if 'website' field is filled by a bot, pretend success and store nothing
    if (body.website && typeof body.website === "string" && body.website.trim() !== "") {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { ...getCorsHeaders(origin), "Content-Type": "application/json" },
      });
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
    const supabaseServiceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
    const supabase = createClient(supabaseUrl, supabaseServiceRoleKey);

    // 3. IP Rate Limiting (5 requests per 10 minutes)
    const clientIp = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
      req.headers.get("cf-connecting-ip") || "127.0.0.1";
    const ipHash = await hashIp(clientIp);

    const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    const { count, error: countError } = await supabase
      .from("rate_limits")
      .select("id", { count: "exact", head: true })
      .eq("ip_hash", ipHash)
      .gte("created_at", tenMinutesAgo);

    if (countError) throw countError;

    if (count !== null && count >= 5) {
      return new Response(JSON.stringify({ ok: false, error: "Too many requests. Please wait a bit." }), {
        status: 429,
        headers: { ...getCorsHeaders(origin), "Content-Type": "application/json" },
      });
    }

    // Record rate limit attempt
    await supabase.from("rate_limits").insert({ ip_hash: ipHash });

    // 4. Validate and Process by Type
    const type = sanitize(body.type, 20);

    if (type === "booking") {
      const name = sanitize(body.name || body.n, 100);
      const phone = sanitize(body.phone || body.p, 30);
      const service = sanitize(body.service || body.s, 100);
      const date = sanitize(body.date || body.d, 30);
      const time = sanitize(body.time || body.h, 30);
      const notes = sanitize(body.notes || body.x, 500);

      if (!name || !phone || !service || !date || !time) {
        return new Response(JSON.stringify({ ok: false, error: "Missing required booking fields" }), {
          status: 400,
          headers: { ...getCorsHeaders(origin), "Content-Type": "application/json" },
        });
      }

      const { data, error } = await supabase
        .from("bookings")
        .insert({ name, phone, service, date, time, notes, status: "new" })
        .select("id")
        .single();

      if (error) throw error;

      // Telegram alert with "Mark done" button
      const alert = `📅 <b>New Booking!</b>\n\n` +
        `<b>Name:</b> ${escapeHtml(name)}\n` +
        `<b>Phone:</b> ${escapeHtml(phone)}\n` +
        `<b>Service:</b> ${escapeHtml(service)}\n` +
        `<b>Date:</b> ${escapeHtml(date)} at ${escapeHtml(time)}\n` +
        `<b>Notes:</b> ${escapeHtml(notes || "None")}`;

      await notifyOwner(alert, [
        [{ text: "✅ Mark Done", callback_data: `done:booking:${data.id}` }],
      ]);

      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { ...getCorsHeaders(origin), "Content-Type": "application/json" },
      });
    } else if (type === "request") {
      const name = sanitize(body.name || body.n, 100);
      const phone = sanitize(body.phone || body.p, 30);
      const title = sanitize(body.title || body.t, 150);
      const kind = sanitize(body.kind || body.k, 50);

      if (!name || !title || !kind) {
        return new Response(JSON.stringify({ ok: false, error: "Missing required request fields" }), {
          status: 400,
          headers: { ...getCorsHeaders(origin), "Content-Type": "application/json" },
        });
      }

      const { data, error } = await supabase
        .from("requests")
        .insert({ name, phone: phone || null, title, kind, status: "new" })
        .select("id")
        .single();

      if (error) throw error;

      // Telegram alert with "Mark done" button
      const alert = `🎬 <b>New Title Request!</b>\n\n` +
        `<b>Name:</b> ${escapeHtml(name)}\n` +
        `<b>Phone:</b> ${escapeHtml(phone || "Not given")}\n` +
        `<b>Title:</b> ${escapeHtml(title)}\n` +
        `<b>Type:</b> ${escapeHtml(kind)}`;

      await notifyOwner(alert, [
        [{ text: "✅ Mark Done", callback_data: `done:request:${data.id}` }],
      ]);

      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { ...getCorsHeaders(origin), "Content-Type": "application/json" },
      });
    } else if (type === "review") {
      const name = sanitize(body.name || body.n, 100);
      const ratingRaw = parseInt(body.rating || body.r, 10);
      const rating = isNaN(ratingRaw) ? 5 : Math.max(1, Math.min(5, ratingRaw));
      const bodyText = sanitize(body.body || body.t, 1000);

      if (!name || !bodyText) {
        return new Response(JSON.stringify({ ok: false, error: "Missing required review fields" }), {
          status: 400,
          headers: { ...getCorsHeaders(origin), "Content-Type": "application/json" },
        });
      }

      const { data, error } = await supabase
        .from("reviews")
        .insert({ name, rating, body: bodyText, status: "pending" })
        .select("id")
        .single();

      if (error) throw error;

      // Telegram alert with Approve & Reject buttons
      const stars = "★".repeat(rating) + "☆".repeat(5 - rating);
      const alert = `⭐ <b>New Review (Pending)!</b>\n\n` +
        `<b>From:</b> ${escapeHtml(name)} (${stars})\n` +
        `<b>Review:</b>\n${escapeHtml(bodyText)}`;

      await notifyOwner(alert, [
        [
          { text: "✅ Approve", callback_data: `rev:app:${data.id}` },
          { text: "❌ Reject", callback_data: `rev:rej:${data.id}` },
        ],
      ]);

      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { ...getCorsHeaders(origin), "Content-Type": "application/json" },
      });
    } else {
      return new Response(JSON.stringify({ ok: false, error: "Unknown submission type" }), {
        status: 400,
        headers: { ...getCorsHeaders(origin), "Content-Type": "application/json" },
      });
    }
  } catch (_err) {
    // Never expose internal errors
    return new Response(JSON.stringify({ ok: false, error: "Unable to process submission" }), {
      status: 400,
      headers: { ...getCorsHeaders(origin), "Content-Type": "application/json" },
    });
  }
});
