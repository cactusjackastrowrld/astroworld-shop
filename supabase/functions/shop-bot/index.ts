import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";

// Canonical genres and common categories
const CANONICAL_GENRES = [
  "Action", "Adventure", "Animation", "Comedy", "Crime", "Documentary",
  "Drama", "Family", "Fantasy", "History", "Horror", "Kids", "Music",
  "Mystery", "News", "Reality", "Romance", "Sci-fi", "Soap", "Spy",
  "Talk", "Thriller", "War", "Western"
];

// Normalize genre names and aliases (including combined genres like "Sci-Fi & Fantasy")
function normalizeGenres(rawGenres: string): string[] {
  // First split by commas or slashes
  const chunks = rawGenres.split(/[,/]/).map(g => g.trim()).filter(Boolean);
  const result = new Set<string>();

  for (const chunk of chunks) {
    const lower = chunk.toLowerCase();

    // Check common combined pairs like "Action & Adventure", "Sci-Fi & Fantasy", "War & Politics"
    if (lower === "action & adventure" || lower === "action and adventure") {
      result.add("Action");
      result.add("Adventure");
      continue;
    }
    if (lower.includes("sci-fi") && lower.includes("fantasy")) {
      result.add("Sci-fi");
      result.add("Fantasy");
      continue;
    }
    if (lower.includes("war") && lower.includes("politic")) {
      result.add("War");
      continue;
    }
    if (lower === "tv movie" || lower === "tv-movie") {
      result.add("Drama");
      continue;
    }
    if (lower === "science fiction" || lower === "sci fi" || lower === "scifi") {
      result.add("Sci-fi");
      continue;
    }
    if (lower === "cartoon" || lower === "animated") {
      result.add("Animation");
      continue;
    }
    if (lower === "children") {
      result.add("Kids");
      continue;
    }
    if (lower === "doc" || lower === "docu") {
      result.add("Documentary");
      continue;
    }
    if (lower === "romcom") {
      result.add("Romance");
      result.add("Comedy");
      continue;
    }

    // Direct match against canonical list (case-insensitive)
    const matched = CANONICAL_GENRES.find(c => c.toLowerCase() === lower);
    if (matched) {
      result.add(matched);
    } else {
      // Clean fallback: capitalize first letter of each word
      const words = lower.split(" ").map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
      result.add(words);
    }
  }

  return Array.from(result);
}

function escapeHtml(str: string): string {
  if (!str) return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

async function tgCall(botToken: string, method: string, payload: any) {
  const url = `https://api.telegram.org/bot${botToken}/${method}`;
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    return await res.json();
  } catch (err) {
    console.error(`Telegram API error on ${method}:`, err);
    return null;
  }
}

serve(async (req) => {
  if (req.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  // 1. Webhook Secret Token Verification
  const webhookSecret = Deno.env.get("SHOP_WEBHOOK_SECRET");
  const receivedToken = req.headers.get("x-telegram-bot-api-secret-token");

  if (!webhookSecret || receivedToken !== webhookSecret) {
    return new Response("Unauthorized", { status: 401 });
  }

  let update: any;
  try {
    update = await req.json();
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }

  const botToken = Deno.env.get("SHOP_BOT_TOKEN") ?? "";
  const ownerId = Deno.env.get("SHOP_OWNER_ID") ?? "";
  const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
  const supabaseServiceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
  const supabase = createClient(supabaseUrl, supabaseServiceRoleKey);

  // 2. Sender Verification: Answer ONLY the owner, silently ignore all others
  const senderId = (
    update.message?.from?.id ||
    update.callback_query?.from?.id
  )?.toString();

  if (!senderId || senderId !== ownerId.toString()) {
    // Silently ignore strangers
    return new Response("OK", { status: 200 });
  }

  // ==========================================
  // CALLBACK QUERIES (Inline button clicks)
  // ==========================================
  if (update.callback_query) {
    const cb = update.callback_query;
    const data = cb.data || "";
    const chatId = cb.message?.chat?.id;
    const messageId = cb.message?.message_id;

    // Answer callback query so button stops spinning
    await tgCall(botToken, "answerCallbackQuery", { callback_query_id: cb.id });

    // Review Moderation: Approve
    if (data.startsWith("rev:app:")) {
      const reviewId = data.replace("rev:app:", "");
      await supabase.from("reviews").update({ status: "approved" }).eq("id", reviewId);

      await tgCall(botToken, "editMessageText", {
        chat_id: chatId,
        message_id: messageId,
        text: `${cb.message.text}\n\n✅ <b>Approved & published to website!</b>`,
        parse_mode: "HTML",
      });
      return new Response("OK", { status: 200 });
    }

    // Review Moderation: Reject
    if (data.startsWith("rev:rej:")) {
      const reviewId = data.replace("rev:rej:", "");
      await supabase.from("reviews").update({ status: "rejected" }).eq("id", reviewId);

      await tgCall(botToken, "editMessageText", {
        chat_id: chatId,
        message_id: messageId,
        text: `${cb.message.text}\n\n❌ <b>Rejected</b>`,
        parse_mode: "HTML",
      });
      return new Response("OK", { status: 200 });
    }

    // Booking or Request: Mark Done
    if (data.startsWith("done:booking:")) {
      const bookingId = data.replace("done:booking:", "");
      await supabase.from("bookings").update({ status: "done" }).eq("id", bookingId);

      await tgCall(botToken, "editMessageText", {
        chat_id: chatId,
        message_id: messageId,
        text: `${cb.message.text}\n\n✅ <b>Marked as Done!</b>`,
        parse_mode: "HTML",
      });
      return new Response("OK", { status: 200 });
    }

    if (data.startsWith("done:request:")) {
      const reqId = data.replace("done:request:", "");
      await supabase.from("requests").update({ status: "done" }).eq("id", reqId);

      await tgCall(botToken, "editMessageText", {
        chat_id: chatId,
        message_id: messageId,
        text: `${cb.message.text}\n\n✅ <b>Marked as Done!</b>`,
        parse_mode: "HTML",
      });
      return new Response("OK", { status: 200 });
    }

    // Catalog Removal (/list)
    if (data.startsWith("cat:rem:")) {
      const catId = data.replace("cat:rem:", "");
      await supabase.from("catalog").update({ active: false }).eq("id", catId);

      await tgCall(botToken, "editMessageText", {
        chat_id: chatId,
        message_id: messageId,
        text: `🗑 <b>Removed from catalog.</b> (active = false)`,
        parse_mode: "HTML",
      });
      return new Response("OK", { status: 200 });
    }

    // Catalog Toggle Trending (/list)
    if (data.startsWith("cat:trend:")) {
      const catId = data.replace("cat:trend:", "");
      const { data: item } = await supabase.from("catalog").select("title, trending").eq("id", catId).single();
      if (item) {
        const nextTrend = !item.trending;
        await supabase.from("catalog").update({ trending: nextTrend }).eq("id", catId);

        await tgCall(botToken, "editMessageText", {
          chat_id: chatId,
          message_id: messageId,
          text: `⚡ <b>${escapeHtml(item.title)}</b> trending status is now: <b>${nextTrend ? "YES ⭐" : "NO"}</b>`,
          parse_mode: "HTML",
        });
      }
      return new Response("OK", { status: 200 });
    }

    // Category Pick in Poster Draft
    if (data.startsWith("cat_pick:")) {
      const pick = data.replace("cat_pick:", "");
      let category = "movies";
      let sub: string | null = null;

      if (pick === "series") category = "series";
      else if (pick === "movies") category = "movies";
      else if (pick === "anim_kids") { category = "animation"; sub = "kids"; }
      else if (pick === "anim_adult") { category = "animation"; sub = "adult"; }
      else if (pick === "anim_series") { category = "animation"; sub = "series"; }
      else if (pick === "anime") category = "anime";

      // Update draft
      await supabase.from("drafts").update({ category, sub, step: "trending" }).eq("chat_id", chatId);

      await tgCall(botToken, "editMessageText", {
        chat_id: chatId,
        message_id: messageId,
        text: `Category selected: <b>${category}${sub ? " (" + sub + ")" : ""}</b>\n\nShow this in <b>Trending now</b> carousel?`,
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [
              { text: "⭐ Yes, Trending", callback_data: "trend_pick:yes" },
              { text: "❌ No", callback_data: "trend_pick:no" },
            ],
          ],
        },
      });
      return new Response("OK", { status: 200 });
    }

    // Trending Pick in Poster Draft
    if (data.startsWith("trend_pick:")) {
      const trending = data === "trend_pick:yes";

      // Fetch draft
      const { data: draft } = await supabase.from("drafts").select("*").eq("chat_id", chatId).single();

      if (!draft) {
        await tgCall(botToken, "sendMessage", {
          chat_id: chatId,
          text: "⚠️ No draft found or upload timed out. Please send the poster again.",
        });
        return new Response("OK", { status: 200 });
      }

      // Insert into catalog
      const { error: insertErr } = await supabase.from("catalog").insert({
        title: draft.title,
        subtitle: draft.subtitle || null,
        category: draft.category,
        sub: draft.sub || null,
        genres: draft.genres,
        description: draft.description,
        image_path: draft.storage_path,
        trending,
        active: true,
      });

      if (insertErr) {
        console.error("Failed to insert catalog item:", insertErr);
        await tgCall(botToken, "sendMessage", {
          chat_id: chatId,
          text: "❌ Failed to save catalog title. Please try again.",
        });
        return new Response("OK", { status: 200 });
      }

      // Delete draft
      await supabase.from("drafts").delete().eq("chat_id", chatId);

      await tgCall(botToken, "editMessageText", {
        chat_id: chatId,
        message_id: messageId,
        text: `🎉 <b>${escapeHtml(draft.title)}</b> is now live on the website!\n\n` +
          `• <b>Category:</b> ${draft.category}${draft.sub ? " (" + draft.sub + ")" : ""}\n` +
          `• <b>Genres:</b> ${draft.genres.join(", ")}\n` +
          `• <b>Trending:</b> ${trending ? "Yes ⭐" : "No"}\n` +
          `• <b>Subtitle:</b> ${escapeHtml(draft.subtitle || "None")}`,
        parse_mode: "HTML",
      });
      return new Response("OK", { status: 200 });
    }

    return new Response("OK", { status: 200 });
  }

  // ==========================================
  // TEXT MESSAGES & PHOTO UPLOADS
  // ==========================================
  const msg = update.message;
  if (!msg) return new Response("OK", { status: 200 });

  const chatId = msg.chat.id;
  const text = (msg.text || "").trim();

  // Command: /start or /help
  if (text === "/start" || text === "/help") {
    const welcome = `🚀 <b>Astro World Shop Bot</b>\n\n` +
      `Here is what you can do:\n\n` +
      `🖼 <b>Upload Poster</b>\n` +
      `Send a photo with this caption format:\n` +
      `<code>Title | Genres | Description | Season info (optional)</code>\n\n` +
      `📋 <b>Commands</b>\n` +
      `• /today - Today's new bookings, requests, and pending reviews\n` +
      `• /reviews - Review moderation queue\n` +
      `• /list - Browse catalog titles with remove & trending toggle\n` +
      `• /help - Show this message`;

    await tgCall(botToken, "sendMessage", { chat_id: chatId, text: welcome, parse_mode: "HTML" });
    return new Response("OK", { status: 200 });
  }

  // Command: /today
  if (text === "/today") {
    const { count: newBookings } = await supabase.from("bookings").select("id", { count: "exact", head: true }).eq("status", "new");
    const { count: newRequests } = await supabase.from("requests").select("id", { count: "exact", head: true }).eq("status", "new");
    const { count: pendingReviews } = await supabase.from("reviews").select("id", { count: "exact", head: true }).eq("status", "pending");

    const summary = `📊 <b>Today's Shop Summary</b>\n\n` +
      `📅 <b>New Bookings:</b> ${newBookings || 0}\n` +
      `🎬 <b>New Requests:</b> ${newRequests || 0}\n` +
      `⭐ <b>Pending Reviews:</b> ${pendingReviews || 0}`;

    await tgCall(botToken, "sendMessage", { chat_id: chatId, text: summary, parse_mode: "HTML" });
    return new Response("OK", { status: 200 });
  }

  // Command: /reviews
  if (text === "/reviews") {
    const { data: pending } = await supabase
      .from("reviews")
      .select("id, name, rating, body, created_at")
      .eq("status", "pending")
      .order("created_at", { ascending: false });

    if (!pending || pending.length === 0) {
      await tgCall(botToken, "sendMessage", { chat_id: chatId, text: "⭐ No pending reviews right now." });
      return new Response("OK", { status: 200 });
    }

    for (const r of pending) {
      const stars = "★".repeat(r.rating) + "☆".repeat(5 - r.rating);
      const reviewMsg = `⭐ <b>Review from ${escapeHtml(r.name)}</b> (${stars})\n\n"${escapeHtml(r.body)}"`;
      await tgCall(botToken, "sendMessage", {
        chat_id: chatId,
        text: reviewMsg,
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [
              { text: "✅ Approve", callback_data: `rev:app:${r.id}` },
              { text: "❌ Reject", callback_data: `rev:rej:${r.id}` },
            ],
          ],
        },
      });
    }
    return new Response("OK", { status: 200 });
  }

  // Command: /list
  if (text === "/list") {
    const { data: items } = await supabase
      .from("catalog")
      .select("id, title, category, sub, trending, active, created_at")
      .eq("active", true)
      .order("created_at", { ascending: false })
      .limit(10);

    if (!items || items.length === 0) {
      await tgCall(botToken, "sendMessage", {
        chat_id: chatId,
        text: "🎬 Catalog is empty. Send a photo with a caption to add your first title!",
      });
      return new Response("OK", { status: 200 });
    }

    for (const item of items) {
      const itemMsg = `🎬 <b>${escapeHtml(item.title)}</b>\n` +
        `Category: ${item.category}${item.sub ? " (" + item.sub + ")" : ""}\n` +
        `Trending: ${item.trending ? "Yes ⭐" : "No"}`;

      await tgCall(botToken, "sendMessage", {
        chat_id: chatId,
        text: itemMsg,
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [
              { text: "⚡ Toggle Trending", callback_data: `cat:trend:${item.id}` },
              { text: "🗑 Remove", callback_data: `cat:rem:${item.id}` },
            ],
          ],
        },
      });
    }
    return new Response("OK", { status: 200 });
  }

  // PHOTO UPLOAD FLOW
  if (msg.photo && msg.photo.length > 0) {
    const caption = (msg.caption || "").trim();
    if (!caption) {
      await tgCall(botToken, "sendMessage", {
        chat_id: chatId,
        text: `⚠️ <b>Missing caption!</b>\n\nPlease send the photo with caption format:\n<code>Title | Genres | Description | Season info (optional)</code>`,
        parse_mode: "HTML",
      });
      return new Response("OK", { status: 200 });
    }

    const parts = caption.split("|").map((p: string) => p.trim());
    if (parts.length < 3) {
      await tgCall(botToken, "sendMessage", {
        chat_id: chatId,
        text: `⚠️ <b>Caption requires at least 3 parts:</b>\n<code>Title | Genres | Description | Season info (optional)</code>\n\nExample:\n<i>Gladiator II | Action, Adventure | Years after Lucilla's death... | In Cinemas</i>`,
        parse_mode: "HTML",
      });
      return new Response("OK", { status: 200 });
    }

    const title = parts[0];
    const genres = normalizeGenres(parts[1]);
    const description = parts[2];
    const subtitle = parts[3] || "";

    // Highest resolution photo is last element
    const highestPhoto = msg.photo[msg.photo.length - 1];
    const fileInfo = await tgCall(botToken, "getFile", { file_id: highestPhoto.file_id });

    if (!fileInfo || !fileInfo.result?.file_path) {
      await tgCall(botToken, "sendMessage", { chat_id: chatId, text: "❌ Failed to fetch photo from Telegram." });
      return new Response("OK", { status: 200 });
    }

    // Download image bytes from Telegram
    const downloadUrl = `https://api.telegram.org/file/bot${botToken}/${fileInfo.result.file_path}`;
    const imgResponse = await fetch(downloadUrl);
    const imgBlob = await imgResponse.blob();

    // Upload to posters storage bucket
    const fileName = `${Date.now()}-${title.toLowerCase().replace(/[^a-z0-9]/g, "-")}.jpg`;
    const { error: uploadError } = await supabase.storage.from("posters").upload(fileName, imgBlob, {
      contentType: "image/jpeg",
      upsert: true,
    });

    if (uploadError) {
      console.error("Storage upload error:", uploadError);
      await tgCall(botToken, "sendMessage", { chat_id: chatId, text: "❌ Failed to upload poster image to storage." });
      return new Response("OK", { status: 200 });
    }

    // Upsert into drafts table
    const { error: draftError } = await supabase.from("drafts").upsert(
      {
        chat_id: chatId,
        storage_path: fileName,
        title,
        genres,
        description,
        subtitle,
        step: "category",
        updated_at: new Date().toISOString(),
      },
      { onConflict: "chat_id" }
    );

    if (draftError) {
      console.error("Draft upsert error:", draftError);
      await tgCall(botToken, "sendMessage", { chat_id: chatId, text: "❌ Failed to save draft. Please retry." });
      return new Response("OK", { status: 200 });
    }

    // Prompt for category with inline buttons
    const catPrompt = `🖼 <b>Poster received for "${escapeHtml(title)}"!</b>\n\n` +
      `• <b>Genres:</b> ${genres.join(", ")}\n` +
      `• <b>Subtitle:</b> ${escapeHtml(subtitle || "None")}\n\n` +
      `Which category does this belong to?`;

    await tgCall(botToken, "sendMessage", {
      chat_id: chatId,
      text: catPrompt,
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [
          [
            { text: "🎬 Movies", callback_data: "cat_pick:movies" },
            { text: "📺 Series", callback_data: "cat_pick:series" },
          ],
          [
            { text: "🧒 Kids Animation", callback_data: "cat_pick:anim_kids" },
            { text: "🔞 Adult Animation", callback_data: "cat_pick:anim_adult" },
          ],
          [
            { text: "🎞 Animated Series", callback_data: "cat_pick:anim_series" },
            { text: "⚡ Anime", callback_data: "cat_pick:anime" },
          ],
        ],
      },
    });

    return new Response("OK", { status: 200 });
  }

  return new Response("OK", { status: 200 });
});
