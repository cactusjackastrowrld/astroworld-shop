import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";

const siteOrigin = Deno.env.get("SITE_ORIGIN") || "https://cactusjackastrowrld.github.io";

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
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Vary": "Origin",
  };
}

serve(async (req) => {
  const origin = req.headers.get("origin");

  // Handle CORS Preflight
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: getCorsHeaders(origin) });
  }

  if (req.method !== "GET") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { ...getCorsHeaders(origin), "Content-Type": "application/json" },
    });
  }

  // Reject wrong origin if explicitly passed (allow siteOrigin and local testing)
  if (origin && !isAllowedOrigin(origin)) {
    return new Response(JSON.stringify({ error: "Forbidden: invalid origin" }), {
      status: 403,
      headers: { ...getCorsHeaders(origin), "Content-Type": "application/json" },
    });
  }

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
    const supabaseServiceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
    const supabase = createClient(supabaseUrl, supabaseServiceRoleKey);

    // 1. Fetch active catalog items (newest first)
    const { data: catalogData, error: catalogError } = await supabase
      .from("catalog")
      .select("id, title, subtitle, category, sub, genres, description, image_path, trending, created_at")
      .eq("active", true)
      .order("created_at", { ascending: false });

    if (catalogError) throw catalogError;

    // Convert items to frontend format with public image URLs
    const catalog = (catalogData || []).map((item) => {
      let imageUrl = item.image_path || "";
      if (imageUrl && !imageUrl.startsWith("http://") && !imageUrl.startsWith("https://") && !imageUrl.startsWith("data:")) {
        imageUrl = `${supabaseUrl}/storage/v1/object/public/posters/${item.image_path}`;
      }
      return {
        id: item.id,
        t: item.title,
        s: item.subtitle || "",
        cat: item.category,
        sub: item.sub || null,
        g: Array.isArray(item.genres) ? item.genres : [],
        d: item.description || "",
        img: imageUrl,
        trend: item.trending ? 1 : 0,
      };
    });

    // 2. Fetch approved reviews only (newest first)
    const { data: reviewsData, error: reviewsError } = await supabase
      .from("reviews")
      .select("id, name, rating, body, created_at")
      .eq("status", "approved")
      .order("created_at", { ascending: false });

    if (reviewsError) throw reviewsError;

    const reviews = (reviewsData || []).map((r) => ({
      id: r.id,
      n: r.name,
      r: r.rating,
      t: r.body,
    }));

    return new Response(JSON.stringify({ catalog, reviews }), {
      status: 200,
      headers: {
        ...getCorsHeaders(origin),
        "Content-Type": "application/json",
        "Cache-Control": "public, max-age=60",
      },
    });
  } catch (_err) {
    return new Response(JSON.stringify({ error: "Failed to load feed" }), {
      status: 500,
      headers: { ...getCorsHeaders(origin), "Content-Type": "application/json" },
    });
  }
});
