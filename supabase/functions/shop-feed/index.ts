import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";

const ALLOWED_ORIGIN = "https://cactusjackastrowrld.github.io";

function isAllowedOrigin(origin: string | null): boolean {
  if (!origin) return true;
  return origin === ALLOWED_ORIGIN;
}

function getCorsHeaders(_origin: string | null) {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Vary": "Origin",
  };
}

const CANONICAL_GENRES = [
  "Action", "Action & Adventure", "Adventure", "Animation", "Comedy", "Crime",
  "Documentary", "Drama", "Family", "Fantasy", "History", "Horror", "Kids",
  "Music", "Mystery", "News", "Reality", "Romance", "Sci-Fi & Fantasy",
  "Science Fiction", "Soap", "Talk", "Thriller", "TV Movie", "War",
  "War & Politics", "Western", "Spy"
];

const GENRE_TOKEN_REGEX = /\b(science\s+fiction\s*(?:&|and)\s*fantasy|sci(?:-|\s)?fi\s*(?:&|and)\s*fantasy|action\s*(?:&|and)\s*adventure|war\s*(?:&|and)\s*politics|science\s+fiction|sci(?:-|\s)?fi|scifi|tv(?:-|\s)+movie|documentary|animation|adventure|thriller|animated|children|cartoons|cartoon|western|romance|mystery|history|reality|fantasy|comedy|horror|family|action|crime|drama|music|kids|news|soap|talk|war|spy|docu|doc)\b/gi;

function normalizeGenres(input: unknown): string[] {
  const raw = Array.isArray(input) ? input.join(", ") : String(input || "");
  const cleaned = raw.replace(/[,/|]+/g, " , ");
  const result = new Set<string>();
  for (const match of cleaned.matchAll(GENRE_TOKEN_REGEX)) {
    const tok = match[1].toLowerCase().replace(/\s+/g, " ").trim();
    if (tok.includes("fantasy") && (tok.includes("sci") || tok.includes("science"))) result.add("Sci-Fi & Fantasy");
    else if (tok.startsWith("action") && tok.includes("adventure")) result.add("Action & Adventure");
    else if (tok.startsWith("war") && tok.includes("politics")) result.add("War & Politics");
    else if (tok === "science fiction" || tok === "sci-fi" || tok === "sci fi" || tok === "scifi") result.add("Science Fiction");
    else if (tok.startsWith("tv") && tok.endsWith("movie")) result.add("TV Movie");
    else if (tok === "animated" || tok === "cartoon" || tok === "cartoons") result.add("Animation");
    else if (tok === "children") result.add("Kids");
    else if (tok === "doc" || tok === "docu") result.add("Documentary");
    else {
      const canonical = CANONICAL_GENRES.find(g => g.toLowerCase() === tok);
      if (canonical) result.add(canonical);
    }
  }
  return Array.from(result);
}

function normalizeCategoryAndSub(rawCat: unknown, rawSub: unknown): { cat: string; sub: string | null } {
  const c = String(rawCat || "").trim().toLowerCase();
  let cat = "movies";
  if (["series", "tv", "show", "shows", "tv series", "tv-series"].includes(c)) cat = "series";
  else if (["movies", "movie", "film", "films"].includes(c)) cat = "movies";
  else if (["animation", "animations", "animated", "cartoon", "cartoons"].includes(c)) cat = "animation";
  else if (["anime", "animes"].includes(c)) cat = "anime";

  let sub: string | null = null;
  if (cat === "animation") {
    const s = String(rawSub || "").trim().toLowerCase();
    if (["kids", "kid", "children", "child", "kids animation"].includes(s)) sub = "kids";
    else if (["adult", "adults", "mature", "adult animation"].includes(s)) sub = "adult";
    else if (["series", "tv", "show", "animated series"].includes(s)) sub = "series";
  }
  return { cat, sub };
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
      const { cat, sub } = normalizeCategoryAndSub(item.category, item.sub);
      return {
        id: item.id,
        t: item.title,
        s: item.subtitle || "",
        cat,
        sub,
        g: normalizeGenres(item.genres),
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
