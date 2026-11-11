# Astro World Cyber Shop — Project Memory & Architecture (`AGENTS.md`)

This file is automatically read by Antigravity on any machine (Windows or Linux Mint) so the AI assistant immediately knows the full project setup, architecture, and rules without needing prior chat history.

## 1. Project Identity & Live URLs
- **Business:** Astro World Cyber (Kenya) — Phone: `+254 742454100` | Email: `astroprint27@gmail.com`
- **GitHub Repo:** `https://github.com/cactusjackastrowrld/astroworld-shop`
- **Live Customer Site:** `https://cactusjackastrowrld.github.io/astroworld-shop/`
- **Live Admin Portal:** `https://cactusjackastrowrld.github.io/astroworld-shop/admin.html`
- **Supabase Project Ref:** `iqdzokybhggiilzscnxv` (`https://iqdzokybhggiilzscnxv.supabase.co`)

## 2. File Structure
- `docs/index.html` & `index.html` — Public website with movie catalog, service booking, movie requests, customer reviews, and live customer chat widget (with Web-Audio notification tunes). **Always keep root `index.html` and `docs/index.html` in sync.**
- `docs/admin.html` & `admin.html` — Admin dashboard (Overview, Bookings, Requests, Reviews, Catalog, Bot & Post, Live Chat, Team, My Account). **Always keep root `admin.html` and `docs/admin.html` in sync.**
- `supabase/functions/shop-feed/index.ts` — Public GET endpoint for active catalog items & approved reviews.
- `supabase/functions/shop-intake/index.ts` — Public POST endpoint for bookings, movie requests, and reviews (+ Telegram alerts).
- `supabase/functions/shop-bot/index.ts` — Telegram webhook bot for owner management.
- `supabase/functions/shop-admin/index.ts` — Admin portal API + Live Chat API (`/chat/open`, `/chat/message`, `/chat/poll`, `/chat/end`, `/chat/conversations`, `/chat/messages`, `/chat/reply`, `/chat/close`, `/chat/delete`).
- `supabase/*.sql` — Database schema files (`schema.sql`, `admin-schema.sql`, `chat-schema.sql`).

## 3. Strict Project Rules & Guidelines
1. **Never expose secrets:** Never print or hardcode `SHOP_BOT_TOKEN`, `SHOP_WEBHOOK_SECRET`, or `SUPABASE_SERVICE_ROLE_KEY` in code or chat.
2. **Design & Branding:** Keep the dark space neon aesthetic (`--bg:#05030f`, `--pink:#ff3d9a`, `--cyan:#2ee6ff`, `--yel:#ffd23f`, `--grn:#39ff88`, `--pur:#8b5cff`). Never add "Aether Ghost Crop" anywhere.
3. **Syncing `docs/` and root HTML:** GitHub Pages serves from the `main` branch `/docs` folder. Whenever editing `docs/index.html` or `docs/admin.html`, always copy them to the root `index.html` and `admin.html` before committing.
4. **Deploying Edge Functions (No Docker required):**
   ```bash
   npx supabase functions deploy shop-admin --no-verify-jwt
   npx supabase functions deploy shop-feed --no-verify-jwt
   npx supabase functions deploy shop-intake --no-verify-jwt
   npx supabase functions deploy shop-bot --no-verify-jwt
   ```
