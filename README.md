# HTB CTF Email Watcher — Functionality & Methodology

## Purpose (functionality)

* Periodically poll the public HackTheBox CTF API and detect CTF events that are **public** (open) or **token-accessible**.
* Send a single-threaded, nicely formatted **HTML email** for each new matching event (includes title, org, start/end times, description and banner image if available).
* Track seen events in a local JSON cache (`ctf_cache.json`) to avoid duplicate notifications.
* Send a **reminder email** 72 hours before a tracked event's start time (only once per event).

---

## Core methodology (how it works)

1. **Configuration**

   * Script reads required secrets/config from environment variables (or `.env` when running locally).
     Required: `SMTP_SERVER`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `EMAIL_TO`, `EMAIL_FROM`.
   * Optional settings: `HTB_API_BASE`, `CACHE_FILE`, `SLEEP_BETWEEN_DETAILS`, `HTTP_TIMEOUT`.

2. **Fetch list of CTFs**

   * Call `GET https://ctf.hackthebox.com/api/public/ctfs` (configurable).
   * Loop through returned CTF summaries.

3. **Per-CTF detail fetch**

   * For each unseen CTF (not in `ctf_cache.json`) fetch `GET /details/<slug>` to get the full event object (description, hasCode, banner, start/end times, etc).
   * Pause (`SLEEP_BETWEEN_DETAILS`) between detail requests to be polite.

4. **Decide whether to alert**

   * Use `hasCode` value:

     * `hasCode == 0` or `hasCode is None` → **public/open** → **alert** (no token required).
     * `hasCode == 1` → usually requires an access code. For these, check the `description` (or other textual fields) for tokens via regex:

       * If a token-like string is present in the description (e.g. `token: ABC123` or `?code=ABC123`) → **alert** and include the token in the email.
     * Otherwise (private/locked) → **do not alert**.
   * The detection function returns `(matched_bool, token_or_None)`.

5. **Send email**

   * Build HTML email including:

     * Name, organiser, human-friendly start/end times (converted from ISO), link to event.
     * Full HTML description (converted to safe HTML/text via BeautifulSoup).
     * Banner image URL (if present) embedded as an `<img src="...">` link (not as attachment).
     * If token found, include it clearly.
   * Use consistent thread headers (`Message-ID`, `In-Reply-To`, `References`) so all alerts show up in the same thread in many mail clients.
   * Send via configured SMTP server (TLS, auth).

6. **Cache & reminders**

   * After sending the initial alert, store event in `ctf_cache.json`:

     ```json
     {
       "<ctf_id>": {
         "slug": "...",
         "starts_at": "2026-03-17T08:30:00.000000Z",
         "checked": "...",
         "reminder_sent": false
       }
     }
     ```
   * On each run:

     * First loop through cache and parse `starts_at`. If `0 <= starts_at - now <= 72 hours` and `reminder_sent` is `false`, fetch details and send a reminder email and set `reminder_sent=true`.
     * Then run detection for new CTFs (above).

---

## Important notes / assumptions

* The script only alerts on **public** or **token-embedded** events (not purely private events).
* `hasCode` may be `0`, `1`, or `null`. Treat `null` the same as `0` (public) unless you want stricter checks.
* Token extraction is heuristic-based (regex). If an event stores its join code in an unusual format, it may be missed.
* Email threading via static `Message-ID` works for many clients, but behavior may vary between mail providers. If your mail provider rewrites headers, thread grouping may not be guaranteed.

---
