#!/usr/bin/env python3
"""
htb_ctf_email.py
- Polls HackTheBox public CTF API
- Detects new/free CTFs or ones with access tokens in their description
- Sends formatted email with optional banner image
- Reads configuration from .env (local) or GitHub Actions secrets
- Keeps seen CTF IDs in ctf_cache.json
"""

import os
import re
import json
import time
import smtplib
import requests
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Optional

# --- Load environment (.env for local, GitHub Secrets for CI) ---
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# --- Config (strict) ---
from sys import exit

# Required variables (must exist)
REQUIRED_ENV_VARS = [
    "SMTP_SERVER",
    "SMTP_PORT",
    "SMTP_USER",
    "SMTP_PASS",
    "EMAIL_TO",
    "EMAIL_FROM",
]

missing = [v for v in REQUIRED_ENV_VARS if not os.getenv(v)]
if missing:
    print(f"❌ Missing required environment variables: {', '.join(missing)}")
    exit(1)

# Core configs
HTB_API_BASE = os.getenv("HTB_API_BASE") or "https://ctf.hackthebox.com/api/public/ctfs"
CACHE_FILE = os.getenv("CACHE_FILE") or "ctf_cache.json"
USER_AGENT = os.getenv("USER_AGENT") or "HTB-CTF-Watcher/EmailBot"

# Strict email configs (no fallback)
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
EMAIL_TO = os.getenv("EMAIL_TO")
EMAIL_FROM = os.getenv("EMAIL_FROM")

# Optional runtime tuning
SLEEP_BETWEEN_DETAILS = float(os.getenv("SLEEP_BETWEEN_DETAILS", "1.0"))
HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "20"))


# --- Token detection ---
TOKEN_RE = re.compile(
    r'(?:token|access\s*(?:code|key)|join\s*code|join\s*key|invite\s*code)\s*[:=\-]?\s*([A-Za-z0-9_\-]{4,40})',
    re.I,
)
URL_TOKEN_RE = re.compile(r'[?&](?:code|token|access_code|invite)=([A-Za-z0-9_\-]{4,80})', re.I)

# --- Helpers ---
def log(*args):
    print(f"[{datetime.now(timezone.utc).isoformat()}]", *args)

def load_cache() -> dict:
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, "r", encoding="utf8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_cache(cache: dict):
    with open(CACHE_FILE, "w", encoding="utf8") as f:
        json.dump(cache, f, indent=2)

def get_ctf_list():
    r = requests.get(HTB_API_BASE, headers={"User-Agent": USER_AGENT}, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    return r.json()

def get_ctf_details(slug: str):
    r = requests.get(f"{HTB_API_BASE}/details/{slug}", headers={"User-Agent": USER_AGENT}, timeout=HTTP_TIMEOUT)
    return r.json() if r.status_code == 200 else None

def extract_token_from_text(text: str) -> Optional[str]:
    if not text:
        return None
    m = URL_TOKEN_RE.search(text) or TOKEN_RE.search(text)
    return m.group(1) if m else None

def is_free_or_has_token(detail: dict):
    has_code = detail.get("hasCode")
    if not has_code:
        return True, None
    text = "\n".join(str(detail.get(k) or "") for k in (
        "description", "long_description", "short_description", "instructions", "join_instructions"
    ))
    token = extract_token_from_text(text)
    return (True, token) if token else (False, None)

def choose_avatar(detail: dict, ctf_summary: dict):
    for key in ("banner", "logo", "avatar", "image", "banner_image"):
        v = detail.get(key) or ctf_summary.get(key)
        if isinstance(v, str) and v.strip():
            if v.startswith("http"): return v
            if v.startswith("//"): return "https:" + v
            if v.startswith("/"): return "https://ctf.hackthebox.com" + v
    return None

def build_email_body(ctf: dict, detail: dict, token: Optional[str]):
    name = ctf.get("name")
    org = ctf.get("org_name") or detail.get("org_name") or "Unknown"
    start = ctf.get("starts_at")
    end = ctf.get("ends_at")
    slug = ctf.get("slug")
    url = f"https://ctf.hackthebox.com/event/{slug}"
    avatar = choose_avatar(detail, ctf)

    html = f"""
    <h2>🟢 New HackTheBox CTF Detected!</h2>
    <p><b>{name}</b></p>
    <p><b>Organiser:</b> {org}<br>
       <b>Starts:</b> {start}<br>
       <b>Ends:</b> {end}<br>
       <a href="{url}">View on HackTheBox</a></p>
    """
    if token:
        html += f"<p><b>🔑 Access Token:</b> <code>{token}</code></p>"
    if avatar:
        html += f'<img src="{avatar}" alt="CTF banner" width="500"><br>'
    return html

def send_email(subject: str, html_body: str):
    if not (SMTP_USER and SMTP_PASS and EMAIL_TO):
        log("❌ Missing email configuration (SMTP_USER, SMTP_PASS, EMAIL_TO)")
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = EMAIL_TO
    msg.set_content("Plain-text email fallback")
    msg.add_alternative(html_body, subtype="html")

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        log(f"✅ Email sent to {EMAIL_TO}")
        return True
    except Exception as e:
        log("❌ Email send failed:", e)
        return False

# --- Main ---
def main():
    log("🚀 Starting HTB CTF Email Watcher")
    cache = load_cache()
    try:
        ctfs = get_ctf_list()
    except Exception as e:
        log("Error fetching HTB list:", e)
        return

    new_ctfs = []
    for ctf in ctfs:
        cid = str(ctf.get("id"))
        slug = ctf.get("slug")
        if not cid or cid in cache:
            continue
        time.sleep(SLEEP_BETWEEN_DETAILS)
        detail = get_ctf_details(slug)
        if not detail:
            continue
        matched, token = is_free_or_has_token(detail)
        if matched:
            html_body = build_email_body(ctf, detail, token)
            subject = f"New HTB CTF: {ctf.get('name')}"
            send_email(subject, html_body)
            new_ctfs.append(ctf.get("name"))
        cache[cid] = {"slug": slug, "checked": datetime.now(timezone.utc).isoformat()}
        save_cache(cache)

    log(f"✅ Found {len(new_ctfs)} new CTF(s)" if new_ctfs else "No new CTFs found.")

if __name__ == "__main__":
    main()
