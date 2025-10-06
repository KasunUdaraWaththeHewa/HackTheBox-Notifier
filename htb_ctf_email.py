#!/usr/bin/env python3
"""
htb_ctf_email.py
- Polls HackTheBox public CTF API
- Detects new/free/public CTFs or ones with access tokens
- Sends formatted email (same thread)
- Sends reminder emails 72h before start time
"""

import os
import re
import json
import time
import smtplib
import requests
from datetime import datetime, timezone, timedelta
from email.message import EmailMessage
from typing import Optional
from dateutil import parser as date_parser
from html import unescape
from bs4 import BeautifulSoup

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

REQUIRED_ENV_VARS = [
    "SMTP_SERVER", "SMTP_PORT", "SMTP_USER",
    "SMTP_PASS", "EMAIL_TO", "EMAIL_FROM",
]
missing = [v for v in REQUIRED_ENV_VARS if not os.getenv(v)]
if missing:
    print(f"❌ Missing required environment variables: {', '.join(missing)}")
    exit(1)

HTB_API_BASE = os.getenv("HTB_API_BASE", "https://ctf.hackthebox.com/api/public/ctfs")
CACHE_FILE = os.getenv("CACHE_FILE", "ctf_cache.json")
USER_AGENT = os.getenv("USER_AGENT", "HTB-CTF-Watcher/EmailBot")

SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
EMAIL_TO = os.getenv("EMAIL_TO")
EMAIL_FROM = os.getenv("EMAIL_FROM")

SLEEP_BETWEEN_DETAILS = float(os.getenv("SLEEP_BETWEEN_DETAILS", "1.0"))
HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "20"))

TOKEN_RE = re.compile(
    r'(?:token|access\s*(?:code|key)|join\s*code|join\s*key|invite\s*code)\s*[:=\-]?\s*([A-Za-z0-9_\-]{4,40})',
    re.I,
)
URL_TOKEN_RE = re.compile(r'[?&](?:code|token|access_code|invite)=([A-Za-z0-9_\-]{4,80})', re.I)


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
    """
    Determine if a CTF should trigger an alert.
    - hasCode is None or 0 → Public/open
    - hasCode == 1 and token found → Token-accessible
    - Otherwise → Private/locked
    """
    has_code = detail.get("hasCode")
    if has_code in (None, 0):
        return True, None
    if has_code == 1:
        text = "\n".join(
            str(detail.get(k, "")) for k in (
                "description", "long_description", "short_description", 
                "instructions", "join_instructions"
            )
        )
        token = extract_token_from_text(text)
        if token:
            return True, token

    return False, None



def choose_avatar(detail: dict, ctf_summary: dict):
    for key in ("banner", "logo", "avatar", "image", "banner_image"):
        v = detail.get(key) or ctf_summary.get(key)
        if isinstance(v, str) and v.strip():
            if v.startswith("http"):
                return v
            if v.startswith("//"):
                return "https:" + v
            if v.startswith("/"):
                return "https://ctf.hackthebox.com" + v
    return None


def format_datetime(iso_str: Optional[str]) -> str:
    """Format ISO datetime string to readable UTC format."""
    if not iso_str:
        return "Unknown"
    try:
        dt = date_parser.parse(iso_str)
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return iso_str


def clean_description(html_text: str) -> str:
    """Convert HTML to safe readable text for emails."""
    if not html_text:
        return ""
    soup = BeautifulSoup(unescape(html_text), "html.parser")
    return str(soup)


def build_email_body(ctf: dict, detail: dict, token: Optional[str]):
    name = ctf.get("name")
    org = ctf.get("org_name") or detail.get("org_name") or "Unknown"
    start = format_datetime(ctf.get("startDate") or detail.get("starts_at"))
    end = format_datetime(ctf.get("endDate") or detail.get("ends_at"))
    slug = ctf.get("slug")
    url = f"https://ctf.hackthebox.com/event/details/{slug}"
    avatar = choose_avatar(detail, ctf)
    desc_html = clean_description(detail.get("description", ""))

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

    if desc_html:
        html += f"<hr><div><b>Description:</b><br>{desc_html}</div>"

    if avatar:
        html += f'<br><img src="{avatar}" alt="CTF banner" width="500"><br>'

    return html


def send_email(html_body: str):
    """Send email (same thread for all alerts)."""
    subject = "HackTheBox CTF Alerts 🟢"
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = EMAIL_TO

    thread_id = "<htb-ctf-alerts@kasun-notify>"
    msg["Message-ID"] = thread_id
    msg["In-Reply-To"] = thread_id
    msg["References"] = thread_id

    msg.set_content("Your email client does not support HTML.")
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


def main():
    log("🚀 Starting HTB CTF Email Watcher")
    cache = load_cache()
    now = datetime.now(timezone.utc)
    reminder_window = timedelta(hours=72)

    for cid, info in list(cache.items()):
        try:
            starts_at = date_parser.parse(info.get("starts_at"))
            delta = starts_at - now
            if not info.get("reminder_sent") and timedelta(0) <= delta <= reminder_window:
                slug = info["slug"]
                detail = get_ctf_details(slug)
                if detail:
                    html_body = f"""
                    <h2>⏰ Reminder: CTF Starting Soon!</h2>
                    <p>The CTF <b>{detail.get('name')}</b> starts in less than 72 hours!</p>
                    <p><a href="https://ctf.hackthebox.com/event/details/{slug}">View Event</a></p>
                    """
                    send_email(html_body)
                    cache[cid]["reminder_sent"] = True
                    save_cache(cache)
                    log(f"📅 Reminder sent for: {detail.get('name')}")
        except Exception as e:
            log("⚠️ Reminder check failed for", cid, e)

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
            send_email(html_body)
            new_ctfs.append(ctf.get("name"))
            cache[cid] = {
                "slug": slug,
                "starts_at": ctf.get("startDate") or detail.get("starts_at"),
                "checked": datetime.now(timezone.utc).isoformat(),
                "reminder_sent": False,
            }
            save_cache(cache)

    log(f"✅ Found {len(new_ctfs)} new CTF(s)" if new_ctfs else "No new CTFs found.")


if __name__ == "__main__":
    main()
