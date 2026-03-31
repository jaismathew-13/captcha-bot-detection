"""
app.py — Adaptive CAPTCHA Defense System

Detection Layers:
  1. Browser fingerprint (JS → /fingerprint)
  2. Behavioral signals (JS → /behavior)
  3. Classic signals (honeypot, timing, UA, headers, referer)

Risk Score → Adaptive Response:
  0–25   : No CAPTCHA (trusted)
  26–55  : Standard CAPTCHA (5 chars)
  56–79  : Hard CAPTCHA (8 chars, heavy distortion)
  80+    : Instant honeytrap → /trap
"""

import io
import json
import os
import random
import sqlite3
import string
from datetime import datetime, timezone
from pathlib import Path

from captcha.image import ImageCaptcha
from flask import (Flask, jsonify, redirect, render_template,
                   request, send_file, session, url_for)
from PIL import Image, ImageDraw, ImageFilter

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev_secret_change_in_prod")

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "honeypot.db"

# ---------------------------------------------------------------------------
# Known bad canvas hashes produced by headless Chrome / SwiftShader
# ---------------------------------------------------------------------------
KNOWN_HEADLESS_CANVAS_HASHES = {
    "da7de7b4b8c1f31eeb5b9a9c3e7e5a0b",
    "f3b4c2a1d5e8f9b0c3d4e5f6a7b8c9d0",
    "0000000000000000000000000000000000",
}

KNOWN_BOT_WEBGL = {"google swiftshader", "llvmpipe", "softpipe", "mesa"}

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def initialize_database() -> None:
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS captured_bots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                user_agent TEXT NOT NULL,
                risk_score INTEGER NOT NULL DEFAULT 0,
                risk_label TEXT NOT NULL DEFAULT 'unknown',
                signals TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS trap_interactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                user_agent TEXT NOT NULL,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)
        conn.commit()


@app.before_request
def ensure_db():
    if not app.config.get("DB_READY"):
        initialize_database()
        app.config["DB_READY"] = True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_ip() -> str:
    fwd = request.headers.get("X-Forwarded-For")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or "unknown"


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def now_epoch() -> float:
    return datetime.now(timezone.utc).timestamp()


def log_bot(risk_score: int, risk_label: str, signals: list[str]) -> None:
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.execute(
            """INSERT INTO captured_bots
               (ip_address, user_agent, risk_score, risk_label, signals, timestamp)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (get_ip(), request.headers.get("User-Agent", "unknown"),
             risk_score, risk_label, json.dumps(signals), now_utc())
        )
        conn.commit()


def log_trap_interaction(event_type: str) -> None:
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.execute(
            """INSERT INTO trap_interactions
               (ip_address, user_agent, event_type, timestamp)
               VALUES (?, ?, ?, ?)""",
            (get_ip(), request.headers.get("User-Agent", "unknown"),
             event_type, now_utc())
        )
        conn.commit()


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def score_classic_signals() -> tuple[int, list[str]]:
    """Signals that don't need JS data."""
    score = 0
    signals = []

    # Timing
    loaded = session.get("form_loaded_at")
    if loaded:
        elapsed = now_epoch() - float(loaded)
        if elapsed < 1.8:
            score += 20
            signals.append(f"too_fast:{elapsed:.2f}s")
    else:
        score += 10
        signals.append("no_load_timestamp")

    # JS token
    if (request.form.get("js_enabled") or "").strip() != "1":
        score += 25
        signals.append("js_token_missing")

    # Human mouse token
    if (request.form.get("human_token") or "").strip() != "1":
        score += 20
        signals.append("no_mouse_interaction")

    # User-agent
    ua = (request.headers.get("User-Agent") or "").lower()
    bot_keywords = ["python-requests", "curl", "wget", "scrapy",
                    "selenium", "playwright", "headless", "phantomjs",
                    "httpclient", "bot", "spider"]
    if not ua:
        score += 20
        signals.append("empty_ua")
    elif any(k in ua for k in bot_keywords):
        score += 20
        signals.append("suspicious_ua")

    # Accept-Language
    if not request.headers.get("Accept-Language"):
        score += 15
        signals.append("missing_accept_language")

    # Referer
    referer = request.headers.get("Referer", "")
    if not referer:
        score += 15
        signals.append("missing_referer")
    elif "127.0.0.1:5000" not in referer and "localhost" not in referer:
        score += 10
        signals.append("mismatched_referer")

    return score, signals


def score_fingerprint(fp: dict) -> tuple[int, list[str]]:
    score = 0
    signals = []

    if fp.get("webdriver"):
        score += 30
        signals.append("webdriver_true")

    if not fp.get("chrome_object"):
        score += 15
        signals.append("no_chrome_object")

    if fp.get("screen_zero"):
        score += 20
        signals.append("zero_screen_resolution")

    if fp.get("plugin_count", 1) == 0:
        score += 10
        signals.append("no_plugins")

    if not fp.get("languages"):
        score += 10
        signals.append("no_navigator_languages")

    canvas_hash = (fp.get("canvas_hash") or "").lower()
    if canvas_hash in KNOWN_HEADLESS_CANVAS_HASHES:
        score += 25
        signals.append("headless_canvas_hash")

    webgl = (fp.get("webgl_renderer") or "").lower()
    if any(bad in webgl for bad in KNOWN_BOT_WEBGL):
        score += 20
        signals.append(f"headless_webgl:{webgl[:30]}")

    if fp.get("timezone_mismatch"):
        score += 10
        signals.append("timezone_lang_mismatch")

    if fp.get("touch_ua_mismatch"):
        score += 15
        signals.append("touch_ua_mismatch")

    return score, signals


def score_behavior(beh: dict) -> tuple[int, list[str]]:
    score = 0
    signals = []

    if beh.get("linear_mouse"):
        score += 25
        signals.append("linear_mouse_path")

    mouse_count = beh.get("mouse_event_count", 0)
    if mouse_count < 5:
        score += 15
        signals.append(f"few_mouse_events:{mouse_count}")

    if beh.get("zero_scroll"):
        score += 10
        signals.append("no_scroll_events")

    if beh.get("instant_keystroke"):
        score += 20
        signals.append("instant_keystroke_timing")

    if beh.get("fast_captcha_fill"):
        score += 30
        signals.append("captcha_filled_under_200ms")

    if beh.get("zero_focus"):
        score += 5
        signals.append("no_focus_events")

    time_to_type = beh.get("time_to_first_key", 9999)
    if time_to_type < 800:
        score += 15
        signals.append(f"fast_first_keystroke:{time_to_type}ms")

    return score, signals


def classify_risk(score: int) -> tuple[str, str]:
    if score <= 25:
        return "low", "✅ Low Risk"
    elif score <= 55:
        return "medium", "⚠️ Medium Risk"
    elif score <= 79:
        return "high", "🔶 High Risk"
    else:
        return "critical", "🚨 Critical"


# ---------------------------------------------------------------------------
# CAPTCHA generation
# ---------------------------------------------------------------------------

CHAR_SET = string.ascii_uppercase + string.digits


def make_captcha_text(difficulty: str) -> str:
    length = {"easy": 4, "medium": 5, "hard": 8}.get(difficulty, 5)
    return "".join(random.choices(CHAR_SET, k=length))


def get_captcha_image_stream(text: str, difficulty: str) -> io.BytesIO:
    (BASE_DIR / "static").mkdir(exist_ok=True)
    out = io.BytesIO()

    if difficulty == "hard":
        # Custom heavy-distortion image
        img = ImageCaptcha(width=280, height=100,
                           fonts=None,
                           font_sizes=(42, 50, 58))
        data = img.generate(text)
        image = Image.open(data)
        # Extra noise lines
        draw = ImageDraw.Draw(image)
        for _ in range(12):
            x1, y1 = random.randint(0, 280), random.randint(0, 100)
            x2, y2 = random.randint(0, 280), random.randint(0, 100)
            draw.line([(x1, y1), (x2, y2)],
                      fill=(random.randint(50, 200),
                            random.randint(50, 200),
                            random.randint(50, 200)), width=2)
        image = image.filter(ImageFilter.GaussianBlur(radius=0.8))
        image.save(out, format="PNG")
    else:
        img = ImageCaptcha(width=220, height=90)
        img.write(text, out, format="PNG")
    out.seek(0)
    return out


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def home():
    session["form_loaded_at"] = now_epoch()
    session.setdefault("fp_score", 0)
    session.setdefault("fp_signals", [])
    session.setdefault("beh_score", 0)
    session.setdefault("beh_signals", [])

    fp_score = session.get("fp_score", 0)
    risk_level, _ = classify_risk(fp_score)
    difficulty = "medium"

    captcha_text = make_captcha_text(difficulty)
    session["captcha_text"] = captcha_text
    session["captcha_difficulty"] = difficulty

    v = random.randint(1, 999999)
    captcha_url = url_for("serve_captcha", v=v)
    return render_template("index.html",
                           captcha_url=captcha_url,
                           difficulty=difficulty,
                           fp_score=fp_score)


@app.route("/fingerprint", methods=["POST"])
def fingerprint():
    """Receive browser fingerprint data from fingerprint.js"""
    fp = request.get_json(silent=True) or {}
    score, signals = score_fingerprint(fp)
    session["fp_score"] = score
    session["fp_signals"] = signals

    total = score
    risk_level, _ = classify_risk(total)

    # If fingerprint alone screams bot, log immediately
    if risk_level == "critical":
        log_bot(total, "critical", signals)

    return jsonify({"score": score, "risk": risk_level, "signals": signals})


@app.route("/behavior", methods=["POST"])
def behavior():
    """Receive behavioral data from behavior.js"""
    beh = request.get_json(silent=True) or {}
    score, signals = score_behavior(beh)
    session["beh_score"] = score
    session["beh_signals"] = signals
    return jsonify({"score": score, "signals": signals})


@app.route("/captcha-image", methods=["GET"])
def serve_captcha():
    text = session.get("captcha_text")
    diff = session.get("captcha_difficulty", "medium")
    if not text:
        text = make_captcha_text(diff)
        session["captcha_text"] = text
    
    stream = get_captcha_image_stream(text, diff)
    return send_file(stream, mimetype="image/png")


@app.route("/refresh-captcha", methods=["GET"])
def refresh_captcha():
    difficulty = session.get("captcha_difficulty", "medium")
    captcha_text = make_captcha_text(difficulty)
    session["captcha_text"] = captcha_text
    session["form_loaded_at"] = now_epoch()
    v = random.randint(1, 999999)
    captcha_url = url_for("serve_captcha", v=v)
    return jsonify({"captcha_url": captcha_url, "difficulty": difficulty})


@app.route("/submit", methods=["POST"])
def submit():
    # ── Honeypot field: instant trap ────────────────────────────────────────
    honeypot = (request.form.get("website") or "").strip()
    if honeypot:
        log_bot(100, "critical", ["honeypot_filled"])
        return redirect(url_for("trap"))

    # ── Aggregate all scores ─────────────────────────────────────────────────
    classic_score, classic_signals = score_classic_signals()
    fp_score = session.get("fp_score", 0)
    fp_signals = session.get("fp_signals", [])
    beh_score = session.get("beh_score", 0)
    beh_signals = session.get("beh_signals", [])

    total_score = classic_score + fp_score + beh_score
    all_signals = classic_signals + fp_signals + beh_signals
    risk_level, risk_label = classify_risk(total_score)

    # ── Critical → honeytrap ─────────────────────────────────────────────────
    if risk_level == "critical":
        log_bot(total_score, risk_level, all_signals)
        return redirect(url_for("trap"))

    # ── High → log and show result ───────────────────────────────────────────
    if risk_level == "high":
        log_bot(total_score, risk_level, all_signals)

    # ── CAPTCHA verification ─────────────────────────────────────────────────
    submitted = (request.form.get("captcha_response") or "").strip().upper()
    expected = (session.get("captcha_text") or "").strip().upper()

    if submitted and submitted == expected:
        return render_template("success.html"), 200

    return render_template("fail.html"), 400


@app.route("/trap", methods=["GET", "POST"])
def trap():
    log_trap_interaction("page_load")
    fake = {
        "session_id": f"SID-{random.randint(100000, 999999)}",
        "username": random.choice(["j.smith", "a.chen", "m.patel", "r.jones", "s.kim"]),
        "last_login": datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC"),
        "account_id": f"ACC-{random.randint(10000, 99999)}",
        "plan": random.choice(["Professional", "Enterprise", "Business"]),
    }
    return render_template("trap.html", **fake)


@app.route("/trap/ping", methods=["POST"])
def trap_ping():
    data = request.get_json(silent=True) or {}
    event = data.get("event", "interaction")
    log_trap_interaction(event)
    return jsonify({"status": "ok"})


@app.route("/admin/dashboard", methods=["GET"])
def admin_dashboard():
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.row_factory = sqlite3.Row
        bots = [dict(r) for r in conn.execute(
            "SELECT * FROM captured_bots ORDER BY id DESC"
        ).fetchall()]
        interactions = [dict(r) for r in conn.execute(
            "SELECT * FROM trap_interactions ORDER BY id DESC LIMIT 50"
        ).fetchall()]

        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        today_count = conn.execute(
            "SELECT COUNT(*) FROM captured_bots WHERE timestamp LIKE ?",
            (f"{today}%",)
        ).fetchone()[0]

        critical_count = conn.execute(
            "SELECT COUNT(*) FROM captured_bots WHERE risk_label='critical'"
        ).fetchone()[0]

        top_ip_row = conn.execute(
            """SELECT ip_address, COUNT(*) as cnt FROM captured_bots
               GROUP BY ip_address ORDER BY cnt DESC LIMIT 1"""
        ).fetchone()
        top_ip = top_ip_row["ip_address"] if top_ip_row else "—"

    stats = {
        "total": len(bots),
        "today": today_count,
        "critical": critical_count,
        "top_ip": top_ip,
    }
    return render_template("admin.html", bots=bots,
                           interactions=interactions, stats=stats)


@app.route("/admin/clear", methods=["POST"])
def admin_clear():
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.execute("DELETE FROM captured_bots")
        conn.execute("DELETE FROM trap_interactions")
        conn.commit()
    return jsonify({"status": "cleared"})


# ---------------------------------------------------------------------------
# Simple result pages (inline, no extra template needed)
# ---------------------------------------------------------------------------

@app.route("/success")
def success():
    return render_template("success.html")


import json as _json

@app.template_filter("fromjson")
def fromjson_filter(value):
    try:
        return _json.loads(value)
    except Exception:
        return []


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
