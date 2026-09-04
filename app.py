"""
URL & File Safety Scanner
--------------------------
A simple Flask dashboard that checks whether a URL or file is
safe by querying threat-intel APIs (VirusTotal, URLhaus, AbuseIPDB).

Run:
    export VT_API_KEY=xxxx
    export ABUSEIPDB_API_KEY=xxxx      # optional
    python app.py
"""

import os
import time
import base64
import hashlib
import sqlite3
import socket
import json
from datetime import datetime

import requests
from flask import Flask, request, jsonify, render_template, g

# ---------------------------------------------------------------
# Config
# ---------------------------------------------------------------
VT_API_KEY = os.environ.get("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

VT_BASE = "https://www.virustotal.com/api/v3"
URLHAUS_BASE = "https://urlhaus-api.abuse.ch/v1"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
DB_PATH = os.path.join(os.path.dirname(__file__), "history.db")
MAX_FILE_SIZE = 32 * 1024 * 1024  # 32 MB - VT free tier limit

app = Flask(__name__)


# ---------------------------------------------------------------
# Database (scan history)
# ---------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            target_type TEXT,
            verdict TEXT,
            detail TEXT,
            scanned_at TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def save_scan(target, target_type, verdict, detail):
    db = get_db()
    db.execute(
        "INSERT INTO scans (target, target_type, verdict, detail, scanned_at) VALUES (?, ?, ?, ?, ?)",
        (target, target_type, verdict, detail, datetime.utcnow().isoformat() + "Z"),
    )
    db.commit()


# ---------------------------------------------------------------
# VirusTotal helpers
# ---------------------------------------------------------------
def vt_headers():
    return {"x-apikey": VT_API_KEY}


def vt_check_url(url):
    """Submit a URL to VirusTotal and poll for the analysis result."""
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not set"}

    # VT wants the URL id as base64(url) without padding
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    # Try existing report first (fast path)
    r = requests.get(f"{VT_BASE}/urls/{url_id}", headers=vt_headers(), timeout=15)
    if r.status_code == 200:
        return parse_vt_stats(r.json())

    # Not seen before -> submit for a fresh scan
    submit = requests.post(
        f"{VT_BASE}/urls", headers=vt_headers(), data={"url": url}, timeout=15
    )
    if submit.status_code not in (200, 201):
        return {"error": f"VT submit failed: {submit.status_code}"}

    analysis_id = submit.json()["data"]["id"]

    # Poll until the analysis finishes (or timeout)
    for _ in range(10):
        time.sleep(3)
        poll = requests.get(
            f"{VT_BASE}/analyses/{analysis_id}", headers=vt_headers(), timeout=15
        )
        data = poll.json()
        status = data["data"]["attributes"]["status"]
        if status == "completed":
            stats = data["data"]["attributes"]["stats"]
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            }
    return {"error": "VT analysis timed out"}


def parse_vt_stats(vt_json):
    stats = vt_json["data"]["attributes"]["last_analysis_stats"]
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }


def vt_check_file_hash(sha256):
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not set"}
    r = requests.get(f"{VT_BASE}/files/{sha256}", headers=vt_headers(), timeout=15)
    if r.status_code == 200:
        return parse_vt_stats(r.json())
    if r.status_code == 404:
        return {"not_found": True}
    return {"error": f"VT lookup failed: {r.status_code}"}


def vt_upload_file(filepath):
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not set"}
    with open(filepath, "rb") as f:
        files = {"file": f}
        r = requests.post(
            f"{VT_BASE}/files", headers=vt_headers(), files=files, timeout=60
        )
    if r.status_code not in (200, 201):
        return {"error": f"VT upload failed: {r.status_code}"}

    analysis_id = r.json()["data"]["id"]
    for _ in range(15):
        time.sleep(4)
        poll = requests.get(
            f"{VT_BASE}/analyses/{analysis_id}", headers=vt_headers(), timeout=15
        )
        data = poll.json()
        status = data["data"]["attributes"]["status"]
        if status == "completed":
            stats = data["data"]["attributes"]["stats"]
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            }
    return {"error": "VT analysis timed out"}


# ---------------------------------------------------------------
# URLhaus helper
# ---------------------------------------------------------------
def urlhaus_check_url(url):
    try:
        r = requests.post(f"{URLHAUS_BASE}/url/", data={"url": url}, timeout=10)
        data = r.json()
        if data.get("query_status") == "ok":
            return {"listed": True, "threat": data.get("threat", "unknown")}
        return {"listed": False}
    except requests.RequestException as e:
        return {"error": str(e)}


# ---------------------------------------------------------------
# AbuseIPDB helper (checks the IP the URL's host resolves to)
# ---------------------------------------------------------------
def abuseipdb_check_host(hostname):
    if not ABUSEIPDB_API_KEY:
        return {"skipped": "ABUSEIPDB_API_KEY not set"}
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return {"error": "could not resolve host"}

    try:
        r = requests.get(
            f"{ABUSEIPDB_BASE}/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        data = r.json().get("data", {})
        return {
            "ip": ip,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
        }
    except requests.RequestException as e:
        return {"error": str(e)}


# ---------------------------------------------------------------
# AI heuristic checker (catches threats not yet in any database)
# ---------------------------------------------------------------
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

def ai_url_heuristic(url):
    """Ask an LLM to judge the URL's structure for phishing indicators,
    independent of any threat database. Catches brand-new/zero-day URLs."""
    if not GROQ_API_KEY:
        return {"skipped": "GROQ_API_KEY not set"}

    system_prompt = (
        "You are a phishing-URL structural analyst. You do NOT have internet "
        "access and cannot look anything up — judge ONLY the URL's structure: "
        "brand impersonation (lookalike domains), suspicious TLDs, IP-address "
        "hosts, excessive subdomains, misleading characters, URL shorteners, "
        "suspicious keywords like login/verify/secure/account paired with "
        "unrelated domains. Respond with ONLY valid JSON, no other text: "
        '{"risk_score": <0-100 integer>, "flags": [<short strings>], '
        '"reasoning": "<one sentence>"}'
    )

    try:
        r = requests.post(
            GROQ_URL,
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": "openai/gpt-oss-20b",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": url},
                ],
                "temperature": 0.2,
                "max_completion_tokens": 500,
                "reasoning_effort": "low",
                "reasoning_format": "hidden",
            },
            timeout=15,
        )
        content = r.json()["choices"][0]["message"]["content"]
        # Strip markdown code fences if the model added them despite instructions
        content = content.strip()
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        content = content.strip()
        return json.loads(content)
    except (requests.RequestException, KeyError, ValueError) as e:
        return {"error": str(e)}


def combine_verdict(vt=None, urlhaus=None, abuseipdb=None, ai=None):
    flags = 0
    reasons = []

    if vt and not vt.get("error"):
        if vt.get("malicious", 0) > 0:
            flags += 2
            reasons.append(f"VirusTotal: {vt['malicious']} engines flagged malicious")
        elif vt.get("suspicious", 0) > 0:
            flags += 1
            reasons.append(f"VirusTotal: {vt['suspicious']} engines flagged suspicious")

    if urlhaus and urlhaus.get("listed"):
        flags += 2
        reasons.append(f"URLhaus: listed as {urlhaus.get('threat')}")

    if abuseipdb and not abuseipdb.get("error") and not abuseipdb.get("skipped"):
        score = abuseipdb.get("abuse_score", 0)
        if score >= 50:
            flags += 1
            reasons.append(f"AbuseIPDB: host abuse score {score}")

    if ai and not ai.get("error") and not ai.get("skipped"):
        risk = ai.get("risk_score", 0)
        if risk >= 70:
            flags += 2
            reasons.append(f"AI heuristic: {ai.get('reasoning', 'high-risk URL structure')}")
        elif risk >= 40:
            flags += 1
            reasons.append(f"AI heuristic: {ai.get('reasoning', 'suspicious URL structure')}")

    if flags >= 2:
        verdict = "Malicious"
    elif flags == 1:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return verdict, reasons


# ---------------------------------------------------------------
# Routes
# ---------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan/url", methods=["POST"])
def scan_url():
    url = request.json.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    vt_result = vt_check_url(url)
    urlhaus_result = urlhaus_check_url(url)

    hostname = url.split("//")[-1].split("/")[0].split(":")[0]
    abuseipdb_result = abuseipdb_check_host(hostname)
    ai_result = ai_url_heuristic(url)

    verdict, reasons = combine_verdict(vt_result, urlhaus_result, abuseipdb_result, ai_result)
    save_scan(url, "url", verdict, "; ".join(reasons))

    return jsonify(
        {
            "target": url,
            "verdict": verdict,
            "reasons": reasons,
            "virustotal": vt_result,
            "urlhaus": urlhaus_result,
            "abuseipdb": abuseipdb_result,
            "ai_heuristic": ai_result,
        }
    )



@app.route("/scan/file", methods=["POST"])
def scan_file():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    uploaded = request.files["file"]
    if uploaded.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    filepath = os.path.join(UPLOAD_DIR, uploaded.filename)
    uploaded.save(filepath)

    if os.path.getsize(filepath) > MAX_FILE_SIZE:
        os.remove(filepath)
        return jsonify({"error": "File exceeds 32MB limit for this scanner"}), 400

    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    file_hash = sha256.hexdigest()

    vt_result = vt_check_file_hash(file_hash)
    if vt_result.get("not_found"):
        vt_result = vt_upload_file(filepath)

    # Never execute the file. Delete it once we've hashed/scanned it.
    os.remove(filepath)

    verdict, reasons = combine_verdict(vt=vt_result)
    save_scan(uploaded.filename, "file", verdict, "; ".join(reasons))

    return jsonify(
        {
            "target": uploaded.filename,
            "sha256": file_hash,
            "verdict": verdict,
            "reasons": reasons,
            "virustotal": vt_result,
        }
    )


@app.route("/history")
def history():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM scans ORDER BY id DESC LIMIT 20"
    ).fetchall()
    return jsonify([dict(row) for row in rows])

init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
