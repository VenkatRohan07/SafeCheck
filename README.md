# URL & File Safety Scanner

A simple web dashboard (Flask) that checks whether a URL or file is safe by
querying real threat-intel sources: **VirusTotal**, **URLhaus**, and
**AbuseIPDB**.

**Render link:** https://safecheck-r3ao.onrender.com

## Features
- Paste a URL → checked against VirusTotal's 70+ engine scan, URLhaus's
  known-malware-URL feed, and AbuseIPDB's reputation score for the resolved host.
- Upload a file → hashed locally (SHA-256), checked against VirusTotal's
  hash database first, and only uploaded for a fresh scan if it's unknown.
  Files are never executed and are deleted right after scanning.
- Combined verdict: **Safe / Suspicious / Malicious**, with the reasons shown.
- Scan history stored locally in SQLite.

## Setup on Kali Linux

```bash
# 1. Go into the project folder
cd url-file-safety-scanner

# 2. Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set your API keys
cp .env.example .env
# edit .env and paste in your VirusTotal (required) and AbuseIPDB (optional) keys
export $(cat .env | xargs)

# 5. Run it
python app.py
```

Then open **http://localhost:5000** in your browser.

## Getting API keys (free tiers)
- VirusTotal: https://www.virustotal.com/gui/join-us — 4 requests/min, 500/day on the free tier
- AbuseIPDB: https://www.abuseipdb.com/register — 1000 checks/day on the free tier
- URLhaus: no key needed, public API

## Project structure
```
url-file-safety-scanner/
├── app.py              # Flask backend + API integrations
├── templates/
│   └── index.html      # Dashboard page
├── static/
│   ├── style.css
│   └── script.js
├── uploads/             # Temp storage for uploaded files (auto-cleared)
├── history.db           # SQLite scan history (created on first run)
├── requirements.txt
└── .env.example
```

## How the verdict is decided
Each source contributes "flag points":
- VirusTotal: malicious hits → +2, suspicious-only → +1
- URLhaus: listed as malware distribution → +2
- AbuseIPDB: host abuse score ≥ 50 → +1

Total flags ≥ 2 → **Malicious**, exactly 1 → **Suspicious**, 0 → **Safe**.
Feel free to tune these thresholds once you see real results.

## Next steps / ideas to extend it
- Add a browser extension that calls the same `/scan/url` endpoint automatically
- Add YARA rule scanning for uploaded files as an extra local layer
- Add a rate-limit-aware queue if you hit VirusTotal free-tier limits often
- Deploy behind `gunicorn` + `nginx` if you want it always-on on your Kali box
