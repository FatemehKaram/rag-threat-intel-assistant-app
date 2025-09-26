# Threat Intelligence Assistant

Analyze IPs, domains, and file hashes in a clean web UI. Risk is driven by AlienVault OTX and AbuseIPDB; ML is fallback only.

## Features
- Simple web app at `http://localhost:5000`
- Live risk based on OTX pulse_count and AbuseIPDB confidence
- Clear report with summary, recommendations, and source links

## Quick Start
1) Install deps
```powershell
pip install -r requirements.txt
```

2) Add `.env` in project root
```env
# OTX: use either name
ALIENVAULT_API_KEY=your_otx_key
OTX_API_KEY=your_otx_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
FLASK_ENV=development
FLASK_DEBUG=True
SECRET_KEY=dev-secret
```

3) Run the app
```powershell
python app.py
```

4) Open the UI
- Browser: `http://localhost:5000`
