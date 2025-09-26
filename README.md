# Threat Intelligence Assistant

A powerful tool that helps users quickly understand whether an IP address, domain, or file hash is potentially dangerous. The Threat Intelligence Assistant automatically gathers data from trusted sources and provides clear, actionable threat reports in seconds.

## 🎯 Features

- Live risk scoring from AlienVault OTX (pulse_count) and AbuseIPDB (confidence)
- Clear report: summary, recommendations, threat types, and source links
- Web UI at `http://localhost:5000` and `POST /analyze` API
- Optional OpenAI summaries (if OPENAI_API_KEY provided)

## 🚀 Quick Start

1) Install
```powershell
pip install -r requirements.txt
```

2) Configure `.env` (project root)
```env
# OTX key (either name works)
ALIENVAULT_API_KEY=your_otx_key
OTX_API_KEY=your_otx_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
OPENAI_API_KEY=    # optional
FLASK_ENV=development
FLASK_DEBUG=True
SECRET_KEY=dev-secret
```

3) Run
```powershell
python app.py
```

4) Use
- Web: open `http://localhost:5000`
- API (PowerShell):
```powershell
Invoke-RestMethod -Uri "http://localhost:5000/analyze" -Method POST -ContentType "application/json" -Body '{"indicator":"8.8.8.8"}' | ConvertTo-Json -Depth 3
```

## 🧠 Risk Logic (rule-based)
- High: AbuseIPDB confidence ≥ 70 OR OTX pulse_count ≥ 5
- Medium: AbuseIPDB confidence ≥ 30 OR OTX pulse_count ≥ 1
- Low: otherwise (ML is fallback when feeds give no signal)

## Notes
- Works without keys (reduced fidelity). OpenAI is optional and only affects summaries.
