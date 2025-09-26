# Threat Intelligence Assistant (Concise)

Analyze IPs, domains, and file hashes via a simple web UI and REST API. Risk is determined directly from AlienVault OTX and AbuseIPDB; ML is used only as a fallback.

## Features
- Web UI at `http://localhost:5000`
- `POST /analyze` API returns a structured report
- Live risk from OTX pulse_count and AbuseIPDB confidence
- Links to original source reports

## Install & Run
```powershell
pip install -r requirements.txt
python app.py
```

## Configure (.env)
```env
# Either name works for OTX
ALIENVAULT_API_KEY=your_otx_key
OTX_API_KEY=your_otx_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
OPENAI_API_KEY=    # optional
FLASK_ENV=development
FLASK_DEBUG=True
SECRET_KEY=dev-secret
```

## Risk Logic (rule-based)
- High: AbuseIPDB confidence ≥ 70 OR OTX pulse_count ≥ 5
- Medium: AbuseIPDB confidence ≥ 30 OR OTX pulse_count ≥ 1
- Low: otherwise

## Quick Test (PowerShell)
```powershell
# Healthy/benign example
Invoke-RestMethod -Uri "http://localhost:5000/analyze" -Method POST -ContentType "application/json" -Body '{"indicator":"8.8.8.8"}' | ConvertTo-Json -Depth 3

# Likely suspicious example (may vary over time/rate limits)
Invoke-RestMethod -Uri "http://localhost:5000/analyze" -Method POST -ContentType "application/json" -Body '{"indicator":"185.220.101.1"}' | ConvertTo-Json -Depth 3
```

## Notes
- Works without keys (falls back to rule-based/ML with limited signal)
- OpenAI is optional and only affects narrative summaries
