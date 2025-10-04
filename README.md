# 🛡️ Threat Intelligence Assistant

A modern, AI-powered threat analysis platform that instantly evaluates IP addresses, domains, and file hashes for potential security risks. Features an intelligent chatbot assistant and beautiful, responsive web interface.

## ✨ Key Features

- **🔍 Multi-Source Analysis**: AlienVault OTX, AbuseIPDB threat intelligence
- **🤖 AI-Powered Chatbot**: Interactive assistant for analysis results
- **🎨 Modern UI**: Glass morphism design with smooth animations
- **📊 Smart Risk Assessment**: ML-enhanced scoring with clear recommendations
- **🌐 Web Interface**: Beautiful, responsive design at `http://localhost:5000`
- **🔗 API Access**: RESTful endpoints for integration
- **🧠 RAG System**: Retrieval-Augmented Generation for intelligent summaries

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Environment
Create `.env` file in project root:
```env
# Threat Intelligence APIs
ALIENVAULT_API_KEY=your_otx_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
OPENAI_API_KEY=your_openai_key_here  # Optional for AI summaries

# Flask Configuration
FLASK_ENV=development
FLASK_DEBUG=True
SECRET_KEY=your-secret-key-here
```

### 3. Run the Application
```bash
python app.py
```

### 4. Access the Interface
- **Web Interface**: Open `http://localhost:5000`
- **API Endpoint**: `POST /analyze` for programmatic access

## 🎯 How It Works

### Threat Analysis
1. **Input**: Enter IP address, domain, or file hash
2. **Intelligence Gathering**: Queries multiple threat intelligence sources
3. **AI Processing**: Uses RAG system for intelligent analysis
4. **Risk Assessment**: Generates risk score and recommendations
5. **Interactive Chat**: Ask questions about results via AI chatbot

### Risk Scoring
- **🔴 High Risk**: AbuseIPDB confidence ≥ 70% OR OTX pulse count ≥ 5
- **🟡 Medium Risk**: AbuseIPDB confidence ≥ 30% OR OTX pulse count ≥ 1  
- **🟢 Low Risk**: Minimal or no threat indicators detected

### Supported Indicators
- **IP Addresses**: IPv4 addresses (e.g., `8.8.8.8`)
- **Domains**: Website domains (e.g., `example.com`)
- **File Hashes**: MD5, SHA1, SHA256 hashes

## 💡 Features

### 🤖 AI Chatbot Assistant
- Context-aware responses about analysis results
- Natural language queries about threats
- Real-time conversation with typing indicators
- Mobile-responsive design

### 🎨 Modern Interface
- Glass morphism design with backdrop blur
- Smooth animations and hover effects
- Responsive layout for all devices
- Beautiful gradient backgrounds

### 🔧 Technical Capabilities
- **RAG System**: Retrieval-Augmented Generation for intelligent summaries
- **Fallback Logic**: Works without API keys (reduced functionality)
- **ML Integration**: Machine learning risk assessment
- **Real-time Analysis**: Instant threat evaluation

## 📝 Usage Examples

### Web Interface
1. Open `http://localhost:5000`
2. Enter threat indicator in the input field
3. Click "Analyze Threat" or press Enter
4. Review results and chat with AI assistant

### API Usage
```bash
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"indicator": "8.8.8.8"}'
```

### Chat API
```bash
curl -X POST http://localhost:5000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What is the risk level?"}'
```

## 🔑 API Keys (Optional)
- **AlienVault OTX**: Get free key at [otx.alienvault.com](https://otx.alienvault.com)
- **AbuseIPDB**: Get free key at [abuseipdb.com](https://abuseipdb.com)
- **OpenAI**: Get key at [platform.openai.com](https://platform.openai.com)

*Note: The app works without API keys but with reduced functionality.*
