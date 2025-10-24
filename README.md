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

## 📋 Prerequisites

Before setting up the application, ensure you have:

- **Python 3.9+** installed on your system
- **pip** (Python package installer)
- **Git** (for cloning the repository)
- **API Keys** (optional but recommended):
  - [AlienVault OTX API Key](https://otx.alienvault.com/api) (free)
  - [AbuseIPDB API Key](https://www.abuseipdb.com/api) (free tier available)
  - [OpenAI API Key](https://platform.openai.com/api-keys) (for AI features)

## 🚀 Installation & Setup

### Method 1: Automated Setup (Recommended)

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd rag-threat-intel-assistant-app
   ```

2. **Run the automated setup script**
   ```bash
   python setup.py
   ```
   This will:
   - Create necessary directories
   - Install Python dependencies
   - Create a `.env` configuration file
   - Set up the project structure

3. **Configure API keys** (Edit the `.env` file created by setup)
   ```env
   # Threat Intelligence APIs
   ALIENVAULT_API_KEY=your_otx_key_here
   ABUSEIPDB_API_KEY=your_abuseipdb_key_here
   OPENAI_API_KEY=your_openai_key_here  # Optional for AI summaries

   # Flask Configuration
   SECRET_KEY=your-secret-key-here
   FLASK_ENV=development
   FLASK_DEBUG=True
   ```

4. **Start the application**
   ```bash
   python app.py
   ```

### Method 2: Manual Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd rag-threat-intel-assistant-app
   ```

2. **Create a virtual environment** (recommended)
   ```bash
   python -m venv venv
   
   # On Windows:
   venv\Scripts\activate
   
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Create necessary directories**
   ```bash
   mkdir -p templates static models logs
   ```

5. **Create environment configuration file**
   Create a `.env` file in the project root:
   ```env
   # Threat Intelligence APIs
   ALIENVAULT_API_KEY=your_otx_key_here
   ABUSEIPDB_API_KEY=your_abuseipdb_key_here
   OPENAI_API_KEY=your_openai_key_here  # Optional for AI summaries

   # Flask Configuration
   SECRET_KEY=your-secret-key-here
   FLASK_ENV=development
   FLASK_DEBUG=True

   # Application Settings
   MAX_RESULTS=50
   CACHE_DURATION=3600
   ```

6. **Run the application**
   ```bash
   python app.py
   ```

### Method 3: Using the Startup Script

1. **Follow steps 1-3 from Method 2**

2. **Use the startup script** (includes dependency checks)
   ```bash
   python run.py
   ```

## 🐳 Docker Deployment

### Using Docker Compose (Recommended)

1. **Create environment file**
   ```bash
   cp .env.example .env  # Edit with your API keys
   ```

2. **Build and run with Docker Compose**
   ```bash
   docker-compose up --build
   ```

### Using Docker directly

1. **Build the Docker image**
   ```bash
   docker build -t threat-intel-assistant .
   ```

2. **Run the container**
   ```bash
   docker run -p 5000:5000 \
     -e ALIENVAULT_API_KEY=your_key \
     -e ABUSEIPDB_API_KEY=your_key \
     -e OPENAI_API_KEY=your_key \
     -e SECRET_KEY=your_secret \
     threat-intel-assistant
   ```

## 🔑 API Key Setup

### AlienVault OTX (Free)
1. Visit [AlienVault OTX](https://otx.alienvault.com/api)
2. Sign up for a free account
3. Navigate to your profile settings
4. Generate an API key
5. Add to your `.env` file as `ALIENVAULT_API_KEY`

### AbuseIPDB (Free tier available)
1. Visit [AbuseIPDB](https://www.abuseipdb.com/api)
2. Create a free account
3. Go to API section in your dashboard
4. Generate an API key
5. Add to your `.env` file as `ABUSEIPDB_API_KEY`

### OpenAI (Optional - for AI features)
1. Visit [OpenAI Platform](https://platform.openai.com/api-keys)
2. Create an account and add billing information
3. Generate an API key
4. Add to your `.env` file as `OPENAI_API_KEY`

**Note**: The application works without API keys but with reduced functionality.

## 🌐 Access the Application

Once running, access the application at:
- **Web Interface**: `http://localhost:5000`
- **API Endpoint**: `POST http://localhost:5000/analyze`
- **Health Check**: `GET http://localhost:5000/health`

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

## 🛠️ Development

### Running in Development Mode

1. **Set development environment**
   ```bash
   export FLASK_ENV=development
   export FLASK_DEBUG=True
   ```

2. **Run with auto-reload**
   ```bash
   python app.py
   ```

### Project Structure

```
rag-threat-intel-assistant-app/
├── app.py                 # Main Flask application
├── config.py             # Configuration settings
├── run.py                # Startup script with checks
├── setup.py              # Automated setup script
├── requirements.txt      # Python dependencies
├── Dockerfile           # Docker configuration
├── docker-compose.yml   # Docker Compose setup
├── templates/           # HTML templates
├── static/             # Static assets (CSS, JS)
├── models/             # ML models and vectorizers
├── logs/               # Application logs
├── threat_data/        # Threat intelligence data storage
└── rag/                # RAG system components
```

## 🚀 Production Deployment

### Using Gunicorn

1. **Install Gunicorn**
   ```bash
   pip install gunicorn
   ```

2. **Run with Gunicorn**
   ```bash
   gunicorn --bind 0.0.0.0:5000 --workers 4 --timeout 120 app:app
   ```

### Environment Variables for Production

```env
FLASK_ENV=production
FLASK_DEBUG=False
SECRET_KEY=your-strong-secret-key-here
ALIENVAULT_API_KEY=your_production_key
ABUSEIPDB_API_KEY=your_production_key
OPENAI_API_KEY=your_production_key
```

### Using Docker in Production

1. **Build production image**
   ```bash
   docker build -t threat-intel-assistant:latest .
   ```

2. **Run with environment variables**
   ```bash
   docker run -d \
     --name threat-intel-app \
     -p 5000:5000 \
     -e FLASK_ENV=production \
     -e SECRET_KEY=your_secret \
     -e ALIENVAULT_API_KEY=your_key \
     -e ABUSEIPDB_API_KEY=your_key \
     -e OPENAI_API_KEY=your_key \
     --restart unless-stopped \
     threat-intel-assistant:latest
   ```

## 🔧 Troubleshooting

### Common Issues

#### 1. Import Errors
**Problem**: `ModuleNotFoundError` when running the application
**Solution**:
```bash
# Ensure you're in the correct directory
cd rag-threat-intel-assistant-app

# Install dependencies
pip install -r requirements.txt

# Or use the setup script
python setup.py
```

#### 2. API Key Issues
**Problem**: "API key not configured" messages
**Solution**:
- Check your `.env` file exists and contains the correct API keys
- Ensure no extra spaces or quotes around the API key values
- Verify the API keys are valid and active

#### 3. Port Already in Use
**Problem**: `Address already in use` error
**Solution**:
```bash
# Find and kill the process using port 5000
# On Windows:
netstat -ano | findstr :5000
taskkill /PID <PID_NUMBER> /F

# On macOS/Linux:
lsof -ti:5000 | xargs kill -9

# Or use a different port
export PORT=8000
python app.py
```

#### 4. Permission Errors (Linux/macOS)
**Problem**: Permission denied when creating directories
**Solution**:
```bash
# Fix permissions
chmod +x setup.py run.py
sudo chown -R $USER:$USER .
```

#### 5. Docker Build Issues
**Problem**: Docker build fails
**Solution**:
```bash
# Clean Docker cache
docker system prune -a

# Rebuild without cache
docker build --no-cache -t threat-intel-assistant .
```

### Debug Mode

Enable debug mode for detailed error messages:

```bash
export FLASK_DEBUG=True
python app.py
```

### Health Check

Test if the application is running correctly:

```bash
curl http://localhost:5000/health
```

Expected response:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00",
  "version": "1.0.0"
}
```

### Logs

Check application logs for errors:

```bash
# View logs in real-time
tail -f logs/app.log

# Or check Docker logs
docker logs threat-intel-app
```

## 📚 Additional Resources

### API Documentation

- **Analysis Endpoint**: `POST /analyze`
  ```bash
  curl -X POST http://localhost:5000/analyze \
    -H "Content-Type: application/json" \
    -d '{"indicator": "8.8.8.8"}'
  ```

- **Chat Endpoint**: `POST /chat`
  ```bash
  curl -X POST http://localhost:5000/chat \
    -H "Content-Type: application/json" \
    -d '{"message": "What is the risk level?"}'
  ```

- **Health Check**: `GET /health`

### Supported Indicators

- **IP Addresses**: IPv4 addresses (e.g., `8.8.8.8`, `192.168.1.1`)
- **Domains**: Website domains (e.g., `example.com`, `malicious-site.org`)
- **File Hashes**: MD5 (32 chars), SHA1 (40 chars), SHA256 (64 chars)

### Risk Assessment

- **🔴 High Risk**: AbuseIPDB confidence ≥ 70% OR OTX pulse count ≥ 5
- **🟡 Medium Risk**: AbuseIPDB confidence ≥ 30% OR OTX pulse count ≥ 1  
- **🟢 Low Risk**: Minimal or no threat indicators detected

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

If you encounter any issues:

1. Check the [Troubleshooting](#-troubleshooting) section
2. Review the application logs
3. Open an issue on GitHub with:
   - Your operating system
   - Python version
   - Error messages
   - Steps to reproduce

---

**Note**: This application works without API keys but with reduced functionality. For full features, configure the API keys as described in the [API Key Setup](#-api-key-setup) section.
