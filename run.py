#!/usr/bin/env python3
"""
Startup script for the Threat Intelligence Assistant
"""
import os
import sys
import subprocess
import time
from pathlib import Path

def check_dependencies():
    """Check if required dependencies are installed"""
    try:
        import flask
        import requests
        import sklearn
        import numpy
        print("✅ All required dependencies are installed")
        return True
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("Please run: pip install -r requirements.txt")
        return False

def check_config():
    """Check if configuration is set up"""
    env_file = Path('.env')
    if not env_file.exists():
        print("⚠️  .env file not found. Creating from template...")
        # Create basic .env file
        env_content = """# Threat Intelligence Assistant Configuration
ALIENVAULT_API_KEY=your_alienvault_otx_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
SECRET_KEY=dev-secret-key-change-in-production
FLASK_ENV=development
FLASK_DEBUG=True
"""
        with open('.env', 'w') as f:
            f.write(env_content)
        print("✅ Created .env file - Please update with your API keys")
    else:
        print("✅ Configuration file found")
    
    return True

def create_directories():
    """Create necessary directories"""
    directories = ['templates', 'static', 'models', 'logs']
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
    print("✅ Created necessary directories")

def main():
    """Main startup function"""
    print("🚀 Starting Threat Intelligence Assistant")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Check configuration
    check_config()
    
    # Create directories
    create_directories()
    
    print("\n🔧 Starting the application...")
    print("📱 Web interface will be available at: http://localhost:5000")
    print("🔍 API endpoint: http://localhost:5000/analyze")
    print("❤️  Health check: http://localhost:5000/health")
    print("\n💡 Tip: Press Ctrl+C to stop the application")
    print("=" * 50)
    
    try:
        # Import and run the Flask app
        from app import app
        app.run(debug=True, host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        print("\n👋 Application stopped by user")
    except Exception as e:
        print(f"\n❌ Error starting application: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()


