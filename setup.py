"""
Setup script for the Threat Intelligence Assistant
"""
import os
import sys
import subprocess
import shutil

def create_directories():
    """Create necessary directories"""
    directories = ['templates', 'static', 'models', 'logs']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✓ Created directory: {directory}")

def create_env_file():
    """Create .env file from template if it doesn't exist"""
    if not os.path.exists('.env'):
        env_content = """# Threat Intelligence Assistant Configuration

# API Keys (Get these from the respective services)
ALIENVAULT_API_KEY=your_alienvault_otx_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
OPENAI_API_KEY=your_openai_api_key_here

# Flask Configuration
SECRET_KEY=your_secret_key_here
FLASK_ENV=development
FLASK_DEBUG=True

# Application Settings
MAX_RESULTS=50
CACHE_DURATION=3600
"""
        with open('.env', 'w') as f:
            f.write(env_content)
        print("✓ Created .env file - Please update with your API keys")
    else:
        print("✓ .env file already exists")

def install_dependencies():
    """Install Python dependencies"""
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        print("✓ Installed Python dependencies")
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to install dependencies: {e}")
        return False
    return True

def create_gitignore():
    """Create .gitignore file"""
    gitignore_content = """# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual Environment
venv/
env/
ENV/

# Environment Variables
.env
.env.local
.env.production

# Models and Cache
models/*.pkl
*.pkl
cache/

# Logs
logs/
*.log

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Flask
instance/
.webassets-cache

# Testing
.coverage
.pytest_cache/
htmlcov/
"""
    with open('.gitignore', 'w') as f:
        f.write(gitignore_content)
    print("✓ Created .gitignore file")

def main():
    """Main setup function"""
    print("🚀 Setting up Threat Intelligence Assistant...")
    print("=" * 50)
    
    # Create directories
    create_directories()
    
    # Create .env file
    create_env_file()
    
    # Create .gitignore
    create_gitignore()
    
    # Install dependencies
    if install_dependencies():
        print("\n" + "=" * 50)
        print("✅ Setup completed successfully!")
        print("\n📋 Next steps:")
        print("1. Update the .env file with your API keys:")
        print("   - Get AlienVault OTX API key: https://otx.alienvault.com/api")
        print("   - Get AbuseIPDB API key: https://www.abuseipdb.com/api")
        print("   - Get OpenAI API key: https://platform.openai.com/api-keys")
        print("2. Run the application: python app.py")
        print("3. Open your browser to: http://localhost:5000")
        print("\n🔧 For production deployment, see the README.md file")
    else:
        print("\n❌ Setup failed. Please check the error messages above.")

if __name__ == "__main__":
    main()



