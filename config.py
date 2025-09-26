"""
Configuration settings for the Threat Intelligence Assistant
"""
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Base configuration class"""
    
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    
    # API Keys
    # Support both ALIENVAULT_API_KEY and OTX_API_KEY env variable names
    ALIENVAULT_API_KEY = os.environ.get('ALIENVAULT_API_KEY') or os.environ.get('OTX_API_KEY', '')
    ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')
    OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', '')
    
    # Application Settings
    MAX_RESULTS = int(os.environ.get('MAX_RESULTS', 50))
    CACHE_DURATION = int(os.environ.get('CACHE_DURATION', 3600))
    
    # API Endpoints
    ALIENVAULT_BASE_URL = "https://otx.alienvault.com/api/v1"
    ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    # Model Settings
    MODEL_PATH = "models/"
    RISK_MODEL_FILE = "risk_assessment_model.pkl"
    VECTORIZER_FILE = "vectorizer.pkl"

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
