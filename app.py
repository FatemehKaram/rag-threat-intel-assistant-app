# Import Flask web framework components for building the web application
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
# Import operating system interface for file and directory operations
import os
# Import JSON handling for data serialization and file storage
import json
# Import logging for application monitoring and debugging
import logging
# Import datetime for timestamp handling
from datetime import datetime
# Import type hints for better code documentation and IDE support
from typing import Dict, List, Optional, Any
# Import requests for making HTTP API calls to threat intelligence sources
import requests
# Import dataclass decorator for creating structured data classes
from dataclasses import dataclass, asdict
# Import regular expressions for pattern matching and validation
import re
# Import hashlib for hash validation and processing
import hashlib
# Import ipaddress for IP address validation and manipulation
import ipaddress
# Import urlparse for URL parsing and validation
from urllib.parse import urlparse
# Import OpenAI for AI-powered threat intelligence synthesis
import openai
# Import scikit-learn components for machine learning-based risk assessment
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
# Import joblib for saving and loading machine learning models
import joblib
# Import numpy for numerical operations
import numpy as np
# Import our custom configuration module
from config import config

# Configure logging system to write to both file and console
logging.basicConfig(
    level=logging.INFO,  # Set logging level to INFO (captures info, warning, error messages)
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # Define log message format
    handlers=[
        logging.FileHandler('logs/app.log'),  # Write logs to file
        logging.StreamHandler()  # Also display logs in console
    ]
)
# Create a logger instance for this module
logger = logging.getLogger(__name__)

# Create Flask application instance
app = Flask(__name__)

# Load configuration based on environment (development/production)
config_name = os.environ.get('FLASK_ENV', 'development')  # Get environment from env var, default to development
app.config.from_object(config[config_name])  # Apply configuration to Flask app

@dataclass
class ThreatIndicator:
    """Represents a threat indicator (IP, domain, or hash)"""
    value: str  # The actual indicator value (e.g., "192.168.1.1", "malicious.com", "abc123...")
    indicator_type: str  # Type of indicator: 'ip', 'domain', or 'hash'
    confidence: float = 0.0  # Confidence score for this indicator (0.0 to 1.0)
    first_seen: Optional[str] = None  # ISO timestamp when first observed
    last_seen: Optional[str] = None  # ISO timestamp when last observed
    sources: List[str] = None  # List of threat intelligence sources that reported this indicator
    
    def __post_init__(self):
        # Initialize sources list if it's None (dataclass default handling)
        if self.sources is None:
            self.sources = []

@dataclass
class ThreatReport:
    """Represents a comprehensive threat analysis report"""
    indicator: ThreatIndicator  # The threat indicator that was analyzed
    risk_level: str  # Risk assessment: 'Low', 'Medium', or 'High'
    risk_score: float  # Numerical risk score from 0.0 (safe) to 1.0 (very dangerous)
    threat_types: List[str]  # List of threat categories (e.g., ["malware", "botnet", "phishing"])
    summary: str  # AI-generated brief summary of the threat
    detailed_analysis: str  # Comprehensive AI analysis of the threat
    recommendations: List[str]  # AI-generated security recommendations
    source_links: List[Dict[str, str]]  # Links to original threat intelligence reports
    analysis_timestamp: str  # ISO timestamp when this analysis was performed
    confidence: float  # Overall confidence in the analysis (0.0 to 1.0)

class ThreatIntelligenceAPI:
    """Handles API calls to various threat intelligence sources"""
    
    def __init__(self):
        # Set base URL for AlienVault OTX (Open Threat Exchange) API
        self.alienvault_base = "https://otx.alienvault.com/api/v1"
        # Set base URL for AbuseIPDB API for IP reputation checking
        self.abuseipdb_base = "https://api.abuseipdb.com/api/v2"
        
    def check_ip_alienvault(self, ip_address: str) -> Dict[str, Any]:
        """Check IP address against AlienVault OTX"""
        try:
            # Check if API key is configured, return default response if not
            if not app.config['ALIENVAULT_API_KEY']:
                return {"source": "AlienVault OTX", "malicious": False, "pulse_count": 0, "pulses": [], "url": f"https://otx.alienvault.com/indicator/ip/{ip_address}", "note": "API key not configured"}
                
            # Set up API headers with the required API key
            headers = {'X-OTX-API-KEY': app.config['ALIENVAULT_API_KEY']}
            # Construct the API endpoint URL for IP lookup
            url = f"{self.alienvault_base}/indicators/IPv4/{ip_address}/general"
            
            # Make HTTP GET request to AlienVault API with 10-second timeout
            response = requests.get(url, headers=headers, timeout=10)
            # Raise exception if HTTP status code indicates an error
            response.raise_for_status()
            
            # Parse JSON response from the API
            data = response.json()
            # Return structured data about the IP address
            return {
                "source": "AlienVault OTX",  # Source identifier
                "malicious": data.get('pulse_info', {}).get('count', 0) > 0,  # True if any threat pulses found
                "pulse_count": data.get('pulse_info', {}).get('count', 0),  # Number of threat pulses
                "pulses": data.get('pulse_info', {}).get('pulses', []),  # Detailed pulse information
                "url": f"https://otx.alienvault.com/indicator/ip/{ip_address}"  # Link to detailed report
            }
        except Exception as e:
            # Log any errors and return error information
            logger.error(f"AlienVault API error for {ip_address}: {str(e)}")
            return {"error": str(e)}
    
    def check_ip_abuseipdb(self, ip_address: str) -> Dict[str, Any]:
        """Check IP address against AbuseIPDB"""
        try:
            # Check if API key is configured, return default response if not
            if not app.config['ABUSEIPDB_API_KEY']:
                return {"source": "AbuseIPDB", "malicious": False, "confidence": 0, "usage_type": "Unknown", "country": "Unknown", "isp": "Unknown", "reports": 0, "url": f"https://www.abuseipdb.com/check/{ip_address}", "note": "API key not configured"}
                
            # Set up API headers with the required API key and content type
            headers = {'Key': app.config['ABUSEIPDB_API_KEY'], 'Accept': 'application/json'}
            # Set up query parameters for the API request
            params = {'ipAddress': ip_address, 'maxAgeInDays': 90, 'verbose': ''}
            
            # Make HTTP GET request to AbuseIPDB API with parameters and timeout
            response = requests.get(f"{self.abuseipdb_base}/check", 
                                  headers=headers, params=params, timeout=10)
            # Raise exception if HTTP status code indicates an error
            response.raise_for_status()
            
            # Parse JSON response from the API
            data = response.json()
            # Extract the data section from the response
            result = data.get('data', {})
            
            # Return structured data about the IP address
            return {
                "source": "AbuseIPDB",  # Source identifier
                "malicious": result.get('abuseConfidencePercentage', 0) > 0,  # True if abuse confidence > 0%
                "confidence": result.get('abuseConfidencePercentage', 0),  # Abuse confidence percentage (0-100)
                "usage_type": result.get('usageType', 'Unknown'),  # Type of usage (hosting, isp, etc.)
                "country": result.get('countryCode', 'Unknown'),  # Country code where IP is located
                "isp": result.get('isp', 'Unknown'),  # Internet Service Provider
                "reports": result.get('totalReports', 0),  # Total number of abuse reports
                "url": f"https://www.abuseipdb.com/check/{ip_address}"  # Link to detailed report
            }
        except Exception as e:
            # Log any errors and return error information
            logger.error(f"AbuseIPDB API error for {ip_address}: {str(e)}")
            return {"error": str(e)}
    
    def check_domain_alienvault(self, domain: str) -> Dict[str, Any]:
        """Check domain against AlienVault OTX"""
        try:
            # Check if API key is configured, return default response if not
            if not app.config['ALIENVAULT_API_KEY']:
                return {"source": "AlienVault OTX", "malicious": False, "pulse_count": 0, "pulses": [], "url": f"https://otx.alienvault.com/indicator/domain/{domain}", "note": "API key not configured"}
                
            # Set up API headers with the required API key
            headers = {'X-OTX-API-KEY': app.config['ALIENVAULT_API_KEY']}
            # Construct the API endpoint URL for domain lookup
            url = f"{self.alienvault_base}/indicators/domain/{domain}/general"
            
            # Make HTTP GET request to AlienVault API with 10-second timeout
            response = requests.get(url, headers=headers, timeout=10)
            # Raise exception if HTTP status code indicates an error
            response.raise_for_status()
            
            # Parse JSON response from the API
            data = response.json()
            # Return structured data about the domain
            return {
                "source": "AlienVault OTX",  # Source identifier
                "malicious": data.get('pulse_info', {}).get('count', 0) > 0,  # True if any threat pulses found
                "pulse_count": data.get('pulse_info', {}).get('count', 0),  # Number of threat pulses
                "pulses": data.get('pulse_info', {}).get('pulses', []),  # Detailed pulse information
                "url": f"https://otx.alienvault.com/indicator/domain/{domain}"  # Link to detailed report
            }
        except Exception as e:
            # Log any errors and return error information
            logger.error(f"AlienVault domain API error for {domain}: {str(e)}")
            return {"error": str(e)}
    
    def check_hash_alienvault(self, file_hash: str) -> Dict[str, Any]:
        """Check file hash against AlienVault OTX"""
        try:
            # Check if API key is configured, return default response if not
            if not app.config['ALIENVAULT_API_KEY']:
                return {"source": "AlienVault OTX", "malicious": False, "pulse_count": 0, "pulses": [], "url": f"https://otx.alienvault.com/indicator/file/{file_hash}", "note": "API key not configured"}
                
            # Set up API headers with the required API key
            headers = {'X-OTX-API-KEY': app.config['ALIENVAULT_API_KEY']}
            # Construct the API endpoint URL for file hash lookup
            url = f"{self.alienvault_base}/indicators/file/{file_hash}/general"
            
            # Make HTTP GET request to AlienVault API with 10-second timeout
            response = requests.get(url, headers=headers, timeout=10)
            # Raise exception if HTTP status code indicates an error
            response.raise_for_status()
            
            # Parse JSON response from the API
            data = response.json()
            # Return structured data about the file hash
            return {
                "source": "AlienVault OTX",  # Source identifier
                "malicious": data.get('pulse_info', {}).get('count', 0) > 0,  # True if any threat pulses found
                "pulse_count": data.get('pulse_info', {}).get('count', 0),  # Number of threat pulses
                "pulses": data.get('pulse_info', {}).get('pulses', []),  # Detailed pulse information
                "url": f"https://otx.alienvault.com/indicator/file/{file_hash}"  # Link to detailed report
            }
        except Exception as e:
            # Log any errors and return error information
            logger.error(f"AlienVault hash API error for {file_hash}: {str(e)}")
            return {"error": str(e)}

class ThreatDataStorage:
    """Handles local storage of threat intelligence data in a single file"""
    
    def __init__(self, storage_dir="threat_data"):
        # Set the directory where threat data file will be stored
        self.storage_dir = storage_dir
        # Create the directory if it doesn't exist (exist_ok=True prevents error if already exists)
        os.makedirs(storage_dir, exist_ok=True)
        # Set the single file path for all threat data
        self.data_file = os.path.join(storage_dir, "latest_threat_analysis.json")
    
    def save_threat_data(self, indicator: ThreatIndicator, raw_data: List[Dict[str, Any]], analysis: ThreatReport):
        """Save threat data to single file, replacing previous data"""
        # Create new data structure for this analysis
        new_data = {
            # Store the indicator information (IP, domain, or hash details)
            "indicator": asdict(indicator),
            # Record when this data was last updated (current timestamp)
            "last_updated": datetime.now().isoformat(),
            # Store the raw data from threat intelligence APIs
            "raw_data": raw_data,
            # Store the latest analysis results
            "latest_analysis": asdict(analysis),
            # Store analysis metadata
            "analysis_metadata": {
                "indicator_type": indicator.indicator_type,
                "indicator_value": indicator.value,
                "analysis_timestamp": analysis.analysis_timestamp,
                "risk_level": analysis.risk_level,
                "risk_score": analysis.risk_score,
                "confidence": analysis.confidence
            }
        }
        
        # Write the new data to the single JSON file (overwrites previous data)
        with open(self.data_file, 'w') as f:
            # Convert Python dictionary to JSON format with 2-space indentation for readability
            json.dump(new_data, f, indent=2)
        
        # Log that the data was successfully saved
        logger.info(f"Saved threat data for {indicator.value} to {self.data_file}")
    
    def load_threat_data(self, indicator: ThreatIndicator) -> Optional[Dict[str, Any]]:
        """Load existing threat data from single file"""
        # Check if the single data file exists
        if os.path.exists(self.data_file):
            try:
                # Open the file for reading
                with open(self.data_file, 'r') as f:
                    # Convert JSON data back to Python dictionary
                    data = json.load(f)
                    # Check if this data is for the same indicator
                    if (data.get("indicator", {}).get("value") == indicator.value and 
                        data.get("indicator", {}).get("indicator_type") == indicator.indicator_type):
                        return data
                    else:
                        # Data is for a different indicator, return None
                        logger.info(f"Data file contains different indicator, treating as new analysis")
                        return None
            except Exception as e:
                # If there's an error reading the file, log it and return None
                logger.error(f"Error loading threat data from {self.data_file}: {str(e)}")
        # Return None if file doesn't exist or there was an error
        return None
    
    def _merge_threat_data(self, historical_data: List[Dict[str, Any]], new_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Merge historical and new threat data"""
        # Create empty list to store merged data
        merged_data = []
        # Keep track of which data sources we've already included
        sources_seen = set()
        
        # First, add all historical data
        for data in historical_data:
            # Get the source name (e.g., "AlienVault OTX", "AbuseIPDB")
            source = data.get("source", "Unknown")
            # Only add if we haven't seen this source before
            if source not in sources_seen:
                merged_data.append(data)
                sources_seen.add(source)
        
        # Then, add new data that we haven't seen before
        for data in new_data:
            # Get the source name
            source = data.get("source", "Unknown")
            # Only add if this is a new source
            if source not in sources_seen:
                merged_data.append(data)
                sources_seen.add(source)
        
        # Return the merged data list
        return merged_data
    
    def clear_data(self):
        """Clear all threat data (delete the single file)"""
        if os.path.exists(self.data_file):
            os.remove(self.data_file)
            logger.info(f"Cleared threat data file: {self.data_file}")
    
    def get_latest_analysis_info(self) -> Optional[Dict[str, Any]]:
        """Get information about the latest analysis without loading full data"""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'r') as f:
                    data = json.load(f)
                    return {
                        "indicator": data.get("indicator", {}),
                        "last_updated": data.get("last_updated"),
                        "analysis_metadata": data.get("analysis_metadata", {})
                    }
            except Exception as e:
                logger.error(f"Error reading latest analysis info: {str(e)}")
        return None

class RAGSystem:
    """Retrieval-Augmented Generation system for threat intelligence synthesis"""
    
    def __init__(self):
        # Initialize OpenAI client as None (will be set if API key is available)
        self.openai_client = None
        # Check if OpenAI API key is configured
        if app.config['OPENAI_API_KEY']:
            # Set the API key for OpenAI
            openai.api_key = app.config['OPENAI_API_KEY']
            # Store the OpenAI client for making API calls
            self.openai_client = openai
    
    def synthesize_threat_intelligence(self, indicator: ThreatIndicator, 
                                     raw_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Synthesize threat intelligence using RAG approach"""
        
        # Extract relevant information from raw API data and structure it
        threat_context = self._extract_threat_context(raw_data)
        
        # Choose between AI-powered or rule-based analysis based on OpenAI availability
        if self.openai_client:
            # Use OpenAI GPT for intelligent threat analysis and synthesis
            return self._generate_ai_summary(indicator, threat_context)
        else:
            # Fall back to rule-based analysis if OpenAI is not available
            return self._generate_rule_based_summary(indicator, threat_context)
    
    def _extract_threat_context(self, raw_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract relevant threat context from raw API data"""
        # Initialize context dictionary to store structured threat information
        context = {
            "malicious_indicators": [],  # List of sources reporting malicious activity
            "threat_types": set(),  # Set of threat categories (malware, botnet, etc.)
            "confidence_scores": [],  # List of confidence scores from different sources
            "source_reports": [],  # List of source report URLs
            "geographic_info": [],  # List of country information
            "temporal_info": []  # List of temporal information (first/last seen)
        }
        
        # Process each piece of raw data from threat intelligence APIs
        for data in raw_data:
            # Skip data entries that contain errors
            if "error" in data:
                continue
                
            # Skip data with notes about missing API keys (not useful for analysis)
            if "note" in data and "API key not configured" in data["note"]:
                continue
                
            # Get the source name (e.g., "AlienVault OTX", "AbuseIPDB")
            source = data.get("source", "Unknown")
            
            # Check if this source reports the indicator as malicious
            if data.get("malicious", False):
                context["malicious_indicators"].append(source)
                
            # Extract confidence scores from pulse counts (AlienVault data)
            if "pulse_count" in data and data["pulse_count"] > 0:
                # Convert pulse count to confidence score (max 100)
                context["confidence_scores"].append(min(data["pulse_count"] * 10, 100))
                
            # Extract confidence scores from abuse confidence (AbuseIPDB data)
            if "confidence" in data:
                context["confidence_scores"].append(data["confidence"])
                
            # Extract threat types from pulse tags (AlienVault data)
            if "pulses" in data:
                for pulse in data["pulses"]:
                    if "tags" in pulse:
                        # Add threat tags to the set (automatically handles duplicates)
                        context["threat_types"].update(pulse["tags"])
                        
            # Extract geographic information (country codes)
            if "country" in data:
                context["geographic_info"].append(data["country"])
                
            # Extract source report URLs for reference
            if "url" in data:
                context["source_reports"].append({
                    "source": source,  # Source name
                    "url": data["url"]  # URL to detailed report
                })
        
        # Convert threat_types set to list for JSON serialization
        context["threat_types"] = list(context["threat_types"])
        # Return the structured threat context
        return context
    
    def _generate_ai_summary(self, indicator: ThreatIndicator, 
                           context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate AI-powered threat summary"""
        try:
            prompt = f"""
            Analyze this threat intelligence data for {indicator.indicator_type.upper()}: {indicator.value}
            
            Context:
            - Malicious indicators: {context['malicious_indicators']}
            - Threat types: {context['threat_types']}
            - Confidence scores: {context['confidence_scores']}
            - Geographic info: {context['geographic_info']}
            
            Provide:
            1. Risk level (Low/Medium/High)
            2. Threat types involved
            3. Plain-language summary
            4. Detailed analysis
            5. Recommendations
            """
            
            # Use the new OpenAI client API
            client = openai.OpenAI(api_key=app.config['OPENAI_API_KEY'])
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=500,
                temperature=0.3
            )
            
            ai_summary = response.choices[0].message.content
            
            return {
                "summary": ai_summary,
                "detailed_analysis": ai_summary,
                "recommendations": self._extract_recommendations(ai_summary)
            }
            
        except Exception as e:
            logger.error(f"OpenAI API error: {str(e)}")
            return self._generate_rule_based_summary(indicator, context)
    
    def _generate_rule_based_summary(self, indicator: ThreatIndicator, 
                                   context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate rule-based threat summary when AI is not available"""
        
        malicious_count = len(context["malicious_indicators"])
        avg_confidence = sum(context["confidence_scores"]) / len(context["confidence_scores"]) if context["confidence_scores"] else 0
        
        # Determine risk level
        if malicious_count >= 2 or avg_confidence >= 70:
            risk_level = "High"
        elif malicious_count >= 1 or avg_confidence >= 30:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        # Generate threat types
        threat_types = context["threat_types"] if context["threat_types"] else ["Unknown"]
        
        # Generate summary
        if risk_level == "High":
            summary = f"This {indicator.indicator_type} has been flagged as malicious by {malicious_count} sources with high confidence. It has been associated with {', '.join(threat_types[:3])} activities."
        elif risk_level == "Medium":
            summary = f"This {indicator.indicator_type} shows suspicious activity with moderate confidence. It may be involved in {', '.join(threat_types[:2])} activities."
        else:
            summary = f"This {indicator.indicator_type} shows minimal or no malicious activity in our threat intelligence sources."
        
        # Generate recommendations
        recommendations = []
        if risk_level == "High":
            recommendations.extend([
                "Block this indicator immediately",
                "Investigate any systems that have communicated with this indicator",
                "Monitor for related indicators"
            ])
        elif risk_level == "Medium":
            recommendations.extend([
                "Monitor this indicator closely",
                "Consider blocking if it appears in your environment",
                "Investigate if suspicious activity is observed"
            ])
        else:
            recommendations.extend([
                "Continue normal monitoring",
                "No immediate action required"
            ])
        
        return {
            "summary": summary,
            "detailed_analysis": f"Analysis based on {malicious_count} threat intelligence sources. Average confidence: {avg_confidence:.1f}%",
            "recommendations": recommendations
        }
    
    def _extract_recommendations(self, ai_summary: str) -> List[str]:
        """Extract recommendations from AI summary"""
        # Simple extraction - in a real implementation, you'd use more sophisticated NLP
        recommendations = []
        if "block" in ai_summary.lower():
            recommendations.append("Consider blocking this indicator")
        if "monitor" in ai_summary.lower():
            recommendations.append("Monitor for suspicious activity")
        if "investigate" in ai_summary.lower():
            recommendations.append("Investigate further")
        
        return recommendations if recommendations else ["Review the analysis and take appropriate action"]

class RiskAssessmentModel:
    """Machine Learning model for risk assessment"""
    
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.load_or_train_model()
    
    def load_or_train_model(self):
        """Load existing model or train a new one"""
        model_path = os.path.join(app.config.get('MODEL_PATH', 'models/'), 
                                 app.config.get('RISK_MODEL_FILE', 'risk_assessment_model.pkl'))
        vectorizer_path = os.path.join(app.config.get('MODEL_PATH', 'models/'), 
                                      app.config.get('VECTORIZER_FILE', 'vectorizer.pkl'))
        
        try:
            if os.path.exists(model_path) and os.path.exists(vectorizer_path):
                self.model = joblib.load(model_path)
                self.vectorizer = joblib.load(vectorizer_path)
                logger.info("Loaded existing risk assessment model")
            else:
                self._train_model()
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            self._train_model()
    
    def _train_model(self):
        """Train a simple risk assessment model"""
        # Get model paths
        model_path = os.path.join(app.config.get('MODEL_PATH', 'models/'), 
                                 app.config.get('RISK_MODEL_FILE', 'risk_assessment_model.pkl'))
        vectorizer_path = os.path.join(app.config.get('MODEL_PATH', 'models/'), 
                                      app.config.get('VECTORIZER_FILE', 'vectorizer.pkl'))
        
        # Sample training data - in production, you'd use real threat intelligence data
        training_data = [
            ("malware distribution botnet command control", "High"),
            ("brute force ssh rdp attacks", "High"),
            ("phishing spam email campaigns", "Medium"),
            ("suspicious network activity", "Medium"),
            ("legitimate business website", "Low"),
            ("cdn content delivery network", "Low"),
            ("tor exit node proxy", "Medium"),
            ("cryptocurrency mining pool", "Low"),
            ("ransomware distribution", "High"),
            ("data exfiltration", "High")
        ]
        
        texts = [item[0] for item in training_data]
        labels = [item[1] for item in training_data]
        
        # Convert labels to numeric
        label_map = {"Low": 0, "Medium": 1, "High": 2}
        numeric_labels = [label_map[label] for label in labels]
        
        # Vectorize text
        self.vectorizer = TfidfVectorizer(max_features=100, stop_words='english')
        X = self.vectorizer.fit_transform(texts)
        
        # Train model
        self.model = RandomForestClassifier(n_estimators=10, random_state=42)
        self.model.fit(X, numeric_labels)
        
        # Save model
        os.makedirs(app.config.get('MODEL_PATH', 'models/'), exist_ok=True)
        joblib.dump(self.model, model_path)
        joblib.dump(self.vectorizer, vectorizer_path)
        
        logger.info("Trained new risk assessment model")
    
    def assess_risk(self, threat_context: Dict[str, Any]) -> tuple:
        """Assess risk level and score"""
        if not self.model or not self.vectorizer:
            return "Medium", 0.5
        
        # Create feature text from context
        feature_text = " ".join([
            " ".join(threat_context.get("threat_types", [])),
            " ".join(threat_context.get("malicious_indicators", [])),
            str(threat_context.get("confidence_scores", [0]))
        ])
        
        # Clean up the feature text and check if it's meaningful
        feature_text = feature_text.strip()
        # If feature text is empty or just contains brackets/spaces, treat as low risk
        if not feature_text or feature_text in ['[]', '  []', '[]  ', '  []  ']:
            return "Low", 0.1
        
        # Vectorize and predict
        X = self.vectorizer.transform([feature_text])
        prediction = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]
        
        # Convert back to label
        label_map = {0: "Low", 1: "Medium", 2: "High"}
        risk_level = label_map[prediction]
        risk_score = probabilities[prediction]
        
        return risk_level, risk_score

class ThreatAnalysisEngine:
    """Main threat analysis engine that orchestrates all components"""
    
    def __init__(self):
        # Initialize the API handler for threat intelligence sources
        self.api = ThreatIntelligenceAPI()
        # Initialize the RAG system for AI-powered analysis
        self.rag = RAGSystem()
        # Initialize the machine learning risk assessment model
        self.risk_model = RiskAssessmentModel()
        # Initialize the file storage system for saving threat data
        self.storage = ThreatDataStorage()
    
    def analyze_indicator(self, indicator_value: str) -> ThreatReport:
        """Analyze a threat indicator and return comprehensive report"""
        
        # Validate the input and determine if it's an IP, domain, or hash
        indicator = self._validate_indicator(indicator_value)
        if not indicator:
            # Raise error if the input is not a valid threat indicator
            raise ValueError(f"Invalid indicator: {indicator_value}")
        
        # Try to load any existing data for this indicator from our local files
        existing_data = self.storage.load_threat_data(indicator)
        
        # Gather fresh data from threat intelligence APIs (AlienVault, AbuseIPDB)
        raw_data = self._gather_threat_data(indicator)
        
        # If we have historical data, merge it with the new data
        if existing_data:
            # Get the historical raw data from the file
            historical_data = existing_data.get("raw_data", [])
            # Merge historical and new data, avoiding duplicates
            raw_data = self.storage._merge_threat_data(historical_data, raw_data)
            # Log that we found and merged existing data
            logger.info(f"Found existing data for {indicator.value}, merged with new data")
        
        # Extract threat context from the combined data
        threat_context = self.rag._extract_threat_context(raw_data)
        
        # Assess risk level using rule-based approach first
        risk_level, risk_score = self._assess_risk_rule_based(raw_data, threat_context)
        # If rule-based assessment fails, use machine learning model
        if risk_level is None:
            risk_level, risk_score = self.risk_model.assess_risk(threat_context)
        
        # Use AI to synthesize the threat intelligence into a summary
        synthesis = self.rag.synthesize_threat_intelligence(indicator, raw_data)
        
        # Create a comprehensive threat report with all the information
        report = ThreatReport(
            indicator=indicator,  # The threat indicator being analyzed
            risk_level=risk_level,  # High, Medium, or Low risk
            risk_score=risk_score,  # Numerical risk score
            threat_types=threat_context.get("threat_types", ["Unknown"]),  # Types of threats detected
            summary=synthesis["summary"],  # AI-generated summary
            detailed_analysis=synthesis["detailed_analysis"],  # Detailed AI analysis
            recommendations=synthesis["recommendations"],  # AI-generated recommendations
            source_links=threat_context.get("source_reports", []),  # Links to source reports
            analysis_timestamp=datetime.now().isoformat(),  # When this analysis was performed
            # Calculate average confidence from all sources
            confidence=sum(threat_context.get("confidence_scores", [0])) / len(threat_context.get("confidence_scores", [0])) if threat_context.get("confidence_scores") else 0
        )
        
        # Save all the data to a local file for future reference
        self.storage.save_threat_data(indicator, raw_data, report)
        
        # Return the complete threat report
        return report

    def _assess_risk_rule_based(self, raw_data: List[Dict[str, Any]], threat_context: Dict[str, Any]) -> tuple:
        """Assess risk using clear, deterministic thresholds from feed responses.

        Returns (risk_level, risk_score) or (None, None) if there is no usable signal.
        """
        if not raw_data:
            return None, None

        max_abuse_confidence = None
        total_pulse_count = 0
        any_feed_present = False

        for entry in raw_data:
            if not isinstance(entry, dict):
                continue
            if "error" in entry:
                continue

            source = entry.get("source")
            if source:
                any_feed_present = True

            # AbuseIPDB confidence
            if source == "AbuseIPDB" and isinstance(entry.get("confidence"), (int, float)):
                conf = float(entry.get("confidence", 0))
                max_abuse_confidence = conf if max_abuse_confidence is None else max(max_abuse_confidence, conf)

            # OTX pulse count
            if source == "AlienVault OTX" and isinstance(entry.get("pulse_count"), (int, float)):
                total_pulse_count += int(entry.get("pulse_count", 0))

        if not any_feed_present:
            return None, None

        # Determine risk level from thresholds
        # High if strong signal from either feed
        if (max_abuse_confidence is not None and max_abuse_confidence >= 70) or (total_pulse_count >= 5):
            return "High", 0.9 if max_abuse_confidence and max_abuse_confidence >= 90 else 0.75

        # Medium for moderate signals
        if (max_abuse_confidence is not None and max_abuse_confidence >= 30) or (total_pulse_count >= 1):
            # scale score between 0.4 and 0.7
            base = 0.5
            if max_abuse_confidence is not None:
                base = max(base, 0.3 + (max_abuse_confidence/100) * 0.4)
            if total_pulse_count:
                base = max(base, 0.45 + min(total_pulse_count, 5) * 0.05)
            return "Medium", min(base, 0.7)

        # Otherwise Low
        return "Low", 0.15
    
    def _validate_indicator(self, value: str) -> Optional[ThreatIndicator]:
        """Validate and determine the type of threat indicator"""
        value = value.strip()
        
        # Check if it's an IP address
        try:
            ipaddress.ip_address(value)
            return ThreatIndicator(value=value, indicator_type="ip")
        except ValueError:
            pass
        
        # Check if it's a domain
        if self._is_valid_domain(value):
            return ThreatIndicator(value=value, indicator_type="domain")
        
        # Check if it's a hash (MD5, SHA1, SHA256)
        if self._is_valid_hash(value):
            return ThreatIndicator(value=value, indicator_type="hash")
        
        return None
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Check if string is a valid domain"""
        try:
            result = urlparse(f"http://{domain}")
            return all([result.scheme, result.netloc]) and '.' in domain
        except:
            return False
    
    def _is_valid_hash(self, hash_value: str) -> bool:
        """Check if string is a valid hash"""
        hash_value = hash_value.lower()
        return (len(hash_value) in [32, 40, 64] and 
                all(c in '0123456789abcdef' for c in hash_value))
    
    def _gather_threat_data(self, indicator: ThreatIndicator) -> List[Dict[str, Any]]:
        """Gather threat data from all available sources"""
        raw_data = []
        
        if indicator.indicator_type == "ip":
            raw_data.append(self.api.check_ip_alienvault(indicator.value))
            raw_data.append(self.api.check_ip_abuseipdb(indicator.value))
        elif indicator.indicator_type == "domain":
            raw_data.append(self.api.check_domain_alienvault(indicator.value))
        elif indicator.indicator_type == "hash":
            raw_data.append(self.api.check_hash_alienvault(indicator.value))
        
        return raw_data

# Initialize the analysis engine
analysis_engine = ThreatAnalysisEngine()

# Global variable to store current analysis results for chatbot context
current_analysis_results = None

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze a threat indicator"""
    global current_analysis_results
    try:
        data = request.get_json()
        indicator_value = data.get('indicator', '').strip()
        
        if not indicator_value:
            return jsonify({'error': 'No indicator provided'}), 400
        
        # Analyze the indicator
        report = analysis_engine.analyze_indicator(indicator_value)
        
        # Convert to JSON-serializable format
        report_dict = asdict(report)
        
        # Store results for chatbot context
        current_analysis_results = report_dict
        
        return jsonify({
            'success': True,
            'report': report_dict
        })
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Analysis error: {str(e)}")
        return jsonify({'error': 'Analysis failed. Please try again.'}), 500

@app.route('/chat', methods=['POST'])
def chat():
    """Handle chatbot messages"""
    global current_analysis_results
    try:
        data = request.get_json()
        message = data.get('message', '').strip()
        
        if not message:
            return jsonify({'error': 'No message provided'}), 400
        
        # Generate response based on current analysis results
        response = generate_chat_response(message, current_analysis_results)
        
        return jsonify({
            'success': True,
            'response': response
        })
        
    except Exception as e:
        logger.error(f"Chat error: {str(e)}")
        return jsonify({'error': 'Chat failed. Please try again.'}), 500

def generate_chat_response(message: str, analysis_results: Optional[Dict[str, Any]]) -> str:
    """Generate contextual chat response using LLM when available, fallback to rule-based"""
    
    # Check if OpenAI API key is available
    openai_key = app.config.get('OPENAI_API_KEY', '')
    logger.info(f"OpenAI API key available: {bool(openai_key and openai_key.strip())}")
    
    # Try to use LLM first if available
    if openai_key and openai_key.strip():
        try:
            logger.info("Attempting to use LLM for chat response")
            response = generate_llm_chat_response(message, analysis_results)
            logger.info("LLM response generated successfully")
            return response
        except Exception as e:
            logger.error(f"LLM chat error: {str(e)}")
            logger.info("Falling back to rule-based response")
            # Fall back to rule-based response
    else:
        logger.info("No OpenAI API key available, using rule-based response")
    
    # Fallback to rule-based responses
    return generate_rule_based_chat_response(message, analysis_results)

def generate_llm_chat_response(message: str, analysis_results: Optional[Dict[str, Any]]) -> str:
    """Generate intelligent chat response using OpenAI LLM"""
    
    # Ensure OpenAI API key is set
    openai_key = app.config.get('OPENAI_API_KEY', '')
    if openai_key:
        openai.api_key = openai_key
    
    # Determine if this is a cybersecurity-related question
    cybersecurity_keywords = [
        'threat', 'security', 'cyber', 'malware', 'virus', 'hack', 'attack', 'breach',
        'firewall', 'vulnerability', 'exploit', 'phishing', 'ransomware', 'botnet',
        'ip', 'domain', 'hash', 'indicator', 'risk', 'analysis', 'intelligence',
        'network', 'system', 'data', 'privacy', 'encryption', 'password', 'auth',
        'app', 'application', 'platform', 'tool', 'what does', 'what is this'
    ]
    
    message_lower = message.lower()
    is_cybersecurity_question = any(keyword in message_lower for keyword in cybersecurity_keywords)
    
    # Create system prompt based on question type
    if is_cybersecurity_question or analysis_results:
        system_prompt = """You are an AI assistant integrated into a Threat Intelligence Analysis platform. You specialize in cybersecurity and threat intelligence analysis, but can also answer general questions. You help users understand threat analysis results, provide cybersecurity guidance, and assist with various topics. Be conversational, professional, and concise (2-4 sentences max)."""
    else:
        system_prompt = """You are an AI assistant integrated into a Threat Intelligence Analysis platform. While you can answer general questions on many topics, you are primarily designed to help with cybersecurity and threat intelligence analysis. You can analyze IP addresses, domains, and file hashes for threats. Be conversational, informative, and concise (2-4 sentences max). When users ask about the app, explain that this is a threat intelligence platform for analyzing potential security threats."""
    
    # Create context based on whether analysis results are available
    if analysis_results:
        # Extract analysis data
        indicator = analysis_results.get('indicator', {})
        risk_level = analysis_results.get('risk_level', 'Unknown')
        risk_score = analysis_results.get('risk_score', 0)
        threat_types = analysis_results.get('threat_types', [])
        summary = analysis_results.get('summary', '')
        detailed_analysis = analysis_results.get('detailed_analysis', '')
        recommendations = analysis_results.get('recommendations', [])
        confidence = analysis_results.get('confidence', 0)
        source_links = analysis_results.get('source_links', [])
        
        context = f"""
        Current Threat Analysis Results:
        - Indicator: {indicator.get('value', 'N/A')} ({indicator.get('indicator_type', 'unknown').upper()})
        - Risk Level: {risk_level}
        - Risk Score: {risk_score:.2f} ({int(risk_score * 100)}%)
        - Threat Types: {', '.join(threat_types) if threat_types else 'None identified'}
        - Summary: {summary}
        - Detailed Analysis: {detailed_analysis}
        - Recommendations: {'; '.join(recommendations) if recommendations else 'None provided'}
        - Confidence: {confidence:.2f} ({int(confidence * 100)}%)
        - Sources: {len(source_links)} threat intelligence sources consulted
        
        User Question: "{message}"
        
        Instructions:
        1. If the question relates to the analysis results, use that data
        2. If it's a general cybersecurity question, provide expert guidance
        3. If it's a non-cybersecurity question, answer helpfully
        4. Be conversational and educational
        """
    else:
        # No analysis results - handle any type of question
        context = f"""
        User Question: "{message}"
        
        Context: You are integrated into a Threat Intelligence Analysis platform that helps users analyze IP addresses, domains, and file hashes for potential security threats. The platform uses multiple threat intelligence sources and AI-powered analysis.
        
        Instructions:
        1. If asked about the app/platform, explain it's a threat intelligence analysis tool
        2. If it's about cybersecurity, provide expert guidance
        3. If it's about threat analysis, guide them to use the main interface to analyze indicators
        4. For other topics, provide general helpful information
        5. Be conversational and informative
        6. Always remember you're part of a threat intelligence platform
        """
    
    try:
        logger.info(f"Sending request to OpenAI with message: {message[:50]}...")
        
        # Use the new OpenAI client API
        client = openai.OpenAI(api_key=openai_key)
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": context}
            ],
            max_tokens=300,
            temperature=0.7
        )
        
        result = response.choices[0].message.content.strip()
        logger.info(f"OpenAI response received: {result[:50]}...")
        return result
        
    except Exception as e:
        logger.error(f"OpenAI API error in chat: {str(e)}")
        logger.error(f"Error type: {type(e).__name__}")
        raise e

def generate_rule_based_chat_response(message: str, analysis_results: Optional[Dict[str, Any]]) -> str:
    """Generate rule-based chat response as fallback"""
    
    message_lower = message.lower()
    
    # If no analysis results available
    if not analysis_results:
        # Greeting responses
        if any(word in message_lower for word in ['hello', 'hi', 'hey', 'good morning', 'good afternoon', 'good evening']):
            return "Hello! I'm your AI assistant. I can help with threat intelligence analysis and answer general questions. Try analyzing a threat indicator or ask me anything!"
        
        # Threat analysis related
        elif any(word in message_lower for word in ['analyze', 'check', 'threat', 'indicator', 'ip', 'domain', 'hash']):
            return "I'd be happy to help you analyze a threat indicator! Please enter an IP address, domain, or file hash in the main interface to get started."
        
        # Cybersecurity questions
        elif any(word in message_lower for word in ['security', 'cyber', 'malware', 'virus', 'hack', 'attack', 'breach', 'firewall']):
            return "I can help with cybersecurity questions! For threat analysis, use the main interface. For general security advice, I can provide guidance based on best practices."
        
        # General knowledge questions
        elif any(word in message_lower for word in ['what is', 'what are', 'how does', 'how do', 'why is', 'why are', 'explain', 'tell me about']):
            return "I'd be happy to explain that! However, I'm currently running in a limited mode. For detailed explanations and general knowledge questions, please ensure you have an OpenAI API key configured in your .env file to enable full AI capabilities."
        
        # Weather, time, etc.
        elif any(word in message_lower for word in ['weather', 'time', 'date', 'temperature']):
            return "I can help with general questions, but for real-time information like weather or current time, you might want to check a dedicated service. Is there anything else I can help you with?"
        
        # Questions starting with what, how, why, etc.
        elif any(word in message_lower for word in ['what', 'how', 'why', 'when', 'where', 'who']):
            return "I'm here to help! I can answer questions about threat intelligence, cybersecurity, and general topics. For detailed explanations, please ensure you have an OpenAI API key configured to enable full AI capabilities."
        
        # Default response
        else:
            return "I'm here to help! I can assist with threat intelligence analysis, cybersecurity questions, and general topics. For comprehensive answers, please ensure you have an OpenAI API key configured in your .env file."
    
    # Context-aware responses based on analysis results
    indicator = analysis_results.get('indicator', {})
    risk_level = analysis_results.get('risk_level', 'Unknown')
    risk_score = analysis_results.get('risk_score', 0)
    threat_types = analysis_results.get('threat_types', [])
    summary = analysis_results.get('summary', '')
    recommendations = analysis_results.get('recommendations', [])
    
    # Risk level questions
    if any(word in message_lower for word in ['risk', 'dangerous', 'safe', 'threat']):
        risk_percentage = int(risk_score * 100)
        if risk_level == 'High':
            return f"The {indicator.get('indicator_type', 'indicator')} {indicator.get('value', '')} has a HIGH risk level with a {risk_percentage}% risk score. This indicates significant threat activity and should be treated with caution."
        elif risk_level == 'Medium':
            return f"The {indicator.get('indicator_type', 'indicator')} {indicator.get('value', '')} has a MEDIUM risk level with a {risk_percentage}% risk score. It shows some suspicious activity and should be monitored closely."
        else:
            return f"The {indicator.get('indicator_type', 'indicator')} {indicator.get('value', '')} has a LOW risk level with a {risk_percentage}% risk score. It appears to be relatively safe based on current threat intelligence."
    
    # Threat types questions
    if any(word in message_lower for word in ['type', 'kind', 'category', 'malware', 'attack']):
        if threat_types and threat_types != ['Unknown']:
            threat_list = ', '.join(threat_types[:3])  # Show top 3
            return f"This indicator has been associated with the following threat types: {threat_list}. This information comes from threat intelligence feeds and security research."
        else:
            return "No specific threat types have been identified for this indicator, or the threat type information is not available in our current data sources."
    
    # Recommendations questions
    if any(word in message_lower for word in ['recommend', 'should', 'action', 'do', 'next']):
        if recommendations:
            rec_list = '; '.join(recommendations[:3])  # Show top 3
            return f"Based on the analysis, here are the key recommendations: {rec_list}"
        else:
            return "Based on the risk assessment, I recommend monitoring this indicator and taking appropriate security measures based on your organization's policies."
    
    # Summary questions
    if any(word in message_lower for word in ['summary', 'overview', 'explain', 'what', 'tell me']):
        return f"Here's the analysis summary: {summary}"
    
    # General questions about the indicator
    if any(word in message_lower for word in ['indicator', 'ip', 'domain', 'hash', 'address']):
        return f"I analyzed the {indicator.get('indicator_type', 'indicator')} '{indicator.get('value', '')}' and found it has a {risk_level} risk level. {summary}"
    
    # Default response
    return f"I can help you understand the analysis results for {indicator.get('value', 'the current indicator')}. You can ask me about the risk level, threat types, recommendations, or request a summary. What would you like to know?"

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

@app.route('/debug/chat-config')
def debug_chat_config():
    """Debug endpoint to check chat configuration"""
    openai_key = app.config.get('OPENAI_API_KEY', '')
    return jsonify({
        'openai_key_configured': bool(openai_key and openai_key.strip()),
        'openai_key_length': len(openai_key) if openai_key else 0,
        'openai_key_prefix': openai_key[:10] + '...' if openai_key and len(openai_key) > 10 else openai_key,
        'config_source': 'environment' if openai_key else 'not_found'
    })

@app.route('/debug/test-llm')
def debug_test_llm():
    """Debug endpoint to test LLM functionality"""
    try:
        openai_key = app.config.get('OPENAI_API_KEY', '')
        if not openai_key or not openai_key.strip():
            return jsonify({'error': 'No OpenAI API key configured'})
        
        # Test simple LLM call with new API
        client = openai.OpenAI(api_key=openai_key)
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Say hello in one sentence."}
            ],
            max_tokens=50,
            temperature=0.7
        )
        
        return jsonify({
            'success': True,
            'response': response.choices[0].message.content.strip(),
            'model': 'gpt-3.5-turbo'
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'error_type': type(e).__name__
        })

@app.route('/stored-data')
def get_stored_data():
    """Get stored threat analysis data"""
    try:
        # Initialize storage to get the data
        storage = ThreatDataStorage()
        data_file = storage.data_file
        
        if not os.path.exists(data_file):
            return jsonify({'error': 'No stored analysis data found'})
        
        with open(data_file, 'r') as f:
            data = json.load(f)
        
        return jsonify({
            'success': True,
            'data': data
        })
        
    except Exception as e:
        logger.error(f"Error loading stored data: {str(e)}")
        return jsonify({'error': 'Failed to load stored data'}), 500

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    os.makedirs('models', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    
    # Initialize the analysis engine
    try:
        analysis_engine = ThreatAnalysisEngine()
        logger.info("Threat Intelligence Assistant initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize analysis engine: {str(e)}")
        analysis_engine = None
    
    # Run the application
    port = int(os.environ.get('PORT', 5000))
    debug = app.config.get('DEBUG', False)
    
    logger.info(f"Starting Threat Intelligence Assistant on port {port}")
    app.run(debug=debug, host='0.0.0.0', port=port)
