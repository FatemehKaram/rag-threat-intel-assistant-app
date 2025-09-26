from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
import requests
from dataclasses import dataclass, asdict
import re
import hashlib
import ipaddress
from urllib.parse import urlparse
import openai
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib
import numpy as np
from config import config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Load configuration
config_name = os.environ.get('FLASK_ENV', 'development')
app.config.from_object(config[config_name])

@dataclass
class ThreatIndicator:
    """Represents a threat indicator (IP, domain, or hash)"""
    value: str
    indicator_type: str  # 'ip', 'domain', 'hash'
    confidence: float = 0.0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    sources: List[str] = None
    
    def __post_init__(self):
        if self.sources is None:
            self.sources = []

@dataclass
class ThreatReport:
    """Represents a comprehensive threat analysis report"""
    indicator: ThreatIndicator
    risk_level: str  # 'Low', 'Medium', 'High'
    risk_score: float  # 0.0 to 1.0
    threat_types: List[str]
    summary: str
    detailed_analysis: str
    recommendations: List[str]
    source_links: List[Dict[str, str]]
    analysis_timestamp: str
    confidence: float

class ThreatIntelligenceAPI:
    """Handles API calls to various threat intelligence sources"""
    
    def __init__(self):
        self.alienvault_base = "https://otx.alienvault.com/api/v1"
        self.abuseipdb_base = "https://api.abuseipdb.com/api/v2"
        
    def check_ip_alienvault(self, ip_address: str) -> Dict[str, Any]:
        """Check IP address against AlienVault OTX"""
        try:
            if not app.config['ALIENVAULT_API_KEY']:
                return {"source": "AlienVault OTX", "malicious": False, "pulse_count": 0, "pulses": [], "url": f"https://otx.alienvault.com/indicator/ip/{ip_address}", "note": "API key not configured"}
                
            headers = {'X-OTX-API-KEY': app.config['ALIENVAULT_API_KEY']}
            url = f"{self.alienvault_base}/indicators/IPv4/{ip_address}/general"
            
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            return {
                "source": "AlienVault OTX",
                "malicious": data.get('pulse_info', {}).get('count', 0) > 0,
                "pulse_count": data.get('pulse_info', {}).get('count', 0),
                "pulses": data.get('pulse_info', {}).get('pulses', []),
                "url": f"https://otx.alienvault.com/indicator/ip/{ip_address}"
            }
        except Exception as e:
            logger.error(f"AlienVault API error for {ip_address}: {str(e)}")
            return {"error": str(e)}
    
    def check_ip_abuseipdb(self, ip_address: str) -> Dict[str, Any]:
        """Check IP address against AbuseIPDB"""
        try:
            if not app.config['ABUSEIPDB_API_KEY']:
                return {"source": "AbuseIPDB", "malicious": False, "confidence": 0, "usage_type": "Unknown", "country": "Unknown", "isp": "Unknown", "reports": 0, "url": f"https://www.abuseipdb.com/check/{ip_address}", "note": "API key not configured"}
                
            headers = {'Key': app.config['ABUSEIPDB_API_KEY'], 'Accept': 'application/json'}
            params = {'ipAddress': ip_address, 'maxAgeInDays': 90, 'verbose': ''}
            
            response = requests.get(f"{self.abuseipdb_base}/check", 
                                  headers=headers, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            result = data.get('data', {})
            
            return {
                "source": "AbuseIPDB",
                "malicious": result.get('abuseConfidencePercentage', 0) > 0,
                "confidence": result.get('abuseConfidencePercentage', 0),
                "usage_type": result.get('usageType', 'Unknown'),
                "country": result.get('countryCode', 'Unknown'),
                "isp": result.get('isp', 'Unknown'),
                "reports": result.get('totalReports', 0),
                "url": f"https://www.abuseipdb.com/check/{ip_address}"
            }
        except Exception as e:
            logger.error(f"AbuseIPDB API error for {ip_address}: {str(e)}")
            return {"error": str(e)}
    
    def check_domain_alienvault(self, domain: str) -> Dict[str, Any]:
        """Check domain against AlienVault OTX"""
        try:
            if not app.config['ALIENVAULT_API_KEY']:
                return {"source": "AlienVault OTX", "malicious": False, "pulse_count": 0, "pulses": [], "url": f"https://otx.alienvault.com/indicator/domain/{domain}", "note": "API key not configured"}
                
            headers = {'X-OTX-API-KEY': app.config['ALIENVAULT_API_KEY']}
            url = f"{self.alienvault_base}/indicators/domain/{domain}/general"
            
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            return {
                "source": "AlienVault OTX",
                "malicious": data.get('pulse_info', {}).get('count', 0) > 0,
                "pulse_count": data.get('pulse_info', {}).get('count', 0),
                "pulses": data.get('pulse_info', {}).get('pulses', []),
                "url": f"https://otx.alienvault.com/indicator/domain/{domain}"
            }
        except Exception as e:
            logger.error(f"AlienVault domain API error for {domain}: {str(e)}")
            return {"error": str(e)}
    
    def check_hash_alienvault(self, file_hash: str) -> Dict[str, Any]:
        """Check file hash against AlienVault OTX"""
        try:
            if not app.config['ALIENVAULT_API_KEY']:
                return {"source": "AlienVault OTX", "malicious": False, "pulse_count": 0, "pulses": [], "url": f"https://otx.alienvault.com/indicator/file/{file_hash}", "note": "API key not configured"}
                
            headers = {'X-OTX-API-KEY': app.config['ALIENVAULT_API_KEY']}
            url = f"{self.alienvault_base}/indicators/file/{file_hash}/general"
            
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            return {
                "source": "AlienVault OTX",
                "malicious": data.get('pulse_info', {}).get('count', 0) > 0,
                "pulse_count": data.get('pulse_info', {}).get('count', 0),
                "pulses": data.get('pulse_info', {}).get('pulses', []),
                "url": f"https://otx.alienvault.com/indicator/file/{file_hash}"
            }
        except Exception as e:
            logger.error(f"AlienVault hash API error for {file_hash}: {str(e)}")
            return {"error": str(e)}

class RAGSystem:
    """Retrieval-Augmented Generation system for threat intelligence synthesis"""
    
    def __init__(self):
        self.openai_client = None
        if app.config['OPENAI_API_KEY']:
            openai.api_key = app.config['OPENAI_API_KEY']
            self.openai_client = openai
    
    def synthesize_threat_intelligence(self, indicator: ThreatIndicator, 
                                     raw_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Synthesize threat intelligence using RAG approach"""
        
        # Extract relevant information from raw data
        threat_context = self._extract_threat_context(raw_data)
        
        # Generate summary using OpenAI if available, otherwise use rule-based approach
        if self.openai_client:
            return self._generate_ai_summary(indicator, threat_context)
        else:
            return self._generate_rule_based_summary(indicator, threat_context)
    
    def _extract_threat_context(self, raw_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract relevant threat context from raw API data"""
        context = {
            "malicious_indicators": [],
            "threat_types": set(),
            "confidence_scores": [],
            "source_reports": [],
            "geographic_info": [],
            "temporal_info": []
        }
        
        for data in raw_data:
            if "error" in data:
                continue
                
            # Skip data with notes about missing API keys
            if "note" in data and "API key not configured" in data["note"]:
                continue
                
            source = data.get("source", "Unknown")
            
            if data.get("malicious", False):
                context["malicious_indicators"].append(source)
                
            if "pulse_count" in data and data["pulse_count"] > 0:
                context["confidence_scores"].append(min(data["pulse_count"] * 10, 100))
                
            if "confidence" in data:
                context["confidence_scores"].append(data["confidence"])
                
            if "pulses" in data:
                for pulse in data["pulses"]:
                    if "tags" in pulse:
                        context["threat_types"].update(pulse["tags"])
                        
            if "country" in data:
                context["geographic_info"].append(data["country"])
                
            if "url" in data:
                context["source_reports"].append({
                    "source": source,
                    "url": data["url"]
                })
        
        context["threat_types"] = list(context["threat_types"])
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
            
            response = self.openai_client.ChatCompletion.create(
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
        self.api = ThreatIntelligenceAPI()
        self.rag = RAGSystem()
        self.risk_model = RiskAssessmentModel()
    
    def analyze_indicator(self, indicator_value: str) -> ThreatReport:
        """Analyze a threat indicator and return comprehensive report"""
        
        # Validate and determine indicator type
        indicator = self._validate_indicator(indicator_value)
        if not indicator:
            raise ValueError(f"Invalid indicator: {indicator_value}")
        
        # Gather raw data from APIs
        raw_data = self._gather_threat_data(indicator)
        
        # Extract threat context
        threat_context = self.rag._extract_threat_context(raw_data)
        
        # Assess risk - prefer rule-based using live API data; fallback to ML if no signal
        risk_level, risk_score = self._assess_risk_rule_based(raw_data, threat_context)
        if risk_level is None:
            risk_level, risk_score = self.risk_model.assess_risk(threat_context)
        
        # Synthesize intelligence
        synthesis = self.rag.synthesize_threat_intelligence(indicator, raw_data)
        
        # Create comprehensive report
        report = ThreatReport(
            indicator=indicator,
            risk_level=risk_level,
            risk_score=risk_score,
            threat_types=threat_context.get("threat_types", ["Unknown"]),
            summary=synthesis["summary"],
            detailed_analysis=synthesis["detailed_analysis"],
            recommendations=synthesis["recommendations"],
            source_links=threat_context.get("source_reports", []),
            analysis_timestamp=datetime.now().isoformat(),
            confidence=sum(threat_context.get("confidence_scores", [0])) / len(threat_context.get("confidence_scores", [0])) if threat_context.get("confidence_scores") else 0
        )
        
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

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze a threat indicator"""
    try:
        data = request.get_json()
        indicator_value = data.get('indicator', '').strip()
        
        if not indicator_value:
            return jsonify({'error': 'No indicator provided'}), 400
        
        # Analyze the indicator
        report = analysis_engine.analyze_indicator(indicator_value)
        
        # Convert to JSON-serializable format
        report_dict = asdict(report)
        
        return jsonify({
            'success': True,
            'report': report_dict
        })
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Analysis error: {str(e)}")
        return jsonify({'error': 'Analysis failed. Please try again.'}), 500

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

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
