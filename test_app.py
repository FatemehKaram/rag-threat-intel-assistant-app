#!/usr/bin/env python3
"""
Simple test script for the Threat Intelligence Assistant
"""
import requests
import json
import time
import sys

def test_health_endpoint():
    """Test the health endpoint"""
    try:
        response = requests.get('http://localhost:5000/health', timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Health check passed: {data['status']}")
            return True
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health check error: {str(e)}")
        return False

def test_analysis_endpoint():
    """Test the analysis endpoint with a safe IP"""
    try:
        # Test with Google's DNS server (should be safe)
        test_data = {"indicator": "8.8.8.8"}
        response = requests.post(
            'http://localhost:5000/analyze',
            json=test_data,
            headers={'Content-Type': 'application/json'},
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                report = data['report']
                print(f"✅ Analysis test passed")
                print(f"   Indicator: {report['indicator']['value']}")
                print(f"   Type: {report['indicator']['indicator_type']}")
                print(f"   Risk Level: {report['risk_level']}")
                print(f"   Risk Score: {report['risk_score']:.2f}")
                return True
            else:
                print(f"❌ Analysis failed: {data.get('error', 'Unknown error')}")
                return False
        else:
            print(f"❌ Analysis request failed: {response.status_code}")
            try:
                error_data = response.json()
                print(f"   Error: {error_data.get('error', 'Unknown error')}")
            except:
                print(f"   Response: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Analysis test error: {str(e)}")
        return False

def test_invalid_indicator():
    """Test with an invalid indicator"""
    try:
        test_data = {"indicator": "invalid-indicator"}
        response = requests.post(
            'http://localhost:5000/analyze',
            json=test_data,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        if response.status_code == 400:
            print("✅ Invalid indicator test passed (correctly rejected)")
            return True
        else:
            print(f"❌ Invalid indicator test failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Invalid indicator test error: {str(e)}")
        return False

def main():
    """Run all tests"""
    print("🧪 Testing Threat Intelligence Assistant")
    print("=" * 50)
    
    # Wait a moment for the server to start
    print("⏳ Waiting for server to start...")
    time.sleep(2)
    
    tests = [
        ("Health Endpoint", test_health_endpoint),
        ("Analysis Endpoint", test_analysis_endpoint),
        ("Invalid Indicator", test_invalid_indicator)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n🔍 Testing {test_name}...")
        if test_func():
            passed += 1
        time.sleep(1)  # Brief pause between tests
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The application is working correctly.")
        return 0
    else:
        print("⚠️  Some tests failed. Please check the application configuration.")
        return 1

if __name__ == "__main__":
    sys.exit(main())



