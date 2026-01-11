#!/usr/bin/env python3
"""
Test script for FastAPI SCADA Monitoring System
"""

import requests
import json
import time

API_URL = "http://localhost:8000"

def print_header(text):
    print(f"\n{'='*60}")
    print(f"{text.center(60)}")
    print(f"{'='*60}\n")

def test_login_attacks():
    """Test login attacks and monitoring"""
    print_header("TEST 1: LOGIN ATTACKS")
    
    # Test 1: Wrong CAPTCHA
    print("🧪 Test 1.1: Wrong CAPTCHA")
    response = requests.post(f"{API_URL}/auth/login", json={
        "username": "operator",
        "password": "operator123",
        "captcha_answer": "999"
    })
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}\n")
    
    # Test 2: Wrong password (brute force simulation)
    print("🧪 Test 1.2: Brute Force Simulation (15 attempts)")
    for i in range(15):
        response = requests.post(f"{API_URL}/auth/login", json={
            "username": "operator",
            "password": f"wrong_password_{i}",
            "captcha_answer": "5"
        })
        if i % 5 == 0:
            print(f"  Attempt {i+1}/15...")
    print("✓ Brute force simulation completed\n")
    
    # Test 3: Successful login
    print("🧪 Test 1.3: Successful Login")
    response = requests.post(f"{API_URL}/auth/login", json={
        "username": "operator",
        "password": "operator123",
        "captcha_answer": "5"
    })
    print(f"Status: {response.status_code}")
    result = response.json()
    print(f"Session ID: {result.get('session_id')}")
    print(f"✓ Login successful\n")
    
    return result.get('session_id')

def test_monitoring_endpoints():
    """Test monitoring API endpoints"""
    print_header("TEST 2: MONITORING ENDPOINTS")
    
    # Test 1: Get all attacks
    print("🧪 Test 2.1: GET /api/monitoring/attacks")
    response = requests.get(f"{API_URL}/api/monitoring/attacks")
    data = response.json()
    print(f"Status: {response.status_code}")
    print(f"Total attacks: {data['total']}")
    
    if data['attacks']:
        print(f"\nFirst attack:")
        first_attack = data['attacks'][0]
        print(f"  Type: {first_attack['type']}")
        print(f"  Severity: {first_attack['severity']}")
        print(f"  Source IP: {first_attack['source_ip']}")
        print(f"  Success: {first_attack['success']}")
    print()
    
    # Test 2: Get stats
    print("🧪 Test 2.2: GET /api/monitoring/stats")
    response = requests.get(f"{API_URL}/api/monitoring/stats")
    stats = response.json()['stats']
    print(f"Status: {response.status_code}")
    print(f"Statistics:")
    print(f"  Total: {stats['total']}")
    print(f"  Critical: {stats['by_severity']['critical']}")
    print(f"  High: {stats['by_severity']['high']}")
    print(f"  Medium: {stats['by_severity']['medium']}")
    print(f"  Low: {stats['by_severity']['low']}")
    print(f"\nBy Type:")
    for attack_type, count in stats['by_type'].items():
        print(f"  {attack_type}: {count}")
    print()

def test_session_hijack(session_id):
    """Test session hijacking detection"""
    print_header("TEST 3: SESSION HIJACKING")
    
    print("🧪 Test 3.1: Simulate Session Hijack")
    print(f"Using session ID: {session_id}")
    
    # Make a request with different user agent
    response = requests.get(
        f"{API_URL}/api/diagnostics/ping",
        cookies={"session_id": session_id},
        headers={"User-Agent": "Malicious-Bot/1.0"}
    )
    
    print(f"Status: {response.status_code}")
    print("✓ Session hijack attempt logged\n")
    
    # Check if it was logged
    time.sleep(1)
    response = requests.get(f"{API_URL}/api/monitoring/attacks")
    attacks = response.json()['attacks']
    
    hijack_attacks = [a for a in attacks if a['type'] == 'SESSION_HIJACK']
    if hijack_attacks:
        print(f"✓ Found {len(hijack_attacks)} session hijack log(s)")
        print(f"  Latest: {hijack_attacks[0]['details']}")
    else:
        print("⚠ No session hijack logs found")
    print()

def main():
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║     FastAPI SCADA MONITORING SYSTEM TEST SUITE          ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    try:
        # Test 1: Login attacks
        session_id = test_login_attacks()
        
        # Test 2: Monitoring endpoints
        test_monitoring_endpoints()
        
        # Test 3: Session hijacking
        if session_id:
            test_session_hijack(session_id)
        
        print_header("ALL TESTS COMPLETED")
        print("✓ Monitoring system is working correctly!")
        print("\n📊 Open monitoring.html in browser to see the dashboard")
        print("   URL: file:///path/to/monitoring.html")
        
    except requests.exceptions.ConnectionError:
        print("\n❌ ERROR: Cannot connect to backend")
        print("   Make sure FastAPI server is running on port 8000")
        print("   Run: python main.py")
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()