#!/usr/bin/env python3
"""
Test script for FastAPI SCADA Monitoring System
Triggers/logs the intentionally insecure behaviors (vulnerabilities) for reporting.

Run:
  python test_monitoring.py

Notes:
- API_URL points to your local FastAPI server.
- Devices router is mounted at /api/devices (per your main.py).
- Modbus test target is the externally hosted PLC endpoint you provided.
"""

import requests
import time
from typing import Optional, Dict, Any, List

API_URL = "http://localhost:8000"

# Router prefixes (match main.py)
DEVICES_PREFIX = "/api/devices"
DIAG_PREFIX = "/api/diagnostics"
LOGS_PREFIX = "/api/logs"
MON_PREFIX = "/api/monitoring"

# Modbus test target (user provided)
MODBUS_IP = "164.92.225.125"
MODBUS_PORT = 5020

# Targets for vulnerability triggers
INTERNAL_IP_FOR_SSRF = "127.0.0.1"
INTERNAL_PORT_FOR_SSRF = 80

PUBLIC_IP_FOR_UNSAFE_ADD = "8.8.8.8"
PUBLIC_PORT_FOR_UNSAFE_ADD = 80


def print_header(text: str):
    print(f"\n{'='*60}")
    print(f"{text.center(60)}")
    print(f"{'='*60}\n")


def safe_json(resp: requests.Response) -> Dict[str, Any]:
    try:
        return resp.json()
    except Exception:
        return {"_raw": resp.text}


def get_attacks() -> Dict[str, Any]:
    r = requests.get(f"{API_URL}{MON_PREFIX}/attacks", timeout=10)
    return safe_json(r)


def find_attacks_by_type(attacks: List[Dict[str, Any]], attack_type: str) -> List[Dict[str, Any]]:
    return [a for a in attacks if a.get("type") == attack_type]


def wait_and_pull_attacks(delay: float = 1.0) -> List[Dict[str, Any]]:
    time.sleep(delay)
    data = get_attacks()
    return data.get("attacks", []) if isinstance(data, dict) else []


def login_get_session_id() -> Optional[str]:
    print_header("TEST 1: LOGIN ATTACKS")

    # 1.1 Wrong CAPTCHA (WEAK_CAPTCHA)
    print("🧪 Test 1.1: Wrong CAPTCHA")
    r = requests.post(f"{API_URL}/auth/login", json={
        "username": "operator",
        "password": "operator123",
        "captcha_answer": "999"
    }, timeout=10)
    print(f"Status: {r.status_code}")
    print(f"Response: {safe_json(r)}\n")

    # 1.2 Brute force simulation (BRUTE_FORCE after >10 attempts)
    print("🧪 Test 1.2: Brute Force Simulation (15 attempts)")
    for i in range(15):
        r = requests.post(f"{API_URL}/auth/login", json={
            "username": "operator",
            "password": f"wrong_password_{i}",
            "captcha_answer": "5"
        }, timeout=10)
        if (i + 1) % 5 == 0:
            print(f"  Attempt {i+1}/15 ... status={r.status_code}")
    print("✓ Brute force simulation completed\n")

    # 1.3 Successful login (WEAK_PASSWORD log)
    print("🧪 Test 1.3: Successful Login")
    r = requests.post(f"{API_URL}/auth/login", json={
        "username": "operator",
        "password": "operator123",
        "captcha_answer": "5"
    }, timeout=10)
    print(f"Status: {r.status_code}")
    result = safe_json(r)
    session_id = result.get("session_id")
    print(f"Session ID: {session_id}")
    print("✓ Login successful\n")
    return session_id


def test_monitoring_endpoints_basic():
    print_header("TEST 2: MONITORING ENDPOINTS (BASIC)")

    print("🧪 Test 2.1: GET /api/monitoring/attacks")
    r = requests.get(f"{API_URL}{MON_PREFIX}/attacks", timeout=10)
    data = safe_json(r)
    print(f"Status: {r.status_code}")
    print(f"Total attacks: {data.get('total')}")
    if data.get("attacks"):
        a0 = data["attacks"][0]
        print("\nFirst attack:")
        print(f"  Type: {a0.get('type')}")
        print(f"  Severity: {a0.get('severity')}")
        print(f"  Source IP: {a0.get('source_ip')}")
        print(f"  Success: {a0.get('success')}")
    print()

    print("🧪 Test 2.2: GET /api/monitoring/stats")
    r = requests.get(f"{API_URL}{MON_PREFIX}/stats", timeout=10)
    payload = safe_json(r)
    stats = payload.get("stats", {})
    print(f"Status: {r.status_code}")
    print("Statistics:")
    print(f"  Total: {stats.get('total')}")
    by_sev = stats.get("by_severity", {})
    print(f"  Critical: {by_sev.get('critical')}")
    print(f"  High: {by_sev.get('high')}")
    print(f"  Medium: {by_sev.get('medium')}")
    print(f"  Low: {by_sev.get('low')}")
    by_type = stats.get("by_type", {})
    print("\nBy Type:")
    for t, c in by_type.items():
        print(f"  {t}: {c}")
    print()

    print("🧪 Test 2.3: GET /api/monitoring/recent?limit=5")
    r = requests.get(f"{API_URL}{MON_PREFIX}/recent", params={"limit": 5}, timeout=10)
    data = safe_json(r)
    print(f"Status: {r.status_code}")
    print(f"Recent returned: {data.get('total')}")
    print()

    print("🧪 Test 2.4: GET /api/monitoring/severity/critical")
    r = requests.get(f"{API_URL}{MON_PREFIX}/severity/critical", timeout=10)
    data = safe_json(r)
    print(f"Status: {r.status_code}")
    print(f"Critical count: {data.get('total')}")
    print()


def test_session_hijack(session_id: str):
    print_header("TEST 3: SESSION HIJACKING (MIDDLEWARE)")

    print("🧪 Test 3.1: Simulate Session Hijack (Different User-Agent)")
    r = requests.post(
        f"{API_URL}{DIAG_PREFIX}/ping",
        cookies={"session_id": session_id},
        headers={"User-Agent": "Malicious-Bot/1.0"},
        json={"host": "127.0.0.1"},
        timeout=10
    )
    print(f"Status: {r.status_code}")
    print(f"Response: {safe_json(r)}")
    print("✓ Session hijack attempt request sent\n")

    attacks = wait_and_pull_attacks(1.0)
    hijacks = find_attacks_by_type(attacks, "SESSION_HIJACK")
    if hijacks:
        print(f"✓ Found {len(hijacks)} SESSION_HIJACK log(s). Showing latest:")
        print(hijacks[0].get("details"))
    else:
        print("⚠ No SESSION_HIJACK logs found")
    print()

    print("🧪 Test 3.2: Simulate Session Hijack (Different IP via X-Forwarded-For)")
    r = requests.post(
        f"{API_URL}{DIAG_PREFIX}/ping",
        cookies={"session_id": session_id},
        headers={
            "User-Agent": "operator-browser",
            "X-Forwarded-For": "203.0.113.77"
        },
        json={"host": "127.0.0.1"},
        timeout=10
    )
    print(f"Status: {r.status_code}")
    print(f"Response: {safe_json(r)}")

    attacks = wait_and_pull_attacks(1.0)
    hijacks = find_attacks_by_type(attacks, "SESSION_HIJACK")
    if hijacks:
        print(f"✓ Found {len(hijacks)} SESSION_HIJACK log(s). Showing latest:")
        print(hijacks[0].get("details"))
    else:
        print("⚠ No SESSION_HIJACK logs found")
    print()


def test_cmd_injection(session_id: str):
    print_header("TEST 4: COMMAND INJECTION (DIAGNOSTICS)")

    payload_host_ping = "127.0.0.1;"
    payload_host_trace = "127.0.0.1;"

    print("🧪 Test 4.1: POST /api/diagnostics/ping (CMD_INJECTION log expected)")
    r = requests.post(
        f"{API_URL}{DIAG_PREFIX}/ping",
        cookies={"session_id": session_id},
        json={"host": payload_host_ping},
        timeout=10
    )
    print(f"Status: {r.status_code}")
    print(f"Response: {safe_json(r)}\n")

    print("🧪 Test 4.2: POST /api/diagnostics/traceroute (CMD_INJECTION log expected)")
    r = requests.post(
        f"{API_URL}{DIAG_PREFIX}/traceroute",
        cookies={"session_id": session_id},
        json={"host": payload_host_trace},
        timeout=10
    )
    print(f"Status: {r.status_code}")
    print(f"Response: {safe_json(r)}\n")

    attacks = wait_and_pull_attacks(1.0)
    cmd = find_attacks_by_type(attacks, "CMD_INJECTION")
    if cmd:
        print(f"✓ Found {len(cmd)} CMD_INJECTION log(s). Showing latest details:")
        print(cmd[0].get("details"))
    else:
        print("⚠ No CMD_INJECTION logs found")
    print()


def test_ssrf_and_stored_ssrf(session_id: str):
    print_header("TEST 5: SSRF + STORED SSRF (DEVICES)")

    print("🧪 Test 5.1: POST /api/devices/check (SSRF log expected)")
    r = requests.post(
        f"{API_URL}{DEVICES_PREFIX}/check",
        cookies={"session_id": session_id},
        json={"ip": INTERNAL_IP_FOR_SSRF, "port": INTERNAL_PORT_FOR_SSRF},
        timeout=10
    )
    print(f"Status: {r.status_code}")
    print(f"Response: {safe_json(r)}\n")

    print("🧪 Test 5.2: POST /api/devices/add (STORED_SSRF log expected)")
    r = requests.post(
        f"{API_URL}{DEVICES_PREFIX}/add",
        cookies={"session_id": session_id},
        json={
            "name": "internal-ssrf-test",
            "ip": INTERNAL_IP_FOR_SSRF,
            "port": INTERNAL_PORT_FOR_SSRF,
            "type": "camera"
        },
        timeout=10
    )
    print(f"Status: {r.status_code}")
    print(f"Response: {safe_json(r)}\n")

    print("🧪 Test 5.3: POST /api/devices/add (UNSAFE_DEVICE_ADD log expected)")
    r = requests.post(
        f"{API_URL}{DEVICES_PREFIX}/add",
        cookies={"session_id": session_id},
        json={
            "name": "public-unsafe-add-test",
            "ip": PUBLIC_IP_FOR_UNSAFE_ADD,
            "port": PUBLIC_PORT_FOR_UNSAFE_ADD,
            "type": "sensor"
        },
        timeout=10
    )
    print(f"Status: {r.status_code}")
    print(f"Response: {safe_json(r)}\n")

    attacks = wait_and_pull_attacks(1.0)
    ssrf = find_attacks_by_type(attacks, "SSRF")
    stored = find_attacks_by_type(attacks, "STORED_SSRF")
    unsafe = find_attacks_by_type(attacks, "UNSAFE_DEVICE_ADD")

    print(f"SSRF logs found: {len(ssrf)}")
    print(f"STORED_SSRF logs found: {len(stored)}")
    print(f"UNSAFE_DEVICE_ADD logs found: {len(unsafe)}")
    if ssrf:
        print("Latest SSRF details:", ssrf[0].get("details"))
    if stored:
        print("Latest STORED_SSRF details:", stored[0].get("details"))
    if unsafe:
        print("Latest UNSAFE_DEVICE_ADD details:", unsafe[0].get("details"))
    print()

    print("🧪 Test 5.4: GET /api/devices/list_all_devices (should return devices)")
    r = requests.get(
        f"{API_URL}{DEVICES_PREFIX}/list_all_devices",
        cookies={"session_id": session_id},
        timeout=10
    )
    print(f"Status: {r.status_code}")
    data = safe_json(r)
    devs = data.get("devices", [])
    print(f"Devices returned: {len(devs) if isinstance(devs, list) else 'N/A'}")
    print()


def test_modbus_unauthorized_read(session_id: str):
    print_header("TEST 6: MODBUS UNAUTHORIZED READ (OT ACCESS LOG)")

    print("🧪 Test 6.1: GET /api/devices/read_specific_device (MODBUS_UNAUTHORIZED log expected)")
    params = {
        "plc_ip": MODBUS_IP,
        "plc_port": MODBUS_PORT,
        "read_input_registers": "true",
        "read_coils": "false",
        "read_discrete_inputs": "false",
        "read_holding_registers": "false"
    }
    r = requests.get(
        f"{API_URL}{DEVICES_PREFIX}/read_specific_device",
        cookies={"session_id": session_id},
        params=params,
        timeout=15
    )
    print(f"Status: {r.status_code}")
    print(f"Response: {safe_json(r)}\n")

    attacks = wait_and_pull_attacks(1.0)
    mod = find_attacks_by_type(attacks, "MODBUS_UNAUTHORIZED")
    if mod:
        print(f"✓ Found {len(mod)} MODBUS_UNAUTHORIZED log(s). Showing latest details:")
        print(mod[0].get("details"))
    else:
        print("⚠ No MODBUS_UNAUTHORIZED logs found")
    print()


def test_path_traversal_and_injection(session_id: str):
    print_header("TEST 7: PATH TRAVERSAL / PATH INJECTION (LOG EXPORT)")

    traversal_name = "../definitely_not_a_real_log.log"
    print("🧪 Test 7.1: GET /api/logs/export?file_name=../... (PATH_TRAVERSAL log expected)")
    r = requests.get(
        f"{API_URL}{LOGS_PREFIX}/export",
        cookies={"session_id": session_id},
        params={"file_name": traversal_name},
        timeout=10
    )
    print(f"Status: {r.status_code}")
    print(f"Response: {safe_json(r)}\n")

    normal_name = "app.log"
    print("🧪 Test 7.2: GET /api/logs/export?file_name=app.log (PATH_INJECTION log expected)")
    r = requests.get(
        f"{API_URL}{LOGS_PREFIX}/export",
        cookies={"session_id": session_id},
        params={"file_name": normal_name},
        timeout=10
    )
    print(f"Status: {r.status_code}")
    print("✓ Request sent (content not displayed)\n")

    attacks = wait_and_pull_attacks(1.0)
    pt = find_attacks_by_type(attacks, "PATH_TRAVERSAL")
    pi = find_attacks_by_type(attacks, "PATH_INJECTION")

    print(f"PATH_TRAVERSAL logs found: {len(pt)}")
    print(f"PATH_INJECTION logs found: {len(pi)}")
    if pt:
        print("Latest PATH_TRAVERSAL details:", pt[0].get("details"))
    if pi:
        print("Latest PATH_INJECTION details:", pi[0].get("details"))
    print()


def optional_clear_logs():
    print_header("OPTIONAL: CLEAR MONITORING LOGS")
    r = requests.post(f"{API_URL}{MON_PREFIX}/clear", timeout=10)
    print(f"Status: {r.status_code}")
    print(f"Response: {safe_json(r)}\n")


def main():
    print("""
╔══════════════════════════════════════════════════════════╗
║        FastAPI SCADA MONITORING SYSTEM TEST SUITE        ║
╚══════════════════════════════════════════════════════════╝
""")

    try:
        # Uncomment if you want clean logs for screenshots:
        # optional_clear_logs()

        session_id = login_get_session_id()
        if not session_id:
            print("❌ Could not obtain session_id; aborting authenticated tests.")
            return

        test_monitoring_endpoints_basic()

        test_session_hijack(session_id)
        test_cmd_injection(session_id)
        test_ssrf_and_stored_ssrf(session_id)
        test_modbus_unauthorized_read(session_id)
        test_path_traversal_and_injection(session_id)

        print_header("ALL TESTS COMPLETED")
        print("✓ All vulnerability triggers attempted. Check your monitoring UI for logs/screenshots.")

    except requests.exceptions.ConnectionError:
        print("\n❌ ERROR: Cannot connect to backend")
        print("   Make sure FastAPI server is running on port 8000")
        print("   Example: uvicorn main:app --reload --host 0.0.0.0 --port 8000")
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
