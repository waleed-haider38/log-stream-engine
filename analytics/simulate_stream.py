import requests
import time
from datetime import datetime, timezone

# Local server endpoint for log ingestion
BASE_URL = "http://127.0.0.1:8000/api/logs/"

def run_simulation():
    print("Starting LogStream Engine Live Simulation...\n")

    # =========================================================================
    # Test 1: Verify the two-pointer parser strips messy error messages
    # =========================================================================
    print("Test 1: Sending a messy CRITICAL crash trace...")
    
    crash_payload = {
        "ip_address": "192.168.1.50",
        "level": "CRITICAL",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "message": "CRITICAL_HALT -> [CORE_DB_ERROR: Connection timed out at pool index 4] -> recovery_failed"
    }
    
    response = requests.post(BASE_URL + "ingest/", json=crash_payload)
    print(f"Response Status: {response.status_code}")
    
    # Securely check if the response is JSON or raw text to avoid crashing
    try:
        print(f"Body: {response.json()}\n")
    except Exception:
        print(f"Raw Server Response (The real error hidden behind HTML):\n{response.text[:800]}\n")


    # =========================================================================
    # Test 2: Verify the sliding window triggers after 5 hits from one IP
    # =========================================================================
    print("Test 2: Simulating a Brute-Force Attack (Rapid Ingestion)...")
    attacker_ip = "10.0.0.99"
    
    for i in range(1, 8):
        attack_payload = {
            "ip_address": attacker_ip,
            "level": "INFO",
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "message": f"User login attempt number {i}"
        }
        
        attack_resp = requests.post(BASE_URL + "ingest/", json=attack_payload)
        print(f"  [Hit {i}] Status: {attack_resp.status_code}")
        
        try:
            print(f"  Response Data: {attack_resp.json()}")
        except Exception:
            print(f"  Raw Error Data: {attack_resp.text[:300]}")
            
        time.sleep(0.2)

if __name__ == "__main__":
    run_simulation()