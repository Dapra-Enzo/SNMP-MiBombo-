import requests
import time
import urllib3
import threading
from concurrent.futures import ThreadPoolExecutor

# Disable SSL warnings for localhost
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://127.0.0.1:5000"

def print_result(name, passed, details=""):
    status = "✅ PASS" if passed else "❌ FAIL"
    print(f"{status} - {name} {details}")

def test_public_endpoints():
    print("\n--- Testing Public Endpoints ---")
    
    # 1. Status
    try:
        r = requests.get(f"{BASE_URL}/api/status", verify=False, timeout=2)
        print_result("GET /api/status", r.status_code == 200)
    except Exception as e:
        print_result("GET /api/status", False, str(e))

    # 2. Ping
    try:
        r = requests.get(f"{BASE_URL}/api/ping", verify=False, timeout=2)
        print_result("GET /api/ping", r.status_code == 200)
    except Exception as e:
        print_result("GET /api/ping", False, str(e))

def test_security_headers():
    print("\n--- Testing Security Headers ---")
    try:
        r = requests.get(f"{BASE_URL}/api/status", verify=False)
        headers = r.headers
        
        checks = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'"
        }
        
        for header, value in checks.items():
            if header in headers and value in headers[header]:
                print_result(f"Header {header}", True)
            else:
                print_result(f"Header {header}", False, f"(Got: {headers.get(header)})")
                
    except Exception as e:
        print_result("Security Headers Check", False, str(e))

def test_rate_limiting():
    print("\n--- Testing Rate Limiting (Brute Force) ---")
    print("Sending 20 requests to /api/capture/start (Limit is 10/min)...")
    
    success_count = 0
    blocked_count = 0
    
    for i in range(15):
        try:
            # Endpoint protégé par rate limit
            r = requests.post(f"{BASE_URL}/api/capture/start", verify=False)
            if r.status_code == 200 or r.status_code == 400: # 400 is ok (missing data), means request went through limit
                success_count += 1
            elif r.status_code == 429:
                blocked_count += 1
        except:
            pass
            
    print_result("Rate Limiting Triggered", blocked_count > 0, f"(Blocked {blocked_count} requests)")

def test_cors():
    print("\n--- Testing CORS ---")
    
    # 1. Valid Origin
    headers = {"Origin": "https://127.0.0.1:5000"}
    r = requests.get(f"{BASE_URL}/api/status", headers=headers, verify=False)
    print_result("CORS Valid Origin", r.status_code == 200 and r.headers.get("Access-Control-Allow-Origin") == headers["Origin"])
    
    # 2. Invalid Origin
    headers = {"Origin": "https://evil.com"}
    r = requests.get(f"{BASE_URL}/api/status", headers=headers, verify=False)
    # Flask-CORS default behavior usually allows request but doesn't send headers, or blocks.
    # With strict config, checking headers.
    cors_header = r.headers.get("Access-Control-Allow-Origin")
    print_result("CORS Invalid Origin", cors_header is None or cors_header != "https://evil.com")

if __name__ == "__main__":
    print(f"Testing API Security on {BASE_URL}")
    print("Ensure MiBombo application is running!")
    time.sleep(1)
    
    test_public_endpoints()
    test_security_headers()
    test_cors()
    test_rate_limiting()
    print("\nTests Completed.")
