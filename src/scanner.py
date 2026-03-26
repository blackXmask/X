import requests
import time
import csv

# -------------------------
# Header checks
# -------------------------
def check_headers(headers):
    issues = []
    required_headers = ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"]
    for h in required_headers:
        if h not in headers:
            issues.append(f"Missing {h}")
    return issues

# -------------------------
# Status code check
# -------------------------
def check_status(code):
    issues = []
    if code == 403:
        issues.append("403 Forbidden (possible firewall)")
    elif code >= 500:
        issues.append("Server error (5xx)")
    elif code >= 300 and code < 400:
        issues.append(f"Redirected ({code})")
    return issues

# -------------------------
# Server info check
# -------------------------
def check_server(headers):
    issues = []
    server = headers.get("Server")
    if server:
        issues.append(f"Server header exposed: {server}")
    return issues

# -------------------------
# Cookie security check
# -------------------------
def check_cookies(headers):
    issues = []
    cookies = headers.get("Set-Cookie", "")
    if cookies:
        if "Secure" not in cookies:
            issues.append("Cookie missing Secure flag")
        if "HttpOnly" not in cookies:
            issues.append("Cookie missing HttpOnly flag")
    return issues

# -------------------------
# HTTP methods check
# -------------------------
def check_methods(url):
    issues = []
    try:
        r = requests.options(url, timeout=10)
        allowed = r.headers.get("Allow", "")
        unsafe_methods = [m for m in ["PUT","DELETE","TRACE","CONNECT"] if m in allowed]
        for m in unsafe_methods:
            issues.append(f"Unsafe HTTP method allowed: {m}")
    except:
        pass
    return issues

# -------------------------
# Main scanner function
# -------------------------
def scan_url(url, save_csv=False):
    try:
        start = time.time()
        r = requests.get(url, timeout=10)
        end = time.time()
        
        headers = dict(r.headers)
        issues = []
        issues += check_headers(headers)
        issues += check_status(r.status_code)
        issues += check_server(headers)
        issues += check_cookies(headers)
        issues += check_methods(url)

        result = {
            "url": url,
            "status": r.status_code,
            "time": round(end-start,2),
            "length": len(r.text),
            "issues": issues
        }

        # Save to CSV for AI later
        if save_csv:
            with open("scan_results.csv", "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    url,
                    r.status_code,
                    round(end-start,2),
                    len(r.text),
                    "|".join(issues)
                ])

        return result

    except Exception as e:
        return {"url": url, "error": str(e)}