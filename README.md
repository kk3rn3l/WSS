# Web Security Scanner

**Web Security Scanner** is a powerful tool designed for **authorized security assessments, vulnerability detection, and educational purposes**. It helps identify **SQL Injection, XSS, CSRF**, and other web security flaws while providing **clear explanations** and **Proof of Concepts (PoCs)**.

---

## Features
✔ **SQL Injection Detection** (including **time-based SQLi**)  
✔ **Cross-Site Scripting (XSS) Detection**  
✔ **Cross-Site Request Forgery (CSRF) Check**  
✔ **Security Headers Analysis**  
✔ **Open Redirect Detection**  
✔ **Directory Traversal Check**  
✔ **Randomized User-Agent Headers** to evade basic detection  
✔ **Detailed Logging** for audit trails  
✔ **Proof of Concept (PoC) for each vulnerability**  

---

## Ethical Usage
**This tool is intended ONLY for authorized security assessments.**  
Ensure you have **explicit permission** before testing a website. **Unauthorized use is illegal and unethical.** Use responsibly!  

---

## Setup

### **Prerequisites**
- **Python 3.x**
- **Internet connection**
- **Explicit authorization to test the target website**

### **Install Required Libraries**
```bash
pip install requests argparse
```

---

## Usage

### **Basic Syntax**
```bash
python security_scan.py -u <TARGET_URL> -p <PARAMETER> [OPTIONS]
```

### **Examples**
#### Test for SQL Injection and XSS
```bash
python security_scan.py -u "https://example.com" -p "search" --sqli --xss
```

#### Check for CSRF and Analyze Security Headers
```bash
python security_scan.py -u "https://example.com" -p "action" --csrf --headers
```

#### Detect Open Redirects and Directory Traversal
```bash
python security_scan.py -u "https://example.com" -p "redirect" --redirect --traversal
```

---

## Available Options

| Option        | Description                               |
|--------------|-------------------------------------------|
| `-u`, `--url`  | Target URL (required)                     |
| `-p`, `--param` | Parameter to test (required)               |
| `--sqli`      | Test for SQL Injection                    |
| `--xss`       | Test for Cross-Site Scripting (XSS)       |
| `--csrf`      | Check for Cross-Site Request Forgery      |
| `--headers`   | Analyze security headers                  |
| `--redirect`  | Check for Open Redirect vulnerabilities  |
| `--traversal` | Check for Directory Traversal attacks    |

---

## Vulnerability Descriptions

### **SQL Injection (SQLi)**
**Risk:** Allows attackers to manipulate database queries, leading to **data breaches** or even **database control**.  
**PoC:** Inject payloads like `' OR '1'='1` to bypass authentication or retrieve sensitive data.  

---

### **Cross-Site Scripting (XSS)**
**Risk:** Allows attackers to inject **malicious JavaScript** into web pages, leading to **data theft, session hijacking, or defacement**.  
**PoC:** Inject payloads like:
```html
<script>alert('XSS')</script>
```
If an alert box appears, the site is vulnerable.  

---

### **Cross-Site Request Forgery (CSRF)**
**Risk:** Forces **authenticated users** to perform **unwanted actions** without their consent.  
**PoC:** Create a malicious HTML form:
```html
<form action="https://example.com/transfer" method="POST">
    <input type="hidden" name="amount" value="1000">
    <input type="submit" value="Steal Money">
</form>
```
If submitting this form **transfers money without user interaction**, the site lacks CSRF protection.

---

### **Security Headers Analysis**
**Risk:** Missing headers like **CSP, HSTS, or X-Frame-Options** make the site vulnerable to various **attacks**.  
**PoC:** Inspect headers using browser DevTools (`F12 > Network > Headers`).  
💡 **Recommended Fix:** Implement headers like:
```http
Content-Security-Policy: default-src 'self';
X-Frame-Options: DENY;
Strict-Transport-Security: max-age=31536000;
```

---

### **Open Redirect**
**Risk:** Redirects users to **malicious sites**, aiding **phishing attacks**.  
**PoC:** Use the following payload in the URL:
```plaintext
https://example.com/redirect?url=https://evil.com
```
If clicking the link **redirects users to a malicious site**, the website is vulnerable.

---

### **Directory Traversal**
**Risk:** Allows access to **sensitive files** on the server.  
**PoC:** Inject `../../etc/passwd` or similar payloads:
```plaintext
https://example.com/file?name=../../etc/passwd
```
If the server returns **password file contents**, it's vulnerable.

---

## Contributing

Contributions, issues, and feature requests are **welcome**!  

**To contribute:**  
1️⃣ **Fork** the repository  
2️⃣ **Create** a new branch (`git checkout -b feature/YourFeature`)  
3️⃣ **Commit** your changes (`git commit -m 'Add YourFeature'`)  
4️⃣ **Push** to the branch (`git push origin feature/YourFeature`)  
5️⃣ **Open a Pull Request**  

---

## Disclaimer
**Unauthorized security testing is illegal!**  
This tool is **strictly for educational purposes** and **authorized penetration testing**.  
**Never test a website without explicit permission!**  

---

## Support  
If you find this tool **useful**, please **give it a star on GitHub!**  

---

### 📢 **Spread Awareness!**  
**Help improve web security by sharing this tool with ethical hackers & developers!** 

---
