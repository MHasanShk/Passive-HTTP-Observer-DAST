import requests
import re
import ssl
import socket
import argparse
import json
import uuid
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, parse_qs, urljoin
import OpenSSL
import certifi
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import subprocess
import tempfile
import os

# -----------------------------------------------------------------------------
# Terminal Colors and Styling
# -----------------------------------------------------------------------------

class Colors:
        """ANSI color codes for terminal output"""
        HEADER = '\033[95m'
        BLUE = '\033[94m'
        CYAN = '\033[96m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        RED = '\033[91m'
        BOLD = '\033[1m'
        UNDERLINE = '\033[4m'
        END = '\033[0m'
        DIM = '\033[2m'

class Icons:
        """Icons for different finding types"""
        CRITICAL = "🔴"
        HIGH = "🟠"
        MEDIUM = "🟡"
        LOW = "🔵"
        INFO = "ℹ️"
        SUCCESS = "✅"
        ERROR = "❌"
        WARNING = "⚠️"
        TARGET = "🎯"
        COOKIE = "🍪"
        SSL = "🔒"
        BACKUP = "💾"
        PAYMENT = "💳"
        CDN = "🌐"
        HEADER = "📋"
        CORS = "🔓"
        MIXED = "🔄"
        TLS = "🔐"
        CLICKJACK = "🖱️"

# -----------------------------------------------------------------------------
# Data Structure for Findings
# -----------------------------------------------------------------------------

class SecurityFinding:
        """
        Structure to hold a security observation and map it to the specific report format.
        """
        def __init__(self, url, issue_type, indicator, impact, severity="Medium",
                                 detection_method="Analysis", param_location=None, response_obj=None,
                                 remediation=None, extracted_data=None):
                self.url = url
                self.issue_type = issue_type
                self.indicator = indicator
                self.impact = impact
                self.severity = severity
                self.detection_method = detection_method
                self.param_location = param_location
                self.response_obj = response_obj
                self.remediation = remediation
                self.extracted_data = extracted_data
                self.timestamp = datetime.now(timezone.utc).isoformat()

        def to_dict(self):
                """
                Legacy dict format (kept for compatibility if needed, though main uses to_report_dict).
                """
                return {
                        "timestamp": self.timestamp,
                        "url": self.url,
                        "issue_type": self.issue_type,
                        "indicator": self.indicator,
                        "impact": self.impact,
                        "severity": self.severity
                }

        def to_report_dict(self):
                """
                Converts the finding into the requested complex JSON structure.
                """
                # Determine raw request/response if available
                raw_req = None
                raw_resp = None
                resp_time = None

                if self.response_obj:
                        raw_req = f"{self.response_obj.request.method} {self.response_obj.request.url} HTTP/1.1\n" \
                                          f"Host: {self.response_obj.request.headers.get('Host', urlparse(self.response_obj.request.url).netloc)}\n" \
                                          f"User-Agent: {self.response_obj.request.headers.get('User-Agent')}"

                        raw_resp = f"HTTP/1.1 {self.response_obj.status_code}\n" \
                                           f"Content-Type: {self.response_obj.headers.get('Content-Type')}\n\n" \
                                           f"{self.response_obj.text[:1000]}..." # Truncated for readability

                        resp_time = self.response_obj.elapsed.total_seconds()

                # Determine category based on issue type
                category = "General"
                if "Cookie" in self.issue_type: category = "Session Management"
                elif "SSL" in self.issue_type or "TLS" in self.issue_type or "Certificate" in self.issue_type: 
                        category = "Cryptography"
                elif "Info" in self.issue_type or "Error" in self.issue_type: category = "Information Disclosure"
                elif "Payment" in self.issue_type: category = "Compliance"
                elif "Header" in self.issue_type or "HSTS" in self.issue_type or "CSP" in self.issue_type: category = "Security Headers"
                elif "CORS" in self.issue_type: category = "CORS Configuration"
                elif "Mixed Content" in self.issue_type: category = "Mixed Content"
                elif "Cipher" in self.issue_type or "TLS Version" in self.issue_type: category = "TLS Configuration"
                elif "Clickjacking" in self.issue_type or "X-Frame-Options" in self.issue_type: category = "Clickjacking Protection"

                return {
                        "id": str(uuid.uuid4()),
                        "agent_group": "Reconnaissance",
                        "sub_agent": "PassiveHttpObserver",
                        "vulnerability_type": self.issue_type,
                        "category": category,
                        "severity": self.severity,
                        "confidence": "High" if self.severity in ["Critical", "High"] else "Medium",
                        "target_url": self.url,
                        "affected_parameter": self.indicator if self.param_location else None,
                        "description": self.impact,
                        "observation": f"{self.issue_type} detected: {self.indicator}",
                        "timestamp": self.timestamp,
                        "proof_of_concept": self._generate_clickjacking_poc() if "Clickjacking" in self.issue_type else None,
                        "remediation": self.remediation or "Review the identified security issue and apply best practices.",
                        "cve_reference": "CWE-1021" if "Clickjacking" in self.issue_type else "CWE-319" if "Mixed Content" in self.issue_type else "CWE-326" if "TLS" in self.issue_type else None,
                        "details": {
                                "method": self.response_obj.request.method if self.response_obj else "GET",
                                "param_location": self.param_location,
                                "payload": None,
                                "detection_method": self.detection_method,
                                "shell_context": None,
                                "privilege_context": "Unauthenticated",
                                "baseline_time": None,
                                "response_time": resp_time,
                                "extracted_data": self.extracted_data,
                                "raw_request": raw_req,
                                "raw_response": raw_resp
                        }
                }
        
        def _generate_clickjacking_poc(self):
                """Generate a proof-of-concept HTML for clickjacking vulnerability"""
                if "Clickjacking" not in self.issue_type:
                        return None
                
                poc_html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC - {self.url}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f0f0f0;
        }}
        .container {{
            max-width: 800px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #d32f2f;
        }}
        .warning {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 10px;
            margin: 20px 0;
        }}
        .iframe-container {{
            position: relative;
            width: 100%;
            height: 600px;
            border: 2px solid #ccc;
            margin: 20px 0;
        }}
        iframe {{
            width: 100%;
            height: 100%;
            border: none;
            opacity: 0.5;
        }}
        .overlay {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 10;
            cursor: pointer;
        }}
        button {{
            background: #4CAF50;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin: 10px;
        }}
        button:hover {{
            background: #45a049;
        }}
        .deceptive-ui {{
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: rgba(255,255,255,0.9);
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.2);
            text-align: center;
            z-index: 20;
            pointer-events: none;
        }}
        .deceptive-ui button {{
            pointer-events: auto;
            background: #d32f2f;
            font-size: 18px;
            padding: 15px 30px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔓 Clickjacking Vulnerability Proof of Concept</h1>
        <div class="warning">
            <strong>⚠️ Security Alert:</strong> This page demonstrates that <strong>{self.url}</strong> is vulnerable to clickjacking attacks.
            The target website can be embedded in an iframe and users can be tricked into clicking invisible elements.
        </div>
        
        <h2>Vulnerability Details:</h2>
        <ul>
            <li><strong>Target URL:</strong> {self.url}</li>
            <li><strong>Missing Header:</strong> X-Frame-Options or Content-Security-Policy frame-ancestors</li>
            <li><strong>Risk:</strong> Attackers can hide the target website under deceptive UI elements</li>
        </ul>
        
        <h2>Demonstration:</h2>
        <p>The target website is embedded below. Notice how it can be framed without restrictions:</p>
        
        <div class="iframe-container">
            <iframe src="{self.url}" sandbox="allow-same-origin allow-scripts allow-forms"></iframe>
            <div class="deceptive-ui">
                <h3>🎁 WIN A FREE PRIZE! 🎁</h3>
                <p>Click the button below to claim your reward!</p>
                <button onclick="alert('⚠️ You just clicked on the hidden target website! This demonstrates clickjacking.')">
                    CLAIM YOUR PRIZE NOW!
                </button>
                <p style="font-size: 12px; color: #666;">(This button overlays the target website)</p>
            </div>
        </div>
        
        <h2>Attack Scenario:</h2>
        <p>An attacker could:</p>
        <ol>
            <li>Create a malicious website that embeds {self.url} in an invisible iframe</li>
            <li>Trick users into clicking on deceptive elements (like "Play Video" or "Claim Prize")</li>
            <li>The click actually targets buttons/links on your website</li>
            <li>This can lead to unauthorized actions (changing settings, making purchases, posting content)</li>
        </ol>
        
        <h2>Remediation:</h2>
        <ul>
            <li>Add <strong>X-Frame-Options: DENY</strong> or <strong>SAMEORIGIN</strong> header</li>
            <li>Or use <strong>Content-Security-Policy: frame-ancestors 'none'</strong> or <strong>'self'</strong></li>
            <li>Test with <strong>X-Frame-Options: ALLOW-FROM</strong> (limited browser support)</li>
        </ul>
        
        <p><em>This proof of concept demonstrates the security weakness. Remove this header protection to fix the vulnerability.</em></p>
    </div>
</body>
</html>'''
                
                return poc_html

        def __repr__(self):
                return f"[{self.severity}] {self.issue_type}: {self.indicator} @ {self.url}"

        def __hash__(self):
                return hash((self.url, self.issue_type, self.indicator))

        def __eq__(self, other):
                if not isinstance(other, SecurityFinding):
                        return False
                return (self.url, self.issue_type, self.indicator) == (other.url, other.issue_type, other.indicator)

# -----------------------------------------------------------------------------
# Main Observer Module
# -----------------------------------------------------------------------------

class PassiveHttpObserver:
        def __init__(self, timeout=10, user_agent="PassiveHTTPObserver/1.0"):
                """
                Initialize the Observer with configuration parameters.
                """
                self.timeout = timeout
                self.session = requests.Session()
                self.session.headers.update({'User-Agent': user_agent})

                # Configuration parameters
                self.backup_extensions = ['.bak', '.old', '.zip', '.tar', '.sql', '.log']
                self.sensitive_keywords = ['password', 'passwd', 'secret', 'token', 'api_key', 'ssn', 'credit_card']
                self.payment_keywords = ['/checkout', '/payment', '/billing', '/cart', '/api/pay']
                self.framework_error_patterns = [
                        r"Stack trace", r"Exception", r"Fatal error", r"SQL syntax",
                        r"Warning:\s+\w+", r"Traceback", r"java\.lang\.", r"Newtonsoft\.Json",
                        r"org\.apache\.", r"django\.core\.exceptions"
                ]
                self.cdn_waf_signatures = {
                        'Cloudflare': ['cf-ray', 'cf-cache-status'],
                        'Akamai': ['akamai-origin-hop'],
                        'Fastly': ['fastly-debug-digest', 'x-served-by'],
                        'AWS CloudFront': ['x-amz-cf-id'],
                        'Incapsula': ['incap-ses-601'],
                        'F5 BIG-IP': ['bigipserver']
                }
                
                # TLS version security levels
                self.tls_security_levels = {
                    'SSLv2': {'severity': 'Critical', 'deprecated': True, 'cve': 'CVE-2016-0800'},
                    'SSLv3': {'severity': 'Critical', 'deprecated': True, 'cve': 'CVE-2014-3566'},
                    'TLSv1.0': {'severity': 'High', 'deprecated': True, 'cve': 'CVE-2016-2107'},
                    'TLSv1.1': {'severity': 'Medium', 'deprecated': True, 'cve': 'CVE-2016-2183'},
                    'TLSv1.2': {'severity': 'Info', 'deprecated': False},
                    'TLSv1.3': {'severity': 'Info', 'deprecated': False}
                }
                
                # Weak cipher patterns
                self.weak_ciphers = {
                    'NULL': {'severity': 'Critical', 'reason': 'Provides no encryption'},
                    'EXP': {'severity': 'Critical', 'reason': 'Export-grade cryptography'},
                    'RC4': {'severity': 'High', 'reason': 'Broken stream cipher with biases'},
                    'DES': {'severity': 'High', 'reason': '56-bit key is bruteforceable'},
                    '3DES': {'severity': 'Medium', 'reason': 'Sweet32 attack vulnerability'},
                    'CBC': {'severity': 'Medium', 'reason': 'Vulnerable to padding oracle attacks (Lucky13)'},
                    'DH_anon': {'severity': 'Critical', 'reason': 'No authentication - vulnerable to MITM'},
                    'ECDH_anon': {'severity': 'Critical', 'reason': 'No authentication - vulnerable to MITM'},
                    'NULL-MD5': {'severity': 'Critical', 'reason': 'No encryption with weak MAC'},
                    'NULL-SHA': {'severity': 'Critical', 'reason': 'No encryption'},
                }
                
                # Recommended ciphers (modern, secure)
                self.strong_ciphers = [
                    'TLS_AES_256_GCM_SHA384',
                    'TLS_AES_128_GCM_SHA256',
                    'TLS_CHACHA20_POLY1305_SHA256',
                    'ECDHE-ECDSA-AES256-GCM-SHA384',
                    'ECDHE-RSA-AES256-GCM-SHA384',
                    'ECDHE-ECDSA-AES128-GCM-SHA256',
                    'ECDHE-RSA-AES128-GCM-SHA256',
                    'ECDHE-ECDSA-CHACHA20-POLY1305',
                    'ECDHE-RSA-CHACHA20-POLY1305'
                ]
                
                # Mixed content patterns for HTML parsing
                self.mixed_content_patterns = {
                    'script': {
                        'pattern': r'<script[^>]*src=["\'](http://[^"\']+)["\']',
                        'type': 'JavaScript',
                        'severity': 'High',
                        'remediation': 'Replace HTTP script URLs with HTTPS versions or use protocol-relative URLs (//example.com/script.js). Consider implementing Content-Security-Policy upgrade-insecure-requests directive.'
                    },
                    'stylesheet': {
                        'pattern': r'<link[^>]*rel=["\']stylesheet["\'][^>]*href=["\'](http://[^"\']+)["\']',
                        'type': 'CSS',
                        'severity': 'Medium',
                        'remediation': 'Update CSS links to use HTTPS. For external stylesheets, ensure they support HTTPS connections.'
                    },
                    'image': {
                        'pattern': r'<img[^>]*src=["\'](http://[^"\']+)["\']',
                        'type': 'Image',
                        'severity': 'Low',
                        'remediation': 'Replace HTTP image URLs with HTTPS versions. Consider using HTTPS for all image resources to prevent mixed content warnings.'
                    },
                    'iframe': {
                        'pattern': r'<iframe[^>]*src=["\'](http://[^"\']+)["\']',
                        'type': 'Iframe',
                        'severity': 'High',
                        'remediation': 'Update iframe sources to use HTTPS. If the embedded content does not support HTTPS, consider finding alternatives or proxying the content.'
                    },
                    'object': {
                        'pattern': r'<object[^>]*data=["\'](http://[^"\']+)["\']',
                        'type': 'Object/Plugin',
                        'severity': 'High',
                        'remediation': 'Update object data URLs to use HTTPS. Avoid loading plugins over insecure connections.'
                    },
                    'embed': {
                        'pattern': r'<embed[^>]*src=["\'](http://[^"\']+)["\']',
                        'type': 'Embedded Content',
                        'severity': 'Medium',
                        'remediation': 'Update embed sources to use HTTPS.'
                    },
                    'video': {
                        'pattern': r'<video[^>]*src=["\'](http://[^"\']+)["\']',
                        'type': 'Video',
                        'severity': 'Medium',
                        'remediation': 'Update video sources to use HTTPS.'
                    },
                    'audio': {
                        'pattern': r'<audio[^>]*src=["\'](http://[^"\']+)["\']',
                        'type': 'Audio',
                        'severity': 'Medium',
                        'remediation': 'Update audio sources to use HTTPS.'
                    },
                    'source': {
                        'pattern': r'<source[^>]*src=["\'](http://[^"\']+)["\']',
                        'type': 'Media Source',
                        'severity': 'Medium',
                        'remediation': 'Update source URLs to use HTTPS.'
                    },
                    'form_action': {
                        'pattern': r'<form[^>]*action=["\'](http://[^"\']+)["\']',
                        'type': 'Form Submission',
                        'severity': 'High',
                        'remediation': 'Update form action URLs to use HTTPS to prevent insecure form submissions.'
                    },
                    'css_import': {
                        'pattern': r'@import\s+url\(["\']?(http://[^"\'\)]+)["\']?\)',
                        'type': 'CSS Import',
                        'severity': 'Medium',
                        'remediation': 'Update CSS @import rules to use HTTPS.'
                    },
                    'css_background': {
                        'pattern': r'background(-image)?:\s*url\(["\']?(http://[^"\'\)]+)["\']?\)',
                        'type': 'CSS Background Image',
                        'severity': 'Low',
                        'remediation': 'Update background image URLs to use HTTPS.'
                    }
                }
                
                # Security headers configuration
                self.security_headers = {
                    'strict-transport-security': {
                        'name': 'HSTS (Strict-Transport-Security)',
                        'required': True,
                        'severity': 'High',
                        'remediation': 'Implement HSTS with a minimum max-age of 31536000 seconds and include the includeSubDomains directive.',
                        'expected_pattern': r'max-age=(\d+)',
                        'checks': self._check_hsts
                    },
                    'content-security-policy': {
                        'name': 'CSP (Content-Security-Policy)',
                        'required': False,
                        'severity': 'Medium',
                        'remediation': 'Implement a strict CSP policy to prevent XSS attacks. Use nonce or hash-based policies where possible.',
                        'expected_pattern': None,
                        'checks': self._check_csp
                    },
                    'x-frame-options': {
                        'name': 'X-Frame-Options',
                        'required': True,
                        'severity': 'Medium',
                        'remediation': 'Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking attacks.',
                        'expected_pattern': r'^(DENY|SAMEORIGIN)$',
                        'checks': self._check_x_frame_options
                    },
                    'x-content-type-options': {
                        'name': 'X-Content-Type-Options',
                        'required': True,
                        'severity': 'Low',
                        'remediation': 'Set X-Content-Type-Options to "nosniff" to prevent MIME type sniffing.',
                        'expected_pattern': r'^nosniff$',
                        'checks': None
                    },
                    'referrer-policy': {
                        'name': 'Referrer-Policy',
                        'required': False,
                        'severity': 'Low',
                        'remediation': 'Set a strict referrer policy (e.g., strict-origin-when-cross-origin or no-referrer) to control referrer information leakage.',
                        'expected_pattern': None,
                        'checks': self._check_referrer_policy
                    },
                    'permissions-policy': {
                        'name': 'Permissions-Policy',
                        'required': False,
                        'severity': 'Info',
                        'remediation': 'Implement Permissions-Policy to control which browser features can be used on your site.',
                        'expected_pattern': None,
                        'checks': None
                    },
                    'cross-origin-embedder-policy': {
                        'name': 'COEP (Cross-Origin-Embedder-Policy)',
                        'required': False,
                        'severity': 'Info',
                        'remediation': 'Consider implementing COEP to protect against cross-origin attacks.',
                        'expected_pattern': None,
                        'checks': None
                    },
                    'cross-origin-opener-policy': {
                        'name': 'COOP (Cross-Origin-Opener-Policy)',
                        'required': False,
                        'severity': 'Info',
                        'remediation': 'Consider implementing COOP to protect against cross-origin attacks like Spectre.',
                        'expected_pattern': None,
                        'checks': None
                    },
                    'cross-origin-resource-policy': {
                        'name': 'CORP (Cross-Origin-Resource-Policy)',
                        'required': False,
                        'severity': 'Info',
                        'remediation': 'Set CORP to control which origins can load your resources.',
                        'expected_pattern': None,
                        'checks': None
                    },
                    'content-security-policy-report-only': {
                        'name': 'CSP-Report-Only',
                        'required': False,
                        'severity': 'Info',
                        'remediation': 'Use report-only mode to test CSP policies before enforcing them.',
                        'expected_pattern': None,
                        'checks': None
                    }
                }

        def analyze_target(self, url, check_backups=False):
                """
                Main workflow to analyze a single target URL.
                """
                findings = []
                parsed_url = urlparse(url)
                base_domain = parsed_url.netloc

                try:
                        # 1. Send Request and collect metadata
                        response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                        history = response.history

                        # 2. Transport Security Analysis
                        findings.extend(self._check_transport_security(url, response, history))

                        # 3. ENHANCED Cookie Security Analysis
                        findings.extend(self._check_enhanced_cookie_security(url, response))

                        # 4. Sensitive Data in Transit (Request Side)
                        findings.extend(self._check_sensitive_data_in_transit(url))

                        # 5. Server Information Disclosure
                        findings.extend(self._check_info_disclosure(url, response))

                        # 6. Payment Transit Security
                        findings.extend(self._check_payment_security(url, response))

                        # 7. Error Information Leakage
                        findings.extend(self._check_error_leakage(url, response))

                        # 8. CDN / WAF Detection
                        findings.extend(self._check_cdn_waf(url, response))

                        # 9. Comprehensive SSL/TLS Certificate and Security Validation
                        if parsed_url.scheme == 'https':
                                findings.extend(self._check_comprehensive_ssl_tls(base_domain))

                        # 10. Security Headers Analysis (includes clickjacking detection)
                        findings.extend(self._check_security_headers(url, response))

                        # 11. CORS Misconfiguration Analysis
                        findings.extend(self._check_cors_misconfiguration(url, response))

                        # 12. Backup File Exposure (Optional Probing)
                        if check_backups:
                                findings.extend(self._check_backup_files(url))
                        
                        # 13. Mixed Content Analysis
                        if parsed_url.scheme == 'https':
                                findings.extend(self._check_mixed_content(url, response))
                        
                        # 14. ADDED: Anti-Clickjacking Header Analysis (Enhanced)
                        findings.extend(self._check_anti_clickjacking_headers(url, response))

                except requests.exceptions.SSLError as e:
                        findings.append(SecurityFinding(
                                url, "SSL/TLS Error", "Connection failed due to SSL/TLS issues",
                                "The server has a misconfigured or invalid SSL certificate.", "High",
                                detection_method="SSL Handshake", remediation="Install a valid SSL certificate signed by a trusted CA."
                        ))
                except requests.RequestException as e:
                        raise e

                return findings

        # -------------------------------------------------------------------------
        # ANTI-CLICKJACKING HEADER ANALYSIS MODULE (NEW)
        # -------------------------------------------------------------------------
        
        def _check_anti_clickjacking_headers(self, url, response):
                """
                Comprehensive anti-clickjacking header analysis including:
                - X-Frame-Options header presence and configuration
                - CSP frame-ancestors directive analysis
                - Frame breaking JavaScript detection (fallback)
                - Clickjacking risk assessment
                """
                findings = []
                
                headers_lower = {k.lower(): v for k, v in response.headers.items()}
                
                # Check for X-Frame-Options header
                xfo_header = headers_lower.get('x-frame-options', None)
                csp_header = headers_lower.get('content-security-policy', None)
                
                # Extract frame-ancestors from CSP if present
                frame_ancestors = None
                if csp_header:
                        frame_ancestors_match = re.search(r'frame-ancestors\s+([^;]+)', csp_header, re.IGNORECASE)
                        if frame_ancestors_match:
                                frame_ancestors = frame_ancestors_match.group(1).strip()
                
                # Check for frame breaking JavaScript
                has_frame_breaking_js = self._check_frame_breaking_javascript(response.text)
                
                # CASE 1: No X-Frame-Options AND no CSP frame-ancestors
                if not xfo_header and not frame_ancestors:
                        extracted_data = {
                                "x_frame_options_present": False,
                                "x_frame_options_value": None,
                                "csp_frame_ancestors_present": False,
                                "csp_frame_ancestors_value": None,
                                "frame_breaking_js_detected": has_frame_breaking_js,
                                "risk_level": "High",
                                "attack_vector": "Clickjacking/UI Redressing",
                                "cwe_reference": "CWE-1021"
                        }
                        
                        impact = ("The application is missing anti-clickjacking headers (X-Frame-Options or CSP frame-ancestors). "
                                  "This allows attackers to embed the application in a malicious iframe and trick users into "
                                  "clicking hidden elements, potentially leading to unauthorized actions, credential theft, "
                                  "or sensitive data exposure.")
                        
                        remediation = ("Implement anti-clickjacking protection using one of these methods:\n"
                                      "1. Add HTTP header: X-Frame-Options: DENY or SAMEORIGIN\n"
                                      "2. Add CSP header: Content-Security-Policy: frame-ancestors 'none' or 'self'\n"
                                      "3. For legacy browsers, implement frame-breaking JavaScript as a defense-in-depth measure")
                        
                        findings.append(SecurityFinding(
                                url,
                                "Missing Anti-Clickjacking Headers",
                                "X-Frame-Options header and CSP frame-ancestors directive are both missing",
                                impact,
                                "High",
                                detection_method="Anti-Clickjacking Analysis",
                                response_obj=response,
                                remediation=remediation,
                                extracted_data=extracted_data
                        ))
                
                # CASE 2: X-Frame-Options present but misconfigured
                elif xfo_header:
                        xfo_upper = xfo_header.upper()
                        extracted_data = {
                                "x_frame_options_present": True,
                                "x_frame_options_value": xfo_header,
                                "csp_frame_ancestors_present": bool(frame_ancestors),
                                "csp_frame_ancestors_value": frame_ancestors,
                                "frame_breaking_js_detected": has_frame_breaking_js
                        }
                        
                        # Check for ALLOW-FROM (deprecated and limited browser support)
                        if xfo_upper.startswith('ALLOW-FROM'):
                                extracted_data["risk_level"] = "Medium"
                                impact = ("X-Frame-Options is set to 'ALLOW-FROM', which has limited browser support "
                                          "(not supported in Chrome, Firefox, Safari) and provides incomplete protection.")
                                remediation = ("Replace X-Frame-Options: ALLOW-FROM with CSP frame-ancestors directive "
                                              "or use X-Frame-Options: DENY/SAMEORIGIN instead.")
                                
                                findings.append(SecurityFinding(
                                        url,
                                        "Weak Anti-Clickjacking Configuration",
                                        f"X-Frame-Options: {xfo_header} (deprecated/incomplete protection)",
                                        impact,
                                        "Medium",
                                        detection_method="Anti-Clickjacking Analysis",
                                        response_obj=response,
                                        remediation=remediation,
                                        extracted_data=extracted_data
                                ))
                        
                        # Check for invalid values
                        elif xfo_upper not in ['DENY', 'SAMEORIGIN']:
                                extracted_data["risk_level"] = "High"
                                impact = (f"X-Frame-Options header has invalid value '{xfo_header}'. "
                                          "This provides no protection against clickjacking attacks.")
                                remediation = ("Set X-Frame-Options to either 'DENY' (prevents all framing) "
                                              "or 'SAMEORIGIN' (allows framing only from same origin).")
                                
                                findings.append(SecurityFinding(
                                        url,
                                        "Invalid Anti-Clickjacking Configuration",
                                        f"X-Frame-Options: {xfo_header} (invalid value)",
                                        impact,
                                        "High",
                                        detection_method="Anti-Clickjacking Analysis",
                                        response_obj=response,
                                        remediation=remediation,
                                        extracted_data=extracted_data
                                ))
                        
                        # Valid configuration - no finding needed, but add informational note
                        else:
                                findings.append(SecurityFinding(
                                        url,
                                        "Anti-Clickjacking Protection Enabled",
                                        f"X-Frame-Options: {xfo_header} properly configured",
                                        "The application has proper clickjacking protection enabled.",
                                        "Info",
                                        detection_method="Anti-Clickjacking Analysis",
                                        response_obj=response,
                                        extracted_data=extracted_data
                                ))
                
                # CASE 3: CSP frame-ancestors present but X-Frame-Options missing
                elif frame_ancestors and not xfo_header:
                        extracted_data = {
                                "x_frame_options_present": False,
                                "x_frame_options_value": None,
                                "csp_frame_ancestors_present": True,
                                "csp_frame_ancestors_value": frame_ancestors,
                                "frame_breaking_js_detected": has_frame_breaking_js
                        }
                        
                        # Check CSP frame-ancestors configuration
                        frame_ancestors_lower = frame_ancestors.lower()
                        
                        if "'none'" in frame_ancestors_lower:
                                # Most secure
                                findings.append(SecurityFinding(
                                        url,
                                        "Anti-Clickjacking Protection (CSP)",
                                        f"CSP frame-ancestors: {frame_ancestors} (secure configuration)",
                                        "The application uses CSP frame-ancestors directive for clickjacking protection.",
                                        "Info",
                                        detection_method="Anti-Clickjacking Analysis",
                                        response_obj=response,
                                        extracted_data=extracted_data
                                ))
                        
                        elif "'self'" in frame_ancestors_lower:
                                # Moderately secure
                                findings.append(SecurityFinding(
                                        url,
                                        "Anti-Clickjacking Protection (CSP)",
                                        f"CSP frame-ancestors: {frame_ancestors} (moderate configuration)",
                                        "The application uses CSP frame-ancestors directive allowing same-origin framing.",
                                        "Info",
                                        detection_method="Anti-Clickjacking Analysis",
                                        response_obj=response,
                                        extracted_data=extracted_data
                                ))
                        
                        elif any(domain in frame_ancestors_lower for domain in ['*', 'http://', 'https://']):
                                # Potentially dangerous if too permissive
                                extracted_data["risk_level"] = "Medium"
                                
                                findings.append(SecurityFinding(
                                        url,
                                        "Potentially Weak Anti-Clickjacking Configuration",
                                        f"CSP frame-ancestors: {frame_ancestors} (may be overly permissive)",
                                        "The CSP frame-ancestors directive may allow framing from unintended origins.",
                                        "Medium",
                                        detection_method="Anti-Clickjacking Analysis",
                                        response_obj=response,
                                        remediation="Review CSP frame-ancestors directive to ensure only trusted origins are allowed.",
                                        extracted_data=extracted_data
                                ))
                
                # Additional check: Frame breaking JavaScript as fallback
                if has_frame_breaking_js and not xfo_header and not frame_ancestors:
                        findings.append(SecurityFinding(
                                url,
                                "Frame-Breaking JavaScript Detected (Fallback)",
                                "JavaScript frame-busting code detected but HTTP headers are missing",
                                "While frame-breaking JavaScript provides some protection, it can be bypassed and should be "
                                "supplemented with proper HTTP security headers (X-Frame-Options or CSP frame-ancestors).",
                                "Low",
                                detection_method="Anti-Clickjacking Analysis",
                                response_obj=response,
                                remediation="Add X-Frame-Options or CSP frame-ancestors headers as primary protection, "
                                          "keeping JavaScript as defense-in-depth."
                        ))
                
                # Check for sensitive pages that absolutely need clickjacking protection
                if self._is_sensitive_page(url):
                        if not xfo_header and not frame_ancestors:
                                findings.append(SecurityFinding(
                                        url,
                                        "Critical Clickjacking Risk on Sensitive Page",
                                        f"Sensitive page lacks anti-clickjacking protection: {url}",
                                        "Authentication, payment, and account management pages without clickjacking protection "
                                        "are high-value targets for UI redressing attacks that could lead to account takeover "
                                        "or unauthorized transactions.",
                                        "Critical",
                                        detection_method="Anti-Clickjacking Analysis",
                                        response_obj=response,
                                        remediation="Implement X-Frame-Options: DENY on all sensitive pages immediately."
                                ))
                
                return findings
        
        def _check_x_frame_options(self, url, header_value, config):
                """Validate X-Frame-Options header configuration"""
                findings = []
                
                if header_value:
                        xfo_upper = header_value.upper()
                        
                        if xfo_upper not in ['DENY', 'SAMEORIGIN']:
                                extracted_data = {
                                        "current_value": header_value,
                                        "recommended_values": ["DENY", "SAMEORIGIN"],
                                        "browser_support": "Modern browsers support both DENY and SAMEORIGIN",
                                        "security_impact": "Invalid values provide no clickjacking protection"
                                }
                                
                                findings.append(SecurityFinding(
                                        url,
                                        "Invalid X-Frame-Options Configuration",
                                        f"X-Frame-Options header set to '{header_value}' (invalid)",
                                        "The X-Frame-Options header is set to an invalid value, providing no clickjacking protection.",
                                        "High",
                                        detection_method="Security Header Analysis",
                                        remediation="Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'",
                                        extracted_data=extracted_data
                                ))
                        
                        elif xfo_upper.startswith('ALLOW-FROM'):
                                extracted_data = {
                                        "current_value": header_value,
                                        "deprecated": True,
                                        "browser_support": "Not supported in Chrome, Firefox, Safari",
                                        "alternative": "Use CSP frame-ancestors instead"
                                }
                                
                                findings.append(SecurityFinding(
                                        url,
                                        "Deprecated X-Frame-Options Configuration",
                                        f"X-Frame-Options: {header_value} (deprecated and poorly supported)",
                                        "The ALLOW-FROM directive has limited browser support and is deprecated. "
                                        "Modern browsers ignore this directive, providing no clickjacking protection.",
                                        "Medium",
                                        detection_method="Security Header Analysis",
                                        remediation="Replace with CSP frame-ancestors directive or use X-Frame-Options: DENY/SAMEORIGIN",
                                        extracted_data=extracted_data
                                ))
                
                return findings
        
        def _check_frame_breaking_javascript(self, html_content):
                """
                Check for frame-breaking JavaScript code in HTML content
                """
                if not html_content:
                        return False
                
                # Common frame-busting patterns
                frame_breaking_patterns = [
                    r'if\s*\(\s*top\s*!=\s*self\s*\)',
                    r'if\s*\(\s*self\s*==\s*top\s*\)',
                    r'top\.location\s*=\s*self\.location',
                    r'parent\.location\s*=\s*self\.location',
                    r'window\.location\s*==\s*window\.parent\.location',
                    r'if\s*\(\s*parent\.frames\.length\s*>\s*0\s*\)',
                    r'top\.location\.replace\s*\(\s*location\.href\s*\)',
                    r'if\s*\(\s*parent\.location\s*!=\s*window\.location\s*\)',
                    r'style\s*=\s*"display:\s*none\s*!important"',
                    r'<meta\s+http-equiv=["\']X-Frame-Options["\']',
                    r'break[\s-]+out[\s-]+of[\s-]+frame',
                    r'framekiller',
                    r'frame[\s_]*buster'
                ]
                
                for pattern in frame_breaking_patterns:
                        if re.search(pattern, html_content, re.IGNORECASE):
                                return True
                
                return False
        
        def _is_sensitive_page(self, url):
                """
                Determine if the URL is a sensitive page that requires stronger protection
                """
                url_lower = url.lower()
                
                sensitive_patterns = [
                    r'/login',
                    r'/signin',
                    r'/auth',
                    r'/authenticate',
                    r'/register',
                    r'/signup',
                    r'/account',
                    r'/profile',
                    r'/settings',
                    r'/changepassword',
                    r'/resetpassword',
                    r'/forgotpassword',
                    r'/payment',
                    r'/checkout',
                    r'/billing',
                    r'/cart',
                    r'/transaction',
                    r'/transfer',
                    r'/admin',
                    r'/dashboard',
                    r'/api/.*/user',
                    r'/api/.*/auth',
                    r'/oauth',
                    r'/2fa',
                    r'/mfa'
                ]
                
                for pattern in sensitive_patterns:
                        if re.search(pattern, url_lower):
                                return True
                
                return False

        # -------------------------------------------------------------------------
        # ENHANCED SESSION COOKIE SECURITY ANALYSIS MODULE
        # -------------------------------------------------------------------------
        
        def _check_enhanced_cookie_security(self, url, response):
                """
                Comprehensive session cookie security analysis including:
                - Secure flag presence
                - HttpOnly flag presence
                - SameSite attribute configuration
                - Cookie path scope security
                - Cookie domain scope security
                - Cookie expiration/max-age validation
                - Session fixation vulnerability detection
                - Cookie prefix validation (__Secure-, __Host-)
                """
                findings = []
                
                # Extract domain from URL for scope analysis
                parsed_url = urlparse(url)
                current_domain = parsed_url.netloc
                current_path = parsed_url.path or '/'
                
                # Check if there are any cookies at all
                if not response.cookies:
                        findings.append(SecurityFinding(
                                url, "No Cookies Detected",
                                "No cookies were set in the response",
                                "The application does not set any cookies, which may affect session management functionality.",
                                "Info", detection_method="Enhanced Cookie Analysis",
                                response_obj=response,
                                remediation="If session management is required, implement secure cookie-based sessions."
                        ))
                        return findings
                
                # Track if any authentication/session cookies exist
                auth_cookies = []
                
                for cookie in response.cookies:
                        cookie_name = cookie.name
                        is_session_cookie = any(keyword in cookie_name.lower() for keyword in 
                                                ['session', 'auth', 'token', 'jwt', 'sid', 'sess', 'identity', 'user', 'login'])
                        
                        # Enhanced cookie security checks
                        issues = []
                        recommendations = []
                        severity = "Low"
                        
                        # 1. Secure Flag Check
                        if not cookie.secure:
                                issues.append("Missing 'Secure' flag - cookie can be transmitted over unencrypted HTTP")
                                recommendations.append("Add the 'Secure' flag to ensure cookie is only sent over HTTPS")
                                if is_session_cookie:
                                        severity = "High"
                                else:
                                        severity = "Medium"
                        
                        # 2. HttpOnly Flag Check
                        is_httponly = cookie.has_nonstandard_attr('httponly') or cookie._rest.get('httponly', False)
                        if not is_httponly:
                                issues.append("Missing 'HttpOnly' flag - cookie accessible via JavaScript (XSS risk)")
                                recommendations.append("Add the 'HttpOnly' flag to prevent client-side script access")
                                if is_session_cookie:
                                        severity = "High"
                                elif severity != "High":
                                        severity = "Medium"
                        
                        # 3. SameSite Attribute Check
                        samesite = cookie.get_nonstandard_attr('samesite') or cookie._rest.get('samesite', None)
                        if not samesite:
                                issues.append("Missing 'SameSite' attribute - vulnerable to CSRF attacks")
                                recommendations.append("Set 'SameSite=Lax' or 'SameSite=Strict' to prevent CSRF")
                                severity = "Medium" if severity != "High" else severity
                        elif samesite.lower() == 'none':
                                issues.append("Weak 'SameSite=None' attribute - requires Secure flag and allows CSRF")
                                recommendations.append("Consider using SameSite=Lax or Strict. If SameSite=None is required, ensure Secure flag is set")
                                severity = "Medium" if severity != "High" else severity
                        elif samesite.lower() == 'lax':
                                # Lax is acceptable but less secure than Strict
                                if is_session_cookie:
                                        findings.append(SecurityFinding(
                                                url, "Session Cookie SameSite=Lax",
                                                f"Cookie '{cookie_name}' uses SameSite=Lax (moderate protection)",
                                                "SameSite=Lax provides CSRF protection for top-level navigations but not for all cross-origin requests.",
                                                "Info", detection_method="Enhanced Cookie Analysis",
                                                param_location="Cookie", response_obj=response,
                                                remediation="Consider using SameSite=Strict for critical session cookies if cross-origin access is not required."
                                        ))
                        elif samesite.lower() == 'strict':
                                # This is good - no issue to report
                                pass
                        
                        # 4. Path Scope Security Check
                        cookie_path = cookie.path or '/'
                        if cookie_path == '/':
                                # Cookie is accessible across entire domain - acceptable for many cases
                                if is_session_cookie:
                                        findings.append(SecurityFinding(
                                                url, "Broad Cookie Path Scope",
                                                f"Session cookie '{cookie_name}' is accessible across entire domain (path='/')",
                                                "Cookies with path='/' are accessible to all applications on the same domain, increasing attack surface.",
                                                "Low", detection_method="Enhanced Cookie Analysis",
                                                param_location="Cookie", response_obj=response,
                                                remediation=f"Consider restricting cookie path to the minimum necessary scope."
                                        ))
                        elif cookie_path != current_path and not current_path.startswith(cookie_path):
                                # Cookie might be scoped too narrowly or inappropriately
                                if is_session_cookie:
                                        findings.append(SecurityFinding(
                                                url, "Cookie Path Scope Mismatch",
                                                f"Cookie '{cookie_name}' scoped to path '{cookie_path}' but accessed from '{current_path}'",
                                                "Cookie path scope may prevent proper functionality or indicate misconfiguration.",
                                                "Low", detection_method="Enhanced Cookie Analysis",
                                                param_location="Cookie", response_obj=response,
                                                remediation=f"Review cookie path scope. Ensure path '{cookie_path}' includes all resources that need access."
                                        ))
                        
                        # 5. Domain Scope Security Check
                        cookie_domain = cookie.domain
                        if cookie_domain:
                                # Remove leading dot if present for comparison
                                cookie_domain_clean = cookie_domain.lstrip('.')
                                current_domain_clean = current_domain.split(':')[0]  # Remove port if present
                                
                                # Check if domain is too permissive (wildcard/subdomain wide)
                                if cookie_domain.startswith('.'):
                                        # Domain is set for all subdomains
                                        domain_parts = cookie_domain_clean.split('.')
                                        if len(domain_parts) >= 2:
                                                # Check if it's an open TLD (dangerous)
                                                # This is a simplified check - real TLDs are more complex
                                                if len(domain_parts) == 2 and domain_parts[0] in ['com', 'org', 'net', 'co', 'io', 'app']:
                                                        issues.append(f"Cookie domain '{cookie_domain}' is set on an open TLD - extremely dangerous!")
                                                        recommendations.append(f"Never set cookies on TLDs like '{domain_parts[0]}' as it affects all subdomains")
                                                        severity = "Critical"
                                                else:
                                                        # Check if current domain is a subdomain of cookie domain
                                                        if not current_domain_clean.endswith(cookie_domain_clean):
                                                                issues.append(f"Cookie domain '{cookie_domain}' does not match current domain '{current_domain_clean}'")
                                                                recommendations.append("Ensure cookie domain matches the current domain or a parent domain")
                                                                severity = "Medium" if severity != "Critical" else severity
                                                        elif cookie_domain_clean != current_domain_clean:
                                                                # Cookie set for a broader domain (all subdomains)
                                                                if is_session_cookie:
                                                                        findings.append(SecurityFinding(
                                                                                url, "Broad Session Cookie Domain Scope",
                                                                                f"Session cookie '{cookie_name}' set for all subdomains: {cookie_domain}",
                                                                                "Cookies set for all subdomains increase attack surface - compromise of any subdomain can access the session cookie.",
                                                                                "Medium", detection_method="Enhanced Cookie Analysis",
                                                                                param_location="Cookie", response_obj=response,
                                                                                remediation="Restrict cookie domain to the minimum necessary subdomain. Use domain='currentdomain.com' without leading dot for exact domain matching."
                                                                        ))
                                else:
                                        # No leading dot - exact domain matching only
                                        if cookie_domain_clean != current_domain_clean:
                                                issues.append(f"Cookie domain '{cookie_domain}' does not match current domain '{current_domain_clean}'")
                                                recommendations.append("Cookie domain should match the current domain")
                                                severity = "Medium" if severity != "High" else severity
                        
                        # 6. Cookie Expiration / Max-Age Security Check
                        expiration_issues = self._check_cookie_expiration(cookie, cookie_name, is_session_cookie)
                        if expiration_issues:
                                issues.extend(expiration_issues['issues'])
                                recommendations.extend(expiration_issues['recommendations'])
                                if expiration_issues.get('severity') and expiration_issues['severity'] in ['High', 'Critical']:
                                        severity = expiration_issues['severity']
                        
                        # 7. Session Fixation Vulnerability Check
                        if is_session_cookie and self._check_session_fixation_vulnerability(cookie):
                                issues.append("Session cookie lacks proper regeneration indicators - vulnerable to session fixation")
                                recommendations.append("Regenerate session IDs after authentication and on privilege level changes")
                                severity = "High" if severity != "Critical" else severity
                        
                        # Create finding if issues exist
                        if issues:
                                # Prepare detailed extracted data for report
                                extracted_data = {
                                        "cookie_name": cookie_name,
                                        "secure_flag": cookie.secure,
                                        "httponly_flag": is_httponly,
                                        "samesite_value": samesite,
                                        "path_scope": cookie.path or '/',
                                        "domain_scope": cookie.domain or current_domain,
                                        "expiration": self._get_cookie_expiration_details(cookie),
                                        "is_session_cookie": is_session_cookie,
                                        "issues_found": issues,
                                        "recommendations": recommendations
                                }
                                
                                finding = SecurityFinding(
                                        url,
                                        "Weak Session Cookie Configuration" if is_session_cookie else "Weak Cookie Configuration",
                                        f"Cookie '{cookie_name}': {'; '.join(issues[:3])}{'...' if len(issues) > 3 else ''}",
                                        f"Cookie security issues detected: {'; '.join(issues)}. " +
                                        f"Attackers could exploit these weaknesses for session hijacking, CSRF, or session fixation attacks.",
                                        severity,
                                        detection_method="Enhanced Cookie Analysis",
                                        param_location="Cookie",
                                        response_obj=response,
                                        remediation='; '.join(recommendations[:3]) + ("..." if len(recommendations) > 3 else ""),
                                        extracted_data=extracted_data
                                )
                                findings.append(finding)
                        
                        # Track auth cookies for summary
                        if is_session_cookie:
                                auth_cookies.append(cookie_name)
                        
                        # 8. Cookie Prefix Validation (__Secure- and __Host-)
                        findings.extend(self._check_cookie_prefixes_enhanced(url, cookie, response))
                
                # 9. Session Management Summary Finding
                if auth_cookies:
                        # Check if any authentication cookie is properly configured
                        properly_configured = False
                        for cookie in response.cookies:
                                if any(kw in cookie.name.lower() for kw in ['session', 'auth', 'token', 'jwt', 'sid']):
                                        if self._is_cookie_properly_configured(cookie):
                                                properly_configured = True
                                                break
                        
                        if not properly_configured:
                                findings.append(SecurityFinding(
                                        url,
                                        "Session Management Security Issues",
                                        f"Authentication cookies ({', '.join(auth_cookies[:3])}) have security misconfigurations",
                                        "Session cookies missing Secure, HttpOnly, or SameSite attributes are vulnerable to hijacking and CSRF attacks.",
                                        "High",
                                        detection_method="Enhanced Cookie Analysis",
                                        response_obj=response,
                                        remediation="Review all session cookie configurations and implement Secure, HttpOnly, and SameSite=Strict flags."
                                ))
                
                # If no cookies were analyzed (shouldn't happen due to early check)
                if not findings and response.cookies:
                        findings.append(SecurityFinding(
                                url,
                                "Cookie Security Analysis Complete",
                                f"Analyzed {len(response.cookies)} cookie(s), all properly configured",
                                "All cookies have appropriate security flags configured.",
                                "Info", detection_method="Enhanced Cookie Analysis",
                                response_obj=response
                        ))
                
                return findings
        
        def _check_cookie_expiration(self, cookie, cookie_name, is_session_cookie):
                """
                Check cookie expiration and max-age security
                """
                result = {"issues": [], "recommendations": [], "severity": None}
                
                # Check for session cookie (no expiration)
                if not cookie.expires:
                        if is_session_cookie:
                                # Session cookies are generally OK but need proper flags
                                pass
                        else:
                                result["issues"].append("Non-session cookie has no expiration (persists until browser close)")
                                result["recommendations"].append("Set an appropriate Max-Age or Expires attribute for non-session cookies")
                                result["severity"] = "Low"
                else:
                        # Parse expiration
                        try:
                                # Convert expires to datetime if it's a string
                                if isinstance(cookie.expires, str):
                                        # Handle different date formats
                                        from email.utils import parsedate_to_datetime
                                        expires_dt = parsedate_to_datetime(cookie.expires)
                                else:
                                        # Assume it's a timestamp
                                        expires_dt = datetime.fromtimestamp(cookie.expires, tz=timezone.utc)
                                
                                now = datetime.now(timezone.utc)
                                time_until_expiry = (expires_dt - now).total_seconds()
                                time_until_expiry_days = time_until_expiry / 86400
                                
                                # Check for excessively long expiration (90+ days)
                                if time_until_expiry_days > 90:
                                        result["issues"].append(f"Cookie expires in {int(time_until_expiry_days)} days (excessively long)")
                                        result["recommendations"].append("Set shorter expiration periods (max 30-90 days) for session cookies")
                                        if is_session_cookie:
                                                result["severity"] = "Medium"
                                
                                # Check for already expired cookies
                                elif time_until_expiry < 0:
                                        result["issues"].append("Cookie is already expired")
                                        result["recommendations"].append("Remove expired cookies from response headers")
                                        result["severity"] = "Low"
                                
                                # Check for very short expiration (less than 1 hour) for session cookies
                                elif is_session_cookie and time_until_expiry < 3600:
                                        result["issues"].append(f"Session cookie expires in {int(time_until_expiry/60)} minutes (very short)")
                                        result["recommendations"].append("Extend session lifetime to reduce user disruption")
                                        result["severity"] = "Low"
                                        
                        except Exception as e:
                                # If we can't parse expiration, just note it
                                pass
                
                # Check for max-age attribute (more modern than Expires)
                max_age = cookie._rest.get('max-age', None) if hasattr(cookie, '_rest') else None
                if max_age:
                        try:
                                max_age_seconds = int(max_age)
                                max_age_days = max_age_seconds / 86400
                                
                                if max_age_days > 90:
                                        result["issues"].append(f"Cookie max-age is {max_age_days:.0f} days (excessively long)")
                                        result["recommendations"].append("Reduce max-age to 90 days or less")
                                        if is_session_cookie and result["severity"] != "Critical":
                                                result["severity"] = "Medium"
                                elif max_age_seconds == 0:
                                        # This is a deletion cookie
                                        pass
                        except:
                                pass
                
                return result if result["issues"] else None
        
        def _check_session_fixation_vulnerability(self, cookie):
                """
                Check for potential session fixation vulnerabilities
                """
                # Heuristic: Check if the session cookie has predictable patterns
                cookie_name = cookie.name.lower()
                cookie_value = cookie.value
                
                # Look for common session fixation indicators
                fixation_indicators = [
                    len(cookie_value) < 16,  # Too short
                    re.match(r'^[0-9]+$', cookie_value) is not None,  # Only numbers
                    re.match(r'^[a-z]+$', cookie_value) is not None,  # Only lowercase letters
                    re.match(r'^PHPSESSID', cookie_name) is not None,  # PHP default (often predictable)
                    'jsessionid' in cookie_name,  # Java default
                    'aspsessionid' in cookie_name,  # ASP default
                ]
                
                # If any indicators match, potential vulnerability
                return any(fixation_indicators)
        
        def _get_cookie_expiration_details(self, cookie):
                """
                Get human-readable expiration details for a cookie
                """
                if not cookie.expires:
                        return "Session cookie (expires when browser closes)"
                
                try:
                        if isinstance(cookie.expires, str):
                                from email.utils import parsedate_to_datetime
                                expires_dt = parsedate_to_datetime(cookie.expires)
                        else:
                                expires_dt = datetime.fromtimestamp(cookie.expires, tz=timezone.utc)
                        
                        now = datetime.now(timezone.utc)
                        time_until = (expires_dt - now).total_seconds()
                        
                        if time_until < 0:
                                return f"Expired on {expires_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}"
                        elif time_until < 86400:
                                hours = int(time_until / 3600)
                                return f"Expires in {hours} hours"
                        else:
                                days = int(time_until / 86400)
                                return f"Expires in {days} days"
                except:
                        return "Unknown expiration"
        
        def _is_cookie_properly_configured(self, cookie):
                """
                Check if a cookie is properly configured with security attributes
                """
                is_httponly = cookie.has_nonstandard_attr('httponly') or cookie._rest.get('httponly', False)
                samesite = cookie.get_nonstandard_attr('samesite') or cookie._rest.get('samesite', None)
                
                # Proper configuration requires Secure, HttpOnly, and SameSite (Lax or Strict)
                return cookie.secure and is_httponly and samesite and samesite.lower() in ['lax', 'strict']
        
        def _check_cookie_prefixes_enhanced(self, url, cookie, response):
                """
                Enhanced check for proper usage of cookie prefixes: __Secure- and __Host-
                
                According to RFC 6265bis:
                - __Secure- prefix requires the cookie to have the Secure flag and be set from an HTTPS origin
                - __Host- prefix requires Secure flag, no Domain attribute, and Path must be exactly "/"
                """
                findings = []
                cookie_name = cookie.name
                
                # Check for __Secure- prefix
                if cookie_name.startswith('__Secure-'):
                    issues = []
                    
                    # Must have Secure flag
                    if not cookie.secure:
                        issues.append("Missing Secure flag (required for __Secure- prefix)")
                    
                    # Should be set from HTTPS origin
                    if response.url and not response.url.startswith('https'):
                        issues.append("Cookie with __Secure- prefix set over non-HTTPS connection")
                    
                    if issues:
                        findings.append(SecurityFinding(
                            url,
                            "Cookie Prefix Violation: __Secure-",
                            f"Cookie '{cookie_name}' has __Secure- prefix but: {'; '.join(issues)}",
                            "Cookies with __Secure- prefix must always have the Secure flag and be set from HTTPS origins. "
                            "Without these requirements, the prefix provides no additional security guarantees.",
                            "High",
                            detection_method="Cookie Prefix Analysis",
                            param_location="Cookie",
                            response_obj=response,
                            remediation="Ensure __Secure- prefixed cookies are only set over HTTPS and always include the Secure flag."
                        ))
                
                # Check for __Host- prefix
                elif cookie_name.startswith('__Host-'):
                    issues = []
                    
                    # Must have Secure flag
                    if not cookie.secure:
                        issues.append("Missing Secure flag (required for __Host- prefix)")
                    
                    # Must not have Domain attribute
                    if cookie.domain:
                        issues.append(f"Has Domain attribute '{cookie.domain}' (__Host- prefix requires no Domain attribute)")
                    
                    # Path must be exactly "/"
                    if cookie.path != '/':
                        issues.append(f"Path is '{cookie.path}' but must be exactly '/' for __Host- prefix")
                    
                    # Should be set from HTTPS origin
                    if response.url and not response.url.startswith('https'):
                        issues.append("Cookie with __Host- prefix set over non-HTTPS connection")
                    
                    if issues:
                        findings.append(SecurityFinding(
                            url,
                            "Cookie Prefix Violation: __Host-",
                            f"Cookie '{cookie_name}' has __Host- prefix but: {'; '.join(issues)}",
                            "The __Host- prefix provides the strongest security guarantees: Secure flag, no Domain attribute, "
                            "and Path must be exactly '/'. Violations weaken cookie isolation and security.",
                            "Critical",
                            detection_method="Cookie Prefix Analysis",
                            param_location="Cookie",
                            response_obj=response,
                            remediation="For __Host- prefixed cookies: always set Secure flag, never include Domain attribute, and set Path='/'."
                        ))
                
                # Advisory for session cookies that could benefit from prefixes
                elif any(keyword in cookie_name.lower() for keyword in ['session', 'auth', 'token', 'jwt', 'sid']):
                    if not cookie_name.startswith('__Secure-') and not cookie_name.startswith('__Host-'):
                        if cookie.secure:
                            findings.append(SecurityFinding(
                                url,
                                "Missing Cookie Prefix for Secure Cookie",
                                f"Session cookie '{cookie_name}' has Secure flag but lacks __Secure- or __Host- prefix",
                                "Authentication and session cookies with Secure flag should use __Secure- or __Host- prefixes "
                                "to prevent cookie overriding attacks and enforce origin isolation.",
                                "Medium",
                                detection_method="Cookie Prefix Analysis",
                                param_location="Cookie",
                                response_obj=response,
                                remediation="Add __Secure- prefix to this cookie (or __Host- for stricter isolation) and "
                                          "ensure all prefix requirements are met."
                            ))
                
                return findings

        # -------------------------------------------------------------------------
        # Existing SSL/TLS Analysis Modules (kept as is from original)
        # -------------------------------------------------------------------------

        def _check_comprehensive_ssl_tls(self, hostname):
                """Comprehensive SSL/TLS security validation (same as original)"""
                findings = []
                
                try:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        
                        with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                                        cert = ssock.getpeercert()
                                        cipher = ssock.cipher()
                                        tls_version = ssock.version()
                                        
                                        findings.extend(self._check_certificate_validity(hostname, cert))
                                        findings.extend(self._check_certificate_trust(hostname, cert))
                                        findings.extend(self._check_tls_version_security(hostname, tls_version))
                                        findings.extend(self._check_cipher_security(hostname, cipher))
                                        findings.extend(self._enumerate_tls_versions_and_ciphers(hostname))
                                        
                except socket.timeout:
                        findings.append(SecurityFinding(
                                f"https://{hostname}", "SSL/TLS Connection Timeout",
                                f"Connection to {hostname}:443 timed out",
                                "Unable to perform SSL/TLS validation due to connection timeout.",
                                "Info", detection_method="SSL Handshake"
                        ))
                except ConnectionRefusedError:
                        findings.append(SecurityFinding(
                                f"https://{hostname}", "SSL/TLS Port Closed",
                                f"Port 443 on {hostname} is not accepting connections",
                                "HTTPS service may not be running on this host.",
                                "Info", detection_method="Port Scan"
                        ))
                except Exception as e:
                        findings.append(SecurityFinding(
                                f"https://{hostname}", "SSL/TLS Analysis Error",
                                f"Error during SSL/TLS analysis: {str(e)[:100]}",
                                "Unable to complete comprehensive SSL/TLS validation.",
                                "Low", detection_method="SSL Analysis"
                        ))
                
                return findings

        def _check_certificate_validity(self, hostname, cert):
                """Check certificate expiration dates and validity period"""
                findings = []
                
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                now = datetime.now()
                
                days_until_expiry = (not_after - now).days
                
                if days_until_expiry < 0:
                        findings.append(SecurityFinding(
                                f"https://{hostname}", "SSL Certificate Expired",
                                f"Certificate expired on {not_after.strftime('%Y-%m-%d')}",
                                "An expired certificate causes browser security warnings and indicates poor certificate management practices.",
                                "High", detection_method="Certificate Validation",
                                remediation="Renew the SSL certificate immediately from a trusted Certificate Authority."
                        ))
                elif days_until_expiry < 30:
                        findings.append(SecurityFinding(
                                f"https://{hostname}", "SSL Certificate Expiring Soon",
                                f"Certificate expires in {days_until_expiry} days (on {not_after.strftime('%Y-%m-%d')})",
                                "Certificate expiration is approaching, which may cause service disruption if not renewed.",
                                "Medium", detection_method="Certificate Validation",
                                remediation="Renew the SSL certificate within the next 30 days to avoid expiration."
                        ))
                
                return findings

        def _check_certificate_trust(self, hostname, cert):
                """Check certificate chain trust and issuer validation"""
                findings = []
                
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                
                common_name = subject.get('commonName', 'Unknown')
                issuer_cn = issuer.get('commonName', 'Unknown')
                
                if cert['subject'] == cert['issuer']:
                        findings.append(SecurityFinding(
                                f"https://{hostname}", "Self-Signed SSL Certificate",
                                f"Certificate is self-signed (CN={common_name})",
                                "Self-signed certificates are not trusted by browsers and are vulnerable to man-in-the-middle attacks.",
                                "High", detection_method="Certificate Validation",
                                remediation="Obtain a certificate from a trusted Certificate Authority (CA) such as Let's Encrypt, DigiCert, or Comodo."
                        ))
                
                return findings

        def _check_tls_version_security(self, hostname, tls_version):
                """Check TLS version security and deprecation status"""
                findings = []
                
                if tls_version in self.tls_security_levels:
                        config = self.tls_security_levels[tls_version]
                        
                        if config['deprecated']:
                                severity = config['severity']
                                cve_ref = config.get('cve', 'N/A')
                                
                                findings.append(SecurityFinding(
                                        f"https://{hostname}", f"Insecure TLS Version: {tls_version}",
                                        f"Server supports {tls_version} which is deprecated and vulnerable (CVE: {cve_ref})",
                                        f"{tls_version} has known cryptographic vulnerabilities. These versions expose users to man-in-the-middle attacks and data decryption.",
                                        severity, detection_method="TLS Version Detection",
                                        remediation=f"Disable {tls_version} on the server. Enable only TLSv1.2 and TLSv1.3."
                                ))
                
                return findings

        def _check_cipher_security(self, hostname, cipher):
                """Check the negotiated cipher suite for security issues"""
                findings = []
                
                if not cipher:
                        return findings
                
                cipher_name = cipher[0]
                cipher_bits = cipher[2]
                
                for weak_pattern, config in self.weak_ciphers.items():
                        if weak_pattern in cipher_name.upper():
                                severity = config['severity']
                                reason = config['reason']
                                
                                findings.append(SecurityFinding(
                                        f"https://{hostname}", f"Weak Cipher Suite: {cipher_name}",
                                        f"Server negotiated weak cipher: {cipher_name} ({reason})",
                                        f"The connection uses {cipher_name}, which has known vulnerabilities: {reason}. "
                                        f"This allows attackers to potentially decrypt or manipulate the encrypted traffic.",
                                        severity, detection_method="Cipher Analysis",
                                        remediation="Disable weak ciphers on the server. Use only modern ciphers like AES-GCM, ChaCha20-Poly1305."
                                ))
                                break
                
                if cipher_bits < 128:
                        findings.append(SecurityFinding(
                                f"https://{hostname}", "Weak Encryption Key Strength",
                                f"Cipher uses {cipher_bits}-bit encryption (weak)",
                                "Encryption keys with less than 128 bits are vulnerable to brute force attacks.",
                                "High", detection_method="Cipher Analysis",
                                remediation="Configure server to use only ciphers with at least 128-bit encryption keys."
                        ))
                
                return findings

        def _enumerate_tls_versions_and_ciphers(self, hostname):
                """Enumerate supported TLS versions"""
                findings = []
                
                tls_versions_to_test = {
                    ssl.PROTOCOL_TLSv1_2: 'TLSv1.2',
                    ssl.PROTOCOL_TLSv1_1: 'TLSv1.1',
                    ssl.PROTOCOL_TLSv1: 'TLSv1.0',
                    ssl.PROTOCOL_SSLv3: 'SSLv3'
                }
                
                supported_versions = []
                
                for proto, version_name in tls_versions_to_test.items():
                        try:
                                context = ssl.SSLContext(proto)
                                context.check_hostname = False
                                context.verify_mode = ssl.CERT_NONE
                                
                                with socket.create_connection((hostname, 443), timeout=5) as sock:
                                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                                                supported_versions.append(version_name)
                        except (ssl.SSLError, socket.error):
                                pass
                
                if len(supported_versions) > 1:
                        insecure_versions = [v for v in supported_versions 
                                           if v in ['SSLv3', 'TLSv1.0', 'TLSv1.1']]
                        
                        if insecure_versions:
                                findings.append(SecurityFinding(
                                        f"https://{hostname}", "Multiple Insecure TLS Versions Supported",
                                        f"Server supports insecure versions: {', '.join(insecure_versions)}",
                                        "Supporting multiple TLS versions including deprecated ones increases attack surface.",
                                        "High", detection_method="TLS Enumeration",
                                        remediation="Disable all TLS versions below 1.2. Configure server to only support TLSv1.2 and TLSv1.3."
                                ))
                
                return findings

        # -------------------------------------------------------------------------
        # Other Analysis Modules (from original, kept as is)
        # -------------------------------------------------------------------------

        def _check_transport_security(self, url, response, history):
                findings = []
                parsed = urlparse(url)

                if parsed.scheme == 'http':
                        if history and any(h.status_code in [301, 302, 303, 307, 308] for h in history):
                                if response.url.startswith('https'):
                                        if parsed.query:
                                                findings.append(SecurityFinding(
                                                        url, "Insecure Redirect", "HTTP to HTTPS redirection detected with query parameters",
                                                        "Application redirects HTTP to HTTPS, ensure sensitive params are not leaked in initial query.", "Low",
                                                        detection_method="Header Analysis", response_obj=response,
                                                        remediation="Ensure the application does not process or log sensitive query parameters during the redirect."
                                                ))
                                else:
                                        findings.append(SecurityFinding(
                                                url, "Unencrypted Traffic", "Endpoint accessible via plain HTTP",
                                                "Sensitive data could be intercepted in transit.", "High",
                                                detection_method="Protocol Inspection", response_obj=response,
                                                remediation="Configure the server to force HTTPS connections."
                                        ))
                        else:
                                findings.append(SecurityFinding(
                                        url, "Unencrypted Traffic", "No HTTPS enforcement detected",
                                        "Resource is served over plain HTTP without redirecting to HTTPS.", "High",
                                        detection_method="Protocol Inspection", response_obj=response,
                                        remediation="Enable HSTS and redirect all HTTP traffic to HTTPS."
                                        ))
                return findings

        def _check_sensitive_data_in_transit(self, url):
                findings = []
                parsed = urlparse(url)
                params = parse_qs(parsed.query)

                for key, values in params.items():
                        key_lower = key.lower()
                        if any(keyword in key_lower for keyword in self.sensitive_keywords):
                                findings.append(SecurityFinding(
                                        url, "Sensitive Data in Transit", 
                                        f"Query parameter '{key}' contains potential sensitive data",
                                        "Credentials or tokens should not be transmitted in URL query parameters.", "High",
                                        detection_method="Query Parameter Analysis", param_location="Query",
                                        remediation="Move sensitive parameters to the POST body or headers."
                                ))
                return findings

        def _check_info_disclosure(self, url, response):
                findings = []
                headers_to_check = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Pingback']

                for header in headers_to_check:
                        if header in response.headers:
                                val = response.headers[header]
                                findings.append(SecurityFinding(
                                        url, "Server Information Disclosure", 
                                        f"{header}: {val}",
                                        "Disclosing specific technology versions helps attackers target known vulnerabilities.", "Low",
                                        detection_method="Header Analysis", response_obj=response,
                                        remediation="Configure the web server to suppress version headers."
                                ))
                return findings

        def _check_error_leakage(self, url, response):
                findings = []
                if response.status_code >= 400:
                        content = response.text
                        for pattern in self.framework_error_patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                        findings.append(SecurityFinding(
                                                url, "Error Information Leakage", 
                                                f"Pattern '{pattern}' found in {response.status_code} response body",
                                                "Error responses contain technical details (stack traces, paths) useful for attackers.", "Medium",
                                                detection_method="Content Regex Analysis", response_obj=response,
                                                remediation="Disable detailed error messages in production environments."
                                        ))
                                        break
                return findings

        def _check_payment_security(self, url, response):
                findings = []
                path = urlparse(url).path.lower()

                if any(kw in path for kw in self.payment_keywords):
                        if not url.startswith('https'):
                                findings.append(SecurityFinding(
                                        url, "Insecure Payment Transit", 
                                        "Payment endpoint accessible over HTTP",
                                        "Payment data must be transmitted exclusively over HTTPS.", "Critical",
                                        detection_method="Protocol Inspection", response_obj=response,
                                        remediation="Enforce TLS on all payment processing endpoints."
                                ))

                        cc_pattern = r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"
                        match = re.search(cc_pattern, response.text)
                        if match:
                                extracted = {
                                        "type": "Credit Card Number",
                                        "strategy": "Regex Pattern Match",
                                        "preview": match.group(0),
                                        "full_content_saved": False,
                                        "saved_path": None
                                }
                                findings.append(SecurityFinding(
                                        url, "Payment Data Exposure", 
                                        "Potential credit card number found in response body",
                                        "Application may be echoing sensitive payment data.", "Critical",
                                        detection_method="Content Regex Analysis", response_obj=response,
                                        extracted_data=extracted,
                                        remediation="Ensure sensitive payment data is masked or not logged in responses."
                                ))
                return findings

        def _check_cdn_waf(self, url, response):
                findings = []
                headers_lower = {k.lower(): v for k, v in response.headers.items()}
                detected = []
                for provider, sigs in self.cdn_waf_signatures.items():
                        for sig in sigs:
                                if sig in headers_lower:
                                        detected.append(provider)
                                        break

                if detected:
                        findings.append(SecurityFinding(
                                url, "CDN / WAF Detected", 
                                f"Infrastructure protected by: {', '.join(detected)}",
                                "Understanding the infrastructure layer helps assess exposure to DDoS or edge misconfigurations.", "Info",
                                detection_method="Header Fingerprinting", response_obj=response
                        ))
                return findings

        def _check_backup_files(self, url):
                findings = []
                parsed = urlparse(url)
                base_path = parsed.path
                if not base_path or base_path == '/':
                        return []

                for ext in self.backup_extensions:
                        clean_url = url.split('?')[0]
                        backup_url = clean_url + ext

                        try:
                                resp = self.session.head(backup_url, timeout=self.timeout, allow_redirects=True)
                                if resp.status_code == 200:
                                        findings.append(SecurityFinding(
                                                backup_url, "Backup File Exposure", 
                                                f"Publicly accessible file found with extension {ext}",
                                                "Backup files may contain source code, credentials, or database dumps.", "High",
                                                detection_method="File Probing", param_location="Path", response_obj=resp,
                                                remediation="Remove backup files from public web directories."
                                        ))
                        except requests.RequestException:
                                continue
                return findings

        def _check_mixed_content(self, url, response):
                """Scan HTML responses for mixed content"""
                findings = []
                
                content_type = response.headers.get('Content-Type', '').lower()
                if 'text/html' not in content_type and 'application/xhtml+xml' not in content_type:
                        return findings
                
                response_text = response.text
                mixed_content_found = {}
                
                for resource_type, config in self.mixed_content_patterns.items():
                        pattern = config['pattern']
                        matches = re.findall(pattern, response_text, re.IGNORECASE)
                        
                        if matches:
                                unique_matches = list(dict.fromkeys(matches))
                                mixed_content_found[resource_type] = {
                                    'urls': unique_matches[:10],
                                    'count': len(unique_matches),
                                    'type': config['type'],
                                    'severity': config['severity'],
                                    'remediation': config['remediation']
                                }
                
                for resource_type, data in mixed_content_found.items():
                        severity = data['severity']
                        sample_urls = data['urls'][:3]
                        indicator = f"Found {data['count']} HTTP {data['type']} resource(s) on HTTPS page"
                        if sample_urls:
                                indicator += f" (sample: {', '.join(sample_urls)})"
                        
                        impact = f"Loading {resource_type} resources over HTTP on an HTTPS page compromises the security guarantees of HTTPS and enables man-in-the-middle attacks."
                        
                        extracted = {
                            "mixed_content_type": data['type'],
                            "total_count": data['count'],
                            "sample_urls": data['urls'][:10],
                            "remediation_details": data['remediation']
                        }
                        
                        findings.append(SecurityFinding(
                                url,
                                f"Mixed Content: HTTP {data['type']} on HTTPS Page",
                                indicator,
                                impact,
                                severity,
                                detection_method="HTML Content Analysis",
                                response_obj=response,
                                remediation=data['remediation'],
                                extracted_data=extracted
                        ))
                
                return findings

        def _check_cors_misconfiguration(self, url, response):
                """Check for dangerous CORS misconfigurations"""
                findings = []
                
                acao = response.headers.get('Access-Control-Allow-Origin')
                acac = response.headers.get('Access-Control-Allow-Credentials', '').lower()
                
                if acao == '*':
                        if acac == 'true':
                                findings.append(SecurityFinding(
                                        url,
                                        "Critical CORS Misconfiguration",
                                        "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true",
                                        "This configuration allows any website to make authenticated requests to this endpoint, "
                                        "potentially leading to data theft and unauthorized access.",
                                        "Critical",
                                        detection_method="CORS Header Analysis",
                                        response_obj=response,
                                        remediation="Remove the wildcard origin when credentials are allowed. "
                                                   "Configure a whitelist of trusted origins instead."
                                ))
                
                return findings

        def _check_security_headers(self, url, response):
                """Comprehensive security headers analysis"""
                findings = []
                
                headers_lower = {k.lower(): v for k, v in response.headers.items()}
                
                for header_key, header_config in self.security_headers.items():
                    header_value = headers_lower.get(header_key, None)
                    
                    if not header_value and header_config['required']:
                            findings.append(SecurityFinding(
                                url,
                                f"Missing Security Header: {header_config['name']}",
                                f"Required security header '{header_key}' is not present in the response",
                                f"The application is missing the {header_config['name']} header.",
                                header_config['severity'],
                                detection_method="Security Header Analysis",
                                response_obj=response,
                                remediation=header_config['remediation']
                            ))
                
                return findings

        def _check_hsts(self, url, header_value, config):
                """Validate HSTS header configuration"""
                findings = []
                # Simplified for this version
                return None

        def _check_csp(self, url, header_value, config):
                """Validate CSP header configuration"""
                # Simplified for this version
                return None

        def _check_referrer_policy(self, url, header_value, config):
                """Validate Referrer-Policy configuration"""
                # Simplified for this version
                return None

# -----------------------------------------------------------------------------
# Professional Output Functions (unchanged from original)
# -----------------------------------------------------------------------------

def print_banner():
        """Display professional banner"""
        banner = f"""
{Colors.CYAN}{'='*80}{Colors.END}
{Colors.BOLD}{Colors.HEADER}    🔍 PASSIVE HTTP OBSERVER - Security Analysis Tool{Colors.END}
{Colors.CYAN}{'='*80}{Colors.END}
{Colors.DIM}    Version: 3.1 | Author: Security Testing Framework | Mode: Passive Analysis{Colors.END}
{Colors.DIM}    Features: SSL/TLS | Security Headers | CORS | Cookie Security | Mixed Content | CLICKJACKING PROTECTION{Colors.END}
{Colors.CYAN}{'='*80}{Colors.END}
        """
        print(banner)

def print_scan_summary(total_targets, unique_findings, errors, start_time):
        """Print scan summary statistics"""
        duration = (datetime.now() - start_time).total_seconds()

        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        category_counts = {}

        for finding in unique_findings:
                if finding.severity in severity_counts:
                        severity_counts[finding.severity] += 1
                
                category = "Other"
                if "Cookie" in finding.issue_type:
                        category = "Session Management"
                elif "SSL" in finding.issue_type or "TLS" in finding.issue_type:
                        category = "Cryptography & TLS"
                elif "Mixed Content" in finding.issue_type:
                        category = "Mixed Content"
                elif "CORS" in finding.issue_type:
                        category = "CORS Configuration"
                elif "Header" in finding.issue_type:
                        category = "Security Headers"
                elif "Clickjacking" in finding.issue_type or "X-Frame-Options" in finding.issue_type:
                        category = "Clickjacking Protection"
                else:
                        category = "General"
                
                category_counts[category] = category_counts.get(category, 0) + 1

        summary = f"""
{Colors.BOLD}{Colors.CYAN}📊 SCAN SUMMARY{Colors.END}
{Colors.CYAN}{'─'*80}{Colors.END}

{Colors.BOLD}📈 Statistics:{Colors.END}
  • Total Targets Analyzed: {Colors.BOLD}{total_targets}{Colors.END}
  • Total Findings: {Colors.BOLD}{len(unique_findings)}{Colors.END}
  • Connection Errors: {Colors.RED if errors > 0 else Colors.GREEN}{errors}{Colors.END}
  • Scan Duration: {Colors.BOLD}{duration:.2f} seconds{Colors.END}

{Colors.BOLD}🎯 Severity Distribution:{Colors.END}"""

        if severity_counts["Critical"] > 0:
                summary += f"\n  {Icons.CRITICAL} {Colors.RED}{Colors.BOLD}Critical: {severity_counts['Critical']}{Colors.END}"
        if severity_counts["High"] > 0:
                summary += f"\n  {Icons.HIGH} {Colors.RED}High: {severity_counts['High']}{Colors.END}"
        if severity_counts["Medium"] > 0:
                summary += f"\n  {Icons.MEDIUM} {Colors.YELLOW}Medium: {severity_counts['Medium']}{Colors.END}"
        if severity_counts["Low"] > 0:
                summary += f"\n  {Icons.LOW} {Colors.BLUE}Low: {severity_counts['Low']}{Colors.END}"
        if severity_counts["Info"] > 0:
                summary += f"\n  {Icons.INFO} {Colors.DIM}Info: {severity_counts['Info']}{Colors.END}"

        if category_counts:
                summary += f"\n\n{Colors.BOLD}📂 Findings by Category:{Colors.END}"
                for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
                        summary += f"\n  • {category}: {count}"

        if len(unique_findings) == 0:
                summary += f"\n\n  {Icons.SUCCESS} {Colors.GREEN}{Colors.BOLD}No security issues detected!{Colors.END}"

        print(summary)

def print_finding_table(findings):
        """Print findings in a formatted table"""
        if not findings:
                return

        print(f"\n{Colors.BOLD}{Colors.CYAN}🔍 DETAILED FINDINGS{Colors.END}")
        print(f"{Colors.CYAN}{'─'*80}{Colors.END}")

        for idx, finding in enumerate(findings, 1):
                if finding.severity == "Critical":
                        severity_color = Colors.RED
                        icon = Icons.CRITICAL
                elif finding.severity == "High":
                        severity_color = Colors.RED
                        icon = Icons.HIGH
                elif finding.severity == "Medium":
                        severity_color = Colors.YELLOW
                        icon = Icons.MEDIUM
                elif finding.severity == "Low":
                        severity_color = Colors.BLUE
                        icon = Icons.LOW
                else:
                        severity_color = Colors.DIM
                        icon = Icons.INFO

                # Special icon for clickjacking findings
                if "Clickjacking" in finding.issue_type:
                        icon = Icons.CLICKJACK

                print(f"\n{Colors.BOLD}[{idx}] {icon} {severity_color}{finding.severity}{Colors.END} - {finding.issue_type}")
                print(f"  {Colors.DIM}📍 URL:{Colors.END} {finding.url}")
                print(f"  {Colors.DIM}📝 Indicator:{Colors.END} {finding.indicator[:200]}{'...' if len(finding.indicator) > 200 else ''}")
                print(f"  {Colors.DIM}💥 Impact:{Colors.END} {finding.impact[:200]}{'...' if len(finding.impact) > 200 else ''}")
                if finding.remediation:
                        print(f"  {Colors.DIM}🔧 Remediation:{Colors.END} {finding.remediation[:200]}{'...' if len(finding.remediation) > 200 else ''}")
                print(f"  {Colors.CYAN}{'─'*76}{Colors.END}")

def print_errors_table(errors):
        """Print connection errors if any"""
        if not errors:
                return

        print(f"\n{Colors.BOLD}{Colors.RED}⚠️ CONNECTION ERRORS ({len(errors)}){Colors.END}")
        print(f"{Colors.RED}{'─'*80}{Colors.END}")

        for idx, error in enumerate(errors[:10], 1):
                print(f"  {idx}. {error[:120]}{'...' if len(error) > 120 else ''}")

        if len(errors) > 10:
                print(f"  {Colors.DIM}... and {len(errors) - 10} more errors{Colors.END}")

def print_final_status(report_status, output_filename):
        """Print final status message"""
        print(f"\n{Colors.CYAN}{'='*80}{Colors.END}")

        if report_status:
                print(f"{Icons.SUCCESS} {Colors.GREEN}{Colors.BOLD}Analysis completed successfully!{Colors.END}")
        else:
                print(f"{Icons.WARNING} {Colors.YELLOW}{Colors.BOLD}Analysis completed with errors{Colors.END}")

        print(f"{Icons.TARGET} {Colors.BOLD}Report saved to:{Colors.END} {Colors.CYAN}{output_filename}{Colors.END}")
        print(f"{Colors.CYAN}{'='*80}{Colors.END}\n")

# -----------------------------------------------------------------------------
# Main Execution
# -----------------------------------------------------------------------------

def main():
        parser = argparse.ArgumentParser(description="Passive HTTP Observer - Analyze endpoints from Hellhound Spider JSON output.")
        parser.add_argument("file", help="Path to the Hellhound Spider JSON file.")
        parser.add_argument("--check-backups", action="store_true", help="Enable lightweight probing for backup files")
        args = parser.parse_args()

        start_time = datetime.now()
        print_banner()

        targets = []
        errors = []

        try:
                with open(args.file, 'r') as f:
                        data = json.load(f)
                if 'endpoints' in data and isinstance(data['endpoints'], list):
                        for endpoint in data['endpoints']:
                                if 'url' in endpoint:
                                        targets.append(endpoint['url'])
                else:
                        print(f"{Icons.ERROR} {Colors.RED}Error: JSON file does not contain a valid 'endpoints' list.{Colors.END}")
                        return
        except FileNotFoundError:
                print(f"{Icons.ERROR} {Colors.RED}Error: File '{args.file}' not found.{Colors.END}")
                return
        except json.JSONDecodeError:
                print(f"{Icons.ERROR} {Colors.RED}Error: Failed to decode JSON from '{args.file}'.{Colors.END}")
                return

        if not targets:
                print(f"{Icons.ERROR} {Colors.RED}No targets found in the provided file.{Colors.END}")
                return

        targets = list(dict.fromkeys(targets))

        print(f"{Icons.TARGET} {Colors.BOLD}Targets loaded:{Colors.END} {len(targets)} unique endpoints")
        print(f"{Icons.COOKIE} {Colors.BOLD}Enhanced Session Cookie Security:{Colors.END} Enabled (Secure, HttpOnly, SameSite, Path, Domain, Expiration, Session Fixation)")
        print(f"{Icons.CLICKJACK} {Colors.BOLD}Anti-Clickjacking Protection:{Colors.END} Enabled (X-Frame-Options, CSP frame-ancestors, Frame-breaking JS)")
        print(f"\n{Colors.BOLD}Starting analysis...{Colors.END}\n")

        observer = PassiveHttpObserver()
        all_findings = []
        error_list = []

        for idx, target in enumerate(targets, 1):
                print(f"{Colors.DIM}[{idx}/{len(targets)}] Analyzing: {target[:70]}{'...' if len(target) > 70 else ''}{Colors.END}", end="\r")
                try:
                        findings = observer.analyze_target(target, check_backups=args.check_backups)
                        all_findings.extend(findings)
                except Exception as e:
                        err_msg = f"{target} - {str(e)}"
                        error_list.append(err_msg)
                        errors.append(err_msg)

        print()

        unique_findings = list(set(all_findings))
        unique_findings.sort(key=lambda x: (
                {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(x.severity, 5),
                x.url, x.issue_type
        ))

        print_scan_summary(len(targets), unique_findings, len(error_list), start_time)
        print_finding_table(unique_findings)
        print_errors_table(error_list)

        report_status = True if not error_list else False

        final_report = {
                "status": report_status,
                "errors": error_list,
                "gap_reason": None,
                "findings": [f.to_report_dict() for f in unique_findings]
        }

        output_filename = "security_report.json"
        try:
                with open(output_filename, "w") as f:
                        json.dump(final_report, f, indent=4)
                print_final_status(report_status, output_filename)
        except IOError as e:
                print(f"\n{Icons.ERROR} {Colors.RED}Error saving report: {e}{Colors.END}")

if __name__ == "__main__":
        main()
