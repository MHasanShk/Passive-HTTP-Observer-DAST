import requests
import re
import argparse
import json
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs
import certifi
from http.cookies import SimpleCookie

# -----------------------------------------------------------------------------
# Terminal Colors and Styling
# -----------------------------------------------------------------------------

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE   = '\033[94m'
    CYAN   = '\033[96m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    RED    = '\033[91m'
    BOLD   = '\033[1m'
    UNDERLINE = '\033[4m'
    END    = '\033[0m'
    DIM    = '\033[2m'


class Icons:
    """Icons for different finding types"""
    CRITICAL  = "🔴"
    HIGH      = "🟠"
    MEDIUM    = "🟡"
    LOW       = "🔵"
    INFO      = "ℹ️"
    SUCCESS   = "✅"
    ERROR     = "❌"
    WARNING   = "⚠️"
    TARGET    = "🎯"
    COOKIE    = "🍪"
    SSL       = "🔒"
    PAYMENT   = "💳"
    CDN       = "🌐"
    HEADER    = "📋"
    CORS      = "🔓"
    MIXED     = "🔄"
    TLS       = "🔐"
    CLICKJACK = "🖱️"


# -----------------------------------------------------------------------------
# Data Structure for Findings
# -----------------------------------------------------------------------------

class SecurityFinding:
    """Structure to hold a security observation."""

    def __init__(self, url, issue_type, indicator, impact, severity="Medium",
                 detection_method="Analysis", param_location=None, response_obj=None,
                 remediation=None, extracted_data=None):
        self.url             = url
        self.issue_type      = issue_type
        self.indicator       = indicator
        self.impact          = impact
        self.severity        = severity
        self.detection_method = detection_method
        self.param_location  = param_location
        self.response_obj    = response_obj
        self.remediation     = remediation
        self.extracted_data  = extracted_data
        self.timestamp       = datetime.now(timezone.utc).isoformat()

    def _categorise(self):
        t = self.issue_type
        if "Cookie" in t:                                           return "Session Management"
        if "SSL" in t or "TLS" in t or "Certificate" in t:         return "Cryptography"
        if "Info" in t or "Error" in t:                             return "Information Disclosure"
        if "Payment" in t:                                          return "Compliance"
        if "Header" in t or "HSTS" in t or "CSP" in t:             return "Security Headers"
        if "CORS" in t:                                             return "CORS Configuration"
        if "Mixed Content" in t:                                    return "Mixed Content"
        if "Clickjacking" in t or "X-Frame-Options" in t or "Anti-Clickjacking" in t:
                                                                    return "Clickjacking Protection"
        return "General"

    def to_report_dict(self):
        raw_req = raw_resp = resp_time = None
        if self.response_obj:
            req = self.response_obj.request
            host = req.headers.get('Host', urlparse(req.url).netloc)
            ua   = req.headers.get('User-Agent', '')
            raw_req  = f"{req.method} {req.url} HTTP/1.1\nHost: {host}\nUser-Agent: {ua}"
            raw_resp = (f"HTTP/1.1 {self.response_obj.status_code}\n"
                        f"Content-Type: {self.response_obj.headers.get('Content-Type', '')}\n\n"
                        f"{self.response_obj.text[:1000]}...")
            resp_time = self.response_obj.elapsed.total_seconds()

        cve = None
        if "Clickjacking" in self.issue_type:    cve = "CWE-1021"
        elif "Mixed Content" in self.issue_type: cve = "CWE-319"

        return {
            "id": str(uuid.uuid4()),
            "agent_group": "Reconnaissance",
            "sub_agent": "PassiveHttpObserver",
            "vulnerability_type": self.issue_type,
            "category": self._categorise(),
            "severity": self.severity,
            "confidence": "High" if self.severity in ("Critical", "High") else "Medium",
            "target_url": self.url,
            "affected_parameter": self.indicator if self.param_location else None,
            "description": self.impact,
            "observation": f"{self.issue_type} detected: {self.indicator}",
            "timestamp": self.timestamp,
            "proof_of_concept": self._generate_clickjacking_poc() if "Clickjacking" in self.issue_type else None,
            "remediation": self.remediation or "Review the identified security issue and apply best practices.",
            "cve_reference": cve,
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
                "raw_response": raw_resp,
            },
        }

    def _generate_clickjacking_poc(self):
        """Generate a proof-of-concept HTML for a clickjacking vulnerability."""
        if "Clickjacking" not in self.issue_type:
            return None
        return f'''<!DOCTYPE html>
<html>
<head>
  <title>Clickjacking PoC – {self.url}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f0f0f0; }}
    .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 20px;
                  border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,.1); }}
    h1 {{ color: #d32f2f; }}
    .warning {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 20px 0; }}
    .iframe-container {{ position: relative; width: 100%; height: 600px;
                         border: 2px solid #ccc; margin: 20px 0; }}
    iframe {{ width: 100%; height: 100%; border: none; opacity: 0.5; }}
    .deceptive-ui {{ position: absolute; top: 50%; left: 50%;
                     transform: translate(-50%, -50%);
                     background: rgba(255,255,255,.9); padding: 20px; border-radius: 10px;
                     box-shadow: 0 4px 20px rgba(0,0,0,.2); text-align: center;
                     z-index: 20; pointer-events: none; }}
    .deceptive-ui button {{ pointer-events: auto; background: #d32f2f; color: white;
                            font-size: 18px; padding: 15px 30px; border: none;
                            border-radius: 4px; cursor: pointer; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>🔓 Clickjacking Proof of Concept</h1>
    <div class="warning">
      <strong>⚠️ Security Alert:</strong> <strong>{self.url}</strong> is vulnerable to clickjacking.
    </div>
    <h2>Details</h2>
    <ul>
      <li><strong>Target URL:</strong> {self.url}</li>
      <li><strong>Missing Header:</strong> X-Frame-Options or Content-Security-Policy frame-ancestors</li>
      <li><strong>Risk:</strong> Attackers can hide the target site under deceptive UI elements</li>
    </ul>
    <h2>Demonstration</h2>
    <div class="iframe-container">
      <iframe src="{self.url}" sandbox="allow-same-origin allow-scripts allow-forms"></iframe>
      <div class="deceptive-ui">
        <h3>🎁 WIN A FREE PRIZE! 🎁</h3>
        <p>Click to claim your reward!</p>
        <button onclick="alert('⚠️ You clicked on the hidden target website!')">
          CLAIM YOUR PRIZE NOW!
        </button>
      </div>
    </div>
    <h2>Remediation</h2>
    <ul>
      <li>Add <strong>X-Frame-Options: DENY</strong> or <strong>SAMEORIGIN</strong></li>
      <li>Or use <strong>Content-Security-Policy: frame-ancestors \'none\'</strong></li>
    </ul>
  </div>
</body>
</html>'''

    def __repr__(self):
        return f"[{self.severity}] {self.issue_type}: {self.indicator} @ {self.url}"

    def __hash__(self):
        return hash((self.url, self.issue_type, self.indicator))

    def __eq__(self, other):
        if not isinstance(other, SecurityFinding):
            return False
        return (self.url, self.issue_type, self.indicator) == (other.url, other.issue_type, other.indicator)


# -----------------------------------------------------------------------------
# Cookie Parser Helper Class
# -----------------------------------------------------------------------------

class CookieParser:
    """
    Robust cookie parser using http.cookies.SimpleCookie.
    """

    @staticmethod
    def parse_set_cookie_header(header_value: str) -> dict:
        """Parse a single raw Set-Cookie header value."""
        try:
            cookie = SimpleCookie()
            cookie.load(header_value)
            for name, morsel in cookie.items():
                secure_attr = morsel.get('secure', '')
                httponly_attr = morsel.get('httponly', '')
                samesite_attr = morsel.get('samesite', None)
                
                is_secure = secure_attr is not None and secure_attr != ''
                is_httponly = httponly_attr is not None and httponly_attr != ''

                return {
                    'name':     name,
                    'value':    morsel.value,
                    'secure':   is_secure,
                    'httponly': is_httponly,
                    'path':     morsel.get('path', '/') or '/',
                    'domain':   morsel.get('domain', None) or None,
                    'samesite': samesite_attr if samesite_attr else None,
                    'expires':  morsel.get('expires', None) or None,
                    'max-age':  morsel.get('max-age', None) or None,
                    'version':  morsel.get('version', None) or None,
                    'comment':  morsel.get('comment', None) or None,
                    'raw_value': header_value,
                }
        except Exception as e:
            return {
                'name': 'unknown', 'value': header_value,
                'secure': False, 'httponly': False, 'path': '/',
                'domain': None, 'samesite': None, 'expires': None,
                'max-age': None, 'version': None, 'comment': None,
                'raw_value': header_value, 'parse_error': str(e),
            }

    @staticmethod
    def parse_all_cookies(response) -> list:
        """
        Extract and parse every Set-Cookie header from a requests.Response.
        """
        set_cookie_headers = []

        if hasattr(response, 'raw') and hasattr(response.raw, 'headers'):
            raw_hdrs = response.raw.headers
            if hasattr(raw_hdrs, 'getlist'):
                set_cookie_headers = raw_hdrs.getlist('Set-Cookie')

        if not set_cookie_headers and hasattr(response, 'raw') and hasattr(response.raw, 'headers'):
            raw_hdrs = response.raw.headers
            if hasattr(raw_hdrs, 'items'):
                set_cookie_headers = [v for k, v in raw_hdrs.items()
                                      if k.lower() == 'set-cookie']

        if not set_cookie_headers:
            val = response.headers.get('Set-Cookie')
            if val:
                set_cookie_headers = [val]

        cookies = []
        seen_names = set()
        for header in set_cookie_headers:
            info = CookieParser.parse_set_cookie_header(header)
            if info and info['name'] not in seen_names:
                cookies.append(info)
                seen_names.add(info['name'])

        return cookies

    @staticmethod
    def is_httponly(cookie_info: dict) -> bool:
        val = cookie_info.get('httponly', False)
        return bool(val)

    @staticmethod
    def is_secure(cookie_info: dict) -> bool:
        val = cookie_info.get('secure', False)
        return bool(val)

    @staticmethod
    def get_samesite(cookie_info: dict):
        ss = cookie_info.get('samesite', None)
        if ss:
            return ss.strip().capitalize()
        return None

    @staticmethod
    def get_expiration_info(cookie_info: dict) -> dict:
        max_age = cookie_info.get('max-age')
        expires = cookie_info.get('expires')

        if max_age:
            try:
                secs = int(max_age)
                return {'type': 'max-age', 'seconds': secs,
                        'days': secs / 86400, 'is_session': secs <= 0}
            except (ValueError, TypeError):
                pass

        if expires:
            return {'type': 'expires', 'value': expires, 'is_session': False}

        return {'type': 'session', 'is_session': True}


# -----------------------------------------------------------------------------
# Main Observer Module
# -----------------------------------------------------------------------------

class PassiveHttpObserver:

    def __init__(self, timeout=10, user_agent="PassiveHTTPObserver/1.0"):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': user_agent})
        self.cookie_parser = CookieParser()

        self.sensitive_keywords  = ['password', 'passwd', 'secret', 'token',
                                    'api_key', 'ssn', 'credit_card']
        self.payment_keywords    = ['/checkout', '/payment', '/billing',
                                    '/cart', '/api/pay']
        self.framework_error_patterns = [
            r"Stack trace", r"Exception", r"Fatal error", r"SQL syntax",
            r"Warning:\s+\w+", r"Traceback", r"java\.lang\.", r"Newtonsoft\.Json",
            r"org\.apache\.", r"django\.core\.exceptions",
        ]
        self.cdn_waf_signatures = {
            'Cloudflare':    ['cf-ray', 'cf-cache-status'],
            'Akamai':        ['akamai-origin-hop'],
            'Fastly':        ['fastly-debug-digest', 'x-served-by'],
            'AWS CloudFront':['x-amz-cf-id'],
            'Incapsula':     ['incap-ses-601'],
            'F5 BIG-IP':     ['bigipserver'],
        }

        self.mixed_content_patterns = {
            'script':     {'pattern': r'<script[^>]*src=["\'](http://[^"\']+)["\']',
                           'type': 'JavaScript', 'severity': 'High',
                           'remediation': 'Replace HTTP script URLs with HTTPS or use protocol-relative URLs.'},
            'stylesheet': {'pattern': r'<link[^>]*rel=["\']stylesheet["\'][^>]*href=["\'](http://[^"\']+)["\']',
                           'type': 'CSS', 'severity': 'Medium',
                           'remediation': 'Update CSS links to use HTTPS.'},
            'image':      {'pattern': r'<img[^>]*src=["\'](http://[^"\']+)["\']',
                           'type': 'Image', 'severity': 'Low',
                           'remediation': 'Replace HTTP image URLs with HTTPS versions.'},
            'iframe':     {'pattern': r'<iframe[^>]*src=["\'](http://[^"\']+)["\']',
                           'type': 'Iframe', 'severity': 'High',
                           'remediation': 'Update iframe sources to use HTTPS.'},
            'object':     {'pattern': r'<object[^>]*data=["\'](http://[^"\']+)["\']',
                           'type': 'Object/Plugin', 'severity': 'High',
                           'remediation': 'Update object data URLs to use HTTPS.'},
            'form_action':{'pattern': r'<form[^>]*action=["\'](http://[^"\']+)["\']',
                           'type': 'Form Submission', 'severity': 'High',
                           'remediation': 'Update form action URLs to use HTTPS.'},
            'css_background':{'pattern': r'background(-image)?:\s*url\(["\']?(http://[^"\'\)]+)["\']?\)',
                              'type': 'CSS Background Image', 'severity': 'Low',
                              'remediation': 'Update background image URLs to use HTTPS.'},
        }

        self.security_headers = {
            'strict-transport-security': {
                'name': 'HSTS (Strict-Transport-Security)',
                'required': True,
                'severity': 'High',
                'remediation': 'Implement HSTS with max-age ≥ 31536000 and includeSubDomains.',
            },
            'x-content-type-options': {
                'name': 'X-Content-Type-Options',
                'required': True,
                'severity': 'Low',
                'remediation': 'Set X-Content-Type-Options: nosniff.',
            },
        }

    # =========================================================================
    # Helper methods
    # =========================================================================
    
    def _check_frame_breaking_javascript(self, html: str) -> bool:
        """Check if the HTML contains frame-breaking JavaScript."""
        if not html:
            return False
        patterns = [
            r'if\s*\(\s*top\s*!=\s*self\s*\)',
            r'if\s*\(\s*self\s*==\s*top\s*\)',
            r'top\.location\s*=\s*self\.location',
            r'parent\.location\s*=\s*self\.location',
            r'window\.location\s*==\s*window\.parent\.location',
            r'top\.location\.replace\s*\(\s*location\.href\s*\)',
            r'framekiller',
            r'frame[\s_]*buster',
        ]
        return any(re.search(p, html, re.IGNORECASE) for p in patterns)

    def _is_sensitive_page(self, url: str) -> bool:
        """Check if the URL appears to be a sensitive page."""
        patterns = [
            r'/login', r'/signin', r'/auth', r'/register', r'/signup',
            r'/account', r'/profile', r'/settings', r'/changepassword',
            r'/resetpassword', r'/forgotpassword', r'/payment', r'/checkout',
            r'/billing', r'/cart', r'/transaction', r'/transfer', r'/admin',
            r'/dashboard', r'/api/.*/user', r'/api/.*/auth', r'/oauth',
            r'/2fa', r'/mfa',
        ]
        url_lower = url.lower()
        return any(re.search(p, url_lower) for p in patterns)

    # =========================================================================
    # Main analysis workflow
    # =========================================================================

    def analyze_target(self, url: str) -> list:
        findings = []
        parsed_url = urlparse(url)
        base_domain = parsed_url.netloc

        try:
            response = self.session.get(url, timeout=self.timeout,
                                        allow_redirects=True)
            history  = response.history

            findings.extend(self._check_transport_security(url, response, history))
            findings.extend(self._check_enhanced_cookie_security(url, response))
            findings.extend(self._check_sensitive_data_in_transit(url))
            findings.extend(self._check_info_disclosure(url, response))
            findings.extend(self._check_payment_security(url, response))
            findings.extend(self._check_error_leakage(url, response))
            findings.extend(self._check_cdn_waf(url, response))
            findings.extend(self._check_security_headers(url, response))
            findings.extend(self._check_anti_clickjacking_headers(url, response))
            findings.extend(self._check_cors_misconfiguration(url, response))

            if parsed_url.scheme == 'https':
                findings.extend(self._check_mixed_content(url, response))

        except requests.exceptions.SSLError:
            findings.append(SecurityFinding(
                url, "SSL/TLS Error",
                "Connection failed due to SSL/TLS issues",
                "The server has a misconfigured or invalid SSL certificate.",
                "High", detection_method="SSL Handshake",
                remediation="Install a valid SSL certificate signed by a trusted CA.",
            ))
        except requests.RequestException as exc:
            raise exc

        return findings

    # =========================================================================
    # Transport Security
    # =========================================================================

    def _check_transport_security(self, url, response, history):
        findings = []
        parsed = urlparse(url)

        if parsed.scheme == 'http':
            redirected_https = (history
                                and any(h.status_code in (301, 302, 303, 307, 308)
                                        for h in history)
                                and response.url.startswith('https'))
            if redirected_https:
                if parsed.query:
                    findings.append(SecurityFinding(
                        url, "Insecure Redirect",
                        "HTTP→HTTPS redirect detected with query parameters",
                        "Sensitive query parameters may be exposed in the initial HTTP request.",
                        "Low", detection_method="Header Analysis",
                        response_obj=response,
                        remediation="Do not pass sensitive data in query strings before the TLS redirect.",
                    ))
            else:
                findings.append(SecurityFinding(
                    url, "Unencrypted Traffic",
                    "No HTTPS enforcement detected",
                    "Resource is served over plain HTTP without redirecting to HTTPS.",
                    "High", detection_method="Protocol Inspection",
                    response_obj=response,
                    remediation="Enable HSTS and redirect all HTTP traffic to HTTPS.",
                ))
        return findings

    # =========================================================================
    # Sensitive Data in URL
    # =========================================================================

    def _check_sensitive_data_in_transit(self, url):
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for key in params:
            if any(kw in key.lower() for kw in self.sensitive_keywords):
                findings.append(SecurityFinding(
                    url, "Sensitive Data in URL",
                    f"Query parameter '{key}' may contain sensitive data",
                    "Credentials/tokens should not be sent in URL query parameters.",
                    "High", detection_method="Query Parameter Analysis",
                    param_location="Query",
                    remediation="Move sensitive parameters to the POST body or request headers.",
                ))
        return findings

    # =========================================================================
    # Server Information Disclosure
    # =========================================================================

    def _check_info_disclosure(self, url, response):
        findings = []
        for header in ('Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Pingback'):
            if header in response.headers:
                findings.append(SecurityFinding(
                    url, "Server Information Disclosure",
                    f"{header}: {response.headers[header]}",
                    "Technology version strings help attackers target known CVEs.",
                    "Low", detection_method="Header Analysis",
                    response_obj=response,
                    remediation="Configure the web server to suppress version headers.",
                ))
        return findings

    # =========================================================================
    # Error Information Leakage
    # =========================================================================

    def _check_error_leakage(self, url, response):
        findings = []
        if response.status_code >= 400:
            for pattern in self.framework_error_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    findings.append(SecurityFinding(
                        url, "Error Information Leakage",
                        f"Pattern '{pattern}' in {response.status_code} response",
                        "Error responses expose stack traces or paths useful to attackers.",
                        "Medium", detection_method="Content Regex Analysis",
                        response_obj=response,
                        remediation="Disable detailed error messages in production.",
                    ))
                    break
        return findings

    # =========================================================================
    # Payment Transit Security
    # =========================================================================

    def _check_payment_security(self, url, response):
        findings = []
        path = urlparse(url).path.lower()
        if not any(kw in path for kw in self.payment_keywords):
            return findings

        if not url.startswith('https'):
            findings.append(SecurityFinding(
                url, "Insecure Payment Transit",
                "Payment endpoint accessible over HTTP",
                "Payment data must be transmitted exclusively over HTTPS.",
                "Critical", detection_method="Protocol Inspection",
                response_obj=response,
                remediation="Enforce TLS on all payment processing endpoints.",
            ))

        cc_pattern = r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"
        match = re.search(cc_pattern, response.text)
        if match:
            findings.append(SecurityFinding(
                url, "Payment Data Exposure",
                "Potential credit card number found in response body",
                "Application may be echoing sensitive payment data.",
                "Critical", detection_method="Content Regex Analysis",
                response_obj=response,
                extracted_data={"type": "Credit Card Number",
                                "preview": match.group(0)},
                remediation="Mask or omit sensitive payment data from API responses.",
            ))
        return findings

    # =========================================================================
    # CDN / WAF Detection
    # =========================================================================

    def _check_cdn_waf(self, url, response):
        findings = []
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        detected = [provider for provider, sigs in self.cdn_waf_signatures.items()
                    if any(sig in headers_lower for sig in sigs)]
        if detected:
            findings.append(SecurityFinding(
                url, "CDN / WAF Detected",
                f"Infrastructure protected by: {', '.join(detected)}",
                "CDN/WAF presence affects exposure to DDoS and edge misconfigurations.",
                "Info", detection_method="Header Fingerprinting",
                response_obj=response,
            ))
        return findings

    # =========================================================================
    # Mixed Content
    # =========================================================================

    def _check_mixed_content(self, url, response):
        findings = []
        ct = response.headers.get('Content-Type', '').lower()
        if 'text/html' not in ct and 'application/xhtml+xml' not in ct:
            return findings

        for resource_type, cfg in self.mixed_content_patterns.items():
            matches = re.findall(cfg['pattern'], response.text, re.IGNORECASE)
            if not matches:
                continue
            unique = list(dict.fromkeys(matches))[:10]
            sample = ', '.join(unique[:3])
            findings.append(SecurityFinding(
                url,
                f"Mixed Content: HTTP {cfg['type']} on HTTPS Page",
                f"Found {len(unique)} HTTP {cfg['type']} resource(s); sample: {sample}",
                f"Loading {resource_type} over HTTP on an HTTPS page undermines TLS guarantees.",
                cfg['severity'],
                detection_method="HTML Content Analysis",
                response_obj=response,
                remediation=cfg['remediation'],
                extracted_data={"mixed_content_type": cfg['type'],
                                "total_count": len(unique),
                                "sample_urls": unique},
            ))
        return findings

    # =========================================================================
    # CORS Misconfiguration
    # =========================================================================

    def _check_cors_misconfiguration(self, url, response):
        findings = []
        acao = response.headers.get('Access-Control-Allow-Origin', '')
        acac = response.headers.get('Access-Control-Allow-Credentials', '').lower()
        if acao == '*' and acac == 'true':
            findings.append(SecurityFinding(
                url, "Critical CORS Misconfiguration",
                "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                "Any site can make authenticated cross-origin requests, enabling data theft.",
                "Critical", detection_method="CORS Header Analysis",
                response_obj=response,
                remediation=("Remove wildcard origin when credentials are enabled. "
                             "Use an explicit origin allowlist."),
            ))
        return findings

    # =========================================================================
    # Security Headers
    # =========================================================================

    def _check_security_headers(self, url, response):
        """Check for mandatory security headers."""
        findings = []
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        for key, cfg in self.security_headers.items():
            if cfg['required'] and key not in headers_lower:
                findings.append(SecurityFinding(
                    url,
                    f"Missing Security Header: {cfg['name']}",
                    f"Required header '{key}' is absent",
                    f"The application is missing the {cfg['name']} header.",
                    cfg['severity'],
                    detection_method="Security Header Analysis",
                    response_obj=response,
                    remediation=cfg['remediation'],
                ))
        return findings

    # =========================================================================
    # Anti-Clickjacking Header Analysis
    # =========================================================================

    def _check_anti_clickjacking_headers(self, url, response):
        """
        Single, consolidated clickjacking protection analysis.
        """
        findings = []
        headers_lower = {k.lower(): v for k, v in response.headers.items()}

        xfo_header = headers_lower.get('x-frame-options')
        csp_header = headers_lower.get('content-security-policy')

        frame_ancestors = None
        if csp_header:
            m = re.search(r'frame-ancestors\s+([^;]+)', csp_header, re.IGNORECASE)
            if m:
                frame_ancestors = m.group(1).strip()

        has_frame_breaking_js = self._check_frame_breaking_javascript(response.text)

        if not xfo_header and not frame_ancestors:
            findings.append(SecurityFinding(
                url, "Missing Anti-Clickjacking Headers",
                "X-Frame-Options and CSP frame-ancestors are both absent",
                ("The application lacks anti-clickjacking protection, allowing attackers "
                 "to embed it in a malicious iframe and trick users into unintended actions."),
                "High", detection_method="Anti-Clickjacking Analysis",
                response_obj=response,
                remediation=("Add X-Frame-Options: DENY (or SAMEORIGIN), or "
                             "Content-Security-Policy: frame-ancestors 'none' (or 'self')."),
                extracted_data={
                    "x_frame_options_present": False,
                    "csp_frame_ancestors_present": False,
                    "frame_breaking_js_detected": has_frame_breaking_js,
                    "cwe_reference": "CWE-1021",
                },
            ))

            if has_frame_breaking_js:
                findings.append(SecurityFinding(
                    url, "Frame-Breaking JavaScript Detected (Fallback Only)",
                    "JavaScript frame-busting code found but HTTP security headers are absent",
                    ("Frame-breaking JavaScript can be bypassed (e.g. via sandbox attribute). "
                     "HTTP headers provide reliable protection."),
                    "Low", detection_method="Anti-Clickjacking Analysis",
                    response_obj=response,
                    remediation=("Add X-Frame-Options or CSP frame-ancestors as primary "
                                 "protection; keep JavaScript as defence-in-depth."),
                ))

            if self._is_sensitive_page(url):
                findings.append(SecurityFinding(
                    url, "Critical Clickjacking Risk on Sensitive Page",
                    f"Sensitive page lacks anti-clickjacking protection: {url}",
                    ("Authentication, payment, and account-management pages without "
                     "clickjacking protection are prime targets for UI-redressing attacks "
                     "that can lead to account takeover or unauthorised transactions."),
                    "Critical", detection_method="Anti-Clickjacking Analysis",
                    response_obj=response,
                    remediation="Implement X-Frame-Options: DENY on all sensitive pages immediately.",
                ))

        elif xfo_header:
            xfo_upper = xfo_header.strip().upper()

            if xfo_upper in ('DENY', 'SAMEORIGIN'):
                findings.append(SecurityFinding(
                    url, "Anti-Clickjacking Protection Enabled",
                    f"X-Frame-Options: {xfo_header} (valid configuration)",
                    "The application has proper clickjacking protection.",
                    "Info", detection_method="Anti-Clickjacking Analysis",
                    response_obj=response,
                ))

            elif xfo_upper.startswith('ALLOW-FROM'):
                findings.append(SecurityFinding(
                    url, "Weak Anti-Clickjacking Configuration",
                    f"X-Frame-Options: {xfo_header} (deprecated / limited browser support)",
                    ("ALLOW-FROM is unsupported in Chrome, Firefox, and Safari, "
                     "providing incomplete clickjacking protection."),
                    "Medium", detection_method="Anti-Clickjacking Analysis",
                    response_obj=response,
                    remediation=("Replace with Content-Security-Policy: frame-ancestors "
                                 "or use X-Frame-Options: DENY / SAMEORIGIN."),
                ))

            else:
                findings.append(SecurityFinding(
                    url, "Invalid Anti-Clickjacking Configuration",
                    f"X-Frame-Options: {xfo_header} (unrecognised value)",
                    f"The header value '{xfo_header}' is not valid and provides no protection.",
                    "High", detection_method="Anti-Clickjacking Analysis",
                    response_obj=response,
                    remediation="Set X-Frame-Options to DENY or SAMEORIGIN.",
                ))

        elif frame_ancestors:
            fa_lower = frame_ancestors.lower()
            if "'none'" in fa_lower:
                severity, note = "Info", "most secure"
            elif "'self'" in fa_lower:
                severity, note = "Info", "allows same-origin framing"
            else:
                severity, note = "Medium", "may be overly permissive"

            findings.append(SecurityFinding(
                url, "Anti-Clickjacking Protection (CSP)",
                f"CSP frame-ancestors: {frame_ancestors} ({note})",
                "The application uses CSP frame-ancestors for clickjacking protection.",
                severity, detection_method="Anti-Clickjacking Analysis",
                response_obj=response,
                remediation=("Review CSP frame-ancestors to ensure only trusted origins are listed."
                             if severity == "Medium" else None),
            ))

        return findings

    # =========================================================================
    # Enhanced Cookie Security
    # =========================================================================

    def _check_enhanced_cookie_security(self, url: str, response) -> list:
        """
        Comprehensive session cookie security analysis.
        """
        findings = []
        parsed_url  = urlparse(url)
        current_domain = parsed_url.netloc
        current_path   = parsed_url.path or '/'

        parsed_cookies = self.cookie_parser.parse_all_cookies(response)

        if not parsed_cookies:
            findings.append(SecurityFinding(
                url, "No Cookies Detected",
                "No cookies were set in the response",
                "The application sets no cookies; review session management requirements.",
                "Info", detection_method="Enhanced Cookie Analysis",
                response_obj=response,
            ))
            return findings

        auth_cookies   = []
        issue_findings = []

        for cookie_info in parsed_cookies:
            cookie_name  = cookie_info['name']
            cookie_value = cookie_info['value']

            is_session_cookie = any(kw in cookie_name.lower() for kw in
                                    ('session', 'auth', 'token', 'jwt', 'sid',
                                     'sess', 'identity', 'user', 'login'))

            is_secure   = self.cookie_parser.is_secure(cookie_info)
            is_httponly = self.cookie_parser.is_httponly(cookie_info)
            samesite    = self.cookie_parser.get_samesite(cookie_info)
            cookie_path = cookie_info.get('path', '/')
            cookie_domain   = cookie_info.get('domain')
            expiration_info = self.cookie_parser.get_expiration_info(cookie_info)

            issues          = []
            recommendations = []
            severity        = "Low"

            if not is_secure:
                issues.append("Missing 'Secure' flag – cookie can be sent over plain HTTP")
                recommendations.append("Add the 'Secure' flag")
                severity = "High" if is_session_cookie else "Medium"

            if not is_httponly:
                issues.append("Missing 'HttpOnly' flag – accessible via JavaScript (XSS risk)")
                recommendations.append("Add the 'HttpOnly' flag")
                if is_session_cookie and severity != "High":
                    severity = "High"

            if not samesite:
                issues.append("Missing 'SameSite' attribute – CSRF risk")
                recommendations.append("Set SameSite=Lax or SameSite=Strict")
                if severity not in ("High", "Critical"):
                    severity = "Medium"
            elif samesite.lower() == 'none':
                issues.append("SameSite=None – requires Secure flag and still allows cross-site requests")
                recommendations.append("Use SameSite=Lax or Strict unless cross-site cookies are required")
                if severity not in ("High", "Critical"):
                    severity = "Medium"
            elif samesite.lower() == 'lax' and is_session_cookie:
                issue_findings.append(SecurityFinding(
                    url, "Session Cookie SameSite=Lax",
                    f"Cookie '{cookie_name}': SameSite=Lax (moderate CSRF protection)",
                    "SameSite=Lax protects top-level navigations but not all cross-origin requests.",
                    "Info", detection_method="Enhanced Cookie Analysis",
                    param_location="Cookie", response_obj=response,
                    remediation="Consider SameSite=Strict for critical session cookies.",
                ))

            if cookie_domain:
                domain_clean   = cookie_domain.lstrip('.')
                current_clean  = current_domain.split(':')[0]
                if cookie_domain.startswith('.'):
                    parts = domain_clean.split('.')
                    if len(parts) == 2 and parts[0] not in ('localhost',):
                        issues.append(f"Cookie domain '{cookie_domain}' set on apex – "
                                      f"shares across ALL subdomains")
                        recommendations.append("Restrict cookie domain to the specific subdomain")
                        if severity not in ("Critical",):
                            severity = "Medium"

            if expiration_info.get('type') == 'max-age':
                max_days = expiration_info.get('days', 0)
                if max_days > 90:
                    issues.append(f"Cookie max-age is {max_days:.0f} days (excessively long)")
                    recommendations.append("Reduce max-age to ≤ 90 days")
                    if severity not in ("High", "Critical"):
                        severity = "Medium"

            if is_session_cookie and self._check_session_fixation_vulnerability_cookie(
                    cookie_name, cookie_value):
                issues.append("Session cookie has predictable value – session fixation risk")
                recommendations.append("Use cryptographically random IDs with ≥ 128 bits of entropy")
                if severity not in ("Critical",):
                    severity = "High"

            if issues:
                extracted_data = {
                    "cookie_name":     cookie_name,
                    "secure_flag":     is_secure,
                    "httponly_flag":   is_httponly,
                    "samesite_value":  samesite,
                    "path_scope":      cookie_path,
                    "domain_scope":    cookie_domain or current_domain,
                    "expiration":      expiration_info,
                    "is_session_cookie": is_session_cookie,
                    "issues_found":    issues,
                    "recommendations": recommendations,
                    "raw_set_cookie":  cookie_info.get('raw_value', 'Unknown'),
                }
                issue_findings.append(SecurityFinding(
                    url,
                    "Weak Session Cookie Configuration" if is_session_cookie else "Weak Cookie Configuration",
                    f"Cookie '{cookie_name}': {'; '.join(issues[:3])}"
                    f"{'...' if len(issues) > 3 else ''}",
                    f"Cookie security issues: {'; '.join(issues)}. "
                    f"Risk of session hijacking, CSRF, or fixation.",
                    severity,
                    detection_method="Enhanced Cookie Analysis",
                    param_location="Cookie",
                    response_obj=response,
                    remediation='; '.join(recommendations[:3]),
                    extracted_data=extracted_data,
                ))

            if is_session_cookie:
                auth_cookies.append(cookie_name)

            issue_findings.extend(
                self._check_cookie_prefixes_enhanced(url, cookie_info, response))

        if auth_cookies:
            any_properly_configured = any(
                self._is_cookie_properly_configured(ci)
                for ci in parsed_cookies
                if any(kw in ci['name'].lower()
                       for kw in ('session', 'auth', 'token', 'jwt', 'sid'))
            )
            if not any_properly_configured:
                findings.append(SecurityFinding(
                    url,
                    "Session Management Security Issues",
                    f"Authentication cookies ({', '.join(auth_cookies[:3])}) have security misconfigurations",
                    "Session cookies missing Secure, HttpOnly, or SameSite are vulnerable to hijacking.",
                    "High", detection_method="Enhanced Cookie Analysis",
                    response_obj=response,
                    remediation="Apply Secure, HttpOnly, and SameSite=Strict to all session cookies.",
                ))

        findings.extend(issue_findings)

        if not findings:
            findings.append(SecurityFinding(
                url, "Cookie Security Analysis Complete",
                f"Analysed {len(parsed_cookies)} cookie(s) – all properly configured",
                "All cookies have appropriate security flags.",
                "Info", detection_method="Enhanced Cookie Analysis",
                response_obj=response,
            ))

        return findings

    def _check_session_fixation_vulnerability_cookie(self, name: str, value: str) -> bool:
        if len(value) < 16:                                       return True
        if re.match(r'^[0-9]+$', value):                          return True
        if re.match(r'^[a-z]+$', value):                          return True
        if re.match(r'^[A-Z]+$', value):                          return True
        if re.match(r'^[0-9A-Fa-f]+$', value) and len(value) < 32: return True
        if re.search(r'\d{10,}', value):                          return True
        if re.search(r'(123|abc|000|111|222|333)', value.lower()): return True
        return False

    def _is_cookie_properly_configured(self, cookie_info: dict) -> bool:
        ss = self.cookie_parser.get_samesite(cookie_info)
        return (self.cookie_parser.is_secure(cookie_info)
                and self.cookie_parser.is_httponly(cookie_info)
                and ss and ss.lower() in ('lax', 'strict'))

    def _check_cookie_prefixes_enhanced(self, url: str, cookie_info: dict, response) -> list:
        findings = []
        name = cookie_info['name']

        if name.startswith('__Secure-'):
            issues = []
            if not self.cookie_parser.is_secure(cookie_info):
                issues.append("Missing Secure flag (required for __Secure- prefix)")
            if response.url and not response.url.startswith('https'):
                issues.append("Set over non-HTTPS connection")
            if issues:
                findings.append(SecurityFinding(
                    url, "Cookie Prefix Violation: __Secure-",
                    f"Cookie '{name}': {'; '.join(issues)}",
                    "__Secure- cookies must have Secure flag and be set over HTTPS.",
                    "High", detection_method="Cookie Prefix Analysis",
                    param_location="Cookie", response_obj=response,
                    remediation="Only set __Secure- cookies over HTTPS with the Secure flag.",
                ))

        elif name.startswith('__Host-'):
            issues = []
            if not self.cookie_parser.is_secure(cookie_info):
                issues.append("Missing Secure flag")
            if cookie_info.get('domain'):
                issues.append(f"Has Domain attribute '{cookie_info['domain']}'")
            if cookie_info.get('path') != '/':
                issues.append(f"Path is '{cookie_info.get('path')}' (must be '/')")
            if response.url and not response.url.startswith('https'):
                issues.append("Set over non-HTTPS connection")
            if issues:
                findings.append(SecurityFinding(
                    url, "Cookie Prefix Violation: __Host-",
                    f"Cookie '{name}': {'; '.join(issues)}",
                    "__Host- cookies require Secure flag, no Domain, and Path=/.",
                    "Critical", detection_method="Cookie Prefix Analysis",
                    param_location="Cookie", response_obj=response,
                    remediation="For __Host- cookies: Secure flag, no Domain attribute, Path=/.",
                ))

        elif (any(kw in name.lower() for kw in ('session', 'auth', 'token', 'jwt', 'sid'))
              and not name.startswith(('__Secure-', '__Host-'))
              and self.cookie_parser.is_secure(cookie_info)):
            findings.append(SecurityFinding(
                url, "Missing Cookie Prefix for Secure Session Cookie",
                f"Session cookie '{name}' has Secure flag but lacks __Secure- or __Host- prefix",
                "Using __Secure- or __Host- prefixes prevents cookie-override attacks.",
                "Medium", detection_method="Cookie Prefix Analysis",
                param_location="Cookie", response_obj=response,
                remediation="Add __Secure- (or __Host- for stricter isolation) prefix to this cookie.",
            ))

        return findings


# -----------------------------------------------------------------------------
# Professional Output Functions
# -----------------------------------------------------------------------------

def print_banner():
    banner = f"""
{Colors.CYAN}{'='*80}{Colors.END}
{Colors.BOLD}{Colors.HEADER}    🔍 PASSIVE HTTP OBSERVER – Security Analysis Tool (Passive Mode){Colors.END}
{Colors.CYAN}{'='*80}{Colors.END}
{Colors.DIM}    Version: 5 | Mode: Passive HTTP Analysis (No Active SSL Probes){Colors.END}
{Colors.CYAN}{'='*80}{Colors.END}
"""
    print(banner)


def print_scan_summary(total_targets, unique_findings, error_count, start_time):
    duration = (datetime.now() - start_time).total_seconds()
    sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    cat: dict[str, int] = {}

    for f in unique_findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1
        c = f._categorise()
        cat[c] = cat.get(c, 0) + 1

    summary = f"""
{Colors.BOLD}{Colors.CYAN}📊 SCAN SUMMARY{Colors.END}
{Colors.CYAN}{'─'*80}{Colors.END}

{Colors.BOLD}📈 Statistics:{Colors.END}
  • Targets Analysed : {Colors.BOLD}{total_targets}{Colors.END}
  • Total Findings   : {Colors.BOLD}{len(unique_findings)}{Colors.END}
  • Connection Errors: {Colors.RED if error_count else Colors.GREEN}{error_count}{Colors.END}
  • Scan Duration    : {Colors.BOLD}{duration:.2f}s{Colors.END}

{Colors.BOLD}🎯 Severity Distribution:{Colors.END}"""

    for label, colour, icon in (
        ("Critical", Colors.RED,    Icons.CRITICAL),
        ("High",     Colors.RED,    Icons.HIGH),
        ("Medium",   Colors.YELLOW, Icons.MEDIUM),
        ("Low",      Colors.BLUE,   Icons.LOW),
        ("Info",     Colors.DIM,    Icons.INFO),
    ):
        if sev.get(label, 0):
            summary += f"\n  {icon} {colour}{Colors.BOLD}{label}: {sev[label]}{Colors.END}"

    if cat:
        summary += f"\n\n{Colors.BOLD}📂 Findings by Category:{Colors.END}"
        for c, n in sorted(cat.items(), key=lambda x: x[1], reverse=True):
            summary += f"\n  • {c}: {n}"

    if not unique_findings:
        summary += f"\n\n  {Icons.SUCCESS} {Colors.GREEN}{Colors.BOLD}No security issues detected!{Colors.END}"

    print(summary)


def print_finding_table(findings):
    if not findings:
        return
    print(f"\n{Colors.BOLD}{Colors.CYAN}🔍 DETAILED FINDINGS{Colors.END}")
    print(f"{Colors.CYAN}{'─'*80}{Colors.END}")

    for idx, f in enumerate(findings, 1):
        if f.severity == "Critical":
            sc, icon = Colors.RED,    Icons.CRITICAL
        elif f.severity == "High":
            sc, icon = Colors.RED,    Icons.HIGH
        elif f.severity == "Medium":
            sc, icon = Colors.YELLOW, Icons.MEDIUM
        elif f.severity == "Low":
            sc, icon = Colors.BLUE,   Icons.LOW
        else:
            sc, icon = Colors.DIM,    Icons.INFO

        if "Clickjacking" in f.issue_type:
            icon = Icons.CLICKJACK

        def trunc(s, n=200):
            return s[:n] + "..." if len(s) > n else s

        print(f"\n{Colors.BOLD}[{idx}] {icon} {sc}{f.severity}{Colors.END} – {f.issue_type}")
        print(f"  {Colors.DIM}📍 URL:{Colors.END}         {f.url}")
        print(f"  {Colors.DIM}📝 Indicator:{Colors.END}   {trunc(f.indicator)}")
        print(f"  {Colors.DIM}💥 Impact:{Colors.END}      {trunc(f.impact)}")
        if f.remediation:
            print(f"  {Colors.DIM}🔧 Remediation:{Colors.END} {trunc(f.remediation)}")
        print(f"  {Colors.CYAN}{'─'*76}{Colors.END}")


def print_errors_table(errors):
    if not errors:
        return
    print(f"\n{Colors.BOLD}{Colors.RED}⚠️  CONNECTION ERRORS ({len(errors)}){Colors.END}")
    print(f"{Colors.RED}{'─'*80}{Colors.END}")
    for idx, e in enumerate(errors[:10], 1):
        print(f"  {idx}. {e[:120]}{'...' if len(e) > 120 else ''}")
    if len(errors) > 10:
        print(f"  {Colors.DIM}... and {len(errors) - 10} more{Colors.END}")


def print_final_status(ok: bool, filename: str):
    print(f"\n{Colors.CYAN}{'='*80}{Colors.END}")
    if ok:
        print(f"{Icons.SUCCESS} {Colors.GREEN}{Colors.BOLD}Analysis completed successfully!{Colors.END}")
    else:
        print(f"{Icons.WARNING} {Colors.YELLOW}{Colors.BOLD}Analysis completed with errors{Colors.END}")
    print(f"{Icons.TARGET} {Colors.BOLD}Report saved to:{Colors.END} {Colors.CYAN}{filename}{Colors.END}")
    print(f"{Colors.CYAN}{'='*80}{Colors.END}\n")


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Passive HTTP Observer – analyse endpoints from a Hellhound Spider JSON file.")
    parser.add_argument("file", help="Path to the Hellhound Spider JSON file.")
    args = parser.parse_args()

    start_time = datetime.now()
    print_banner()

    targets = []
    try:
        with open(args.file) as fh:
            data = json.load(fh)
        if isinstance(data.get('endpoints'), list):
            targets = [ep['url'] for ep in data['endpoints'] if 'url' in ep]
        else:
            print(f"{Icons.ERROR} {Colors.RED}JSON file lacks a valid 'endpoints' list.{Colors.END}")
            return
    except FileNotFoundError:
        print(f"{Icons.ERROR} {Colors.RED}File '{args.file}' not found.{Colors.END}")
        return
    except json.JSONDecodeError:
        print(f"{Icons.ERROR} {Colors.RED}Failed to parse JSON from '{args.file}'.{Colors.END}")
        return

    if not targets:
        print(f"{Icons.ERROR} {Colors.RED}No targets found.{Colors.END}")
        return

    targets = list(dict.fromkeys(targets))
    print(f"{Icons.TARGET} {Colors.BOLD}Targets loaded:{Colors.END} {len(targets)} unique endpoints")
    print(f"\n{Colors.BOLD}Starting analysis…{Colors.END}\n")

    observer    = PassiveHttpObserver()
    all_findings: list[SecurityFinding] = []
    error_list:   list[str]             = []

    for idx, target in enumerate(targets, 1):
        label = target[:70] + ("..." if len(target) > 70 else "")
        print(f"{Colors.DIM}[{idx}/{len(targets)}] Analysing: {label}{Colors.END}", end="\r")
        try:
            all_findings.extend(
                observer.analyze_target(target))
        except Exception as exc:
            error_list.append(f"{target} – {exc}")

    print()

    unique_findings = list(set(all_findings))
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    unique_findings.sort(key=lambda x: (sev_order.get(x.severity, 5), x.url, x.issue_type))

    print_scan_summary(len(targets), unique_findings, len(error_list), start_time)
    print_finding_table(unique_findings)
    print_errors_table(error_list)

    report = {
        "status":     not bool(error_list),
        "errors":     error_list,
        "gap_reason": None,
        "findings":   [f.to_report_dict() for f in unique_findings],
    }

    output_file = "security_report.json"
    try:
        with open(output_file, "w") as fh:
            json.dump(report, fh, indent=4)
        print_final_status(not bool(error_list), output_file)
    except IOError as exc:
        print(f"\n{Icons.ERROR} {Colors.RED}Error saving report: {exc}{Colors.END}")


if __name__ == "__main__":
    main()
