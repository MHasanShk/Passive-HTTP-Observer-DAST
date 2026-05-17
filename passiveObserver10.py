import requests
import re
import ssl
import socket
import argparse
import json
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs

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
		elif "SSL" in self.issue_type or "TLS" in self.issue_type: category = "Cryptography"
		elif "Info" in self.issue_type or "Error" in self.issue_type: category = "Information Disclosure"
		elif "Payment" in self.issue_type: category = "Compliance"

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
			"proof_of_concept": None,
			"remediation": self.remediation or "Review the identified security issue and apply best practices.",
			"cve_reference": None,
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

			# 3. Cookie Security Analysis
			findings.extend(self._check_cookie_security(url, response))

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

			# 9. SSL/TLS Certificate Validation (only for HTTPS)
			if parsed_url.scheme == 'https':
				findings.extend(self._check_ssl_tls(base_domain))

			# 10. Backup File Exposure (Optional Probing)
			if check_backups:
				findings.extend(self._check_backup_files(url))

		except requests.exceptions.SSLError as e:
			findings.append(SecurityFinding(
				url, "SSL/TLS Error", "Connection failed due to SSL/TLS issues",
				"The server has a misconfigured or invalid SSL certificate.", "High",
				detection_method="SSL Handshake", remediation="Install a valid SSL certificate signed by a trusted CA."
			))
		except requests.RequestException as e:
			# We don't add a finding for every connection error (might be offline), 
			# but we could return the exception to be logged in the 'errors' list of the report
			raise e

		return findings

	# -------------------------------------------------------------------------
	# Analysis Modules
	# -------------------------------------------------------------------------

	def _check_transport_security(self, url, response, history):
		findings = []
		parsed = urlparse(url)

		# Check if the initial request was HTTP
		if parsed.scheme == 'http':
			# Check if it redirected to HTTPS
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

	def _check_cookie_security(self, url, response):
		findings = []
		for cookie in response.cookies:
			issues = []
			if not cookie.secure:
				issues.append("Missing 'Secure' flag")

			is_httponly = cookie.has_nonstandard_attr('httponly') or cookie._rest.get('httponly', False)
			if not is_httponly:
				issues.append("Missing 'HttpOnly' flag")

			samesite = cookie.get_nonstandard_attr('samesite') or cookie._rest.get('samesite', None)
			if not samesite:
				issues.append("Missing 'SameSite' attribute")
			elif samesite.lower() not in ['strict', 'lax']:
				issues.append(f"Weak 'SameSite' attribute ({samesite})")

			if issues:
				findings.append(SecurityFinding(
					url, "Weak Session Cookie Configuration", 
					f"Cookie '{cookie.name}': {', '.join(issues)}",
					"Cookies are vulnerable to interception or XSS attacks.", "Medium",
					detection_method="Cookie Header Analysis", param_location="Cookie", response_obj=response,
					remediation="Set 'Secure', 'HttpOnly', and 'SameSite=Lax' or 'Strict' on all session cookies."
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

	def _check_ssl_tls(self, hostname):
		findings = []
		context = ssl.create_default_context()

		try:
			with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
				with context.wrap_socket(sock, server_hostname=hostname) as ssock:
					cert = ssock.getpeercert()
					if cert['subject'] == cert['issuer']:
						findings.append(SecurityFinding(
							f"https://{hostname}", "Self-Signed Certificate (Trusted)", 
							f"Certificate appears to be self-signed but is in the local trust store.",
							"While currently trusted, self-signed certificates complicate certificate management and rotation.", "Info",
							detection_method="Certificate Inspection",
							remediation="Use certificates signed by a public Certificate Authority."
						))
		except ssl.SSLCertVerificationError:
			findings.append(SecurityFinding(
				f"https://{hostname}", "SSL Certificate Invalid", 
				"Certificate verification failed",
				"The certificate chain is invalid, untrusted, or expired.", "High",
				detection_method="Certificate Validation",
				remediation="Renew the SSL certificate and ensure the chain is complete."
			))
		except Exception:
			pass 
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

# -----------------------------------------------------------------------------
# Professional Output Functions
# -----------------------------------------------------------------------------

def print_banner():
	"""Display professional banner"""
	banner = f"""
{Colors.CYAN}{'='*80}{Colors.END}
{Colors.BOLD}{Colors.HEADER}    🔍 PASSIVE HTTP OBSERVER - Security Analysis Tool{Colors.END}
{Colors.CYAN}{'='*80}{Colors.END}
{Colors.DIM}    Version: 1.0 | Author: Security Testing Framework | Mode: Passive Analysis{Colors.END}
{Colors.CYAN}{'='*80}{Colors.END}
	"""
	print(banner)

def print_scan_summary(total_targets, unique_findings, errors, start_time):
	"""Print scan summary statistics"""
	duration = (datetime.now() - start_time).total_seconds()

	# Calculate severity counts
	severity_counts = {
		"Critical": 0,
		"High": 0,
		"Medium": 0,
		"Low": 0,
		"Info": 0
	}

	for finding in unique_findings:
		if finding.severity in severity_counts:
			severity_counts[finding.severity] += 1

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

	if len(unique_findings) == 0:
		summary += f"\n\n  {Icons.SUCCESS} {Colors.GREEN}{Colors.BOLD}No security issues detected!{Colors.END}"

	print(summary)

def print_finding_table(findings):
	"""Print findings in a formatted table with full URLs"""
	if not findings:
		return

	print(f"\n{Colors.BOLD}{Colors.CYAN}🔍 DETAILED FINDINGS{Colors.END}")
	print(f"{Colors.CYAN}{'─'*80}{Colors.END}")

	for idx, finding in enumerate(findings, 1):
		# Determine color based on severity
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

		print(f"\n{Colors.BOLD}[{idx}] {icon} {severity_color}{finding.severity}{Colors.END} - {finding.issue_type}")
		# Display full URL without truncation
		print(f"  {Colors.DIM}📍 URL:{Colors.END} {finding.url}")

		if finding.param_location:
			print(f"  {Colors.DIM}🔧 Parameter:{Colors.END} {finding.param_location}")

		print(f"  {Colors.DIM}📝 Indicator:{Colors.END} {finding.indicator[:100]}{'...' if len(finding.indicator) > 100 else ''}")
		print(f"  {Colors.DIM}💥 Impact:{Colors.END} {finding.impact[:100]}{'...' if len(finding.impact) > 100 else ''}")

		if finding.remediation:
			print(f"  {Colors.DIM}🔧 Remediation:{Colors.END} {finding.remediation[:100]}{'...' if len(finding.remediation) > 100 else ''}")

		print(f"  {Colors.DIM}⏱️  Detection:{Colors.END} {finding.detection_method}")
		print(f"  {Colors.CYAN}{'─'*76}{Colors.END}")

def print_errors_table(errors):
	"""Print connection errors if any"""
	if not errors:
		return

	print(f"\n{Colors.BOLD}{Colors.RED}⚠️ CONNECTION ERRORS ({len(errors)}){Colors.END}")
	print(f"{Colors.RED}{'─'*80}{Colors.END}")

	for idx, error in enumerate(errors[:10], 1):  # Show first 10 errors
		print(f"  {idx}. {error[:120]}{'...' if len(error) > 120 else ''}")

	if len(errors) > 10:
		print(f"  {Colors.DIM}... and {len(errors) - 10} more errors (see report for details){Colors.END}")

def print_final_status(report_status, output_filename):
	"""Print final status message"""
	print(f"\n{Colors.CYAN}{'='*80}{Colors.END}")

	if report_status:
		print(f"{Icons.SUCCESS} {Colors.GREEN}{Colors.BOLD}Analysis completed successfully!{Colors.END}")
	else:
		print(f"{Icons.WARNING} {Colors.YELLOW}{Colors.BOLD}Analysis completed with errors (see report for details){Colors.END}")

	print(f"{Icons.TARGET} {Colors.BOLD}Report saved to:{Colors.END} {Colors.CYAN}{output_filename}{Colors.END}")
	print(f"{Colors.CYAN}{'='*80}{Colors.END}\n")

# -----------------------------------------------------------------------------
# Usage Example
# -----------------------------------------------------------------------------

def main():
	parser = argparse.ArgumentParser(description="Passive HTTP Observer - Analyze endpoints from Hellhound Spider JSON output.")
	parser.add_argument("file", help="Path to the Hellhound Spider JSON file.")
	parser.add_argument("--check-backups", action="store_true", help="Enable lightweight probing for backup files (.bak, .old, etc.)")
	args = parser.parse_args()

	# Record start time
	start_time = datetime.now()

	# Print banner
	print_banner()

	targets = []
	errors = []

	# Load and Parse JSON
	try:
		with open(args.file, 'r') as f:
			data = json.load(f)
		if 'endpoints' in data and isinstance(data['endpoints'], list):
			for endpoint in data['endpoints']:
				if 'url' in endpoint:
					targets.append(endpoint['url'])
		else:
			print(f"{Icons.ERROR} {Colors.RED}Error: The JSON file does not contain a valid 'endpoints' list.{Colors.END}")
			return
	except FileNotFoundError:
		print(f"{Icons.ERROR} {Colors.RED}Error: File '{args.file}' not found.{Colors.END}")
		return
	except json.JSONDecodeError:
		print(f"{Icons.ERROR} {Colors.RED}Error: Failed to decode JSON from '{args.file}'. Check file format.{Colors.END}")
		return

	if not targets:
		print(f"{Icons.ERROR} {Colors.RED}No targets found in the provided file.{Colors.END}")
		return

	# Deduplicate targets
	targets = list(dict.fromkeys(targets))

	print(f"{Icons.TARGET} {Colors.BOLD}Targets loaded:{Colors.END} {len(targets)} unique endpoints")
	print(f"{Icons.WARNING} {Colors.YELLOW}Backup file checking:{Colors.END} {'Enabled' if args.check_backups else 'Disabled'}")
	print(f"\n{Colors.BOLD}Starting analysis...{Colors.END}\n")

	observer = PassiveHttpObserver()
	all_findings = []
	error_list = []

	# Progress tracking
	for idx, target in enumerate(targets, 1):
		print(f"{Colors.DIM}[{idx}/{len(targets)}] Analyzing: {target[:70]}{'...' if len(target) > 70 else ''}{Colors.END}", end="\r")
		try:
			findings = observer.analyze_target(target, check_backups=args.check_backups)
			all_findings.extend(findings)
		except Exception as e:
			# Capture connection errors for the report's 'errors' list
			err_msg = f"{target} - {str(e)}"
			error_list.append(err_msg)
			errors.append(err_msg)

	print()  # New line after progress indicator

	# Deduplicate findings
	unique_findings = list(set(all_findings))
	unique_findings.sort(key=lambda x: (
		{"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(x.severity, 5),
		x.url, x.issue_type
	))

	# Print detailed results
	print_scan_summary(len(targets), unique_findings, len(error_list), start_time)
	print_finding_table(unique_findings)
	print_errors_table(error_list)

	# Construct Final Report Structure
	report_status = True if not error_list else False

	final_report = {
		"status": report_status,
		"errors": error_list,
		"gap_reason": None,
		"findings": [f.to_report_dict() for f in unique_findings]
	}

	# Output Report
	output_filename = "security_report.json"
	try:
		with open(output_filename, "w") as f:
			json.dump(final_report, f, indent=4)
		print_final_status(report_status, output_filename)
	except IOError as e:
		print(f"\n{Icons.ERROR} {Colors.RED}Error saving report to file: {e}{Colors.END}")

if __name__ == "__main__":
	main()
