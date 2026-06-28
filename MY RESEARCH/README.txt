usage: passiveObserver3.py [-h] [--workers WORKERS] [--rate-limit RATE_LIMIT] [--timeout TIMEOUT] [--max-pcap-mb MAX_PCAP_MB]
                           [--passive-rate-limit PASSIVE_RATE_LIMIT] [--verbose]
                           file

Passive HTTP Observer v9.3 - Comprehensive Security Analysis Tool

positional arguments:
  file                  Path to input file (HAR, Burp XML, PCAP, or Spider Hellhound JSON)

options:
  -h, --help            show this help message and exit
  --workers WORKERS     Concurrent workers (default: 5)
  --rate-limit RATE_LIMIT
                        Seconds between requests (default: 0.5)
  --timeout TIMEOUT     Request timeout in seconds (default: 10)
  --max-pcap-mb MAX_PCAP_MB
                        Max PCAP size in MB (default: 1024)
  --passive-rate-limit PASSIVE_RATE_LIMIT
                        Rate limit for passive scanning (default: 1.0)
  --verbose             Enable verbose logging

------------------------------------------------------------------------------------------------------

SUMMARY

To run the code, enter the below:

python3 passiveObserver3.py <Path to input file (HAR, Burp XML, PCAP, or Spider Hellhound JSON)>

------------------------------------------------------------------------------------------------------

VULNERABILITY VERIFICATION

To Verify vulnerabilities, in a new session tab in kali, run the below:

curl -I "<Target URL>"   // Verify Server Information Disclosure Vulnerability
wafw00f "<Target URL>"   // Verify CDN/WAF Detected Vulnerability

To verify cookie vulnerability:

1) Go to Kali browser
2) Paste the Target URL, you want to check
3) Press F12 in keyboard and verify the cookies.

To verify missing security headers vulnerability:

1) Open the web page in your browser.
2) Press F12 (or Ctrl + Shift + I).
3) Go to the Network tab.
4) Refresh the page.
5) Click the first request (usually the HTML document).
6) Under Headers, look at the Response Headers section.

Kali Linux NUCLEI command to verify all the vulnerabilities:

nuclei -l urls.txt \
  -t http/ \
  -t ssl/ \
  -t http/exposures/ \
  -t http/misconfiguration/ \
  -tags http,ssl,exposures,misconfiguration,headers,cors,cookie,cookies,hsts,csp,mixed-content,tech,information-disclosure \
  -o nuclei_report.txt

Kali Linux Bash Script To Perform OWASP ZAP Proxy:

./zap_passive_scan.sh

