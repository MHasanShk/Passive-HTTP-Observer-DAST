usage: passiveObserver.py [-h] file

Passive HTTP Observer – analyse endpoints from a Hellhound Spider JSON file.

positional arguments:
  file        Path to the Hellhound Spider JSON file.

options:
  -h, --help  show this help message and exit

------------------------------------------------------------------------------------------------------

SUMMARY

To run the code, enter the below:

python3 passiveObserver.py <SPIDER HELLHOUND JSON FILENAME>

------------------------------------------------------------------------------------------------------

VULNERABILITY VERIFICATION

To Verify vulnerabilities, in a new session tab in kali, run the below:

curl -I "<Target URL>"   // Verify Server Information Disclosure Vulnerability
wafw00f "<Target URL>"   // Verify CDN/WAF Detected Vulnerability

To verify cookie vulnerability:

1) Go to Kali browser
2) Paste the Target URL, you want to check
3) Press F12 in keyboard and verify the cookies.

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

