#!/bin/bash

# ==========================================
# OWASP ZAP Passive Scan Automation Script
# ==========================================

# Configuration
ZAP_PORT=8090
URL_FILE="urls.txt"
REPORT_JSON="zap_passive_report.json"
REPORT_HTML="zap_report.html"

echo "[+] Starting OWASP ZAP daemon..."

# Start ZAP in daemon mode
zaproxy -daemon \
  -port $ZAP_PORT \
  -config api.disablekey=true \
  > /dev/null 2>&1 &

ZAP_PID=$!

echo "[+] Waiting for ZAP to initialize..."
sleep 20

# Check if URLs file exists
if [ ! -f "$URL_FILE" ]; then
    echo "[-] Error: $URL_FILE not found!"
    kill $ZAP_PID 2>/dev/null
    exit 1
fi

echo "[+] Importing URLs for passive scanning..."

# Send URLs to ZAP
while read -r url; do

    # Skip empty lines
    [ -z "$url" ] && continue

    echo "[*] Scanning: $url"

    curl -s \
    "http://127.0.0.1:$ZAP_PORT/JSON/core/action/accessUrl/?url=$url" \
    > /dev/null

done < "$URL_FILE"

echo "[+] Waiting for passive scan analysis..."
sleep 60

echo "[+] Exporting JSON report..."

curl -s \
"http://127.0.0.1:$ZAP_PORT/JSON/core/view/alerts/" \
| jq '.' > "$REPORT_JSON"

echo "[+] Exporting HTML report..."

curl -s \
"http://127.0.0.1:$ZAP_PORT/OTHER/core/other/htmlreport/" \
-o "$REPORT_HTML"

echo "[+] Passive scan completed."

echo "[+] Reports generated:"
echo "    - $REPORT_JSON"
echo "    - $REPORT_HTML"

echo "[+] Stopping ZAP daemon..."
kill $ZAP_PID 2>/dev/null

echo "[+] Done."
