import requests
import json
import os
from dotenv import load_dotenv
import time
import tldextract
import datetime
import pytz
import tzlocal
import sys

load_dotenv()

# Function: Convert Unix time to UTC datetime, then convert to local timezeone
def print_Unix_Time_To_Current_Timezone(unix_time):
    utc_dt = datetime.datetime.fromtimestamp(unix_time, tz=datetime.timezone.utc)
    local_tz = pytz.timezone(tzlocal.get_localzone_name())
    local_dt = utc_dt.astimezone(local_tz)
    return local_dt.strftime("%Y-%m-%d %H:%M:%S %Z")

# Ensure URL in command line argument
if len(sys.argv) < 2:
    print("Usage: python URLScanner.py <url>")
    sys.exit(1)

# Parse URL to extract only domain
url = sys.argv[1]
extracted = tldextract.extract(url) 
domain = f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}"
print(f"\nScanning {domain} through VirtusTotal and URLScan.io.\n")

# -------------------------------- VirusTotal --------------------------------
print("----------------------------------------\nScanning through VirusTotal...\n----------------------------------------")

# Request scan setup
url = f"https://www.virustotal.com/api/v3/domains/{domain}"

headers = {"accept": "application/json",
           "x-apikey": os.getenv('VIRUSTOTAL_API')}

# Get JSON string from VirusTotal and save all of it
parsed = json.loads(requests.get(url, headers=headers).text)  
analysis_results = parsed['data']['attributes']['last_analysis_results']
dns_results = parsed['data']['attributes']['last_dns_records']
time_results = parsed['data']['attributes']['last_analysis_date']

print(f"Scan created at: {print_Unix_Time_To_Current_Timezone(time_results)}")

# Gather IPv4 and IPv6 addresses resolved by DNS
ip_addresses = []
for info in dns_results:
    if info['type'].lower() in ['a','aaaa']:
        ip_addresses.append(info['value'])

print(f"\nResolved IP adresses:{ip_addresses}")

# Create a new dictionary of engines that detect this domain as malicious and suspicious
detected_malicious = {}
detected_suspicious = {}
detected_harmless = {}
malicious_count = 0
suspicious_count = 0
harmless_count = 0
total_engines = 0
for engine, info in analysis_results.items():
    if info['category'].lower() == 'malicious':
        detected_malicious[engine] = info
        malicious_count += 1
    elif info['category'].lower() == 'suspicious':
        detected_suspicious[engine] = info
        suspicious_count += 1
    elif info['category'].lower() == 'harmless':
        detected_harmless[engine] = info
        harmless_count += 1  
    total_engines += 1

# Print malicious & suspicious detections
if len(detected_malicious) != 0:
    print("\nEngines detected domain as malicious:")
    for engine, info in detected_malicious.items():
        print(f"{engine}: {info['result']}")

if len(detected_suspicious) != 0:
    print("\nEngines detected domain as suspicious:")
    for engine, info in detected_suspicious.items():
        print(f"{engine}: {info['result']}")

print(f"Detected as malicious by \033[91m{malicious_count}\033[0m engine(s)")
print(f"           suspicious by \033[93m{suspicious_count}\033[0m engine(s)")
print(f"             harmless by \033[92m{harmless_count}\033[0m/\033[92m{total_engines}\033[0m engine(s)")

# -------------------------------- URLScan.io -------------------------------- 
print("----------------------------------------\nScanning through URLScan.io...\n----------------------------------------")

# Request a scan from URLScan
url = 'https://urlscan.io/api/v1/scan/'
headers = {'API-Key':os.getenv('URLSCAN_API'),
           'Content-Type':'application/json'}
data = {"url": domain, 
        "visibility": "public"}

response = requests.post(url,headers=headers, data=json.dumps(data))
if response.status_code != 200:
    print(f"Unable to submit URLScan.io scan: Error {response.status_code}: {response.json().get("message")}")
    exit()

# If request to scan was successful, get the results
print("Submission to URLScan.io scanner successful!")
results_url = response.json()['result']
results_uuid = response.json()['uuid']

# Wait for scanner to respond with results (with rate limiting)
# Poll up to 20 times + 5 seconds (65 seconds total)
print("Waiting for scan to finish..", end='', flush=True)
time.sleep(5)
for _ in range(30): 
    result = requests.get(results_url)
    if result.status_code == 200:
        print("Scan complete!")
        break
    else:
        print('.', end='', flush=True)
    time.sleep(2)
else:
    print("Scan not ready or failed.")
    exit()

# Get URL analysis results
analysis_url = f"https://urlscan.io/api/v1/result/{results_uuid}"
analysis = requests.get(analysis_url)

# Wait for scanner to respond with screenshot results (with rate limiting)
# Poll up to 20 times + 5 seconds (65 seconds total)
print("Waiting for screenshot to be sent..", end='', flush=True)
time.sleep(2)
for _ in range(30): 
    screenshot_response = requests.get(f'https://urlscan.io/screenshots/{results_uuid}.png')

    if screenshot_response.status_code == 200:
        with open(f'{domain}.png', 'wb') as f:
            f.write(screenshot_response.content)
        print("Screenshot saved!")
        break
    else:
        print('.', end='', flush=True)
    time.sleep(2)
else:
    print("Screenshot not available.")
    exit()

# Extract threat analysis from URL Scanner
# Ensure URLScan.io has a verdict before printing it out
#print(analysis.json())
verdicts = analysis.json().get("verdicts", {}).get("urlscan", {})
has_verdict = verdicts.get("hasVeridicts")

if has_verdict is None:
    print(f"URLScan.io has no verdict on {domain}")
else:
    # Print out threat score
    score = verdicts.get("score")
    print(f"Threat Score: {score}")

    # Print out categories (e.g., phishing, malware)
    categories = verdicts.get("categories", [])
    if categories:
        print("Threat Categories:")
        for category in categories:
            print(f"- {category}")
    else:
        print("No threat categories found.")

    # Print out detected brand impersonations
    brands = verdicts.get("brands", [])
    if brands:
        print("Detected Brand Impersonation:")
        for brand in brands:
            name = brand.get("name")
            country = ", ".join(brand.get("country", [])) or "N/A"
            vertical = ", ".join(brand.get("vertical", [])) or "N/A"
            print(f"- {name} (Country: {country}, Industry: {vertical})")
    else:
        print("No brand impersonation detected.")
