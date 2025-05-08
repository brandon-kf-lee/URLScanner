# URLScanner
## ISP 452: Digital Forensics (Final Project)
Scans URLs and provides a report for forensic analysis
### Features
* Input URL and receive a detailed report from VirusTotal, PhishTank, and AbuseIPDB
    - Allows bulk input from .csv formatted file
* Displays any reports of malicious activity associated with the URL and detected IP addresses
* Displays any other relevant information from the URL
* Output formatting
    - Color-coded console output: red (malicious), yellow (suspicious), green (clean)
    - Timestamps for each lookup
    - (Optional) Output results to .csv file