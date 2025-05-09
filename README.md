# URLScanner
## ISP 452: Digital Forensics (Final Project)
Ever wnted to quickly see if a URL is safe to click on? This tool will give you a quick consensus from the most powerful antivirus engines and even safely provide a screenshot of the site's landing page so you can see for yourself!

### Features
* Integration with:
    - [VirusTotal](https://www.virustotal.com/)
    - [URLScan.io](https://urlscan.io/)
* Input URL and receive a summarised report from VirusTotal and URLScan.io
* Displays any reports of malicious or suspicious activity associated with the URL
* Displays any other relevant information from the URL 
    - Saves a screenshot of the landing page (obtained through URLScan.io)
    - Any resolved URLs (IPv4 and IPv6)
* Output formatting
    - Color-coded console output: red (malicious), yellow (suspicious), green (clean)
    - Timestamps for each lookup

### To Run
* pip install -r requirements.txt
    - Install required Python libraries
* touch .env
    - Add VirusTotal and URLScan.io API keys
* python URLScanner.py \<URL\>
    - Input a URL of any format