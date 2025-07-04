
![image](https://github.com/user-attachments/assets/0b49b5f6-379c-4a0e-941b-0a52a0dac94e)


### ⚡ About R3CON-X

**R3CON-X** is an actively developed **reconnaissance automation framework** designed to simplify and supercharge bug bounty recon workflows. Built with modularity and speed in mind, it seamlessly integrates top-tier tools and automates critical steps — from subdomain discovery to crawling and JS extraction.

> 💡 **More recon modules are coming soon**: DNS brute-forcing, JS secret extraction, wayback machine scraping, GF pattern matching, directory fuzzing, and more will be added in future updates. Stay tuned!

---

### 📁 What R3CON-X Does

R3CON-X automatically performs:

- Subdomain Enumeration → via Subfinder, Assetfinder, Amass  
- Subdomain Takeover Detection → via Subzy  
- Live Domain Probing → via Httpx  
- Crawling & JS File Discovery → via Katana  
- `.js` file saving, directory creation, and organized result storage  

---

### 📂 Output Directory Structure

For every domain, a structured folder is created in `output/<domain>/` containing:

- `subdomains.txt` → merged results from Subfinder, Assetfinder, Amass  
- `live.txt` → live domains identified by Httpx  
- `takeover.txt` → vulnerable subdomains (if any) from Subzy  
- `js_files.txt` → extracted JavaScript file URLs  
- `crawled_urls.txt` → all URLs crawled by Katana  
- `katana_output/` → raw Katana output folder  
- `js_files/` → downloaded JS files folder  

All outputs are timestamped and separated for clean organization.

---

### ⚙️ Customization Options

To modify internal delays or tool behavior:

- Change sleep delay → edit `time.sleep()` around **line 700**
- Change tool configs → update `ToolConfig` in lines 27–37 (like concurrency, ports, extensions)

---

### 🛠️ Installation Guide

#### **1. Clone the repository**
```
git clone https://github.com/saurabhsingh-26/R3CON-X.git
cd R3CON-X
```
**2. Set executable permission (Linux/macOS)**
``` 
chmod +x recon.py

```
**3.Create & activate virtual environment
bash**
```
python3 -m venv venv
source venv/bin/activate      # Linux/macOS
venv\Scripts\activate.bat     # Windows

```
**4. Install required Python packages**
```
pip install -r requirements.txt

```
🔧 **External Tools Required (Pre-installed or Install via Go)**
```
subfinder
assetfinder
amass
subzy
httpx
katana

UNIX commands: grep, awk, sort, cut
```

**Install Go-based tools using:**
```
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/LukaSikic/subzy@latest
```

 **Example Usage**
```
python3 recon.py -d example.com -t 40
-d = target domain
-t = threads
--skip amass = skip amass
--help = see full options
```


**📌 Coming Soon**
```
Nuclie
Wayback URL extraction
JS secrets/keys/fetch pattern finder
GF patterns & vulnerability filters
Fuzzing with wordlists (e.g., Dirsearch or FFUF)

```
🙌 Author
Made with 🔥 by Saurabh Singh
Bug Bounty Hunter | Recon Automation Enthusiast | Security Researcher

Let me know if you want this as a README.md file or if you'd like the requirements.txt updated now too!
