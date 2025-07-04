#!/usr/bin/env python3
import os
import subprocess
import argparse
import sys
import time
import shutil
import json
import threading
import psutil
from datetime import datetime
import re
import signal

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

class ToolConfig:
    """Default tool configurations"""
    DEFAULT_AMASS_TIMEOUT = 25
    DEFAULT_SUBZY_CONCURRENCY = 100
    DEFAULT_HTTPX_PORTS = "80,443,8080,8000,8888"
    DEFAULT_HTTPX_THREADS = 200
    DEFAULT_HTTPX_TIMEOUT = 10
    DEFAULT_KATANA_DEPTH = 5
    DEFAULT_KATANA_CONCURRENCY = 50
    DEFAULT_KATANA_RATE_LIMIT = 100
    DEFAULT_KATANA_EXCLUDE_EXTENSIONS = "woff,css,png,svg,jpg,woff2,jpeg,gif,svg"

class ReconStats:
    def __init__(self):
        self.subdomains_found = 0
        self.live_domains = 0
        self.js_files = 0
        self.takeover_vulns = 0
        self.start_time = time.time()
        self.lock = threading.Lock()
    
    def update_subdomains(self, count):
        with self.lock:
            self.subdomains_found = count
    
    def update_live(self, count):
        with self.lock:
            self.live_domains = count
    
    def update_js(self, count):
        with self.lock:
            self.js_files = count
    
    def update_takeover(self, count):
        with self.lock:
            self.takeover_vulns = count
    
    def get_runtime(self):
        return time.time() - self.start_time

stats = ReconStats()
def banner():
    print(f"{Colors.GREEN}{Colors.BOLD}" + r"""
════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
           .--,-``-.                   ,----..            ,--.                         
,-.----.    /   /     '.    ,----..     /   /   \         ,--.'|          ,--,     ,--,  
\    /  \  / ../        ;  /   /   \   /   .     :    ,--,:  : |          |'. \   / .`|  
;   :    \ \ ``\  .`-    '|   :     : .   /   ;.  \,`--.'`|  ' :    ,---,.; \ `\ /' / ;  
|   | .\ :  \___\/   \   :.   |  ;. /.   ;   /  ` ;|   :  :  | |  ,'  .' |`. \  /  / .'  
.   : |: |       \   :   |.   ; /--` ;   |  ; \ ; |:   |   \ | :,---.'   , \  \/  / ./   
|   |  \ :       /  /   / ;   | ;    |   :  | ; | '|   : '  '; ||   |    |  \  \.'  /    
|   : .  /       \  \   \ |   : |    .   |  ' ' ' :'   ' ;.    ;:   :  .'    \  ;  ;     
;   | |  \   ___ /   :   |.   | '___ '   ;  \; /  ||   | | \   |:   |.'     / \  \  \    
|   | ;\  \ /   /\   /   :'   ; : .'| \   \  ',  / '   : |  ; .'`---'      ;  /\  \  \   
:   ' | \.'/ ,,/  ',-    .'   | '/  :  ;   :    /  |   | '`--'           ./__;  \  ;  \  
:   : :-'  \ ''\        ; |   :    /    \   \ .'   '   : |               |   : / \  \  ; 
|   |.'     \   \     .'   \   \ .'      `---`     ;   |.'               ;   |/   \  ' | 
`---'        `--`-,,-'      `---`                  '---'                 `---'     `--`  
                        
════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
""" + f"{Colors.YELLOW}{Colors.BOLD}" + r"""
                                ★ R3CON-X = BY SAURABH - Enhanced Recon Automation Tool ★ 
════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
""" + f"{Colors.RESET}")

def get_system_threads():
    """Auto-detect optimal thread count based on system resources"""
    cpu_count = psutil.cpu_count()
    memory_gb = psutil.virtual_memory().total / (1024**3)
    
    if memory_gb >= 8:
        return min(cpu_count * 2, 100)
    elif memory_gb >= 4:
        return min(cpu_count, 50)
    else:
        return min(cpu_count // 2, 20)

def progress_bar(current, total, bar_length=50):
    """Create a progress bar"""
    if total == 0:
        return f"[{'█' * bar_length}] 100%"
    
    percent = float(current) / total
    filled_length = int(bar_length * percent)
    bar = '█' * filled_length + '▒' * (bar_length - filled_length)
    return f"[{bar}] {percent:.1%}"

def print_status(message, level="info"):
    """Print colored status messages"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    colors = {
        "info": Colors.BLUE,
        "success": Colors.GREEN,
        "warning": Colors.YELLOW,
        "error": Colors.RED,
        "critical": Colors.RED + Colors.BOLD
    }
    
    color = colors.get(level, Colors.WHITE)
    print(f"{color}[{timestamp}] {message}{Colors.RESET}")

def print_stats():
    """Print real-time statistics"""
    runtime = stats.get_runtime()
    print(f"\n{Colors.CYAN}{'='*80}")
    print(f"📊 LIVE STATS - Runtime: {runtime:.0f}s")
    print(f"🔍 Subdomains Found: {Colors.GREEN}{stats.subdomains_found}{Colors.CYAN}")
    print(f"🌐 Live Domains: {Colors.GREEN}{stats.live_domains}{Colors.CYAN}")
    print(f"📄 JS Files: {Colors.GREEN}{stats.js_files}{Colors.CYAN}")
    print(f"⚠️  Takeover Vulns: {Colors.RED}{stats.takeover_vulns}{Colors.CYAN}")
    print(f"{'='*80}{Colors.RESET}")

def save_state(domain, completed_modules):
    """Save progress state"""
    state = {
        "domain": domain,
        "completed_modules": completed_modules,
        "timestamp": datetime.now().isoformat(),
        "stats": {
            "subdomains_found": stats.subdomains_found,
            "live_domains": stats.live_domains,
            "js_files": stats.js_files,
            "takeover_vulns": stats.takeover_vulns
        }
    }
    
    with open(f".{domain}_recon_state", "w") as f:
        json.dump(state, f, indent=2)

def load_state(domain):
    """Load progress state"""
    state_file = f".{domain}_recon_state"
    if os.path.exists(state_file):
        try:
            with open(state_file, "r") as f:
                return json.load(f)
        except:
            return None
    return None

def clean_temp_files(domain):
    """Clean temporary files"""
    temp_files = [f".{domain}_recon_state"]
    for temp_file in temp_files:
        if os.path.exists(temp_file):
            os.remove(temp_file)
            print_status(f"Cleaned temporary file: {temp_file}", "info")

def check_and_install_tools(verbose=False):
    """Check for required tools and offer installation"""
    tools = {
        "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
        "amass": "sudo apt install amass -y",
        "subzy": "go install -v github.com/LukaSikic/subzy@latest",
        "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "katana": "go install github.com/projectdiscovery/katana/cmd/katana@latest"
    }
    
    missing_tools = []
    for tool, install_cmd in tools.items():
        if not shutil.which(tool) and not shutil.which(f"{tool}-toolkit"):
            missing_tools.append((tool, install_cmd))
    
    if missing_tools:
        print_status(f"Missing tools detected: {', '.join([t[0] for t in missing_tools])}", "warning")
        
        if verbose:
            for tool, install_cmd in missing_tools:
                print(f"  {Colors.YELLOW}Install {tool}:{Colors.RESET} {install_cmd}")
        
        install = input(f"{Colors.YELLOW}Install missing tools? (y/n): {Colors.RESET}")
        if install.lower() == 'y':
            for tool, install_cmd in missing_tools:
                print_status(f"Installing {tool}...", "info")
                try:
                    subprocess.run(install_cmd, shell=True, check=True)
                    print_status(f"Successfully installed {tool}", "success")
                except subprocess.CalledProcessError:
                    print_status(f"Failed to install {tool}", "error")
    else:
        print_status("All required tools are installed", "success")

def count_lines_in_file(filepath):
    """Count lines in a file efficiently"""
    if not os.path.exists(filepath):
        return 0
    try:
        with open(filepath, 'r') as f:
            return sum(1 for _ in f)
    except:
        return 0

def remove_duplicates_realtime(input_files, output_file, exclude_patterns=None):
    """Remove duplicates in real-time with exclude patterns"""
    seen = set()
    exclude_regex = []
    
    if exclude_patterns:
        for pattern in exclude_patterns:
            try:
                exclude_regex.append(re.compile(pattern))
            except re.error:
                print_status(f"Invalid regex pattern: {pattern}", "warning")
    
    with open(output_file, 'w') as outf:
        for input_file in input_files:
            if os.path.exists(input_file):
                with open(input_file, 'r') as inf:
                    for line in inf:
                        domain = line.strip()
                        if domain and domain not in seen:
                            # Check exclude patterns
                            excluded = False
                            for regex in exclude_regex:
                                if regex.search(domain):
                                    excluded = True
                                    break
                            
                            if not excluded:
                                seen.add(domain)
                                outf.write(domain + '\n')
                                stats.update_subdomains(len(seen))
    
    return len(seen)

def setup_folders(domain):
    """Setup output directories"""
    print_status("Setting up output directories", "info")
    os.makedirs(domain, exist_ok=True)
    os.makedirs(f"{domain}/katana", exist_ok=True)
    print_status("✓ Directory structure created", "success")

def run_subfinder(domain, output_dir, threads=50, wordlist=None, resolvers=None, timeout=30, verbose=False):
    """Run subfinder with enhanced options"""
    print_status("🔍 Running Subfinder", "info")
    
    cmd = f"subfinder -d {domain} -all -recursive -t {threads} -timeout {timeout}"
    
    if wordlist:
        cmd += f" -w {wordlist}"
    if resolvers:
        cmd += f" -r {resolvers}"
    if verbose:
        cmd += " -v"
    
    cmd += f" -o {output_dir}/subfinder.txt"
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            count = count_lines_in_file(f"{output_dir}/subfinder.txt")
            print_status(f"✓ Subfinder completed - Found {count} subdomains", "success")
            return True
        else:
            print_status(f"✗ Subfinder failed: {result.stderr}", "error")
            return False
    except Exception as e:
        print_status(f"✗ Subfinder error: {str(e)}", "error")
        return False

def run_assetfinder(domain, output_dir, verbose=False):
    """Run assetfinder with enhanced options"""
    print_status("🔍 Running Assetfinder", "info")
    
    cmd = f"assetfinder --subs-only {domain}"
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            with open(f"{output_dir}/assetfinder.txt", 'w') as f:
                f.write(result.stdout)
            count = count_lines_in_file(f"{output_dir}/assetfinder.txt")
            print_status(f"✓ Assetfinder completed - Found {count} subdomains", "success")
            return True
        else:
            print_status(f"✗ Assetfinder failed: {result.stderr}", "error")
            return False
    except Exception as e:
        print_status(f"✗ Assetfinder error: {str(e)}", "error")
        return False

def run_amass(domain, output_dir, timeout=None, verbose=False):
    """Run amass with enhanced options"""
    print_status("🔍 Running Amass", "info")
    
    # Use default timeout if not specified
    if timeout is None:
        timeout = ToolConfig.DEFAULT_AMASS_TIMEOUT
    
    cmd = f"amass enum -passive -d {domain} -timeout {timeout}"
    if verbose:
        cmd += " -v"
    cmd += f" -o {output_dir}/amass.txt"
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            count = count_lines_in_file(f"{output_dir}/amass.txt")
            print_status(f"✓ Amass completed - Found {count} subdomains", "success")
            return True
        else:
            print_status(f"✗ Amass failed: {result.stderr}", "error")
            return False
    except Exception as e:
        print_status(f"✗ Amass error: {str(e)}", "error")
        return False

def run_parallel_subdomain_enum(domain, output_dir, threads, wordlist, resolvers, timeout, verbose, amass_timeout=None):
    """Run subdomain enumeration tools in parallel"""
    print_status("🚀 Running subdomain enumeration in parallel", "info")
    
    def run_subfinder_thread():
        return run_subfinder(domain, output_dir, threads, wordlist, resolvers, timeout, verbose)
    
    def run_assetfinder_thread():
        return run_assetfinder(domain, output_dir, verbose)
    
    def run_amass_thread():
        return run_amass(domain, output_dir, amass_timeout, verbose)
    
    # Start all threads
    threads_list = []
    results = {}
    
    t1 = threading.Thread(target=lambda: results.update({"subfinder": run_subfinder_thread()}))
    t2 = threading.Thread(target=lambda: results.update({"assetfinder": run_assetfinder_thread()}))
    t3 = threading.Thread(target=lambda: results.update({"amass": run_amass_thread()}))
    
    threads_list = [t1, t2, t3]
    
    for t in threads_list:
        t.start()
    
    # Wait for all to complete
    for t in threads_list:
        t.join()
    
    # Check results
    successful_tools = [tool for tool, success in results.items() if success]
    failed_tools = [tool for tool, success in results.items() if not success]
    
    if successful_tools:
        print_status(f"✓ Parallel enumeration completed. Successful: {', '.join(successful_tools)}", "success")
    if failed_tools:
        print_status(f"⚠ Some tools failed: {', '.join(failed_tools)}", "warning")
    
    return len(successful_tools) > 0

def combine_subdomains(output_dir, exclude_patterns=None):
    """Combine subdomains and remove duplicates"""
    print_status("🔄 Combining subdomains and removing duplicates", "info")
    
    input_files = [
        f"{output_dir}/subfinder.txt",
        f"{output_dir}/assetfinder.txt",
        f"{output_dir}/amass.txt"
    ]
    
    total_unique = remove_duplicates_realtime(input_files, f"{output_dir}/subdomains.txt", exclude_patterns)
    print_status(f"✓ Combined {total_unique} unique subdomains", "success")
    return True

def run_subzy(output_dir, concurrency=None, verbose=False):
    """Run subzy for subdomain takeover detection"""
    print_status("🔍 Checking for subdomain takeover vulnerabilities", "info")
    
    # Use default concurrency if not specified
    if concurrency is None:
        concurrency = ToolConfig.DEFAULT_SUBZY_CONCURRENCY
    
    # Clean the subdomains file first - remove protocols and paths
    clean_domains_file = f"{output_dir}/subdomains_clean.txt"
    clean_cmd = f"cat {output_dir}/subdomains.txt | sed 's|https\\?://||' | sed 's|/.*||' | sort -u > {clean_domains_file}"
    
    try:
        # Clean the domains first
        subprocess.run(clean_cmd, shell=True, check=True)
        
        # Check if cleaned file exists and has content
        if not os.path.exists(clean_domains_file) or count_lines_in_file(clean_domains_file) == 0:
            print_status("✗ No clean domains found for subzy scan", "error")
            return False
        
        clean_count = count_lines_in_file(clean_domains_file)
        print_status(f"📝 Cleaned {clean_count} domains for subzy scan", "info")
        
        # Run subzy with cleaned domains
        cmd = f"subzy run --targets {clean_domains_file} --concurrency {concurrency} --hide_fails --verify_ssl"
        
        if verbose:
            cmd += " --verbose"
        
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        # Save full output
        with open(f"{output_dir}/subdomain_takeover.txt", 'w') as f:
            f.write(result.stdout)
            if result.stderr:
                f.write("\n--- STDERR ---\n")
                f.write(result.stderr)
        
        # Parse and save vulnerable domains with details
        vulnerable_domains = []
        lines = result.stdout.split('\n')
        
        for line in lines:
            if line.strip():
                # Look for vulnerable indicators in the output
                if any(keyword in line.upper() for keyword in ['VULNERABLE', 'TAKEOVER', 'CNAME']):
                    vulnerable_domains.append(line.strip())
        
        # Save vulnerable domains separately
        if vulnerable_domains:
            with open(f"{output_dir}/vulnerable_subdomains.txt", 'w') as f:
                for vuln in vulnerable_domains:
                    f.write(vuln + '\n')
            
            vulns_count = len(vulnerable_domains)
            stats.update_takeover(vulns_count)
            print_status(f"⚠️  Found {vulns_count} potential subdomain takeover vulnerabilities", "critical")
            
            # Print vulnerable domains for immediate attention
            print(f"\n{Colors.RED}🚨 VULNERABLE SUBDOMAINS FOUND:{Colors.RESET}")
            for vuln in vulnerable_domains[:5]:  # Show first 5
                print(f"   {Colors.YELLOW}• {vuln}{Colors.RESET}")
            if len(vulnerable_domains) > 5:
                print(f"   {Colors.CYAN}... and {len(vulnerable_domains) - 5} more (check vulnerable_subdomains.txt){Colors.RESET}")
        else:
            stats.update_takeover(0)
            print_status("✓ No subdomain takeover vulnerabilities found", "success")
        
        # Clean up temporary file
        if os.path.exists(clean_domains_file):
            os.remove(clean_domains_file)
        
        return True
        
    except subprocess.CalledProcessError as e:
        print_status(f"✗ Domain cleaning failed: {e}", "error")
        return False
    except Exception as e:
        print_status(f"✗ Subzy error: {str(e)}", "error")
        return False

def run_httpx(output_dir, ports=None, threads=None, timeout=None, verbose=False):
    """Run httpx to find live domains"""
    print_status("🌐 Scanning for live domains with httpx", "info")
    
    httpx_cmd = shutil.which("httpx") or shutil.which("httpx-toolkit")
    if not httpx_cmd:
        print_status("✗ httpx not found. Skipping...", "error")
        return False
    
    # Use default values if not specified
    if ports is None:
        ports = ToolConfig.DEFAULT_HTTPX_PORTS
    if threads is None:
        threads = ToolConfig.DEFAULT_HTTPX_THREADS
    if timeout is None:
        timeout = ToolConfig.DEFAULT_HTTPX_TIMEOUT
    
    cmd = f"{httpx_cmd} -l {output_dir}/subdomains.txt -ports {ports} -threads {threads} -timeout {timeout} -title -status-code"
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        with open(f"{output_dir}/httpx.txt", 'w') as f:
            f.write(result.stdout)
        
        # Extract live domains
        subprocess.run(f"awk '{{print $1}}' {output_dir}/httpx.txt > {output_dir}/live.txt", shell=True)
        
        live_count = count_lines_in_file(f"{output_dir}/live.txt")
        stats.update_live(live_count)
        print_status(f"✓ Found {live_count} live domains", "success")
        
        return True
    except Exception as e:
        print_status(f"✗ Httpx error: {str(e)}", "error")
        return False

def run_katana(output_dir, depth=None, concurrency=None, rate_limit=None, exclude_extensions=None, verbose=False):
    """Run katana for web crawling"""
    print_status("🕷️ Crawling with Katana", "info")
    
    # Use default values if not specified
    if depth is None:
        depth = ToolConfig.DEFAULT_KATANA_DEPTH
    if concurrency is None:
        concurrency = ToolConfig.DEFAULT_KATANA_CONCURRENCY
    if rate_limit is None:
        rate_limit = ToolConfig.DEFAULT_KATANA_RATE_LIMIT
    if exclude_extensions is None:
        exclude_extensions = ToolConfig.DEFAULT_KATANA_EXCLUDE_EXTENSIONS
    
    katana_output = f"{output_dir}/katana/katana.txt"
    cmd = f"katana -list {output_dir}/live.txt -d {depth} -jc -kf all -ef {exclude_extensions} -c {concurrency} -rl {rate_limit}"
    
    if verbose:
        cmd += " -v"
    
    cmd += f" -o {katana_output}"
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        # Extract JS files
        subprocess.run(f"grep '\\.js$' {katana_output} | sort -u > {output_dir}/katana/js-only.txt", shell=True)
        
        js_count = count_lines_in_file(f"{output_dir}/katana/js-only.txt")
        stats.update_js(js_count)
        print_status(f"✓ Katana completed - Found {js_count} JS files", "success")
        
        return True
    except Exception as e:
        print_status(f"✗ Katana error: {str(e)}", "error")
        return False

def generate_report(domain, output_format="txt"):
    """Generate final report"""
    print_status("📊 Generating final report", "info")
    
    report_data = {
        "domain": domain,
        "scan_date": datetime.now().isoformat(),
        "runtime": f"{stats.get_runtime():.2f} seconds",
        "statistics": {
            "subdomains_found": stats.subdomains_found,
            "live_domains": stats.live_domains,
            "js_files": stats.js_files,
            "takeover_vulnerabilities": stats.takeover_vulns
        }
    }
    
    if output_format == "json":
        with open(f"{domain}/report.json", 'w') as f:
            json.dump(report_data, f, indent=2)
        print_status("✓ JSON report generated", "success")
    elif output_format == "csv":
        import csv
        with open(f"{domain}/report.csv", 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Metric', 'Value'])
            writer.writerow(['Domain', report_data['domain']])
            writer.writerow(['Scan Date', report_data['scan_date']])
            writer.writerow(['Runtime', report_data['runtime']])
            for key, value in report_data['statistics'].items():
                writer.writerow([key.replace('_', ' ').title(), value])
        print_status("✓ CSV report generated", "success")
    else:
        with open(f"{domain}/report.txt", 'w') as f:
            f.write(f"R3CON-X Scan Report\n")
            f.write(f"==================\n\n")
            f.write(f"Domain: {report_data['domain']}\n")
            f.write(f"Scan Date: {report_data['scan_date']}\n")
            f.write(f"Runtime: {report_data['runtime']}\n\n")
            f.write(f"Statistics:\n")
            for key, value in report_data['statistics'].items():
                f.write(f"  {key.replace('_', ' ').title()}: {value}\n")
        print_status("✓ Text report generated", "success")

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    print_status("\n🛑 Scan interrupted by user", "warning")
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    
    banner()
    
    parser = argparse.ArgumentParser(
        description="R3CON-X - Enhanced Recon Automation Tool for Bug Bounty Hunters",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d example.com                          # Basic scan
  %(prog)s -d example.com -P                       # Parallel subdomain enumeration
  %(prog)s -d example.com -t 100 -v 2              # High threads, verbose output
  %(prog)s -d example.com --exclude "*.cdn.*"      # Exclude CDN subdomains
  %(prog)s --resume example.com                    # Resume interrupted scan
  %(prog)s -d example.com -o json                  # Output in JSON format
  %(prog)s -d example.com --amass-timeout 30       # Custom amass timeout
  %(prog)s -d example.com --subzy-concurrency 150  # Custom subzy concurrency
  %(prog)s -d example.com --httpx-ports 80,443     # Custom httpx ports
  %(prog)s -d example.com --katana-depth 3         # Custom katana depth
        """
    )
    
    # Main arguments
    parser.add_argument("-d", "--domain", help="Target domain (e.g., example.com)")
    parser.add_argument("--resume", help="Resume interrupted scan for domain")
    parser.add_argument("--from", dest="from_step", help="Start from a specific step (e.g., subdomains.txt)")
    parser.add_argument("--skip", nargs="*", default=[], help="Modules to skip: subfinder assetfinder amass subzy httpx katana")
    
  # Enhanced options
    parser.add_argument("-t", "--threads", type=int, help="Custom thread count per tool (default: auto-detect)")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist path for subdomain enumeration")
    parser.add_argument("-r", "--resolvers", help="Custom DNS resolvers file")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Verbose output (-v, -vv for more verbose)")
    parser.add_argument("-P", "--parallel", action="store_true", help="Run subdomain enumeration in parallel")
    parser.add_argument("-o", "--output", choices=["txt", "json", "csv"], default="txt", help="Output format for reports")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout for individual tool operations")
    parser.add_argument("--exclude", nargs="*", help="Exclude patterns for subdomain filtering")
    
    # Tool-specific options
    parser.add_argument("--amass-timeout", type=int, default=ToolConfig.DEFAULT_AMASS_TIMEOUT, help="Amass timeout in minutes")
    parser.add_argument("--subzy-concurrency", type=int, default=ToolConfig.DEFAULT_SUBZY_CONCURRENCY, help="Subzy concurrency level")
    parser.add_argument("--httpx-ports", default=ToolConfig.DEFAULT_HTTPX_PORTS, help="Httpx ports to scan")
    parser.add_argument("--httpx-threads", type=int, default=ToolConfig.DEFAULT_HTTPX_THREADS, help="Httpx thread count")
    parser.add_argument("--httpx-timeout", type=int, default=ToolConfig.DEFAULT_HTTPX_TIMEOUT, help="Httpx timeout")
    parser.add_argument("--katana-depth", type=int, default=ToolConfig.DEFAULT_KATANA_DEPTH, help="Katana crawl depth")
    parser.add_argument("--katana-concurrency", type=int, default=ToolConfig.DEFAULT_KATANA_CONCURRENCY, help="Katana concurrency")
    parser.add_argument("--katana-rate-limit", type=int, default=ToolConfig.DEFAULT_KATANA_RATE_LIMIT, help="Katana rate limit")
    parser.add_argument("--katana-exclude-extensions", default=ToolConfig.DEFAULT_KATANA_EXCLUDE_EXTENSIONS, help="Katana exclude extensions")
    
    # Utility options
    parser.add_argument("--check-tools", action="store_true", help="Check and install required tools")
    parser.add_argument("--clean", action="store_true", help="Clean temporary files after scan")
    parser.add_argument("--no-stats", action="store_true", help="Disable real-time statistics")
    parser.add_argument("--auto-threads", action="store_true", help="Use auto-detected thread count")
    
    args = parser.parse_args()
    
    # Check tools if requested
    if args.check_tools:
        check_and_install_tools(verbose=True)
        return
    
    # Validate domain or resume option
    if not args.domain and not args.resume:
        print_status("❌ Error: Please provide a domain (-d) or resume option (--resume)", "error")
        parser.print_help()
        sys.exit(1)
    
    # Set domain
    domain = args.domain or args.resume
    
    # Auto-detect threads if not specified
    if args.auto_threads or not args.threads:
        args.threads = get_system_threads()
        print_status(f"🔧 Auto-detected optimal thread count: {args.threads}", "info")
    
    # Check if resuming
    if args.resume:
        print_status(f"🔄 Attempting to resume scan for {domain}", "info")
        saved_state = load_state(domain)
        if saved_state:
            print_status(f"✓ Found saved state from {saved_state['timestamp']}", "success")
            completed_modules = saved_state.get('completed_modules', [])
            # Update stats from saved state
            saved_stats = saved_state.get('stats', {})
            stats.subdomains_found = saved_stats.get('subdomains_found', 0)
            stats.live_domains = saved_stats.get('live_domains', 0)
            stats.js_files = saved_stats.get('js_files', 0)
            stats.takeover_vulns = saved_stats.get('takeover_vulns', 0)
        else:
            print_status("⚠️ No saved state found, starting fresh scan", "warning")
            completed_modules = []
    else:
        completed_modules = []
    
    # Check required tools
    print_status("🔍 Checking required tools", "info")
    check_and_install_tools(verbose=args.verbose > 0)
    
    # Setup directories
    setup_folders(domain)
    
    # Start statistics thread if enabled
    if not args.no_stats:
        def stats_thread():
            while True:
                time.sleep(120)
                print_stats()
        
        stats_t = threading.Thread(target=stats_thread, daemon=True)
        stats_t.start()
    
    try:
        # Phase 1: Subdomain Enumeration
        print_status("🚀 Starting Phase 1: Subdomain Enumeration", "info")
        
        if args.parallel and 'subdomain_enum' not in completed_modules:
            if run_parallel_subdomain_enum(domain, domain, args.threads, args.wordlist, 
                                         args.resolvers, args.timeout, args.verbose > 0, args.amass_timeout):
                completed_modules.append('subdomain_enum')
                save_state(domain, completed_modules)
        else:
            # Sequential subdomain enumeration
            if 'subfinder' not in args.skip and 'subfinder' not in completed_modules:
                if run_subfinder(domain, domain, args.threads, args.wordlist, args.resolvers, 
                               args.timeout, args.verbose > 0):
                    completed_modules.append('subfinder')
                    save_state(domain, completed_modules)
            
            if 'assetfinder' not in args.skip and 'assetfinder' not in completed_modules:
                if run_assetfinder(domain, domain, args.verbose > 0):
                    completed_modules.append('assetfinder')
                    save_state(domain, completed_modules)
            
            if 'amass' not in args.skip and 'amass' not in completed_modules:
                if run_amass(domain, domain, args.amass_timeout, args.verbose > 0):
                    completed_modules.append('amass')
                    save_state(domain, completed_modules)
        
        # Combine subdomains
        if 'combine' not in completed_modules:
            if combine_subdomains(domain, args.exclude):
                completed_modules.append('combine')
                save_state(domain, completed_modules)
        
        # Phase 2: Subdomain Takeover Detection
        print_status("🚀 Starting Phase 2: Subdomain Takeover Detection", "info")
        
        if 'subzy' not in args.skip and 'subzy' not in completed_modules:
            if run_subzy(domain, args.subzy_concurrency, args.verbose > 0):
                completed_modules.append('subzy')
                save_state(domain, completed_modules)
        
        # Phase 3: Live Domain Detection
        print_status("🚀 Starting Phase 3: Live Domain Detection", "info")
        
        if 'httpx' not in args.skip and 'httpx' not in completed_modules:
            if run_httpx(domain, args.httpx_ports, args.httpx_threads, args.httpx_timeout, args.verbose > 0):
                completed_modules.append('httpx')
                save_state(domain, completed_modules)
        
        # Phase 4: Web Crawling
        print_status("🚀 Starting Phase 4: Web Crawling", "info")
        
        if 'katana' not in args.skip and 'katana' not in completed_modules:
            if run_katana(domain, args.katana_depth, args.katana_concurrency, 
                         args.katana_rate_limit, args.katana_exclude_extensions, args.verbose > 0):
                completed_modules.append('katana')
                save_state(domain, completed_modules)
        
        # Final Report Generation
        print_status("🚀 Starting Final Report Generation", "info")
        generate_report(domain, args.output)
        
        # Final statistics
        print_stats()
        
        # Success message
        print(f"\n{Colors.GREEN}{Colors.BOLD}✅ SCAN COMPLETED SUCCESSFULLY!{Colors.RESET}")
        print(f"{Colors.CYAN}📁 Results saved in: {Colors.YELLOW}{domain}/{Colors.RESET}")
        print(f"{Colors.CYAN}📊 Report: {Colors.YELLOW}{domain}/report.{args.output}{Colors.RESET}")
        
        # Clean temporary files if requested
        if args.clean:
            clean_temp_files(domain)
        
    except KeyboardInterrupt:
        print_status("\n🛑 Scan interrupted by user", "warning")
        save_state(domain, completed_modules)
        print_status(f"💾 Progress saved. Resume with: --resume {domain}", "info")
        sys.exit(0)
    except Exception as e:
        print_status(f"❌ Fatal error: {str(e)}", "error")
        save_state(domain, completed_modules)
        sys.exit(1)

if __name__ == "__main__":
    main()