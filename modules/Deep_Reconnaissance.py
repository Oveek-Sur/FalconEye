#!/usr/bin/env python3
"""FalconEye Deep Reconnaissance Module - Final Stable Version with Optimized Flow and Logic Fixes"""
import os
import re
import shutil
import subprocess
import sys
import time
import socket
import tempfile
import platform
import json
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

# --- External Library Check ---
try:
    import requests
    from requests.exceptions import RequestException
    import dns.resolver
except ImportError:
    requests = None
    RequestException = None
    dns = None

# --- Global Wordlist Paths (Defaults) ---
DEFAULT_DNS_WORDLISTS = [
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
]
DEFAULT_DIR_WORDLISTS = [
    "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirb/common.txt"
]

# =======================================================
# --- REQUIRED MODULE ATTRIBUTES ---
# =======================================================
name = "Deep Reconnaissance (CLI Report - Final)"
description = "Gathers detailed DNS, WHOIS, Web Tech, WAF, performs Visual Recon, Vulnerability Check, and Directory/Employee Search. Focuses on robust, non-interactive execution."
version = "8.4 (Final Live Gobuster Fix)"

# Global variables for report paths (set in run function)
GLOBAL_REPORT_DIR: Optional[str] = None
GLOBAL_TARGET_DOMAIN: Optional[str] = None

# =======================================================
# --- STANDALONE HELPER FUNCTIONS ---
# =======================================================

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    LIGHT_GRAY = '\033[37m'
    CYAN = '\033[36m'
    YELLOW = '\033[33m'

def print_colored(text: str, color=Colors.ENDC, bold: bool = False):
    """Print colored text to terminal"""
    style = Colors.BOLD if bold else ""
    print(f"{color}{style}{text}{Colors.ENDC}")

def draw_separator(char="─", width: int = 80, color=Colors.LIGHT_GRAY):
    """Draw a horizontal separator line"""
    print_colored(char * width, color=color)

# --- REPORT MANAGEMENT (Simplified to only write, no interactive save) ---
def write_to_report(filename: str, content: str, mode='w'):
    """Writes content to a file inside the GLOBAL_REPORT_DIR."""
    if GLOBAL_REPORT_DIR:
        path = os.path.join(GLOBAL_REPORT_DIR, filename)
        try:
            with open(path, mode) as f:
                f.write(content)
            print_colored(f"  [SAVE] Saved output to: {filename}", Colors.LIGHT_GRAY)
        except Exception as e:
            print_colored(f"  [ERROR] Could not write to report file {filename}: {e}", Colors.FAIL)

def get_custom_timeouts():
    """Prompts user to select a scan speed profile and returns Nuclei and Gobuster DIR timeouts."""
    print_colored("\n[?] Select Scan Speed Profile:", Colors.CYAN, bold=True)
    print("  [1] Fast (Nuclei: 10m, Dir: 5m) - For quick checks.")
    print("  [2] Recommended (Nuclei: 30m, Dir: 10m) - Balanced scan.")
    print("  [3] Deep (Nuclei: 60m, Dir: 15m) - For thorough penetration testing. (Default)")
    
    choice = input("  -> Enter choice (1/2/3, Default: 3): ").strip() or '3'
    
    if choice == '1':
        return 600, 300 
    elif choice == '2':
        return 1800, 600
    elif choice == '3':
        return 3600, 900
    else:
        print_colored("  [!] Invalid choice. Using Default: Deep.", Colors.WARNING)
        return 3600, 900


def check_external_tools() -> Dict[str, str]:
    """Check for necessary system tools and return a dictionary of their status and installation instructions."""
    status_map = {}
    tool_list = {
        'gobuster': "sudo apt install gobuster",
        'whois': "sudo apt install whois",
        'theharvester': "sudo apt install theharvester",
        'sublist3r': "sudo apt install sublist3r",
        'amass': "sudo snap install amass --classic OR go install -v github.com/owasp-amass/amass/v3/...@latest",
        'subfinder': "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        'httpx': "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        'nuclei': "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
        'wappalyzer': "npm install -g wappalyzer-cli", 
        'gowitness': "go install github.com/sensepost/gowitness@latest",
        'gau': "go install github.com/lc/gau/v2/cmd/gau@latest", 
        'subjs': "go install github.com/lc/subjs@latest", 
        'naabu': "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", 
    }

    for tool, install_cmd in tool_list.items():
        if shutil.which(tool): status_map[tool] = "Found"
        else: status_map[tool] = "Missing"; status_map[f'{tool}_install'] = install_cmd

    if requests is None: status_map['requests'] = "Missing"; status_map['requests_install'] = "pip3 install requests"
    else: status_map['requests'] = "Found"
    if dns is None and shutil.which("dig") is None: status_map['dnspython/dig'] = "Missing"; status_map['dnspython/dig_install'] = "pip3 install dnspython OR sudo apt install dnsutils"
    else: status_map['dnspython/dig'] = "Found"
    return status_map


# -----------------------------------------------------------------------
# FIX: CRITICAL HELPER FUNCTIONS DEFINED HERE TO AVOID NAMERROR
# -----------------------------------------------------------------------

def check_host_alive_http(target: str) -> str:
    """Checks host aliveness by attempting a basic HTTP/HTTPS connection."""
    if not requests: return "N/A (Requests Missing)"
    clean_target = target.split('//')[-1].split(':')[0].strip('/')
    urls = [f"https://{clean_target}", f"http://{clean_target}"]
    for url in urls:
        try:
            r = requests.head(url, timeout=5, allow_redirects=True)
            if r.status_code < 500: return f"Alive (HTTP {r.status_code} on {url.split(':')[0]})"
        except RequestException: continue
    return "Down (HTTP/S Failed)"

def check_host_alive_ping(target: str) -> str:
    """Checks host aliveness using system ping command."""
    if shutil.which("ping") is None: return "N/A (Ping Tool Missing)"
    clean_target = target.split('//')[-1].split(':')[0].strip('/')
    try:
        param = '-c' if platform.system().lower() != 'windows' else '-n'
        cmd = ["ping", param, "1", clean_target]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if proc.returncode == 0: return "Alive (ICMP/Ping Success)"
        else:
            if "ttl" in proc.stdout.lower() or "received = 1" in proc.stdout.lower(): return "Alive (ICMP/Ping Success)"
            return "Down (Ping Error - Probable Firewall/ACL)"
    except Exception: return "Down (Ping Error - Tool Execution Failed)"

def get_dns_info(target: str) -> Dict[str, List[str]]:
    """Get A, MX, NS records."""
    results = {'A': [], 'MX': [], 'NS': []}
    clean_target = target.split('//')[-1].split(':')[0].strip('/')
    try: _, _, ipaddrs = socket.gethostbyname_ex(clean_target); results['A'].extend(ipaddrs)
    except socket.gaierror: pass
    if dns:
        for r_type in ['MX', 'NS']:
            try:
                records = dns.resolver.resolve(clean_target, r_type)
                for rdata in records:
                    if r_type == 'MX': results['MX'].append(f"{rdata.preference} {rdata.exchange.to_text()}")
                    elif r_type == 'NS': results['NS'].append(rdata.target.to_text())
            except Exception: pass
    elif shutil.which("dig"):
        for r_type in ['MX', 'NS']:
            cmd = ["dig", clean_target, r_type, "+short"]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                output = proc.stdout.strip()
                for line in output.splitlines():
                    line = line.strip()
                    if not line or line.startswith(';'): continue
                    parts = line.split()
                    if r_type == 'MX' and len(parts) >= 2 and re.match(r'^\d+$', parts[0]): results['MX'].append(f"{parts[0]} {parts[1]}")
                    elif r_type == 'NS' and len(parts) >= 1: results['NS'].append(parts[0])
            except Exception: pass
    results['MX'] = sorted(list(set(results['MX'])))
    results['A'] = sorted(list(set(results['A'])))
    results['NS'] = sorted(list(set(results['NS'])))
    return results

# 💡 সংশোধিত get_whois_info ফাংশন
def get_whois_info(target: str) -> Dict[str, str]:
    """Get detailed WHOIS information for reconnaissance including contact location (Enhanced)."""
    
    fields = [
        ('Registrar', r'registrar'), ('Domain Status', r'status'), ('Name Servers', r'name server'),
        ('Registrant Name', r'registrant name'), ('Registrant Email', r'registrant email|admin contact email|admin email'), 
        ('Registrant Phone', r'registrant phone|admin phone|tech phone'), ('Registrant Country', r'registrant country|country'), 
        ('Creation Date', r'creation date'), ('Expiration Date', r'registry expiry date|expire date|expire'),
        ('DNSSEC', r'dnssec')
    ]
    
    results = {field[0]: 'N/A' for field in fields}
    
    if shutil.which("whois") is None: return results
    clean_target = target.split('//')[-1].split(':')[0].strip('/')
    try: socket.inet_aton(clean_target); return results
    except socket.error: pass
    
    name_servers = []
    
    try:
        cmd = ["whois", clean_target]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90) 
        output = proc.stdout
        
        for key, pattern_re in fields:
            pattern = re.compile(r'^(?:' + pattern_re + r')(?:\s*:\s*)(.*?)(?:\n|$)', re.IGNORECASE | re.MULTILINE)
            matches = pattern.findall(output)
            
            if key == 'Name Servers':
                name_servers.extend([m.strip() for m in matches if m.strip()])
                continue
            
            if matches:
                for match in matches:
                    value = match.strip()
                    if value:
                        if not value or value.lower() in ['n/a', 'not available', 'redacted for privacy', 'withheld for privacy', 'none', 'null', 'privacy', 'proxy']: continue
                        value = re.sub(r'https?://[^\s]*', '', value)
                        value = re.sub(r'\s{2,}', ' ', value).strip()
                        if value: 
                            results[key] = value.split('\n')[0].strip()
                            break
        
        if name_servers:
            results['Name Servers'] = '\n' + '\n'.join(sorted(list(set(name_servers))))
            
    except subprocess.TimeoutExpired: print_colored(f"[-] WHOIS Error: Command timed out after 90 seconds.", Colors.WARNING)
    except Exception as e: print_colored(f"[-] WHOIS Error: {str(e)}", Colors.WARNING)
    
    return results

def detect_waf(headers_dict: Dict[str, str], page_content: str) -> str:
    """Enhanced WAF detection logic."""
    waf_signatures = {
        'Cloudflare WAF': ('cf-ray', 'cloudflare'), 'Sucuri WAF': ('x-sucuri-cache', 'sucuri'), 'Incapsula/Imperva': ('x-iinfo', 'incapsula'), 'Akamai WAF/GTM': ('x-akamai-transformed', 'akamai'), 'AWS WAF/CloudFront': ('x-amz-cf-id', 'aws'), 'F5 BIG-IP ASM': ('set-cookie', 'bigip'), 'Palo Alto (Cloud)': ('x-paloalto-cloud', 'paloalto'), 'Barracuda WAF': ('x-barracuda-deny-key', 'barracuda'), 'ModSecurity': ('mod_security_sanity_check', 'mod_security')
    }
    found_wafs = set()
    for waf, (header_key, header_val_part) in waf_signatures.items():
        if header_key in headers_dict: found_wafs.add(waf)
        elif header_val_part in headers_dict.get('server', '').lower(): found_wafs.add(waf)
        # FIX applied here: checking headers_dict
        elif header_key == 'set-cookie' and header_val_part in headers_dict.get('set-cookie', '').lower() or 'incapsula' in headers_dict: found_wafs.add(waf) 
    if "blocked by mod_security" in page_content: found_wafs.add("ModSecurity")
    elif "incident ID" in page_content and "sucuri" in page_content: found_wafs.add("Sucuri WAF")
    elif 'waf detected block' in page_content.lower(): found_wafs.add("Generic WAF/Security Policy")
    return ', '.join(sorted(list(found_wafs))) if found_wafs else 'No Named WAF Detected'

# 💡 সংশোধিত get_technology ফাংশন (HTTPS ব্যর্থ হলে HTTP-তে দ্রুত ফলব্যাক নিশ্চিত করবে)
def get_technology(target: str) -> Dict[str, Dict[str, str]]:
    """Detect detailed web server technology and WAF, with robust HTTPS/HTTP fallback."""
    tech_results = {'Web Server': {'Server': 'N/A', 'X-Powered-By': 'N/A'}, 'WAF / CDN': {'WAF': 'N/A', 'CDN/Service': 'N/A', 'WAF/Proxy Trace': 'N/A'}, 'CMS / Framework': {'Inferred': 'N/A'}, 'Frontend / JS': {'Libraries': 'N/A'}, 'Traces': {'Set-Cookie': 'N/A'}, 'Status': {}}
    if not requests: tech_results['Status'] = {"Error": "Requests library not available"}; return tech_results

    clean_target = target.split('//')[-1].split(':')[0].strip('/')
    
    # 1. Try HTTPS first
    url_https = f"https://{clean_target}"
    test_headers = {'User-Agent': 'FalconEye Recon/8.4', 'Accept': 'text/html', 'X-Test': '<script>alert(1)</script>'}
    
    r = None
    
    try:
        r = requests.get(url_https, timeout=10, allow_redirects=True, headers=test_headers)
    except (requests.exceptions.SSLError, requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout):
        # 2. Fallback to HTTP if HTTPS fails
        url_http = f"http://{clean_target}"
        try:
            r = requests.get(url_http, timeout=10, allow_redirects=True, headers=test_headers)
        except RequestException as e_http:
            # Both HTTPS and HTTP failed
            tech_results['Status'] = {"Error": f"Connection Error (HTTPS Failed, HTTP Failed): {str(e_http)}"}
            return tech_results
    except RequestException as e_general:
        # Other general request errors
        tech_results['Status'] = {"Error": f"General Connection Error: {str(e_general)}"}
        return tech_results

    # 3. Process the successful response (r)
    if r is None:
        tech_results['Status'] = {"Error": "Both HTTPS and HTTP attempts failed during technology detection."}
        return tech_results
    
    # Existing logic for extracting technology information:
    tech_results['Status'] = {'Final URL': r.url, 'HTTP Status': str(r.status_code)}
    
    if r.status_code >= 400: return tech_results
    
    headers_dict = {k.lower(): v for k, v in r.headers.items()}
    page_content = r.text.lower()
    server_header = headers_dict.get('server', 'N/A')
    powered_by_header = headers_dict.get('x-powered-by', 'N/A')
    cookie_header = headers_dict.get('set-cookie', 'N/A')
    
    tech_results['Web Server']['Server'] = server_header.upper().split('(')[0].strip() if server_header != 'N/A' else 'N/A'
    tech_results['Web Server']['X-Powered-By'] = powered_by_header if powered_by_header else 'N/A'
    
    waf_result = detect_waf(headers_dict, page_content)
    tech_results['WAF / CDN']['WAF'] = waf_result
    
    cdn_security = []
    if 'cloudflare' in server_header.lower() or 'cf-ray' in headers_dict: cdn_security.append('Cloudflare')
    if 'akamai' in server_header.lower() or 'x-akamai-transformed' in headers_dict: cdn_security.append('Akamai')
    if 'sucuri' in headers_dict.get('x-sucuri-cache', '').lower(): cdn_security.append('Sucuri')
    if 'incapsula' in server_header.lower() or 'x-iinfo' in headers_dict: cdn_security.append('Incapsula/Imperva')
    if any(header in headers_dict for header in ['x-amz-cf-id', 'x-amz-cf-pop']): cdn_security.append('AWS CloudFront')
    tech_results['WAF / CDN']['CDN/Service'] = ', '.join(sorted(list(set(cdn_security)))) if cdn_security else 'N/A'
    tech_results['WAF / CDN']['WAF/Proxy Trace'] = headers_dict.get('cf-ray', headers_dict.get('x-iinfo', 'N/A'))
    
    cms_framework = set()
    generator_matches = re.findall(r'<meta[^>]*name=["\']?generator["\']?[^>]*content=["\']?([^>"\']*)', r.text, re.IGNORECASE)
    for match in generator_matches:
        if 'wordpress' in match.lower(): cms_framework.add('WordPress')
        elif 'joomla' in match.lower(): cms_framework.add('Joomla')
        elif 'drupal' in match.lower(): cms_framework.add('Drupal')
        elif 'magento' in match.lower(): cms_framework.add('Magento')
    if '/wp-content/' in page_content or '/wp-includes/' in page_content: cms_framework.add('WordPress')
    if '/media/jui/' in page_content or '/templates/joomla/' in page_content: cms_framework.add('Joomla')
    if '/sites/default/' in page_content: cms_framework.add('Drupal')
    if 'magento' in page_content: cms_framework.add('Magento')
    if 'shopify' in page_content: cms_framework.add('Shopify E-commerce')
    if 'asp.net' in server_header.lower() or 'x-aspnet-version' in headers_dict: cms_framework.add('ASP.NET')
    if 'express' in server_header.lower() or 'koa' in server_header.lower(): cms_framework.add('Node.js/Express')
    if 'php' in powered_by_header.lower(): cms_framework.add('PHP')
    tech_results['CMS / Framework']['Inferred'] = ', '.join(sorted(list(cms_framework))) if cms_framework else 'N/A'
    
    html_traces = set()
    all_sources = re.findall(r'(?:<script|.*link)[^>]*src=["\']([^"\']*)', r.text, re.IGNORECASE)
    js_libs = {'Bootstrap': ['bootstrap.min.js', 'bootstrap.css'], 'jQuery': ['jquery'], 'React': ['react.js', 'react-dom'], 'Vue.js': ['vue.js'], 'Google Analytics': ['google-analytics.com', 'googletagmanager.com'], 'Stripe/Payment': ['stripe.com/v1/checkout'] }
    for lib, keywords in js_libs.items():
        for source in all_sources:
            source_lower = source.lower()
            for keyword in keywords:
                if keyword in source_lower: html_traces.add(lib); break
    tech_results['Frontend / JS']['Libraries'] = ', '.join(sorted(list(html_traces))) if html_traces else 'N/A'
    
    if cookie_header:
        security_flags = []
        if 'secure' in cookie_header.lower(): security_flags.append('Secure')
        if 'httponly' in cookie_header.lower(): security_flags.append('HttpOnly')
        if 'samesite' in cookie_header.lower(): security_flags.append('SameSite')
        if security_flags: tech_results['Traces']['Set-Cookie'] = f"SESSION traces found ({', '.join(security_flags)})"
        else: tech_results['Traces']['Set-Cookie'] = "SESSION traces found (Insecure flags)"
    return tech_results

# -----------------------------------------------------------------------
# --- HTML REPORT GENERATOR (MOVED UP FOR CORRECT DEFINITION) ---
# -----------------------------------------------------------------------
def generate_html_report(results: Dict):
    """Generates a comprehensive HTML report from the scan results."""
    if not GLOBAL_REPORT_DIR: return

    # Simplified HTML structure for demonstration
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>FalconEye Recon Report: {results['target']}</title>
        <style>
            body {{ font-family: monospace; background-color: #1e1e1e; color: #d4d4d4; margin: 20px; }}
            h1 {{ color: #569cd6; border-bottom: 2px solid #569cd6; padding-bottom: 10px; }}
            h2 {{ color: #4ec9b0; margin-top: 30px; }}
            .section {{ margin-left: 20px; border-left: 2px solid #333; padding-left: 10px; }}
            .finding {{ background-color: #333; padding: 10px; margin-bottom: 10px; border-radius: 5px; }}
            .vulnerable {{ color: #f44747; font-weight: bold; }}
            .screenshot-container {{ display: flex; flex-wrap: wrap; gap: 20px; }}
            .screenshot-item {{ border: 1px solid #444; padding: 5px; background-color: #252526; }}
            .img-thumb {{ width: 300px; height: auto; cursor: pointer; }}
        </style>
    </head>
    <body>
        <h1>FalconEye Deep Reconnaissance Report</h1>
        <p><strong>Target:</strong> {results['target']}</p>
        <p><strong>Date:</strong> {time.strftime('%Y-%m-%d %H:%M:%S')}</p>

        <h2>1. Infrastructure & WHOIS</h2>
        <div class="section">
            <h3>DNS Records</h3>
            {'<br>'.join(f"• {k}: {v}" for k, v in results['DNS Records'].items())}
            <h3>WHOIS Data</h3>
            {'<br>'.join(f"• {k}: {v.replace('\\n', '<br>&nbsp;&nbsp;&nbsp;&nbsp;')}" for k, v in results['WHOIS Information'].items() if k != 'target')}
        </div>

        <h2>2. Web Technology & Security</h2>
        <div class="section">
            <h3>Tech Stack</h3>
            <pre>{json.dumps(results['Technology Detection'], indent=2)}</pre>
        </div>

        <h2>3. Asset Discovery & Live Hosts</h2>
        <div class="section">
            <h3>Passive Subdomains ({len(results['Subdomains'])})</h3>
            <textarea style="width: 90%; height: 100px; background: #222; color: #ddd;">{'\\n'.join(results['Subdomains'])}</textarea>
            
            <h3>Active Hosts ({len(results.get('Active Hosts', {}).get('Alive', []))})</h3>
            <textarea style="width: 90%; height: 100px; background: #222; color: #ddd;">{'\\n'.join(results.get('Active Hosts', {}).get('Alive', []))}</textarea>
        </div>
        
        <h2>4. Advanced Endpoints & Ports</h2>
        <div class="section">
            <h3>Historical/GAU Endpoints ({len(results.get('Endpoint Gathering', {}).get('Historical URLs', []))})</h3>
            <textarea style="width: 90%; height: 100px; background: #222; color: #ddd;">{'\\n'.join(results.get('Endpoint Gathering', {}).get('Historical URLs', ['None']))}</textarea>
            <h3>JS Endpoints ({len(results.get('Endpoint Gathering', {}).get('JS Endpoints', []))})</h3>
            <textarea style="width: 90%; height: 100px; background: #222; color: #ddd;">{'\\n'.join(results.get('Endpoint Gathering', {}).get('JS Endpoints', ['None']))}</textarea>

            <h3>Open Ports ({len(results.get('Open Ports', []))})</h3>
            <pre>{'\\n'.join(results.get('Open Ports', ['None']))}</pre>
        </div>
        
        <h2>5. Vulnerability & Directories</h2>
        <div class="section">
            <h3>Nuclei Findings ({len(results['Vulnerability Check'])})</h3>
            {''.join(f'<div class="finding vulnerable">{f}</div>' for f in results['Vulnerability Check']) if results['Vulnerability Check'] else '<p>No quick-win vulnerabilities found.</p>'}
            
            <h3>Directory Bruteforce Hits ({len(results['Directory Paths'])})</h3>
            {'<p>' + '<br>'.join(results['Directory Paths']) + '</p>' if results['Directory Paths'] else '<p>No common directories found (or blocked).</p>'}
        </div>

        <h2>6. Visual Reconnaissance</h2>
        <p>Screenshots are saved locally in the <code>screenshots/</code> folder within the report directory. Check that folder manually.</p>
    </body>
    </html>
    """
    write_to_report('00_report.html', html_content)
    print_colored("  [FINISH] Comprehensive HTML Report generated: 00_report.html", Colors.HEADER, bold=True)
# -----------------------------------------------------------------------


# -----------------------------------------------------------------------
# --- WORDLIST HELPER FUNCTION (UNCHANGED) ---
# -----------------------------------------------------------------------

def get_manual_wordlist_path(scan_type: str, default_paths: List[str]) -> Optional[str]:
    """
    Prompts user for a manual wordlist path and validates it.
    If input is empty, it tries to find a default wordlist.
    """
    
    print_colored(f"\n  [?] Do you want to use a manual wordlist for {scan_type.upper()}?", Colors.CYAN)
    manual_path = input("    -> Enter path (Leave empty to use default): ").strip()
    
    if manual_path:
        if os.path.exists(manual_path):
            print_colored(f"  [+] Using manual wordlist: {manual_path}", Colors.OKGREEN)
            return manual_path
        else:
            print_colored(f"  [!] Manual path not found: {manual_path}. Falling back to default.", Colors.WARNING)
    
    # Try to find a default wordlist
    for path in default_paths:
        if os.path.exists(path):
            print_colored(f"  [+] Using default wordlist: {os.path.basename(path)}", Colors.LIGHT_GRAY)
            return path
            
    print_colored("  [!] No usable wordlist found (Manual or Default). Skipping scan.", Colors.FAIL)
    return None


# -----------------------------------------------------------------------
# --- GOUBUSTER LIVE PROGRESS FUNCTIONS (DIRECT CLI EXECUTION) ---
# -----------------------------------------------------------------------

def run_gobuster_live(cmd: List[str], target: str, scan_type: str, timeout: int = 420) -> List[str]:
    """
    Executes the Gobuster command and prints live output, ensuring line clearing on finish/timeout.
    """
    # 💡 FIX: Using shell=True for Gobuster DNS/DIR to display its own progress bar correctly
    print_colored(f"\n  [INFO] Running Gobuster {scan_type.upper()} directly in CLI mode...", Colors.CYAN)
    
    # Convert list of commands into a single string for shell execution
    cmd_str = " ".join(cmd)
    
    try:
        # We run it with shell=True and let it manage its own output and progress
        # stdout=None means output goes directly to terminal
        result = subprocess.run(cmd_str, shell=True, check=False, timeout=timeout, stdout=None, stderr=None)
        
        # 💡 FIX: Manually ensure the line is cleared after the process terminates
        sys.stdout.write('\r' + ' ' * 80 + '\r')
        sys.stdout.flush()
        
        if result.returncode == 0:
            print_colored("\n  [INFO] Gobuster scan finished successfully.", Colors.OKGREEN)
        elif result.returncode == 124: # Timeout return code
            print_colored("\n  [!] Gobuster process was stopped by Python timeout.", Colors.WARNING)
        else:
            print_colored(f"\n  [!] Gobuster process finished with status code {result.returncode}. Check console output.", Colors.WARNING)
        
        # NOTE: Returning empty list as results are printed live.
        return [] 

    except subprocess.TimeoutExpired:
        # 💡 FIX: Line clear even if an exception occurs
        sys.stdout.write('\r' + ' ' * 80 + '\r')
        sys.stdout.flush()
        print_colored(f"\n  [!] Gobuster {scan_type} process killed due to timeout.", Colors.FAIL)
    except Exception as e:
        print_colored(f"\n  [!] Gobuster {scan_type} execution error: {str(e)}", Colors.FAIL)
    
    return []

# -----------------------------------------------------------------------
# --- NEW: ACTIVE HOST CHECKING & STATUS (HTTPX with FALLBACK LOGIC) ---
# -----------------------------------------------------------------------

def run_httpx_check(subdomains: List[str]) -> Dict[str, List[str]]:
    """
    Runs httpx in Stealth Mode first. If no live hosts found, falls back 
    to DNS check to find hosts with A Records (to bypass aggressive WAF).
    """
    results = {'Alive': [], 'Status Codes': {}}
    clean_subdomains = list(set(subdomains)) # Unique list for processing
    
    if not clean_subdomains or shutil.which("httpx") is None: 
        print_colored("  [!] httpx not found or no subdomains to check.", Colors.WARNING)
        return results

    
    ### 🥇 STAGE 1: STEALTH HTTPX CHECK (Primary Attempt) ###
    
    print_colored("\n  [>] Starting httpx (Stealth Mode)...", Colors.CYAN)
    
    with tempfile.NamedTemporaryFile(mode='w+', delete=True) as temp_input:
        temp_input.write('\n'.join(clean_subdomains))
        temp_input.flush()
        
        # Stealth Mode Command: Low threads, low rate limit, browser User-Agent
        cmd = ["httpx", "-l", temp_input.name, "-silent", "-sc", "-title", 
               "-threads", "10",  
               "-rl", "5",        
               "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36",
               "-p", "http,https",
               "-status-code-filter", "403,503", # Filter out common WAF blocking codes
               "-no-fallback", 
               "-timeout", "10"]
        
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            output = proc.stdout.strip().splitlines()
            
            status_map = {}
            live_urls = set()
            for line in output:
                # Example: https://app.example.com [200] [App]
                match = re.search(r'(https?:\/\/\S+)\s\[(\d+)\]\s\[(.*?)\]', line)
                if match:
                    url = match.group(1).strip('/')
                    status = match.group(2)
                    title = match.group(3).replace(' ', '').strip()
                    
                    if status not in status_map: status_map[status] = []
                    status_map[status].append(f"{url} (Title: {title})")
                    live_urls.add(url)
            
            results['Alive'] = sorted(list(live_urls))
            results['Status Codes'] = status_map
            
            if results['Alive']:
                print_colored(f"  [+] Stealth httpx found {len(results['Alive'])} live hosts. Using primary data.", Colors.OKGREEN)
                return results # SUCCESS! Return the data immediately
            
        except subprocess.TimeoutExpired: 
            print_colored("  [!] Stealth httpx timed out. Falling back to DNS Check...", Colors.WARNING)
        except Exception as e: 
            print_colored(f"  [!] Stealth httpx error: {str(e)}. Falling back to DNS Check...", Colors.WARNING)

    
    ### 🥈 STAGE 2: DNS A RECORD FALLBACK (Secondary Attempt) ###
    
    print_colored("\n  [>] Fallback: Checking for valid DNS A Records to bypass WAF...", Colors.YELLOW)
    fallback_alive_hosts = set()
    
    for host in clean_subdomains:
        try:
            # Check for A record resolution
            ip_addresses = socket.gethostbyname_ex(host)[-1]
            if ip_addresses:
                # If an IP is found, assume it is 'live' enough to test with Nuclei/Gowitness
                fallback_alive_hosts.add(host) 
        except socket.gaierror:
            pass # No A record found, skip
    
    if fallback_alive_hosts:
        # Reformat results for the final report
        results['Alive'] = sorted(list(fallback_alive_hosts))
        results['Status Codes'] = {'DNS Resolved (Fallback)': [f"http(s)://{host}" for host in results['Alive']]}
        
        print_colored(f"  [+] Fallback DNS Check found {len(results['Alive'])} hosts with A Records. Using secondary data.", Colors.YELLOW)
        return results
    else:
        print_colored("  [!] Fallback DNS Check failed to find any resolved hosts.", Colors.FAIL)
        return {'Alive': [], 'Status Codes': {}}


# -----------------------------------------------------------------------
# --- NEW: PORT SCANNING (NAABU) ---
# -----------------------------------------------------------------------

def run_naabu_scan(live_hosts: List[str]) -> List[str]:
    """Runs naabu for a quick port scan on live hosts (Top 1000)."""
    results = []
    if not live_hosts or shutil.which("naabu") is None:
        print_colored("\n  [!] Naabu not found or no hosts to scan. Skipping Port Scan.", Colors.WARNING)
        return results

    print_colored("\n  [>] Running naabu (Top 1000 Port Scan)...", Colors.CYAN)
    
    with tempfile.NamedTemporaryFile(mode='w+', delete=True) as temp_input:
        # Naabu requires only domain/IP without protocol
        bare_hosts = [h.split('//')[-1].split('/')[0] for h in live_hosts]
        temp_input.write('\n'.join(bare_hosts))
        temp_input.flush()

        # Naabu command: -iL (input list), -p top-1000, -silent, -json
        cmd = ["naabu", "-iL", temp_input.name, "-top-ports", "1000", "-silent", "-json", "-c", "20"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Process JSON output to extract host and port
            for line in proc.stdout.strip().splitlines():
                try:
                    data = json.loads(line)
                    results.append(f"{data.get('host')}:{data.get('port')} ({data.get('service')})")
                except json.JSONDecodeError:
                    pass
            
            write_to_report('07_Port_Scan_Results.txt', '\n'.join(results))
            print_colored(f"  [+] Naabu finished. Found {len(results)} open ports.", Colors.OKGREEN)
        except subprocess.TimeoutExpired: print_colored("  [!] Naabu timed out.", Colors.WARNING)
        except Exception as e: print_colored(f"  [!] Naabu error: {str(e)}", Colors.WARNING)
    
    return results


# -----------------------------------------------------------------------
# --- NEW: VISUAL RECON (GOWITNESS) ---
# -----------------------------------------------------------------------

def run_visual_recon(live_hosts: List[str], target: str):
    """Runs gowitness to take screenshots of live hosts and saves to report folder."""
    if not live_hosts or shutil.which("gowitness") is None or not GLOBAL_REPORT_DIR:
        print_colored("\n  [!] gowitness not found or no live hosts. Skipping Visual Recon.", Colors.WARNING)
        return False
    
    # Use permanent report folder for gowitness output
    output_dir = os.path.join(GLOBAL_REPORT_DIR, 'screenshots')
    os.makedirs(output_dir, exist_ok=True)
    
    print_colored(f"\n  [>] Starting gowitness (Taking Screenshots of {len(live_hosts)} hosts)...", Colors.CYAN)
    
    with tempfile.NamedTemporaryFile(mode='w+', delete=True) as temp_host_file:
        # Gowitness requires full URLs, so we prepend http:// if not already present (Fallback hosts will be domain names only)
        full_urls = [host if host.startswith('http') else f"http://{host}" for host in live_hosts]
        temp_host_file.write('\n'.join(full_urls))
        temp_host_file.flush()
        
        # Changed output directory to permanent folder
        cmd = ["gowitness", "file", "-f", temp_host_file.name, 
               "-d", output_dir, "--delay", "5", "--timeout", "20"]
        
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            print_colored(f"  [+] gowitness finished. Screenshots saved in: screenshots/", Colors.OKGREEN)
            return True
        except subprocess.TimeoutExpired: 
            print_colored("  [!] gowitness process killed due to timeout (600s).", Colors.FAIL)
        except Exception as e: 
            print_colored(f"  [!] gowitness execution error: {str(e)}", Colors.FAIL)
    
    return False

# -----------------------------------------------------------------------
# --- NEW: VULNERABILITY SCAN (NUCLEI - EXTENDED TIMEOUT & LIVE COUNT) ---
# -----------------------------------------------------------------------

# Helper function to check for non-blocking input (only used by run_nuclei_scan)
def is_key_pressed():
    """Checks for a key press (like 'q') without blocking."""
    if platform.system() not in ['Linux', 'Darwin']:
        return None
        
    old_settings = termios.tcgetattr(sys.stdin)
    try:
        # Set terminal to non-blocking mode
        tty.setraw(sys.stdin.fileno())
        i, o, e = select.select([sys.stdin], [], [], 0)
        if i:
            char = sys.stdin.read(1)
            return char
    finally:
        # Restore terminal settings
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
    return None

def run_nuclei_scan(live_hosts: List[str], scan_timeout: int) -> List[str]:
    """Runs nuclei for a quick scan against live hosts with progress simulation."""
    results = []
    if not live_hosts or shutil.which("nuclei") is None:
        print_colored("\n  [!] Nuclei not found or no live hosts to scan. Skipping Vulnerability Check.", Colors.WARNING)
        return results
    
    templates = "default-logins,misconfiguration,security-misconfiguration,exposed-panels"
    
    print_colored(f"\n  [>] Starting nuclei scan (Templates: {templates}, Max time: {scan_timeout}s). Press 'q' to skip early.", Colors.CYAN)
    
    with tempfile.NamedTemporaryFile(mode='w+', delete=True) as temp_input:
        full_urls = [host if host.startswith('http') else f"http://{host}" for host in live_hosts]
        temp_input.write('\n'.join(full_urls))
        temp_input.flush()
        
        cmd = ["nuclei", "-l", temp_input.name, "-t", templates, 
               "-silent", "-timeout", "10", "-c", "50", "-no-color"]
        
        try:
            # Use subprocess.Popen for manual timeout and progress tracking
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            start_time = time.time()
            vulnerability_counter = 0
            
            user_stopped = False

            # Progress Simulation Loop
            while process.poll() is None:
                
                # Check for User Input ('q' pressed)
                if platform.system() in ['Linux', 'Darwin']:
                    key = is_key_pressed()
                    if key and key.lower() == 'q':
                        user_stopped = True
                        break

                # Read lines from Nuclei stdout without blocking
                raw_line = process.stdout.readline()
                
                if raw_line:
                    line = raw_line.strip()
                    # Check if the line looks like a vulnerability finding 
                    if len(line) > 10 and ':' in line and not line.startswith('['):
                        # FOUND VULNERABILITY!
                        vulnerability_counter += 1
                        results.append(line)
                        
                
                elapsed_time = time.time() - start_time
                scan_progress_ratio = elapsed_time / scan_timeout
                progress_percent = min(100, int(scan_progress_ratio * 100))
                
                # Print progress bar (simple ASCII)
                bar_length = 20
                filled_length = int(bar_length * progress_percent / 100)
                bar = "#" * filled_length + " " * (bar_length - filled_length)
                
                # Rewrites the progress line with live findings counter
                sys.stdout.write(f"\r  [INFO] Progress: [{bar}] {progress_percent}% ({int(elapsed_time)}s elapsed) | Findings: {vulnerability_counter}")
                sys.stdout.flush()
                
                if elapsed_time > scan_timeout:
                    process.terminate()
                    raise subprocess.TimeoutExpired(cmd, scan_timeout)

                time.sleep(0.5) # Check output/input frequently (0.5s)
            
            # Termination handling
            if user_stopped or process.poll() is not None:
                if process.poll() is None:
                    process.terminate()
                
                # Final output capture after termination
                stdout, stderr = process.communicate(timeout=5)

                # Process any remaining lines from the buffer
                for line in stdout.strip().splitlines():
                    if line and len(line) > 10 and ':' in line and not line.startswith('[') and line not in results:
                        vulnerability_counter += 1
                        results.append(line)
                        
                # Print final status
                final_message = "Scan stopped by user" if user_stopped else "Completed"
                sys.stdout.write(f"\r  [INFO] Progress: [{'#'*20}] 100% ({final_message}) | Total Findings: {vulnerability_counter}   ")
                sys.stdout.write('\n')
                sys.stdout.flush()
                
                if user_stopped:
                    print_colored(f"  [!] Nuclei scan manually stopped. Found {vulnerability_counter} issues so far.", Colors.YELLOW)
                else:
                    print_colored(f"  [+] Nuclei finished. Found {vulnerability_counter} potential issues.", Colors.OKGREEN)
                
                return results

        except subprocess.TimeoutExpired: 
            print_colored(f"\n  [!] Nuclei process killed due to timeout ({scan_timeout}s).", Colors.FAIL)
        except Exception as e: 
            print_colored(f"\n  [!] Nuclei execution error: {str(e)}", Colors.FAIL)
    
    return results

# -----------------------------------------------------------------------
# --- NEW: ENDPOINT GATHERING (GAU + SUBJS) ---
# -----------------------------------------------------------------------

def run_endpoint_gathering(live_hosts: List[str]) -> Dict[str, List[str]]:
    """Runs gau and subjs to find historical and exposed endpoints."""
    results = {'Historical URLs': [], 'JS Endpoints': []}
    
    if not live_hosts: return results

    # 1. Run GAU (Historical URLs)
    if shutil.which("gau"):
        print_colored("\n  [>] Running gau (Historical/Archive URLs)...", Colors.CYAN)
        # Use first host as the base domain for GAU
        base_domain = live_hosts[0].split('//')[-1].split('/')[0]
        cmd = ["gau", base_domain, "--threads", "10", "--timeout", "30", "-subs"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            results['Historical URLs'].extend(proc.stdout.strip().splitlines())
            results['Historical URLs'] = sorted(list(set(results['Historical URLs'])))
            write_to_report('05_Historical_URLs.txt', '\n'.join(results['Historical URLs']))
            print_colored(f"  [+] GAU finished. Found {len(results['Historical URLs'])} historical endpoints.", Colors.OKGREEN)
        except subprocess.TimeoutExpired: print_colored("  [!] GAU timed out.", Colors.WARNING)
        except Exception: pass
    
    # 2. Run SUBJS (JavaScript Endpoints)
    if shutil.which("subjs"):
        print_colored("\n  [>] Running subjs (JS Endpoint Extraction)...", Colors.CYAN)
        # Pass live hosts to subjs via temporary file
        with tempfile.NamedTemporaryFile(mode='w+', delete=True) as temp_input:
            # Subjs needs full URLs
            temp_input.write('\n'.join([h if h.startswith('http') else f"https://{h}" for h in live_hosts]))
            temp_input.flush()
            
            cmd = ["subjs", "-l", temp_input.name, "-c", "20"]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                results['JS Endpoints'].extend(proc.stdout.strip().splitlines())
                results['JS Endpoints'] = sorted(list(set(results['JS Endpoints'])))
                write_to_report('06_JS_Endpoints.txt', '\n'.join(results['JS Endpoints']))
                print_colored(f"  [+] subjs finished. Found {len(results['JS Endpoints'])} endpoints in JavaScript.", Colors.OKGREEN)
            except subprocess.TimeoutExpired: print_colored("  [!] subjs timed out.", Colors.WARNING)
            except Exception: pass
            
    return results

# -----------------------------------------------------------------------
# --- WRAPPER FUNCTIONS (SUBDOMAINS - AMASS PROGRESS ADDED) ---
# -----------------------------------------------------------------------

def run_amass_subfinder(target: str) -> Set[str]:
    """Run Amass and Subfinder for passive and active subdomain enumeration with Amass progress."""
    
    clean_target = target.split('//')[-1].split(':')[0].strip('/')
    all_subdomains = set()
    
    with tempfile.TemporaryDirectory() as temp_dir:
        amass_output_file = os.path.join(temp_dir, f"amass_{clean_target}.txt")
        subfinder_output_file = os.path.join(temp_dir, f"subfinder_{clean_target}.txt")
        
        # --- 1. Subfinder Execution (Unchanged) ---
        if shutil.which("subfinder"):
            print_colored(f"\n  [>] Starting subfinder (Passive/OSINT)...", Colors.CYAN)
            cmd = ["subfinder", "-d", clean_target, "-silent", "-o", subfinder_output_file]
            
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if os.path.exists(subfinder_output_file):
                    with open(subfinder_output_file, 'r') as f:
                        for line in f:
                            all_subdomains.add(line.strip())
                    print_colored(f"  [+] Subfinder finished. Total unique hosts so far: {len(all_subdomains)}.", Colors.OKGREEN)
            except subprocess.TimeoutExpired: print_colored("  [!] Subfinder timed out.", Colors.WARNING)
            except Exception as e: print_colored(f"  [!] Subfinder error: {str(e)}", Colors.WARNING)
        else:
            print_colored("  [!] Subfinder not found. Skipping Subfinder scan.", Colors.WARNING)

        # --- 2. Amass Execution (Basic Passive) ---
        if shutil.which("amass"):
            AMASS_TIMEOUT = 300 # 5 minutes
            print_colored(f"\n  [>] Starting amass (Passive OSINT, Max time: 5m)...", Colors.CYAN)
            cmd = ["amass", "enum", "-passive", "-d", clean_target, "-o", amass_output_file]
            
            try:
                # Start Amass process
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                start_time = time.time()
                initial_count = len(all_subdomains)

                # Progress Simulation Loop
                while process.poll() is None:
                    elapsed_time = time.time() - start_time
                    progress_percent = min(100, int((elapsed_time / AMASS_TIMEOUT) * 100))
                    
                    # Print progress bar
                    bar_length = 20
                    filled_length = int(bar_length * progress_percent / 100)
                    bar = "#" * filled_length + " " * (bar_length - filled_length)
                    
                    sys.stdout.write(f"\r  [INFO] Progress: [{bar}] {progress_percent}% ({int(elapsed_time)}s elapsed) | Amass Running...")
                    sys.stdout.flush()
                    
                    if elapsed_time > AMASS_TIMEOUT:
                        process.terminate()
                        raise subprocess.TimeoutExpired(cmd, AMASS_TIMEOUT)

                    time.sleep(5) # Update every 5 seconds
                
                # Wait for the process to truly finish and capture output
                process.communicate(timeout=5)
                
                # Process output file
                if os.path.exists(amass_output_file):
                    with open(amass_output_file, 'r') as f:
                        for line in f:
                            all_subdomains.add(line.strip())
                    
                added_hosts = len(all_subdomains) - initial_count
                
                # Print final status
                sys.stdout.write(f"\r  [INFO] Progress: [{'#'*20}] 100% (Completed) | Hosts Added: {added_hosts}   ")
                sys.stdout.write('\n')
                sys.stdout.flush()
                print_colored(f"  [+] Amass finished. Added {added_hosts} new hosts.", Colors.OKGREEN)

            except subprocess.TimeoutExpired: 
                # Print the progress bar line again before error
                sys.stdout.write(f"\r  [INFO] Progress: [{'#'*20}] 100% (Timeout) | Amass Running...")
                sys.stdout.write('\n')
                sys.stdout.flush()
                print_colored(f"  [!] Amass timed out. Max time ({AMASS_TIMEOUT}s) reached.", Colors.WARNING)
            except Exception as e: 
                print_colored(f"\n  [!] Amass error: {str(e)}", Colors.WARNING)
        else:
            print_colored("  [!] Amass not found. Skipping Amass scan.", Colors.WARNING)

    return all_subdomains


def run_sublist3r(target: str) -> Set[str]:
    """Run passive subdomain enumeration using sublist3r if available."""
    subdomains = set()
    
    if shutil.which("sublist3r") is None: return set()
    clean_target = target.split('//')[-1].split(':')[0].strip('/')
    
    try:
        with tempfile.NamedTemporaryFile(mode='w+', delete=True) as temp_file:
            print_colored(f"\n  [>] Starting sublist3r (Passive Enumeration)...", Colors.CYAN)
            cmd = ["sublist3r", "-d", clean_target, "-o", temp_file.name, "-e", "bing,yahoo,ask,netcraft,threatcrowd", "-t", "50", "-v"] 
            
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            
            # FIX: Improved parsing logic to clean up <br> issue
            output = proc.stdout
            for line in output.splitlines():
                if clean_target in line:
                    # Clean up multiple domains found in one line by some tools/parsers
                    cleaned_line = line.replace('<br>', ' ').replace(',', ' ').strip()
                    for part in cleaned_line.split():
                        relevance_match = re.search(r'(\S+\.' + re.escape(clean_target) + r')', part)
                        if relevance_match:
                            subdomains.add(relevance_match.group(1).rstrip('.'))

    except subprocess.TimeoutExpired: print_colored("  [!] Sublist3r timed out.", Colors.WARNING)
    except Exception as e: print_colored(f"  [!] Sublist3r error: {str(e)}", Colors.WARNING)
        
    return subdomains


def run_subdomain_enum(target: str) -> List[str]:
    """Run gobuster, sublist3r, amass, and subfinder for comprehensive subdomain enumeration."""
    
    # 1. Run Passive Tools
    all_subdomains: Set[str] = set()
    all_subdomains.update(run_sublist3r(target))
    all_subdomains.update(run_amass_subfinder(target))
    
    # 2. Print Passive info
    total_passive = len(all_subdomains)
    if total_passive > 0:
        print_colored(f"\n  [INFO] Passive tools (Sublist3r/Amass/Subfinder) found {total_passive} subdomains.", Colors.YELLOW)
    else:
        print_colored("\n  [INFO] Passive tools found no subdomains.", Colors.WARNING)

    # 3. Gobuster DNS Brute-force
    if shutil.which("gobuster"):
        clean_target = target.split('//')[-1].split(':')[0].strip('/')
        wordlist_path = get_manual_wordlist_path("Subdomain Enumeration", DEFAULT_DNS_WORDLISTS)
        
        if wordlist_path:
            print_colored(f"\n  [>] Starting Gobuster DNS (Brute-force Enumeration)...", Colors.CYAN)
            cmd = [
                "gobuster", "dns", "-d", clean_target,
                "-w", wordlist_path,
                "-t", "150",         
                "--timeout", "30s"   
            ]
            # Gobuster DNS runs live and handles its own output
            run_gobuster_live(cmd, clean_target, 'dns', timeout=300)
    
    # FIX: Clear the terminal line after gobuster finishes its live output to prevent overlap
    sys.stdout.write('\r' + ' ' * 80 + '\r')
    sys.stdout.flush()
    
    return sorted(list(all_subdomains))


def run_directory_bruteforce(target: str, timeout: int) -> List[str]:
    """Run directory and file brute-force using gobuster/dirb (Direct CLI Execution)."""
    
    if shutil.which("gobuster") is None: 
        print_colored("[!] Gobuster not found. Skipping Directory Brute-force.", Colors.WARNING)
        return []

    # Check aliveness to determine protocol preference
    url = target
    if not url.startswith(('http://', 'https://')):
        # FIX: This logic is now essential for Gobuster DIR to choose HTTP on non-HTTPS sites
        http_check = check_host_alive_http(target)
        if "http" in http_check.lower() and "https" not in http_check.lower():
            url = f"http://{target}"
        elif "https" in http_check.lower():
            url = f"https://{target}"
        else:
            url = f"https://{target}" 
    
    wordlist_path = get_manual_wordlist_path("Directory Brute-force", DEFAULT_DIR_WORDLISTS)
            
    if not wordlist_path: return []

    print_colored(f"\n  [>] Starting Gobuster Directory Brute-force (Live Mode, Max time: {timeout}s). Press 'q' to stop.", Colors.CYAN)
    
    # FIX: --exclude-length 178 added to ignore the wildcard 301 responses
    cmd = [
        "gobuster", "dir", "-u", url,
        "-w", wordlist_path,
        "-t", "150",         
        "-s", "200,204,301,302,307",  
        "-k",
        f"--timeout", "30s", # Individual request timeout remains 30s
        '--status-codes-blacklist=""', 
        "--exclude-length", "178"
    ]
    
    # We use the simplified live runner. It prints output directly and is timed.
    # We must ensure to capture the live output for printing on the console
    run_gobuster_live(cmd, url, 'dir', timeout=timeout)
    
    # NOTE: We return empty list as requested (no file saving)
    return [] 

# -----------------------------------------------------------------------
# --- EMPLOYEE HARVESTER & CLI FORMATTING ---
# -----------------------------------------------------------------------

def get_name_from_email(email: str) -> Optional[str]:
    """Tries to guess a full name from an email address (e.g., john.doe@ -> John Doe)"""
    match = re.search(r'^(.*?)(?:@|\+)', email)
    if not match: return None
    local_part = match.group(1)
    parts = re.split(r'[._-]', local_part)
    if len(parts) >= 2:
        first = parts[0].capitalize()
        last = parts[-1].capitalize()
        if len(first) > 1 and len(last) > 1: return f"{first} {last}"
    return None

def run_theharvester(target: str) -> Dict[str, List[str]]:
    """Run theharvester for employee/email/name enumeration (Enhanced)."""
    results = {'Emails': [], 'Hosts': [], 'Inferred Names': []}
    
    if shutil.which("theharvester") is None:
        print_colored("  [!] TheHarvester not found. Skipping email enumeration.", Colors.WARNING)
        return results
    
    clean_target = target.split('//')[-1].split(':')[0].strip('/')
    
    try:
        print_colored("  [>] Running theHarvester (This can take time)...", Colors.CYAN)
        sources = ['google', 'bing']
        all_emails = set()
        all_hosts = set()
        
        for source in sources:
            with tempfile.NamedTemporaryFile(suffix=".xml", delete=True) as tmp:
                temp_file = tmp.name
                cmd = ["theharvester", "-d", clean_target, "-b", source, "-l", "100", "-f", temp_file] 
                
                try:
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    output = proc.stdout
                    
                    email_pattern = r'\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9.-]*\.)?' + re.escape(clean_target.split('.')[-2] + '.' + clean_target.split('.')[-1]) + r'\b'
                    emails = re.findall(email_pattern, output, re.IGNORECASE)
                    all_emails.update(emails)
                    
                    host_lines = re.findall(r'(\S+\.' + re.escape(clean_target) + r')(?:\s|:|\Z)', output, re.IGNORECASE)
                    all_hosts.update([h.strip().strip('.') for h in host_lines])
                    
                except subprocess.TimeoutExpired: print_colored(f"  [!] TheHarvester source {source} timed out.", Colors.WARNING)
                except Exception as e: print_colored(f"  [!] TheHarvester error on {source}: {str(e)}", Colors.WARNING)

        results['Emails'] = sorted(list(all_emails))
        results['Hosts'] = sorted(list(all_hosts))
        
        inferred_names = set()
        for email in all_emails:
            name = get_name_from_email(email)
            if name: inferred_names.add(name)
        results['Inferred Names'] = sorted(list(inferred_names))
        
        return results

    except Exception as e:
        print_colored(f"[-] TheHarvester primary error: {str(e)}", Colors.FAIL)
        return {'Emails': [], 'Hosts': [], 'Inferred Names': []}


def format_cli_report(data: Dict, title: str, title_color=Colors.HEADER) -> str:
    """Format nested dictionary data for detailed, clean CLI display."""
    
    output = f"\n{title_color}{Colors.BOLD}{'=' * 5} {title.upper()} {'=' * 5}{Colors.ENDC}\n"
    has_data = False
    
    if not data:
        output += f"{Colors.WARNING}  No information available.{Colors.ENDC}\n"
        return output
    
    for section, section_data in data.items():
        if isinstance(section_data, dict):
            output += f"{Colors.CYAN}{Colors.BOLD}  • {section}:{Colors.ENDC}\n"
            section_has_data = False
            for key, value in section_data.items():
                # Special handling for Name Servers (which is multiline)
                if key == 'Name Servers' and isinstance(value, str) and '\n' in value:
                    output += f"{Colors.OKBLUE}    - {key}:{Colors.ENDC}\n"
                    # Add extra indentation for multiline Name Servers
                    output += '    ' + value + '\n' 
                    section_has_data = True
                elif isinstance(value, list) and value:
                    output += f"{Colors.OKBLUE}    - {key}:{Colors.ENDC}\n"
                    for item in value: output += f"      -> {item}\n"
                    section_has_data = True
                elif value and value != 'N/A' and value not in ['', 'False']:
                    output += f"{Colors.OKBLUE}    - {key}:{Colors.ENDC} {value}\n"
                    section_has_data = True
            
            if section_has_data: has_data = True

        elif isinstance(section_data, list):
            if section_data:
                has_data = True
                output += f"{Colors.CYAN}{Colors.BOLD}  • {section} ({len(section_data)} found):{Colors.ENDC}\n"
                for item in section_data: output += f"    -> {item}\n"
            
        elif section_data and section_data != 'N/A' and section_data not in ['', 'False']:
            has_data = True
            output += f"{Colors.OKBLUE}  • {section}:{Colors.ENDC} {section_data}\n"

    # 💡 ADDED: Manual Check Prompt for WHOIS
    if title == "WHOIS INFORMATION 📜":
        output += f"\n{Colors.LIGHT_GRAY}  NOTE: For more exhaustive detail (dates, contacts, full status chain), you can use 'whois {data.get('target', 'domain')}' manually.{Colors.ENDC}\n"

    if not has_data and title not in ["ALIVENESS CHECK 🚦", "DNS RECORDS 🌍"]:
        if any(v != 'N/A' for v in data.values() if isinstance(v, str)): return output
        return f"\n{title_color}{Colors.BOLD}{'=' * 5} {title.upper()} {'=' * 5}{Colors.ENDC}\n{Colors.WARNING}  No core information found for this module.{Colors.ENDC}\n"

    return output

# -----------------------------------------------------------------------
# --- MAIN EXECUTION LOGIC (UPDATED FLOW) ---
# -----------------------------------------------------------------------

def run(target: Optional[str] = None) -> Dict:
    """
    Main execution function: Executes recon and prints detailed CLI report.
    Updated flow to include new tools and place Directory brute-force at the end.
    """
    global GLOBAL_REPORT_DIR, GLOBAL_TARGET_DOMAIN
    
    tool_status = check_external_tools()
    missing_tools = [k for k, v in tool_status.items() if v == 'Missing']
    
    print_colored(f"\n⚙ System & Tool Check ({len(missing_tools)} Missing):", Colors.OKBLUE)
    draw_separator(color=Colors.OKBLUE)
    
    found_count = 0
    
    for tool in sorted(tool_status.keys()):
        if tool.endswith('_install'):
            continue
        status = tool_status[tool]
        
        if status == "Found":
            print_colored(f"  [+] {tool.ljust(15)}: {status}", Colors.OKGREEN)
            found_count += 1
        else:
            print_colored(f"  [-] {tool.ljust(15)}: {status}", Colors.WARNING)
    
    print(f"\n{Colors.CYAN}{found_count} tools FOUND, {len(missing_tools)} tools MISSING.{Colors.ENDC}")

    if missing_tools:
        print_colored("\n🚨 Installation Instructions (Copy & Paste):", Colors.FAIL, bold=True)
        for tool_name in missing_tools:
            install_cmd = tool_status.get(f'{tool_name}_install')
            if install_cmd:
                print(f"  $ {install_cmd}")
        print_colored("--------------------------------------------------------------------------------", Colors.FAIL)

    draw_separator(char="═", width=80, color=Colors.HEADER)
    
    # --- Menu Compatibility Check (Gets Target) ---
    if target is None:
        print_colored("\n[*] Target input required for Deep Reconnaissance.", Colors.OKBLUE)
        target = input("Enter target domain or IP (e.g., example.com): ").strip()

    if not target:
        print_colored("[-] Target cannot be empty. Returning to menu.", Colors.FAIL)
        return {}
    
    GLOBAL_TARGET_DOMAIN = target.strip()
    
    # 💡 NEW: Report Folder Creation (File Saving is retained for HTML only, removed for individual steps)
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    report_folder_name = f"reports/{GLOBAL_TARGET_DOMAIN}_{timestamp}"
    GLOBAL_REPORT_DIR = os.path.abspath(report_folder_name)
    
    os.makedirs(GLOBAL_REPORT_DIR, exist_ok=True)
    print_colored(f"\n[INFO] Saving all results to folder: {GLOBAL_REPORT_DIR}", Colors.YELLOW)
    
    # 💡 NEW: Get Custom Timeouts
    GLOBAL_NUCLEI_TIMEOUT, GLOBAL_GOBUSTER_DIR_TIMEOUT = get_custom_timeouts()
    
    print_colored(f"\n✨ Starting FalconEye Deep Reconnaissance on: {Colors.BOLD}{GLOBAL_TARGET_DOMAIN}{Colors.ENDC}", Colors.HEADER, bold=True)
    print_colored(f"[INFO] Scan Profile: Nuclei Max Time: {GLOBAL_NUCLEI_TIMEOUT}s, Gobuster Dir Max Time: {GLOBAL_GOBUSTER_DIR_TIMEOUT}s", Colors.CYAN)
    draw_separator(char="═", width=80, color=Colors.HEADER)
    
    results: Dict = {
        'target': GLOBAL_TARGET_DOMAIN,
        'Alive Check': {},
        'DNS Records': {},
        'WHOIS Information': {},
        'Technology Detection': {},
        'Subdomains': [],
        'Active Hosts': {}, 
        'Open Ports': [], # Added Naabu
        'Endpoint Gathering': {}, # Added Gau/Subjs
        'Vulnerability Check': [], 
        'Employee/Host Harvester': {},
        'Directory Paths': [] 
    }
    
    # --- 0. Aliveness Check ---
    print_colored("🚦 Checking Target Aliveness (HTTP/Ping)...", Colors.OKBLUE)
    alive_status = {
        'HTTP/S Check': check_host_alive_http(GLOBAL_TARGET_DOMAIN),
        'Ping Check': check_host_alive_ping(GLOBAL_TARGET_DOMAIN)
    }
    results['Alive Check'] = alive_status
    print(format_cli_report(results['Alive Check'], "ALIVENESS CHECK 🚦"))
    write_to_report('01_aliveness_check.txt', json.dumps(alive_status, indent=2))
    draw_separator()

    # --- 1. DNS & WHOIS ---
    results['DNS Records'] = get_dns_info(GLOBAL_TARGET_DOMAIN)
    print(format_cli_report(results['DNS Records'], "DNS RECORDS 🌍"))
    write_to_report('02_dns_records.txt', json.dumps(results['DNS Records'], indent=2))
    draw_separator()

    whois_data = get_whois_info(GLOBAL_TARGET_DOMAIN)
    whois_data['target'] = GLOBAL_TARGET_DOMAIN 
    results['WHOIS Information'] = whois_data
    print(format_cli_report(results['WHOIS Information'], "WHOIS INFORMATION 📜"))
    write_to_report('03_whois_info.txt', json.dumps(results['WHOIS Information'], indent=2))
    draw_separator()

    # --- 2. Tech Detection (Now uses robust HTTP/S fallback) ---
    print_colored("🔍 Detecting Web Technologies & WAF (HTTP/S Request)...", Colors.OKBLUE)
    results['Technology Detection'] = get_technology(GLOBAL_TARGET_DOMAIN)
    print(format_cli_report(results['Technology Detection'], "TECHNOLOGY STACK & WAF 💻"))
    write_to_report('04_tech_stack.txt', json.dumps(results['Technology Detection'], indent=2))
    draw_separator()

    # --- 3. Subdomain Enumeration (Passive + Brute-force) ---
    print_colored("🚀 Enumerating Subdomains (Passive + Brute-force)...", Colors.OKBLUE)
    results['Subdomains'] = run_subdomain_enum(GLOBAL_TARGET_DOMAIN)
    
    if results['Subdomains']:
        print(format_cli_report({'Found Subdomains': results['Subdomains']}, "PASSIVE SUBDOMAIN LIST 🌐"))
        write_to_report('05_subdomains_all.txt', '\n'.join(results['Subdomains']))
    else:
        print_colored("  [!] No subdomains found.", Colors.WARNING)
    draw_separator()

    # --- 4. Active Host Check (httpx with Layered Fallback) ---
    if results['Subdomains']:
        print_colored("🟢 Checking Live Status & Titles (httpx)...", Colors.OKBLUE)
        active_host_data = run_httpx_check(results['Subdomains'])
        results['Active Hosts'] = active_host_data
        print(format_cli_report(results['Active Hosts'], "ACTIVE HOSTS & HTTP STATUS 🟢"))
        write_to_report('06_active_hosts.txt', '\n'.join(active_host_data.get('Alive', [])))
        draw_separator()
        live_hosts_list = active_host_data.get('Alive', [])
    else:
        live_hosts_list = []
        print_colored("  [!] Skipping Active Host Check: No subdomains found.", Colors.WARNING)
        draw_separator()

    # 💡 NEW: Port Scan (Naabu) ---
    if live_hosts_list:
        results['Open Ports'] = run_naabu_scan(live_hosts_list)
        if results['Open Ports']:
            print(format_cli_report({'Open Ports (Top 1000)': results['Open Ports']}, "OPEN PORTS (NAABU) 🔌"))
        draw_separator()

    # 💡 NEW: Endpoint Gathering (GAU + Subjs) ---
    if live_hosts_list:
        results['Endpoint Gathering'] = run_endpoint_gathering(live_hosts_list)
        if results['Endpoint Gathering'].get('Historical URLs') or results['Endpoint Gathering'].get('JS Endpoints'):
            print(format_cli_report(results['Endpoint Gathering'], "ADVANCED ENDPOINT DISCOVERY 🔗"))
        draw_separator()

    # --- 5. Visual Recon (gowitness) ---
    if live_hosts_list:
        print_colored("📸 Running Visual Reconnaissance (gowitness)...", Colors.OKBLUE)
        run_visual_recon(live_hosts_list, GLOBAL_TARGET_DOMAIN)
        draw_separator()

    # --- 6. TheHarvester (Employee/Host Enumeration) ---
    print_colored("📧 Running Employee/Host Harvester...", Colors.OKBLUE)
    results['Employee/Host Harvester'] = run_theharvester(GLOBAL_TARGET_DOMAIN)
    
    harvester_report = {}
    if results['Employee/Host Harvester'].get('Inferred Names'):
        harvester_report['Inferred Names'] = results['Employee/Host Harvester']['Inferred Names']
    if results['Employee/Host Harvester'].get('Emails'):
        harvester_report['Collected Emails'] = results['Employee/Host Harvester']['Emails']
    if results['Employee/Host Harvester'].get('Hosts'):
        harvester_report['Discovered Hosts'] = results['Employee/Host Harvester']['Hosts']

    if harvester_report:
        print(format_cli_report(harvester_report, "PERSONNEL/HOST DISCOVERY 👤"))
        write_to_report('08_employee_data.txt', json.dumps(harvester_report, indent=2))
    else:
        print_colored("  [!] No email or personnel information found.", Colors.WARNING)
    draw_separator()

    # --- 7. Vulnerability/Misconfiguration Check (Nuclei - Now with Progress) ---
    if live_hosts_list:
        print_colored("🔥 Running Vulnerability/Misconfiguration Check (Nuclei)...", Colors.OKBLUE)
        results['Vulnerability Check'] = run_nuclei_scan(live_hosts_list, GLOBAL_NUCLEI_TIMEOUT)
        if results['Vulnerability Check']:
            print(format_cli_report({'Found Issues': results['Vulnerability Check']}, "VULNERABILITY SCAN (NUCLEI) 🔥", title_color=Colors.FAIL))
            write_to_report('09_nuclei_findings.txt', '\n'.join(results['Vulnerability Check']))
        else:
            print_colored("  [!] Nuclei found no quick-win vulnerabilities/misconfigurations.", Colors.OKGREEN)
    draw_separator()

    # --- 8. Directory Brute-force (LAST STEP as requested) ---
    print_colored("📂 Running Directory Brute-force (Gobuster Dir)...", Colors.OKBLUE)
    # The Gobuster Dir function now prints live output and returns an empty list
    results['Directory Paths'] = run_directory_bruteforce(GLOBAL_TARGET_DOMAIN, GLOBAL_GOBUSTER_DIR_TIMEOUT)
    
    if results['Directory Paths']:
        print(format_cli_report({'Found Directories & Files': results['Directory Paths']}, "DIRECTORY BRUTE-FORCE 📂"))
        write_to_report('10_dir_bruteforce_hits.txt', '\n'.join(results['Directory Paths']))
    else:
        # We rely on the live output for Dir hits, so this message is printed if the process completes cleanly.
        print_colored("  [!] Gobuster Directory Brute-force finished (Live hits shown above).", Colors.OKGREEN)
    draw_separator()

    # --- FINAL REPORTING ---
    generate_html_report(results)

    draw_separator(char="═", width=80, color=Colors.HEADER)
    print_colored("\n✅ Deep reconnaissance completed successfully!", Colors.OKGREEN, bold=True)
    print_colored(f"Report folder created at: {GLOBAL_REPORT_DIR}/", Colors.YELLOW)
    
    return results

def main():
    """Standalone execution function."""
    if len(sys.argv) < 2:
        run() 
    else:
        target = sys.argv[1].strip()
        run(target)

if __name__ == "__main__":
    main()
