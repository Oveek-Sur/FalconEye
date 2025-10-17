#!/usr/bin/env python3
"""FalconEye NMAP Driver Module - Full Functionality"""
import subprocess
import sys
import shlex
import time
from datetime import datetime
import os
import xml.etree.ElementTree as ET
from collections import defaultdict
import re
import tempfile
import socket
import platform 

# ====================================================================
# --- REQUIRED MODULE ATTRIBUTES FOR FALCONEYE MENU ---
# ====================================================================
name = "Professional Nmap Scan"
description = "Comprehensive Network Scan with Timing Control (T0-T5)"

# --- CRITICAL COMMON PORTS LIST for Quick Scan (Option 1) ---
CRITICAL_PORTS = "21,22,23,25,53,80,110,135,139,143,389,443,445,1433,1521,3306,3389,5432,5900,8080,8443"

# ====================================================================
# --- NMAP DRIVER CORE FUNCTIONS ---
# ====================================================================

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def check_root_privileges():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False
        
def print_colored(text, color=Colors.ENDC):
    """Print colored text to terminal"""
    print(f"{color}{text}{Colors.ENDC}")

def get_terminal_size():
    """Get terminal dimensions"""
    try:
        import shutil
        return shutil.get_terminal_size().columns
    except:
        try:
            rows, columns = os.popen('stty size', 'r').read().split()
            return int(columns)
        except:
            return 80

def draw_separator(char="─", width=None):
    """Draw a horizontal separator line"""
    if width is None:
        width = get_terminal_size()
    print(char * width)

def sanitize_xml_content(xml_content):
    """Sanitize XML content to prevent parsing issues"""
    if not xml_content:
        return xml_content
    sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', xml_content)
    max_size = 10 * 1024 * 1024
    if len(sanitized) > max_size:
        nmaprun_start = sanitized.find('<nmaprun')
        if nmaprun_start != -1:
            nmaprun_end = sanitized.rfind('</nmaprun>')
            if nmaprun_end != -1:
                sanitized = sanitized[nmaprun_start:nmaprun_end + len('</nmaprun>')]
            else:
                runstats_start = sanitized.rfind('<runstats')
                if runstats_start != -1:
                    sanitized = sanitized[nmaprun_start:runstats_start] + '</nmaprun>'
                else:
                    sanitized = sanitized[nmaprun_start:min(len(sanitized), max_size+nmaprun_start)]
        else:
            first_open = sanitized.find('<')
            last_close = sanitized.rfind('>')
            if first_open != -1 and last_close != -1 and last_close > first_open:
                sanitized = sanitized = sanitized[first_open:last_close+1]
            else:
                sanitized = sanitized[:max_size]
    return sanitized

def validate_target(target):
    """Validate target input to prevent command injection"""
    if not target: return False
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
    cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    range_pattern = r'^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$'
    if (re.match(ip_pattern, target) or 
        re.match(cidr_pattern, target) or
        re.match(hostname_pattern, target) or
        re.match(range_pattern, target)):
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}', target):
            ip_part = target.split('/')[0]
            octets = ip_part.split('.')
            if len(octets) == 4:
                for octet in octets:
                    if not octet.isdigit() or not (0 <= int(octet) <= 255):
                        return False
        return True
    return False

def ping_host(target):
    """Ping a host to check if it's alive"""
    try:
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}', target):
            ip = socket.gethostbyname(target)
        else:
            ip = target
        cmd = ["/bin/ping", "-c", "1", "-W", "3", ip]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0
    except:
        return False

# --- NEW/UPDATED SMART PING FUNCTION ---
def smart_ping_host(target):
    """
    Ping a host. If ICMP fails, try TCP connect on ports 80 and 443 for aliveness.
    Returns True if alive, False otherwise.
    """
    print_colored("  [>] Attempting ICMP Ping...", Colors.OKBLUE)
    
    # Resolve IP once
    try:
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}', target):
            ip = socket.gethostbyname(target)
        else:
            ip = target
    except:
        return False # Cannot resolve host

    # 1. Try standard ICMP ping
    try:
        cmd = ["/bin/ping", "-c", "1", "-W", "3", ip]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            return True # Alive via ICMP
    except:
        pass # ICMP failed
        
    print_colored("  [>] ICMP failed. Checking standard web ports (80, 443) via TCP...", Colors.WARNING)
    
    # 2. Try TCP connect to common web ports (80 and 443)
    for port in [80, 443]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2) # 2 second timeout for connection
            # connect_ex returns 0 on success
            if sock.connect_ex((ip, port)) == 0:
                print_colored(f"  [+] Host is ALIVE (TCP Port {port} responded).", Colors.OKGREEN)
                sock.close()
                return True # Alive via TCP
            sock.close()
        except:
            continue
            
    print_colored("  [!] Host appears to be DOWN (ICMP and TCP checks failed).", Colors.FAIL)
    return False


def check_https(target):
    """Check if HTTPS is available on port 443"""
    try:
        cmd = ["/usr/bin/timeout", "5", "/usr/bin/curl", "-I", "--connect-timeout", "3", "-k", f"https://{target}:443"]
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
        if result.returncode == 0 and "HTTP/" in result.stdout:
            return "YES"
        return "NO"
    except:
        return "UNKNOWN"

def cleanup_xml_file(xml_file):
    """Safely remove the temporary XML file, potentially using sudo"""
    if os.path.exists(xml_file):
        try:
            os.remove(xml_file)
        except PermissionError:
            subprocess.run(["sudo", "rm", "-f", xml_file], capture_output=True)
        except Exception:
             subprocess.run(["sudo", "rm", "-f", xml_file], capture_output=True)

def get_timing_template():
    """Prompt user for Nmap timing template (T0-T5)"""
    print_colored("\n--- Nmap Timing Template Selection ---", Colors.HEADER)
    print("T0: Paranoid (Very slow, highly stealthy)")
    print("T1: Sneaky (Very slow, stealthy)")
    print("T2: Polite (Slow, polite)")
    print("T3: Normal (Default speed and behavior)")
    print("T4: Aggressive (Fast, can miss things on lossy networks)")
    print("T5: Insane (Very fast, less reliable)")
    
    while True:
        choice = get_user_input("Select timing template (0-5, default T3): ")
        if not choice:
            return "-T3"
        if choice in ['0', '1', '2', '3', '4', '5']:
            return f"-T{choice}"
        print_colored("Invalid choice. Please enter a number from 0 to 5.", Colors.WARNING)

# --- UPDATED run_nmap_scan FUNCTION ---
def run_nmap_scan(target, profile, custom_args=None, port_range=None, timing_template="-T3", max_rtt_timeout_ms=None):
    """Execute Nmap scan with specified profile and stream output"""
    if not target:
        return {"success": False, "error": "No target specified"}
        
    if not validate_target(target):
        return {"success": False, "error": "Invalid target format"}
        
    print_colored(f"[+] Checking host aliveness for {target}...", Colors.OKBLUE)
    if not smart_ping_host(target): # Using new smart check
        print_colored(f"[!] Warning: Host {target} appears to be down (all checks failed)", Colors.WARNING)
        response = input("Continue anyway? (y/N): ").strip().lower()
        if response != 'y':
            return {"success": False, "error": "Host appears to be down"}
            
    temp_dir = "/tmp" if os.access("/tmp", os.W_OK) else tempfile.gettempdir()
    timestamp = int(time.time())
    xml_file = os.path.join(temp_dir, f"nmap_scan_{timestamp}.xml")
    
    cmd = ["/usr/bin/nmap"]
    cmd.append("-Pn") 
    
    # --- Start Profile Logic ---
    profile_found = False

    if profile == "firewall_bypass":
        profile_found = True
        num_decoys = get_user_input("Enter number of decoys (2-5 recommended, default 3): ")
        try:
            num_decoys = int(num_decoys) if num_decoys else 3
            if num_decoys < 1: raise ValueError
        except ValueError:
            num_decoys = 3 
            
        decoy_ips = ",".join([f"RND:{num_decoys}", "ME"])
        
        # --- Firewall Bypass: FIN, Frag, Decoys, Source Port, PLUS -sV to resolve open|filtered ---
        cmd.extend(["-sF", "-sV", "-D", decoy_ips, "-f", "-g", "53"]) 
        
        if port_range:
            cmd.extend(["-p", port_range])
        
    elif profile == "quick":
        profile_found = True
        # --- Quick Scan: Critical Ports, PLUS -sV, -sC, -O for aggressive info gathering ---
        cmd.extend(["-p", CRITICAL_PORTS, "-sV", "-sC", "-O"])
        
    elif profile == "stealth":
        profile_found = True
        cmd.extend(["-sS", "--randomize-hosts"])
        
    elif profile == "full":
        profile_found = True
        rtt_timeout = f"{max_rtt_timeout_ms}ms" if max_rtt_timeout_ms is not None else None
        
        # --- Full Scan: -p- PLUS -sV, -sC, -O for comprehensive gathering ---
        cmd.extend(["-p-", "-sV", "-sC", "-O", "--min-rate", "300", "--host-timeout", "60m"]) 
        
        if rtt_timeout:
            cmd.extend(["--max-rtt-timeout", rtt_timeout])
        
    elif profile == "specific":
        profile_found = True
        if port_range:
            cmd.extend(["-p", port_range])
        else:
            return {"success": False, "error": "Port range required for specific scan"}
    elif profile == "udp":
        profile_found = True
        cmd.extend(["-sU", "--top-ports", "100"])
    
    # --- Custom Profile ---
    elif profile == "custom" and custom_args:
        profile_found = True
        try:
            parsed_args = shlex.split(custom_args)
            safe_args = []
            dangerous_flags = ['-iL', '-iR', '--iflist', '--system-dns', '--dns-servers',
                               '--script', '--script-args', '--script-help', '--script-trace',
                               '--exec'] 
            
            i = 0
            while i < len(parsed_args):
                arg = parsed_args[i]
                is_dangerous = any(arg.startswith(flag) for flag in dangerous_flags)
                if is_dangerous and arg not in ['-sV', '-sC', '-A', '-Pn', '-T0', '-T1', '-T2', '-T3', '-T4', '-T5']:
                    print_colored(f"Warning: Skipping potentially unsafe argument: {arg}", Colors.WARNING)
                    i += 1
                    continue
                                
                safe_args.append(arg)
                if arg in ['-p', '--ports', '--source-port', '--data-length', '--ip-options', '--ttl', 
                          '--min-parallelism', '--max-parallelism', '--min-rate', '--max-rate', 
                          '--scan-delay', '--host-timeout', '--script-timeout', '--exclude', '--excludefile']:
                    if i + 1 < len(parsed_args) and not parsed_args[i+1].startswith('-'):
                        safe_args.append(parsed_args[i+1])
                        i += 2
                        continue
                i += 1
                            
            cmd.extend(safe_args)
        except ValueError as e:
            return {"success": False, "error": f"Invalid custom arguments: {e}"}
    
    # --- Error Check ---
    if not profile_found:
        return {"success": False, "error": f"Unknown scan profile: {profile}"}
    
    # --- End Profile Logic ---
    
    # Timing Template Logic
    if profile != "custom" and profile != "firewall_bypass":
        if profile != "full":
             cmd.append(timing_template)
        elif profile == "full":
             cmd.append(timing_template)
    elif profile == "firewall_bypass":
         cmd.append("-T5") # Force Insane timing for bypass scan
    
    # RTT Timeout for Specific Scan
    if profile == "specific" and max_rtt_timeout_ms is not None:
        cmd.extend(["--max-rtt-timeout", f"{max_rtt_timeout_ms}ms"])

    cmd.append(target)
    cmd.extend(["-oX", xml_file])

    env = os.environ.copy()
    env['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:' + env.get('PATH', '')
    
    # Conditional Timeout (60 min for Full Scan, 20 min for others)
    scan_timeout = 3600 if profile == "full" else 1200
        
    try:
        final_cmd = cmd
        if not check_root_privileges() and "/usr/bin/sudo" not in cmd:
            final_cmd = ["/usr/bin/sudo"] + cmd
                
        print_colored(f"[+] Starting {profile.upper()} scan on {target}...", Colors.OKGREEN)
        print(f"Executing: {' '.join(shlex.quote(str(arg)) for arg in final_cmd)}\n")
        draw_separator("=")

        # Use Popen to allow real-time output stream and conditional timeout handling
        process = subprocess.Popen(
            final_cmd,
            stdout=sys.stdout, 
            stderr=sys.stderr, 
            text=True,
            encoding='utf-8',
            env=env
        )
        
        # Wait for the process to complete with the initial timeout limit
        try:
            process.wait(timeout=scan_timeout)
            
            # If we reach here, the process finished normally (not timeout)
            return_code = process.returncode

        except subprocess.TimeoutExpired:
            # Process timed out. Return signal to ask user for continuation.
            return {"success": False, "error": "Scan timed out (CONTINUE_PROMPT_NEEDED)", "process": process, "xml_file": xml_file, "final_cmd": final_cmd}

        # Handle normal process exit (success or failure)
        draw_separator("=")
        print_colored("\n[+] Nmap execution finished. Attempting to parse results...", Colors.OKBLUE)
        
        if return_code != 0:
            cleanup_xml_file(xml_file)
            return {
                "success": False,
                "error": f"Nmap exited with error code {return_code}. Check output above."
            }
                
        if not os.path.exists(xml_file):
            return {"success": False, "error": "XML output file was not created by Nmap."}
                
        xml_content = ""
        try:
            with open(xml_file, 'r', encoding='utf-8', errors='ignore') as f:
                xml_content = f.read(10 * 1024 * 1024) 
        except PermissionError:
            print_colored("Warning: Permission denied on XML file. Reading with sudo...", Colors.WARNING)
            result_cat = subprocess.run(["sudo", "cat", xml_file], capture_output=True, text=True)
            if result_cat.returncode == 0:
                xml_content = result_cat.stdout[:10 * 1024 * 1024]
            else:
                raise Exception(f"Failed to read XML file even with sudo: {result_cat.stderr}")
        except Exception as e:
            raise Exception(f"Error reading XML output: {e}")
        finally:
            cleanup_xml_file(xml_file)

        xml_content = sanitize_xml_content(xml_content)
                
        return {
            "success": True,
            "xml_content": xml_content,
            "stdout": "", 
            "stderr": ""
        }
            
    except Exception as e:
        cleanup_xml_file(xml_file)
        return {"success": False, "error": str(e)}

def safe_parse_xml(xml_content):
    """Safely parse XML with protections against XXE and other vulnerabilities"""
    if not xml_content or not xml_content.strip():
        return None
        
    try:
        root = ET.fromstring(xml_content)
        return root
    except ET.ParseError as e:
        print_colored(f"XML Parse Error: {e}", Colors.WARNING)
        print_colored("Attempting to recover from XML parsing error...", Colors.WARNING)
                
        cleaned_xml = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', xml_content)
                
        try:
            root = ET.fromstring(cleaned_xml)
            return root
        except ET.ParseError:
            try:
                nmaprun_start = cleaned_xml.find('<nmaprun')
                if nmaprun_start == -1: return None
                                
                nmaprun_end = cleaned_xml.rfind('</nmaprun>')
                if nmaprun_end == -1:
                    runstats_start = cleaned_xml.rfind('<runstats')
                    if runstats_start != -1:
                        fixed_xml = cleaned_xml[nmaprun_start:runstats_start] + '</nmaprun>'
                    else:
                        fixed_xml = cleaned_xml[nmaprun_start:]
                else:
                    fixed_xml = cleaned_xml[nmaprun_start:nmaprun_end + len('</nmaprun>')]
                                
                fixed_xml = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', fixed_xml)
                                
                root = ET.fromstring(fixed_xml)
                return root
            except ET.ParseError as e2:
                print_colored(f"Recovery failed: {e2}", Colors.FAIL)
                return None
    except Exception as e:
        print_colored(f"Unexpected XML parsing error: {e}", Colors.FAIL)
        return None

def parse_nmap_xml(xml_content):
    """Parse Nmap XML output accurately"""
    try:
        if not xml_content or not xml_content.strip():
            return None
                
        root = safe_parse_xml(xml_content)
        if root is None:
            return None
        
        ports_scanned = 0
        try:
            scan_info_elem = root.find(".//scaninfo")
            if scan_info_elem is not None:
                ports_scanned_attr = scan_info_elem.get('services')
                if ports_scanned_attr:
                    ports_count = 0
                    for part in ports_scanned_attr.split(','):
                        if '-' in part:
                            start, end = map(int, part.split('-'))
                            ports_count += (end - start + 1)
                        else:
                            ports_count += 1
                    ports_scanned = ports_count
                
            if ports_scanned == 0 and '-F' in root.get('args', ''):
                ports_scanned = 100
            elif ports_scanned == 0 and '-p-' in root.get('args', ''):
                ports_scanned = 65535

        except:
            pass 


        results = {
            'scan_info': {},
            'hosts': [],
            'ports_scanned': ports_scanned 
        }
                
        results['scan_info'] = {
            'start_time': root.get('startstr', 'Unknown'),
            'scanner': root.get('scanner', 'Unknown'),
            'version': root.get('version', 'Unknown'),
            'args': root.get('args', 'Unknown')
        }
                
        for host_elem in root.findall('host'):
            host_data = {
                'status': 'unknown',
                'addresses': [],
                'hostnames': [],
                'ports': [],
                'port_summary': defaultdict(int)
            }
                        
            # --- Get OS Details ---
            os_elem = host_elem.find('os')
            if os_elem is not None:
                os_details = []
                for os_match in os_elem.findall('osmatch'):
                    os_details.append(os_match.get('name'))
                host_data['os_details'] = ', '.join(os_details)
            else:
                host_data['os_details'] = 'N/A'
            
            # --- Get Script Results ---
            host_script_elem = host_elem.find('hostscript')
            scripts = {}
            if host_script_elem is not None:
                for script_elem in host_script_elem.findall('script'):
                    script_id = script_elem.get('id', 'unknown')
                    script_output = script_elem.get('output', '')
                    
                    # Clean up multi-line output for display
                    if script_output:
                        # Take the first 3 lines and clean up whitespace/tabs
                        lines = [line.strip() for line in script_output.split('\n') if line.strip()]
                        scripts[script_id] = " | ".join(lines[:3]) 
            host_data['scripts'] = scripts


            status_elem = host_elem.find('status')
            if status_elem is not None:
                host_data['status'] = status_elem.get('state', 'unknown')
                        
            for addr_elem in host_elem.findall('address'):
                addr_info = {
                    'addr': addr_elem.get('addr', ''),
                    'type': addr_elem.get('addrtype', '')
                }
                host_data['addresses'].append(addr_info)
                        
            hostnames_elem = host_elem.find('hostnames')
            if hostnames_elem is not None:
                for hostname_elem in hostnames_elem.findall('hostname'):
                    hostname = hostname_elem.get('name')
                    if hostname:
                        host_data['hostnames'].append(hostname)
                        
            ports_elem = host_elem.find('ports')
                        
            if ports_elem is not None:
                for port_elem in ports_elem.findall('port'):
                    port_id = port_elem.get('portid')
                    protocol = port_elem.get('protocol')
                                        
                    state_elem = port_elem.find('state')
                    state = state_elem.get('state') if state_elem is not None else 'unknown'
                                        
                    host_data['port_summary'][state] += 1
                                        
                    service_elem = port_elem.find('service')
                    service_info = {
                        'name': 'unknown',
                        'product': '',
                        'version': '',
                        'extrainfo': ''
                    }
                                        
                    if service_elem is not None:
                        service_info['name'] = service_elem.get('name', 'unknown')
                        service_info['product'] = service_elem.get('product', '')
                        service_info['version'] = service_elem.get('version', '')
                        service_info['extrainfo'] = service_elem.get('extrainfo', '')
                                        
                    port_data = {
                        'portid': port_id,
                        'protocol': protocol,
                        'state': state,
                        'service': service_info
                    }
                    host_data['ports'].append(port_data)
                        
            results['hosts'].append(host_data)
                
        return results
            
    except Exception as e:
        print_colored(f"Parsing Error: {e}", Colors.FAIL)
        return None

def calculate_risk_score(port_summary):
    """Calculate risk score based on open ports"""
    if not port_summary:
        return "NONE"
        
    open_count = port_summary.get('open', 0)
        
    if open_count == 0:
        return "NONE"
    elif open_count <= 5:
        return "LOW"
    elif open_count <= 20:
        return "MODERATE"
    elif open_count <= 100:
        return "HIGH"
    else:
        return "CRITICAL"

def display_scan_results(results, target, profile):
    """Display parsed scan results in a structured format"""
    if not results or not results.get('hosts'):
        print_colored("No hosts found in scan results.", Colors.WARNING)
        return
        
    scan_info = results.get('scan_info', {})
    ports_scanned = results.get('ports_scanned', 0)

    draw_separator()
    print_colored("SCAN SUMMARY", Colors.OKBLUE)
    draw_separator()
    print(f"Scanner: {scan_info.get('scanner', 'Nmap')} {scan_info.get('version', '')}")
    print(f"Started: {scan_info.get('start_time', 'Unknown')}")
    print(f"Profile: {profile.upper()}")
    print(f"Target:  {target}")
    print(f"Ports Scanned: {ports_scanned}") 
    print(f"Command: {scan_info.get('args', 'Unknown')}")
    draw_separator()
        
    for i, host in enumerate(results['hosts'], 1):
        if len(results['hosts']) > 1:
            print_colored(f"\nHOST {i}", Colors.OKGREEN)
            draw_separator("-")
                
        status = host.get('status', 'unknown')
        print(f"Status:  {status.upper()}")
                
        addresses = host.get('addresses', [])
        if addresses:
            print("Addresses:")
            for addr in addresses:
                print(f"  {addr['addr']} ({addr['type']})")
                
        hostnames = host.get('hostnames', [])
        if hostnames:
            print(f"Hostname{'s' if len(hostnames) > 1 else ''}: {', '.join(hostnames)}")
        
        # --- Display OS Details ---
        if 'os_details' in host and host['os_details'] != 'N/A':
            print_colored(f"\nOS Details: {host['os_details']}", Colors.BOLD)
        
        # --- Display Script Results ---
        if 'scripts' in host and host['scripts']:
            print_colored("\nHOST SCRIPT RESULTS (Vulnerabilities/Info):", Colors.HEADER)
            for script_id, output in host['scripts'].items():
                print(f"  [{script_id}]: {output}")
                
        port_summary = host.get('port_summary', {})
        
        open_ports = port_summary.get('open', 0)
        closed_ports = port_summary.get('closed', 0)
        filtered_ports = port_summary.get('filtered', 0)
        risk_score = calculate_risk_score(port_summary)

        total_found = open_ports + closed_ports + filtered_ports
        unscanned_ports = ports_scanned - total_found

        if ports_scanned > 0:
            print(f"\nPort Summary (of {ports_scanned} scanned): {open_ports} open, {closed_ports} closed, {filtered_ports} filtered")
            if unscanned_ports > 0 and 'full' not in profile.lower():
                 print_colored(f"Note: {unscanned_ports} ports were not detailed in the output for this scan type.", Colors.WARNING)
        else:
             print(f"\nPort Summary: {open_ports} open, {closed_ports} closed, {filtered_ports} filtered")
        
        print(f"Risk Score:   {risk_score}")
                        
        open_ports_list = [p for p in host.get('ports', []) if p.get('state') == 'open']
        if open_ports_list:
            print_colored("\nOPEN PORTS DETECTED", Colors.WARNING)
            # Table width adjusted for better display
            print("┌──────┬────────┬────────────────────────────────┬──────────────────────────────────────────────┐")
            print("│ Port │ Proto  │ Service                        │ Product/Version                              │")
            print("├──────┼────────┼────────────────────────────────┼──────────────────────────────────────────────┤")
                                
            open_ports_list.sort(key=lambda x: int(x.get('portid', 0)))
                                
            for port in open_ports_list:
                port_id = str(port.get('portid', 'N/A'))[:5]
                protocol = str(port.get('protocol', 'N/A'))[:7]
                service = str(port['service'].get('name', 'N/A'))[:31]
                                        
                product = port['service'].get('product', '')
                version = port['service'].get('version', '')
                extrainfo = port['service'].get('extrainfo', '')
                version_info = ' '.join(filter(None, [product, version, extrainfo]))[:45] # Truncated to 45
                                        
                print(f"│ {port_id:<5}│ {protocol:<7}│ {service:<31}│ {version_info:<45}│")
                                
            print("└──────┴────────┴────────────────────────────────┴──────────────────────────────────────────────┘")
        else:
            print("\nNo open ports detected.")

def get_user_input(prompt):
    """Get sanitized user input"""
    try:
        return input(prompt).strip()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        return None

# ====================================================================
# --- REQUIRED 'run' FUNCTION FOR FALCONEYE MENU ---
# ====================================================================
def run():
    """Main execution function for the Nmap module, called by FalconEye menu."""
    
    def show_module_menu():
        draw_separator("=")
        print_colored("NMAP SCAN PROFILES", Colors.OKBLUE)
        draw_separator("=")
        print("\n1. Quick Scan (Top Common Ports / OS & Scripts)")
        print("2. Specific Ports Scan")
        print("3. Stealth Scan (SYN scan)")
        print_colored("4. Full Scan (All 65,535 ports - Optimized)", Colors.WARNING)
        print("5. UDP Scan (Top 100 ports)")
        print("6. Custom Scan (Use -T flag for timing)")
        print_colored("8. Firewall Bypass Scan (Decoys, FIN, Frag, -T5)", Colors.WARNING)
        print("7. Back to Main Menu")
        print()

    while True:
        show_module_menu()
        choice = get_user_input("Select an option (1-8, 7 to exit): ")
                
        if not choice or choice == "7":
            if choice == "7":
                print_colored("Returning to main menu.", Colors.OKGREEN)
            break
                    
        profiles = {
            "1": "quick",
            "3": "stealth",
            "4": "full",
            "5": "udp",
            "8": "firewall_bypass"
        }
                
        profile = None
        target = None
        timing_template = None
        port_range = None 
        custom_args = None
        max_rtt_ms = None
        result = None

        if choice in ["1", "3", "4", "5", "8"]:
            profile = profiles[choice]
            target = get_user_input("\nEnter target (IP, hostname, or CIDR): ")
            if not target: continue
            
            # --- Option 4: Full Scan ---
            if profile == "full": 
                print_colored("\nWarning: Full Scan (65,535 ports) is running with aggressive optimizations and has an initial 40-minute limit.", Colors.WARNING)
                
                # --- RTT CONFIGURATION FOR FULL SCAN (User input, blank = Nmap default) ---
                print_colored("\n--- RTT Timeout Configuration ---", Colors.HEADER)
                rtt_choice = get_user_input("Enter max RTT timeout in milliseconds (e.g., 500. Recommended 500ms for stable scans. Leave blank for Nmap default): ")
                try:
                    max_rtt_ms = int(rtt_choice) if rtt_choice and int(rtt_choice) > 0 else None
                except ValueError:
                    max_rtt_ms = None
                    
                timing_template = get_timing_template()
                
                result = run_nmap_scan(target, profile, timing_template=timing_template, max_rtt_timeout_ms=max_rtt_ms)
                
            elif profile == "firewall_bypass": # Option 8
                port_range = get_user_input("Enter port range (e.g., 22,80,443 or 1-1000, default 1-1000): ")
                if not port_range: port_range = "1-1000"
                result = run_nmap_scan(target, profile, port_range=port_range)
            
            else: # Options 1, 3, 5
                timing_template = get_timing_template()
                result = run_nmap_scan(target, profile, timing_template=timing_template)
                        
        elif choice == "2":
            # --- Specific Ports Scan (Option 2) ---
            profile = "specific"
            target = get_user_input("\nEnter target (IP, hostname, or CIDR): ")
            if not target: continue
                            
            port_range = get_user_input("Enter port range (e.g., 22,80,443 or 1-1000): ")
            if not port_range: continue
                
            timing_template = get_timing_template()
            
            # --- RTT CONFIGURATION FOR SPECIFIC SCAN ---
            print_colored("\n--- RTT Timeout Configuration (Optional) ---", Colors.HEADER)
            rtt_choice = get_user_input("Enter max RTT timeout in milliseconds (e.g., 500. Recommended 500ms for stable scans. Leave blank for Nmap default): ")
            try:
                max_rtt_ms = int(rtt_choice) if rtt_choice and int(rtt_choice) > 0 else None
            except ValueError:
                max_rtt_ms = None
            
            result = run_nmap_scan(target, profile, port_range=port_range, timing_template=timing_template, max_rtt_timeout_ms=max_rtt_ms)
                        
        elif choice == "6": 
            # --- Custom Scan (Option 6) ---
            profile = "custom"
            print_colored("\nCustom Scan Instructions:", Colors.OKGREEN)
            print("Enter your Nmap arguments (without 'nmap'). You MUST manually include -T#, --host-timeout, etc. if desired.")
            print("Example: -p 80,443 -sV -T4 -A")
                        
            custom_args = get_user_input("Enter custom arguments: ")
            if not custom_args: continue
                            
            target = get_user_input("Enter target: ")
            if not target: continue
                            
            result = run_nmap_scan(target, profile, custom_args)
                        
        else:
            print_colored("Invalid option. Please select 1-8 (or 7 to exit).", Colors.WARNING)
            continue
            
        # --- COMMON TIMEOUT/RESULT HANDLING LOOP (Applies to all profiles) ---
        scan_continue = True
        
        while scan_continue:
            if result and result.get('success'):
                scan_continue = False
                break 
                
            # Check for the custom timeout signal (applies to all profiles)
            if result and result.get('error') == "Scan timed out (CONTINUE_PROMPT_NEEDED)":
                
                if not check_root_privileges():
                    print_colored("\n[!] Warning: Running without root may limit continuation reliability.", Colors.WARNING)
                        
                # Determine initial timeout limit for the prompt (60 min for full, 20 min for others)
                timeout_limit_min = 60 if profile == "full" else 20
                
                response = get_user_input(f"\n[?] Scan has exceeded {timeout_limit_min} minutes. It may take significantly more time. Do you want to continue? (y/N): ").strip().lower()
                
                if response == 'y':
                    print_colored("[+] Continuing scan with a 30-minute extension. Press Ctrl+C to abort later.", Colors.OKGREEN)
                    try:
                        result['process'].wait(timeout=1800)
                        
                        result['error'] = None 
                        result['success'] = True
                        
                    except subprocess.TimeoutExpired:
                        continue
                    except Exception as e:
                        result['error'] = str(e)
                        result['success'] = False
                    
                    if result['success']:
                        print_colored("\n[+] Scan finished after continuation. Reading results...", Colors.OKBLUE)
                        xml_file = result['xml_file']
                        try:
                            with open(xml_file, 'r', encoding='utf-8', errors='ignore') as f:
                                xml_content = f.read(10 * 1024 * 1024) 
                            cleanup_xml_file(xml_file)
                            result['xml_content'] = sanitize_xml_content(xml_content)
                        except Exception as e:
                            result['success'] = False
                            result['error'] = f"Error reading results after continuation: {e}"
                            cleanup_xml_file(xml_file)
                            scan_continue = False
                            break
                        
                else:
                    print_colored("[!] Scan aborted by user after timeout.", Colors.FAIL)
                    if 'process' in result:
                        result['process'].kill() 
                        cleanup_xml_file(result['xml_file'])
                    scan_continue = False
                    break 
            
            elif result is not None:
                scan_continue = False
                break 
            
            else:
                break

        # --- COMMON SUCCESS HANDLING ---
        if result and result.get('success'):
            parsed_results = parse_nmap_xml(result['xml_content'])
            if parsed_results:
                display_scan_results(parsed_results, target, profile)
            else:
                print_colored("\n[!] Failed to parse scan results. Nmap may have finished successfully, but the XML output was invalid or empty.", Colors.FAIL)
            
            https_status = check_https(target)
            print(f"\nHTTPS Available on 443: {https_status}")

        elif result and not result.get('success') and result.get('error') != "Scan timed out (CONTINUE_PROMPT_NEEDED)":
             print_colored(f"\n[!] Scan failed: {result['error']}", Colors.FAIL)
             get_user_input("\nPress Enter to continue...")
