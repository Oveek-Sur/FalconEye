# <Falcon_Eye--See throufh the wall, Its a recon tool which helps to save the time of penetesters>
# Copyright (C) 2025 Oveek Sur
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

# falconeye/menu.py

import os
import importlib.util
import sys
import subprocess
import platform

# Tool header
TOOL_NAME = "FalconEye"
TOOL_TAGLINE = "See through the walls"

def is_root():
    """Check if the script is running as root/administrator"""
    try:
        if platform.system().lower() == "windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False

def get_public_ip():
    """Get public IP address using multiple fast methods"""
    try:
        import urllib.request
        import socket
        
        # Set timeout
        socket.setdefaulttimeout(7)
        
        # Try multiple services
        services = [
            "https://api.ipify.org",
            "https://icanhazip.com",
            "https://ident.me"
        ]
        
        for service in services:
            try:
                req = urllib.request.Request(
                    service,
                    headers={
                        'User-Agent': 'FalconEye/1.0',
                        'Accept': 'text/plain'
                    }
                )
                with urllib.request.urlopen(req, timeout=7) as response:
                    ip = response.read().decode().strip()
                    # Basic validation
                    if ip and len(ip) > 6 and ('.' in ip or ':' in ip):
                        return ip
            except Exception as e:
                # Try next service
                continue
                
        return "Unknown"
    except Exception as e:
        return f"Error: {str(e)[:30]}"

def check_internet():
    """Check internet connectivity with a simple ping"""
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        cmd = ["ping", param, "1", "8.8.8.8"]
        
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5
        )
        return "OK" if result.returncode == 0 else "Unreachable"
    except Exception:
        # Fallback to DNS resolution test
        try:
            import socket
            socket.gethostbyname("google.com")
            return "OK (DNS)"
        except Exception:
            return "Unreachable"

def check_nmap():
    """Check if Nmap is installed"""
    try:
        # Try different ways to check nmap based on OS
        if platform.system().lower() == "windows":
            result = subprocess.run(["where", "nmap"], 
                                  stdout=subprocess.DEVNULL, 
                                  stderr=subprocess.DEVNULL, 
                                  timeout=10)
        else:
            result = subprocess.run(["which", "nmap"], 
                                  stdout=subprocess.DEVNULL, 
                                  stderr=subprocess.DEVNULL, 
                                  timeout=10)
        
        if result.returncode == 0:
            # Verify nmap works
            subprocess.run(["nmap", "--version"], 
                         stdout=subprocess.DEVNULL, 
                         stderr=subprocess.DEVNULL, 
                         timeout=10)
            return "Found"
        else:
            return "Not Found"
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        return "Not Found"

def load_modules():
    """Dynamically load all modules from the modules/ directory"""
    modules = []
    modules_dir = "modules"
    
    # Normalize path for cross-platform compatibility
    modules_dir = os.path.normpath(modules_dir)
    
    if not os.path.exists(modules_dir):
        print(f"[!] Modules directory '{modules_dir}' does not exist.")
        return modules
    
    # Add modules directory to path
    if modules_dir not in sys.path:
        sys.path.insert(0, modules_dir)
        
    # Sort files for consistent ordering
    try:
        files = sorted(os.listdir(modules_dir))
    except OSError as e:
        print(f"[!] Error reading modules directory: {e}")
        return modules
        
    for filename in files:
        if filename.endswith(".py") and filename != "__init__.py":
            module_path = os.path.join(modules_dir, filename)
            
            # Only process files, not directories
            if not os.path.isfile(module_path):
                continue
                
            module_name = filename[:-3]  # Remove .py extension
            
            # Skip if module name is invalid
            if not module_name.replace('_', '').replace('-', '').isalnum():
                print(f"[!] Skipping module with invalid name: {filename}")
                continue
            
            try:
                spec = importlib.util.spec_from_file_location(module_name, module_path)
                if spec is None:
                    print(f"[!] Failed to create spec for module {filename}")
                    continue
                    
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
            except Exception as e:
                print(f"[!] Failed to load module {filename}: {e}")
                continue
                
            # Check if module has required attributes
            if (hasattr(module, 'name') and 
                hasattr(module, 'description') and 
                hasattr(module, 'run')):
                
                # Additional validation to ensure they are not empty
                if (isinstance(module.name, str) and 
                    isinstance(module.description, str) and 
                    callable(module.run) and
                    module.name.strip() and 
                    module.description.strip()):
                    modules.append(module)
                else:
                    print(f"[!] Module {filename} has invalid or empty required attributes")
            else:
                print(f"[!] Module {filename} is missing required attributes (name, description, run)")
                
    return modules

def display_header():
    """Display the tool header"""
    print(f"=== {TOOL_NAME} — {TOOL_TAGLINE} ===\n")

def display_status():
    """Display system status information"""
    public_ip = get_public_ip()
    internet_status = check_internet()
    nmap_status = check_nmap()
    root_status = "Yes" if is_root() else "No"
    
    print(f"Public IP: {public_ip} | Internet: {internet_status} | Nmap: {nmap_status} | Root: {root_status}\n")

def display_modules(modules):
    """Display available modules"""
    if not modules:
        print("[!] No modules available.\n")
        return
        
    print("Available Modules:")
    print("-" * 30)
    for i, module in enumerate(modules, 1):
        # Truncate long descriptions
        desc = module.description[:50] + "..." if len(module.description) > 50 else module.description
        print(f"{i:2}) {module.name:<15} - {desc}")
    print(" 0) Exit")
    print("-" * 30 + "\n")

def get_user_choice(modules):
    """Get user's module choice"""
    if not modules:
        return None
        
    try:
        choice = input("Choose module [0-{}]: ".format(len(modules))).strip()
        if not choice:
            print("[!] No input provided. Please try again.\n")
            return get_user_choice(modules)
            
        choice = int(choice)
        if choice == 0:
            return None
        elif 1 <= choice <= len(modules):
            return modules[choice-1]
        else:
            print(f"[!] Invalid choice. Please enter a number between 0 and {len(modules)}.\n")
            return get_user_choice(modules)
    except ValueError:
        print("[!] Invalid input. Please enter a number.\n")
        return get_user_choice(modules)
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user.")
        return None

def main():
    """Main menu loop"""
    # Ensure we're in the correct directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    try:
        while True:
            # Clear screen (works on both Windows and Unix-like systems)
            os.system('cls' if os.name == 'nt' else 'clear')
            display_header()
            display_status()
            
            modules = load_modules()
            display_modules(modules)
            
            if not modules:
                print("No modules found. Please add modules to the 'modules' directory.")
                choice = input("Press Enter to refresh or 'q' to quit: ").strip().lower()
                if choice == 'q':
                    print("\n[*] Exiting. Goodbye!")
                    break
                else:
                    continue  # Refresh modules
                
            chosen_module = get_user_choice(modules)
            
            if chosen_module is None:
                print("\n[*] Exiting. Goodbye!")
                break
                
            try:
                print(f"\n[*] Running module: {chosen_module.name}")
                print("=" * 50)
                # Pass the root status to the module if needed
                if hasattr(chosen_module, 'set_root_status'):
                    chosen_module.set_root_status(is_root())
                chosen_module.run()
            except Exception as e:
                print(f"\n[!] Error running module {chosen_module.name}: {e}")
                import traceback
                traceback.print_exc()  # For debugging
                
            print("\n" + "=" * 50)
            input("Press Enter to return to menu...")
    except KeyboardInterrupt:
        print("\n\n[*] Program interrupted by user. Exiting...")
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
