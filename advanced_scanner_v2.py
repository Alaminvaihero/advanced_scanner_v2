import socket
import threading
import requests
import re

# Function to display the banner
def display_banner():
    banner = """
████████╗ ██████╗  ██████╗ ██╗     
╚══██╔══╝██╔═══██╗██╔═══██╗██║     
   ██║   ██║   ██║██║   ██║██║     
   ██║   ██║   ██║██║   ██║██║     
   ██║   ╚██████╔╝╚██████╔╝███████╗
   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
Advanced Web Scanner - Made by MDALAMIN
GitHub: https://www.github.com/Alaminvaihero
    """
    print(banner)

# Function to get the IP address of a domain
def get_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"\n[✔] IP Address of {domain}: {ip}")
        return ip
    except socket.gaierror:
        print(f"\n[✘] Error: Unable to resolve {domain}")
        return None

# Subdomain enumeration
def find_subdomains(domain):
    print(f"\n[🔍] Finding subdomains for: {domain}...")
    subdomains = ["www", "mail", "ftp", "admin", "dev", "test"]
    found_subdomains = []

    for sub in subdomains:
        subdomain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            found_subdomains.append(subdomain)
            print(f"    [✔] Found: {subdomain} -> {ip}")
        except socket.gaierror:
            pass

    if not found_subdomains:
        print("    [✘] No subdomains found.")

# Custom function to scan ports using threading
def scan_port(ip, port, open_ports):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
            print(f"    [✔] Port {port} is OPEN")
        s.close()
    except:
        pass

# Function to perform port scanning
def scan_ports(ip):
    print(f"\n[⚡] Scanning ports for {ip}...")
    open_ports = []
    threads = []
    
    for port in range(1, 1025):  
        t = threading.Thread(target=scan_port, args=(ip, port, open_ports))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    if open_ports:
        print(f"\n[✔] Open Ports: {open_ports}")
    else:
        print("\n[✘] No open ports found.")

# Function to check basic web vulnerabilities
def check_vulnerabilities(domain):
    print(f"\n[⚠] Checking vulnerabilities for: {domain}...")
    vulnerabilities = []
    headers = {}
    
    try:
        response = requests.get(f"http://{domain}", headers={'User-Agent': 'Mozilla/5.0'}, timeout=3)
        headers = response.headers
        
        sql_payloads = ["'", "' OR '1'='1", "' OR '1'='1' --", "1' ORDER BY 1--"]
        for payload in sql_payloads:
            test_url = f"http://{domain}/?id={payload}"
            test_response = requests.get(test_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=3)
            if "error" in test_response.text.lower():
                vulnerabilities.append("SQL Injection Detected")
                break

        xss_payloads = ['<script>alert(1)</script>', '"><script>alert(1)</script>']
        for payload in xss_payloads:
            test_url = f"http://{domain}/?q={payload}"
            test_response = requests.get(test_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=3)
            if "<script>" in test_response.text.lower():
                vulnerabilities.append("XSS Vulnerability Detected")
                break

        if response.status_code == 200 and re.search(r'Index of /', response.text):
            vulnerabilities.append("Open Directory Listing Enabled")

        if 'Server' in headers:
            server_header = headers['Server']
            print(f"    [ℹ] Server Header: {server_header}")
            if "apache" in server_header.lower():
                vulnerabilities.append("Apache Server Detected (Possible misconfigurations)")
            elif "nginx" in server_header.lower():
                vulnerabilities.append("Nginx Server Detected")

    except requests.RequestException:
        vulnerabilities.append(f"Error: Unable to connect to {domain}")
    
    if vulnerabilities:
        print("\n[✔] Vulnerabilities Found:")
        for vuln in vulnerabilities:
            print(f"    * {vuln}")
    else:
        print("\n[✘] No common vulnerabilities found.")

# Function to detect CMS
def detect_cms(domain):
    print(f"\n[🛠] Detecting CMS for: {domain}...")
    try:
        response = requests.get(f"http://{domain}", headers={'User-Agent': 'Mozilla/5.0'}, timeout=3)
        if "wp-content" in response.text or "wp-includes" in response.text:
            print("    [✔] WordPress Detected")
        elif "Joomla" in response.text:
            print("    [✔] Joomla Detected")
        elif "Drupal.settings" in response.text:
            print("    [✔] Drupal Detected")
        else:
            print("    [✘] No known CMS detected.")
    except requests.RequestException:
        print("    [✘] Unable to check CMS.")

# Directory brute-force
def directory_bruteforce(domain):
    print(f"\n[📂] Brute-forcing directories for: {domain}...")
    directories = ["admin", "login", "dashboard", "wp-admin", "panel"]
    found_dirs = []

    for directory in directories:
        url = f"http://{domain}/{directory}/"
        try:
            response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=3)
            if response.status_code == 200:
                found_dirs.append(url)
                print(f"    [✔] Found: {url}")
        except requests.RequestException:
            pass

    if not found_dirs:
        print("    [✘] No directories found.")

# Display tool info
def display_tool_info():
    print("\n[💻] Tool Information:")
    print("    Tool made by: MDALAMIN")
    print("    GitHub: https://www.github.com/Alaminvaihero")

# Main function
def main():
    display_banner()  # Show the banner first
    domain = input("\nEnter the domain to scan (e.g., example.com): ").strip()

    if not domain:
        print("Error: Domain is required.")
        return

    ip = get_ip(domain)
    if ip:
        find_subdomains(domain)
        scan_ports(ip)
        check_vulnerabilities(domain)
        detect_cms(domain)
        directory_bruteforce(domain)
        display_tool_info()

# Run the script
if __name__ == "__main__":
    main()
