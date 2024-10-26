import os
from colorama import init, Fore, Style
import subprocess
import requests
from urllib.parse import urlparse

# Initialize colorama
init(autoreset=True)

def generate_report(data, report_name):
    """Generate a report and save it to a text file."""
    with open(report_name, "w") as report_file:
        report_file.write(data)
    print(f"Report generated: {report_name}")

def whois_lookup(domain):
    """Perform a WHOIS lookup on the specified domain."""
    print(f"Performing WHOIS lookup for {domain}...")
    result = subprocess.run(["whois", domain], capture_output=True, text=True)
    return result.stdout

def dns_recon(domain):
    """Perform DNS reconnaissance on the specified domain."""
    print(f"Performing DNS reconnaissance for {domain}...")
    result = subprocess.run(["dig", domain], capture_output=True, text=True)
    return result.stdout

def ssl_tls_check(domain):
    """Check SSL/TLS configuration for the specified domain."""
    print(f"Checking SSL/TLS configuration for {domain}...")
    result = subprocess.run(["openssl", "s_client", "-connect", f"{domain}:443"], capture_output=True, text=True)
    return result.stdout

def http_security_headers(domain):
    """Check HTTP security headers for the specified domain."""
    print(f"Checking HTTP security headers for {domain}...")
    response = requests.get(f"https://{domain}")
    headers = response.headers
    return headers

def subdomain_enumeration(domain):
    """Enumerate subdomains using a popular tool like sublist3r."""
    print(f"Enumerating subdomains for {domain}...")
    result = subprocess.run(["sublist3r", "-d", domain], capture_output=True, text=True)
    return result.stdout

def directory_enumeration(domain):
    """Perform directory enumeration using gobuster."""
    print(f"Performing directory enumeration for {domain}...")
    result = subprocess.run(["gobuster", "dir", "-u", f"https://{domain}", "-w", "/path/to/wordlist.txt"], capture_output=True, text=True)
    return result.stdout

def network_scanning(ip):
    """Scan the specified IP address using nmap."""
    print(f"Performing network scan on {ip}...")
    result = subprocess.run(["nmap", ip], capture_output=True, text=True)
    return result.stdout

def cms_detection(domain):
    """Detect the CMS and check for known vulnerabilities."""
    print(f"Detecting CMS for {domain}...")
    # Placeholder for CMS detection logic
    cms_info = "Detected CMS: WordPress\nPlugins: Sample Plugin (v1.0) - Vulnerable"
    return cms_info

def parameter_tampering(domain):
    """Identify potential injection points for parameter tampering."""
    print(f"Identifying parameter tampering points for {domain}...")
    # Placeholder for parameter tampering logic
    return "Potential injection points: /login?username=admin&password=admin"

def web_technology_fingerprinting(domain):
    """Fingerprint web technologies used by the domain."""
    print(f"Fingerprinting technologies for {domain}...")
    # Placeholder for web technology fingerprinting logic
    tech_info = "Detected Technologies: Apache, jQuery v3.6.0"
    return tech_info

def main():
    print(Fore.CYAN + Style.BRIGHT + r"""
              _                     __  __
 /\   /\_   _| |_ __   ___ _ __ __ _\ \/ /
 \ \ / / | | | | '_ \ / _ \ '__/ _` |\  / 
  \ V /| |_| | | | | |  __/ | | (_| |/  \ 
   \_/  \__,_|_|_| |_|\___|_|  \__,_/_/\_\                         
""" + Style.RESET_ALL)
    print(Fore.MAGENTA + "\t\t\t\t\t Created By Cb-Kali\n")
    print(Fore.YELLOW + "Welcome to the Advanced Web Scanning Tool \n" + Style.RESET_ALL)
    domain = input(Fore.GREEN + "Enter the target domain (e.g., example.com): " + Style.RESET_ALL)

    while True:
        print(Fore.BLUE + "\nSelect an option:" + Style.RESET_ALL)
        print(Fore.WHITE + "1. WHOIS Lookup")
        print(Fore.WHITE + "2. DNS Reconnaissance")
        print(Fore.WHITE + "3. SSL/TLS Security Check")
        print(Fore.WHITE + "4. HTTP Security Headers and Info Check")
        print(Fore.WHITE + "5. Subdomain Enumeration")
        print(Fore.WHITE + "6. Directory Enumeration")
        print(Fore.WHITE + "7. Network Scanning (nmap)")
        print(Fore.WHITE + "8. CMS Detection and Plugin Vulnerability Identification")
        print(Fore.WHITE + "9. Parameter Tampering and Injection Point Identification")
        print(Fore.WHITE + "10. Web Technology Fingerprinting and Version Detection")
        print(Fore.MAGENTA + "0. Exit" + Style.RESET_ALL)

        choice = input(Fore.GREEN + "\n Enter your choice: " + Style.RESET_ALL)

        if choice == '1':
            result = whois_lookup(domain)
            print(result)
            if input("Do you want to generate a report? (yes/no): ").lower() == 'yes':
                generate_report(result, "whois_report.txt")

        elif choice == '2':
            result = dns_recon(domain)
            print(result)
            if input("Do you want to generate a report? (yes/no): ").lower() == 'yes':
                generate_report(result, "dns_recon_report.txt")

        elif choice == '3':
            result = ssl_tls_check(domain)
            print(result)
            if input("Do you want to generate a report? (yes/no): ").lower() == 'yes':
                generate_report(result, "ssl_tls_report.txt")

        elif choice == '4':
            headers = http_security_headers(domain)
            print(headers)
            if input("Do you want to generate a report? (yes/no): ").lower() == 'yes':
                generate_report(str(headers), "http_security_headers_report.txt")

        elif choice == '5':
            result = subdomain_enumeration(domain)
            print(result)
            if input("Do you want to generate a report? (yes/no): ").lower() == 'yes':
                generate_report(result, "subdomain_report.txt")

        elif choice == '6':
            result = directory_enumeration(domain)
            print(result)
            if input("Do you want to generate a report? (yes/no): ").lower() == 'yes':
                generate_report(result, "directory_enum_report.txt")

        elif choice == '7':
            ip = input("Enter the IP address to scan: ")
            result = network_scanning(ip)
            print(result)
            if input("Do you want to generate a report? (yes/no): ").lower() == 'yes':
                generate_report(result, "network_scan_report.txt")

        elif choice == '8':
            result = cms_detection(domain)
            print(result)
            if input("Do you want to generate a report? (yes/no): ").lower() == 'yes':
                generate_report(result, "cms_detection_report.txt")

        elif choice == '9':
            result = parameter_tampering(domain)
            print(result)
            if input("Do you want to generate a report? (yes/no): ").lower() == 'yes':
                generate_report(result, "param_tampering_report.txt")

        elif choice == '10':
            result = web_technology_fingerprinting(domain)
            print(result)
            if input("Do you want to generate a report? (yes/no): ").lower() == 'yes':
                generate_report(result, "web_tech_fingerprinting_report.txt")

        elif choice == '0':
            print(Fore.LIGHTMAGENTA_EX + "Exiting the tool. Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()