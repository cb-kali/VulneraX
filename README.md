# Overview
**VulneraX** is an advanced, versatile web scanning and reconnaissance tool designed for cybersecurity professionals and ethical hackers to automate comprehensive analysis and assessment of web-based assets. The primary goal of VulneraX is to gather critical information about a target domain and identify potential vulnerabilities. By integrating various scanning and reconnaissance features, this tool enables users to assess the security posture of a web asset, raising awareness about possible risks and providing a foundation for vulnerability management.

## Purpose
VulneraX was developed to streamline the reconnaissance phase of web security assessments. With automated modules for different reconnaissance and scanning tasks, VulneraX helps detect weak points in a web application’s infrastructure, allowing security analysts to uncover misconfigurations, security flaws, and other vulnerabilities that could be exploited by malicious actors. 

## Key Features and Their Purpose

1. **WHOIS Lookup**  
   - **Purpose**: Retrieves domain ownership information, registration dates, and contact details, offering insights into the domain's history and possible weaknesses in domain privacy.
   
2. **DNS Reconnaissance**  
   - **Purpose**: Collects DNS records to map subdomains and understand the DNS infrastructure, which helps identify potential entry points or exposed services.

3. **SSL/TLS Security Check**  
   - **Purpose**: Assesses SSL/TLS certificate validity and configuration, ensuring encrypted communication is secure and that certificates adhere to industry standards.

4. **HTTP Security Headers and Info Check**  
   - **Purpose**: Analyzes HTTP headers for security-related configurations, such as HSTS and CSP, which help mitigate vulnerabilities like XSS, clickjacking, and other web attacks.

5. **Subdomain Enumeration**  
   - **Purpose**: Enumerates subdomains associated with the main domain, revealing potentially overlooked or insecure subdomains within the target’s ecosystem.

6. **Directory Enumeration**  
   - **Purpose**: Searches for hidden directories and files on the server to uncover sensitive data or unprotected endpoints, often a first step in finding misconfigurations.

7. **Network Scanning (Nmap)**  
   - **Purpose**: Identifies open ports and active services on the target’s IP address, providing insight into services that might be exploitable.

8. **CMS Detection and Plugin Vulnerability Identification**  
   - **Purpose**: Detects the CMS used (e.g., WordPress, Joomla) and searches for known vulnerabilities in plugins or themes, pinpointing software that may need updates or patches.

9. **Parameter Tampering and Injection Point Identification**  
   - **Purpose**: Identifies input fields or URL parameters that could be vulnerable to tampering or injection attacks, helping users locate areas for SQL injection, XSS, and other exploits.

10. **Web Technology Fingerprinting and Version Detection**  
    - **Purpose**: Identifies backend technologies, server software, and their versions, allowing users to search for any known vulnerabilities specific to these technologies.

## Pre-Configuration for VulneraX
Before using VulneraX, you need to configure your environment and install required dependencies. VulneraX requires Python 3.x and some essential libraries to operate effectively.

**Step 1: Install Python**
Ensure Python 3.x is installed on your system. You can download it from the [Python official site](https://python.org).

**Step 2: Install Dependencies**
Clone or download the VulneraX repository.

Inside the repository folder, install dependencies using the following command:
> pip install -r requirements.txt

**Additional Tools:**
> pip install sublist3r # Linux

> pip install gobuster # Linux 


## How to Use VulneraX

**Launching the Tool**
1. Open a terminal and navigate to the directory where VulneraX is saved.
2. Run the scripts:
   > python vulnerax.py

This launches VulneraX and presents a welcome screen.

### Using VulneraX

1. **Input Domain**: Start by entering the target domain (e.g., example.com).
2. **Selecting Options**: A menu will display different options, each representing a module in the tool. Enter the corresponding number to perform the desired action:

```
Option 1: WHOIS Lookup – retrieves domain ownership details.
Option 2: DNS Reconnaissance – collects DNS records.
Option 3: SSL/TLS Security Check – assesses SSL/TLS configuration.
Option 4: HTTP Security Headers – checks HTTP headers for security configurations.
Option 5: Subdomain Enumeration – finds subdomains.
Option 6: Directory Enumeration – searches for hidden directories.
Option 7: Network Scanning (Nmap) – performs port and service scans.
Option 8: CMS Detection and Plugin Vulnerability – checks for CMS and plugin vulnerabilities.
Option 9: Parameter Tampering and Injection Points – identifies parameters susceptible to injection attacks.
Option 10: Web Technology Fingerprinting – detects backend technologies and versions.
```
3. **Report Generation**: After each scan, VulneraX will prompt you to create a report for that module. Enter yes to generate a text report or no to skip.
4. **Exiting the Tool**: Enter 0 when you are ready to exit.


_Using VulneraX, you can easily perform comprehensive reconnaissance and analysis of a target web application, enhancing your web security testing capabilities with this powerful, automated tool._

## Conclusion
VulneraX is designed to cover essential aspects of web application security testing, focusing on gathering detailed information and spotting common security flaws. Each feature provides critical insights into the security of web applications and underlying infrastructure, making VulneraX an effective tool for anyone involved in web security assessments or penetration testing. 

By utilizing VulneraX, cybersecurity professionals can streamline their reconnaissance processes, gather actionable information quickly, and ultimately strengthen the security of their web applications and digital assets.
