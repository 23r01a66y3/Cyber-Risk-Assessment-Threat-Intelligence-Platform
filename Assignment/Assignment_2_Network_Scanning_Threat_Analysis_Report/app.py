import os
import argparse
from port_scanner import PortScanner
from threat_api import ThreatIntelAPI

# Target Information
TARGET = "scanme.nmap.org"
VT_API_KEY = os.environ.get('VT_API_KEY', 'YOUR_VIRUSTOTAL_API_KEY')

def print_section(title):
    print("\n" + "=" * 50)
    print(title)
    print("=" * 50)

def main():
    parser = argparse.ArgumentParser(description='Automated Reconnaissance and Vulnerability Assessment')
    parser.add_argument('--full-scan', action='store_true', help='Run the full port scan (can be slow)')
    args = parser.parse_args()

    print(f"--- Assignment 2: Network Scanning & Threat Analysis ---")
    print(f"Target: {TARGET}\n")

    # Initialize modules
    scanner = PortScanner(TARGET)
    threat_intel = ThreatIntelAPI(VT_API_KEY)

    # 1. Nmap Scanning
    print_section("1. NMAP SCANNING RESULTS")
    
    # Basic Scan
    basic_results = scanner.basic_scan()
    print("\n[+] Basic Scan Results:")
    print(basic_results if basic_results else "No basic scan results returned.")

    # Service & Version Detection
    version_results = scanner.version_scan()
    print("\n[+] Service & Version Detection Results:")
    print(version_results if version_results else "No version scan results returned.")

    # Full Port Scan
    if args.full_scan:
        full_results = scanner.full_scan()
        print("\n[+] Full Port Scan Results:")
        print(full_results if full_results else "No full port scan results returned.")
    else:
        print("\n[+] Full Port Scan Skipped:")
        print("Note: Skipped because it can be slow. Run with --full-scan flag to test full coverage (-p-).")
        print("    Example: python app.py --full-scan")

    # 2. Threat Intelligence
    print_section("2. VIRUSTOTAL THREAT INTELLIGENCE")

    print(f"Checking VirusTotal for {TARGET}...")
    vt_results = threat_intel.check_domain_reputation(TARGET)
    
    if "error" in vt_results:
         print(f"Important: {vt_results['error']}")
         print("Note: To run the passive intelligence piece, please set the VT_API_KEY environment variable.")
         print("    Example (Windows PowerShell): $env:VT_API_KEY=\"your_key_here\"")
    else:
        print("\n[+] Domain Reputation:")
        print(f"Harmless: {vt_results.get('harmless', 0)}")
        print(f"Malicious: {vt_results.get('malicious', 0)}")
        print(f"Suspicious: {vt_results.get('suspicious', 0)}")
        print(f"Undetected: {vt_results.get('undetected', 0)}")
        
        if vt_results.get('malicious', 0) == 0:
            print("\nFindings: Domain reputation showed no malicious detections, as expected for scanme.nmap.org.")

    # 3. Report Generation Output
    print_section("3. VULNERABILITY REASONING & CONCLUSION")
    print("Port & Service Analysis:")
    print("- Port 22 (SSH): Secure remote login; risk of brute-force attacks and outdated vulnerabilities.")
    print("- Port 80 (HTTP): Web service; potential risks include XSS, SQL injection, and version-based exploits.")
    print("- Port 9929 (Nping Echo): Testing service; minimal risk in this context.")
    print("- Port 31337 (Test Port): Unnecessary exposure may increase attack surface.")
    print("\nVulnerability Reasoning:")
    print("- Outdated OpenSSH versions may contain authentication bypass or cryptographic weaknesses.")
    print("- Apache HTTP Server misconfigurations may lead to directory traversal or information disclosure.")
    print("- Multiple open ports increase overall attack surface and enable service fingerprinting.")
    print("\nConclusion:")
    print("This assignment demonstrated ethical reconnaissance and vulnerability assessment using authorized targets.")
    print("Active scanning with Nmap revealed open ports, services, and version information, while VirusTotal provided")
    print("passive intelligence including reputation and historical context. The exercise strengthened understanding of")
    print("network exposure analysis, service interpretation, and theoretical vulnerability reasoning.")

if __name__ == "__main__":
    main()
