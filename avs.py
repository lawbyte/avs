#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AVS (APK Vulnerability Scanner)
A comprehensive tool for analyzing Android APK files for vulnerabilities
"""

import os
import sys
import argparse
import pyfiglet
from colorama import init, Fore, Style
from rich.console import Console
from rich.progress import Progress
import json
import tempfile
import subprocess
import re
import traceback

from modules.scanner import Scanner
from modules.exploit import ExploitGenerator
from modules.mitigator import Mitigator

# Initialize colorama
init(autoreset=True)

console = Console()

def print_banner():
    """Print the AVS banner"""
    banner = pyfiglet.figlet_format("AVS", font="slant")
    console.print(f"{Fore.CYAN}{banner}{Style.RESET_ALL}")
    console.print(f"{Fore.GREEN}APK Vulnerability Scanner{Style.RESET_ALL}")
    console.print(f"{Fore.YELLOW}Version 1.0.0{Style.RESET_ALL}\n")

def extract_evidence_from_quark(vulnerability_data):
    """
    Extract detailed evidence from Quark vulnerability data based on CWE type
    
    Args:
        vulnerability_data (dict): The vulnerability data from the scan
        
    Returns:
        str: Formatted evidence string
    """
    evidence = ""
    
    # Get the vulnerability type and details
    vuln_type = vulnerability_data.get('type', '').lower()
    details = vulnerability_data.get('details', {})
    
    # Special handling for CWE-22 and CWE-23 which have method.fullName as evidence
    if 'cwe_22' in vuln_type or 'cwe-22' in vuln_type or 'cwe_23' in vuln_type or 'cwe-23' in vuln_type:
        if 'method_name' in vulnerability_data:
            return f"Vulnerable Method: {vulnerability_data['method_name']}"
        
        if isinstance(details, dict):
            if 'caller' in details:
                return f"Vulnerable Method: {details['caller']}"
            if 'fullName' in details:
                return f"Vulnerable Method: {details['fullName']}"
            if 'method_name' in details:
                return f"Vulnerable Method: {details['method_name']}"
    
    # Check for locations data
    if isinstance(details, dict) and 'locations' in details:
        locations = details['locations']
        evidence_parts = []
        
        for i, loc in enumerate(locations):
            if not isinstance(loc, dict):
                evidence_parts.append(str(loc))
                continue
                
            loc_evidence = []
            
            # Extract class and method information - this is the key evidence from CWE scripts
            if loc.get('class'):
                loc_evidence.append(f"Class: {loc['class']}")
            if loc.get('method'):
                loc_evidence.append(f"Method: {loc['method']}")
            if loc.get('class2'):
                loc_evidence.append(f"Related Class: {loc['class2']}")
            if loc.get('method2'):
                loc_evidence.append(f"Related Method: {loc['method2']}")
            if loc.get('fullName'):
                loc_evidence.append(f"Full Method: {loc['fullName']}")
                
            # Extract parameters which often contain critical info for vulnerabilities
            if loc.get('params') and isinstance(loc['params'], list):
                param_strs = []
                for j, param in enumerate(loc['params']):
                    param_value = str(param)
                    param_strs.append(f"  {j+1}. {param_value}")
                if param_strs:
                    loc_evidence.append("Parameters:")
                    loc_evidence.extend(param_strs)
            
            # Extract file and line information if available
            if loc.get('file'):
                loc_evidence.append(f"File: {loc['file']}")
            if loc.get('line'):
                loc_evidence.append(f"Line: {loc['line']}")
                
            # Add CWE identifier
            if loc.get('cwe'):
                loc_evidence.append(f"CWE: {loc['cwe']}")
            if loc.get('description'):
                loc_evidence.append(f"Description: {loc['description']}")
                
            # For specific CWE types, add specialized evidence extraction
            if 'cwe_22' in vuln_type or 'cwe-22' in vuln_type:
                loc_evidence.append("Vulnerability: Path Traversal")
                if 'fullName' in loc:
                    loc_evidence.append(f"Detected in method: {loc['fullName']}")
                    
            elif 'cwe_23' in vuln_type or 'cwe-23' in vuln_type:
                loc_evidence.append("Vulnerability: Relative Path Traversal")
                if 'fullName' in loc:
                    loc_evidence.append(f"Detected in method: {loc['fullName']}")
                    
            elif 'cwe_89' in vuln_type or 'cwe-89' in vuln_type:
                loc_evidence.append("Vulnerability: SQL Injection")
                if 'behaviorOccur' in loc:
                    loc_evidence.append(f"SQL command execution with unvalidated input detected")
                    
            elif 'cwe_798' in vuln_type or 'cwe-798' in vuln_type:
                loc_evidence.append("Vulnerability: Use of Hard-coded Credentials")
                if 'key' in loc:
                    loc_evidence.append(f"Hard-coded key: {loc['key']}")
                elif 'params' in loc and len(loc['params']) > 0:
                    loc_evidence.append(f"Hard-coded value: {loc['params'][0]}")
                    
            elif 'cwe_327' in vuln_type or 'cwe-327' in vuln_type:
                loc_evidence.append("Vulnerability: Use of a Broken or Risky Cryptographic Algorithm")
                if 'algorithm' in loc:
                    loc_evidence.append(f"Weak algorithm: {loc['algorithm']}")
                elif 'params' in loc and len(loc['params']) > 0:
                    for param in loc['params']:
                        if param in ["DES", "ARC4", "BLOWFISH", "RC4", "MD5", "SHA1"]:
                            loc_evidence.append(f"Weak algorithm: {param}")
                            
            elif 'cwe_502' in vuln_type or 'cwe-502' in vuln_type:
                loc_evidence.append("Vulnerability: Deserialization of Untrusted Data")
                if 'fullName' in loc:
                    loc_evidence.append(f"Detected in method: {loc['fullName']}")
                    
            if loc_evidence:
                evidence_parts.append("\n".join(loc_evidence))
                
        if evidence_parts:
            evidence = "\n\n".join(evidence_parts)
    
    # If no evidence found from locations, try to extract it from other fields
    if not evidence:
        # Try to extract directly from behaviorOccurList if available
        if 'behaviorOccurList' in vulnerability_data:
            behaviors = vulnerability_data['behaviorOccurList']
            behavior_evidence = []
            
            for behavior in behaviors:
                if isinstance(behavior, dict):
                    if 'methodCaller' in behavior:
                        caller = behavior['methodCaller']
                        if isinstance(caller, dict) and 'fullName' in caller:
                            behavior_evidence.append(f"Method Caller: {caller['fullName']}")
                        else:
                            behavior_evidence.append(f"Method Caller: {caller}")
                    if 'fullName' in behavior:
                        behavior_evidence.append(f"Method: {behavior['fullName']}")
                    if 'params' in behavior and isinstance(behavior['params'], list):
                        behavior_evidence.append("Parameters:")
                        for i, param in enumerate(behavior['params']):
                            behavior_evidence.append(f"  {i+1}. {param}")
                else:
                    behavior_evidence.append(str(behavior))
                    
            if behavior_evidence:
                evidence = "\n".join(behavior_evidence)
                
        # Try using direct evidence field
        elif 'evidence' in vulnerability_data:
            evidence = str(vulnerability_data['evidence'])
            
        # Try using the findings field
        elif 'findings' in vulnerability_data:
            findings = vulnerability_data['findings']
            if isinstance(findings, list):
                findings_evidence = []
                
                for i, finding in enumerate(findings):
                    if isinstance(finding, dict):
                        finding_part = []
                        for key, value in finding.items():
                            finding_part.append(f"{key}: {value}")
                        findings_evidence.append("\n".join(finding_part))
                    else:
                        findings_evidence.append(str(finding))
                        
                if findings_evidence:
                    evidence = "\n\n".join(findings_evidence)
            else:
                evidence = str(findings)
        
        # For CWE-22 and CWE-23, ensure we have at least some basic evidence
        if ('cwe_22' in vuln_type or 'cwe-22' in vuln_type or 'cwe_23' in vuln_type or 'cwe-23' in vuln_type) and not evidence:
            if 'name' in vulnerability_data:
                evidence = f"Vulnerability Type: {vulnerability_data['name']}\n"
                evidence += "Evidence: Path traversal vulnerability detected in the application."
                
            # For CWE-22 specifically
            if 'cwe_22' in vuln_type or 'cwe-22' in vuln_type:
                evidence += "\nFile access without proper path validation can lead to accessing files outside of the intended directory."
                
            # For CWE-23 specifically
            if 'cwe_23' in vuln_type or 'cwe-23' in vuln_type:
                evidence += "\nRelative path traversal can allow attackers to navigate to parent directories using '../' sequences."
    
    return evidence

def run_quark_cwe_detection(apk_path, cwe_dir, cwe_script_path):
    """
    Run a specific CWE detection script from quark-script and extract evidence directly
    
    Args:
        apk_path (str): Path to the APK file to analyze
        cwe_dir (str): Directory name (e.g., 'CWE-22')
        cwe_script_path (str): Path to the CWE Python script
        
    Returns:
        tuple: (detected (bool), evidence (str), methods_detected (list))
    """
    import subprocess
    
    # Get just the CWE number
    cwe_id = cwe_dir
    
    methods_detected = []
    detected = False
    
    try:
        # Execute the script directly with the APK path as a parameter
        process = subprocess.Popen(
            ['python3', cwe_script_path, '-f', apk_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=os.path.dirname(cwe_script_path)
        )
        stdout, stderr = process.communicate()
        
        # Check if any vulnerabilities were detected in the output
        for line in stdout.split('\n'):
            # Different CWE scripts have different output formats
            if f"{cwe_id} is detected" in line:
                detected = True
                
                # Extract method name from output (format: "CWE-XX is detected in method, <method_name>")
                method_match = re.search(r'detected in method,\s*(.+)', line)
                if method_match:
                    method_name = method_match.group(1).strip()
                    methods_detected.append(method_name)
            
            # Also check for other patterns like "Found hard-coded" for CWE-798
            elif "Found hard-coded" in line:
                detected = True
                methods_detected.append(line.strip())
                
        # If we encountered errors but no detections, check stderr
        if stderr and not detected:
            print(f"Warning: {cwe_script_path} had errors: {stderr}")
            
    except Exception as e:
        print(f"Error running {cwe_script_path}: {str(e)}")
        return False, f"Error: {str(e)}", []
    
    # Create evidence from detected methods
    evidence = ""
    for i, method in enumerate(methods_detected):
        evidence += f"{i+1}. Detected in: {method}\n"
    
    # If no methods were found but output suggests detection
    if detected and not methods_detected:
        evidence = f"{cwe_id} vulnerability detected (no specific methods identified)"
        
    return detected, evidence, methods_detected

def main():
    """Main function to handle command line arguments and drive the program"""
    parser = argparse.ArgumentParser(description="APK Vulnerability Scanner")
    
    # Main commands
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan an APK for vulnerabilities')
    scan_parser.add_argument('-f', '--file', help='APK file path', required=True)
    scan_parser.add_argument('-a', '--json', help='Output JSON file path (optional)')
    scan_parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    # Exploit command
    exploit_parser = subparsers.add_parser("exploit", help="Generate exploit APK")
    exploit_parser.add_argument("-f", "--file", required=True, help="Path to original APK file")
    exploit_parser.add_argument("-v", "--vulnerability", required=True, help="Vulnerability type to exploit")
    exploit_parser.add_argument("-o", "--output", help="Output path for exploit APK")
    
    # Mitigate command
    mitigate_parser = subparsers.add_parser("mitigate", help="Get mitigation strategies")
    mitigate_parser.add_argument("-f", "--file", help="Path to scan results file (JSON format)")
    mitigate_parser.add_argument("-v", "--vulnerability", help="Get mitigation for specific vulnerability")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Display banner
    print_banner()
    
    # No command specified
    if not args.command:
        parser.print_help()
        return
    
    try:
        # Handle scan command
        if args.command == "scan":
            if not os.path.exists(args.file):
                console.print(f"[bold red]Error:[/bold red] APK file not found: {args.file}")
                return
            
            scanner = Scanner(args.file, verbose=args.verbose)
            results = scanner.scan()
            
            # Check for output file
            if args.json:
                output_path = args.json
            else:
                # Generate a default output path based on APK name
                base_name = os.path.basename(args.file)
                name_without_ext = os.path.splitext(base_name)[0]
                output_path = f"{name_without_ext}.json"
            
            # Save scan results as JSON
            scanner.save_results(results, output_path)
            console.print(f"[bold green]Results saved to:[/bold green] {output_path}")
            
            # Generate HTML report
            html_report_path = f"{name_without_ext}.html"
            reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
            os.makedirs(reports_dir, exist_ok=True)
            
            # Use the package name for the report if available
            if "apk_info" in results and "package_name" in results["apk_info"]:
                package_name = results["apk_info"]["package_name"]
                html_report_path = os.path.join(reports_dir, f"{package_name}_report.html")
            else:
                html_report_path = os.path.join(reports_dir, html_report_path)
            
            # Load the detailed results from the saved JSON file
            try:
                with open(output_path, 'r') as json_file:
                    detailed_results = json.load(json_file)
                    
                # Extract APK info and vulnerabilities from the detailed JSON results
                apk_info = detailed_results.get("apk_info", results.get("apk_info", {}))
                vulnerabilities = detailed_results.get("vulnerabilities", [])
                
                if not vulnerabilities:
                    # If no vulnerabilities found in that field, check findings
                    vulnerabilities = detailed_results.get("findings", [])
                    
                # Check scan_info for additional details
                if "scan_info" in detailed_results:
                    scan_info = detailed_results["scan_info"]
                    console.print(f"[cyan]Scan timestamp:[/cyan] {scan_info.get('timestamp', 'N/A')}")
            except Exception as e:
                console.print(f"[bold red]Error loading JSON results:[/bold red] {str(e)}")
                if args.verbose:
                    import traceback
                    console.print(traceback.format_exc())
            
            # Try to normalize the vulnerability data structure
            normalized_vulns = []
            for vuln in vulnerabilities:
                if isinstance(vuln, dict):
                    # Handle different possible formats and normalize them
                    title = vuln.get('title', '')
                    vuln_type = vuln.get('type', '')
                    name = vuln.get('name', '')
                    details = vuln.get('details', {})
                    
                    if isinstance(details, dict):
                        # Extract from details if available
                        if not title and 'name' in details:
                            title = details['name']
                        if 'description' in details:
                            description = details['description']
                        else:
                            description = vuln.get('description', 'No description available')
                        
                        if 'severity' in details:
                            severity = details['severity']
                        else:
                            severity = vuln.get('severity', vuln.get('risk', 'Medium'))
                            
                        # Get category/CWE
                        category = vuln.get('category', '')
                        if not category and 'cwe' in details:
                            category = details['cwe']
                        elif not category and vuln_type.startswith('cwe_'):
                            category = 'CWE-' + vuln_type[4:].upper()
                        elif not category:
                            category = vuln_type.replace('_', ' ').title()
                            
                        # Extract evidence from locations if available
                        evidence = extract_evidence_from_quark(vuln)
                    else:
                        # Fallbacks if details is not a dict
                        description = vuln.get('description', 'No description available')
                        severity = vuln.get('severity', vuln.get('risk', 'Medium'))
                        category = vuln.get('category', vuln.get('cwe', vuln_type.replace('_', ' ').title()))
                        evidence = ""
                     
                    # If no title found yet, use type or generic name
                    if not title:
                        title = vuln_type.replace('_', ' ').title() if vuln_type else name or 'Unknown Vulnerability'
                    
                    # Add the normalized vulnerability to our list
                    normalized_vulns.append({
                        'title': title,
                        'severity': severity,
                        'category': category,
                        'description': description,
                        'evidence': evidence
                    })
                else:
                    # If it's not a dict, create a simple structure
                    normalized_vulns.append({
                        'title': str(vuln),
                        'severity': 'Medium',
                        'category': 'Vulnerability',
                        'description': 'No details available',
                        'evidence': ''
                    })
            
            # If no vulnerabilities were found, check the quark-script folder for rules
            if not normalized_vulns and os.path.exists('quark-script'):
                console.print("[bold yellow]No vulnerabilities found in initial scan. Checking quark-script rules...[/bold yellow]")
                
                # Add quark-script directory to path so imports work
                sys.path.append(os.path.abspath('quark-script'))
                
                # Initialize an object to store CWE detection results
                quark_results = {}
                
                # CWE names and descriptions
                cwe_titles = {
                    "CWE-22": "Path Traversal",
                    "CWE-23": "Relative Path Traversal",
                    "CWE-78": "OS Command Injection",
                    "CWE-89": "SQL Injection",
                    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
                    "CWE-502": "Deserialization of Untrusted Data",
                    "CWE-798": "Use of Hard-coded Credentials"
                }
                
                cwe_descriptions = {
                    "CWE-22": "The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.",
                    "CWE-23": "The software uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize sequences such as \"..\" that can resolve to a location that is outside of that directory.",
                    "CWE-78": "The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.",
                    "CWE-89": "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.",
                    "CWE-327": "The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information.",
                    "CWE-502": "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
                    "CWE-798": "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data."
                }
                
                # Run Python scripts in each subdirectory of quark-script
                for cwe_dir in os.listdir('quark-script'):
                    cwe_path = os.path.join('quark-script', cwe_dir)
                    
                    # Skip if not a directory or doesn't match CWE pattern
                    if not os.path.isdir(cwe_path) or not cwe_dir.startswith('CWE-'):
                        continue
                    
                    console.print(f"[bold cyan]Checking {cwe_dir} rules...[/bold cyan]")
                    
                    # Get the CWE number
                    cwe_id = cwe_dir
                    
                    # Find and run the python script with the same name as the directory
                    cwe_script = os.path.join(cwe_path, f"{cwe_dir}.py")
                    if os.path.exists(cwe_script):
                        try:
                            # Directly run the CWE detection script
                            vulnerability_detected, evidence, methods_detected = run_quark_cwe_detection(
                                args.file, cwe_id, cwe_script
                            )
                            
                            if vulnerability_detected:
                                # Get CWE title
                                cwe_title = cwe_titles.get(cwe_id, f"{cwe_id.replace('-', ' ').title()} Vulnerability")
                                
                                # Get CWE description
                                description = cwe_descriptions.get(cwe_id, "No detailed description available.")
                                
                                # Add to normalized vulnerabilities
                                normalized_vulns.append({
                                    'title': cwe_title,
                                    'type': cwe_id.lower().replace('-', '_'),
                                    'severity': 'High',  # Most CWE findings are high severity
                                    'category': cwe_id,
                                    'description': description,
                                    'evidence': evidence
                                })
                                
                                console.print(f"[bold red]✓ {cwe_id} vulnerability detected![/bold red]")
                                
                                # If verbose mode, print the detected methods
                                if args.verbose and methods_detected:
                                    console.print("[yellow]Detected in methods:[/yellow]")
                                    for method in methods_detected:
                                        console.print(f"  - {method}")
                            else:
                                console.print(f"[green]✓ No {cwe_id} vulnerabilities found.[/green]")
                                
                        except Exception as e:
                            console.print(f"[bold red]Error running {cwe_script}: {str(e)}[/bold red]")
                            if args.verbose:
                                traceback.print_exc()
            
            # Make sure apk_info has the required fields
            if not apk_info:
                apk_info = {
                    "package_name": "Unknown Package",
                    "version": "Unknown",
                    "min_sdk": "Unknown",
                    "target_sdk": "Unknown",
                    "activities": [],
                    "services": [],
                    "receivers": [],
                    "providers": [],
                    "permissions": []
                }
            
            # Make sure app_name is set
            if "app_name" not in apk_info and "package_name" in apk_info:
                apk_info["app_name"] = apk_info["package_name"]
            
            # Generate the HTML report
            scanner.generate_html_report(apk_info, normalized_vulns, html_report_path)
            console.print(f"[bold green]HTML report generated:[/bold green] {html_report_path}")
            console.print("To view the report, open it in a web browser.")
        
        # Handle exploit command
        elif args.command == "exploit":
            if not os.path.exists(args.file):
                console.print(f"[bold red]Error:[/bold red] APK file not found: {args.file}")
                return
            
            exploit_gen = ExploitGenerator(args.file)
            exploit_gen.generate_exploit(args.vulnerability, output_path=args.output)
        
        # Handle mitigate command
        elif args.command == "mitigate":
            mitigator = Mitigator()
            
            if args.file:
                if not os.path.exists(args.file):
                    console.print(f"[bold red]Error:[/bold red] Results file not found: {args.file}")
                    return
                mitigator.load_from_file(args.file)
                
            if args.vulnerability:
                mitigator.show_mitigation(args.vulnerability)
            else:
                mitigator.show_all_mitigations()
    
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        if args.verbose:
            import traceback
            console.print(traceback.format_exc())

if __name__ == "__main__":
    main()
