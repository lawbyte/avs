#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Scanner module for AVS
Handles the vulnerability scanning functionality using Quark Engine
"""

import os
import re
import json
import magic
import html
import tempfile
import traceback
import datetime
from datetime import datetime as dt
from rich.console import Console
from rich.table import Table
from quark.core.quark import Quark
from androguard.core.bytecodes.apk import APK
import subprocess

# Try to import apkid, but make it optional
try:
    import apkid
    APKID_AVAILABLE = True
except (ImportError, AttributeError):
    APKID_AVAILABLE = False

console = Console()

class Scanner:
    """Class to handle APK vulnerability scanning"""
    
    def __init__(self, apk_path, verbose=False):
        """Initialize Scanner with APK path"""
        self.apk_path = apk_path
        self.verbose = verbose
        self.vulnerabilities = {
            "intent_redirection": {
                "name": "Intent Redirection",
                "description": "The application uses Intents in an insecure way allowing for redirection attacks",
                "severity": "High"
            },
            "insecure_file_permissions": {
                "name": "Insecure File Permissions",
                "description": "Files are created with insecure permissions, allowing unauthorized access",
                "severity": "Medium"
            },
            "sql_injection": {
                "name": "SQL Injection",
                "description": "The application uses raw SQL queries that could be vulnerable to injection",
                "severity": "Critical"
            },
            "webview_javascript": {
                "name": "WebView JavaScript Enabled",
                "description": "JavaScript is enabled in WebViews without proper input validation",
                "severity": "Medium"
            },
            "weak_crypto": {
                "name": "Weak Cryptography",
                "description": "The application uses weak cryptographic algorithms",
                "severity": "High"
            },
            "hardcoded_secrets": {
                "name": "Hardcoded Secrets",
                "description": "The application contains hardcoded credentials or API keys",
                "severity": "Critical"
            },
            "data_leakage": {
                "name": "Data Leakage",
                "description": "Sensitive data is logged or stored insecurely",
                "severity": "High"
            },
            "broadcast_theft": {
                "name": "Broadcast Theft",
                "description": "Sensitive information sent via broadcasts can be intercepted",
                "severity": "Medium"
            },
            "exported_components": {
                "name": "Unprotected Exported Components",
                "description": "Components are exported without proper protection",
                "severity": "High"
            },
            "path_traversal": {
                "name": "Path Traversal",
                "description": "The application is vulnerable to path traversal attacks",
                "severity": "Critical"
            }
        }
    
    def _validate_apk(self):
        """Validate that the file is a valid APK"""
        try:
            mime = magic.Magic(mime=True)
            file_type = mime.from_file(self.apk_path)
            
            if "application/zip" not in file_type and "application/java-archive" not in file_type and "application/vnd.android.package-archive" not in file_type:
                raise ValueError(f"Not a valid APK file: {file_type}")
                
            # Try to parse with androguard
            apk = APK(self.apk_path)
            return apk
        except Exception as e:
            raise ValueError(f"Failed to validate APK: {str(e)}")
    
    def _get_apk_info(self, apk):
        """Get basic information about the APK"""
        info = {
            "package_name": apk.get_package(),
            "version_name": apk.get_androidversion_name(),
            "version_code": apk.get_androidversion_code(),
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version(),
            "permissions": apk.get_permissions(),
            "activities": [a for a in apk.get_activities()],
            "services": [s for s in apk.get_services()],
            "receivers": [r for r in apk.get_receivers()],
            "providers": [p for p in apk.get_providers()]
        }
        return info
    
    def _identify_apk(self):
        """Identify APK using apkid (optional)"""
        try:
            import subprocess
            import json
            
            # Run APKiD using subprocess instead of the Python API
            cmd = ["apkid", "--json", self.apk_path]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = process.communicate()
            
            if process.returncode != 0:
                if self.verbose:
                    console.print(f"[yellow]Warning: APKiD analysis failed - {error.decode('utf-8')}[/yellow]")
                else:
                    console.print("[yellow]Warning: APKiD analysis skipped (use -v for details)[/yellow]")
                return {}
                
            # Parse JSON output
            try:
                results = json.loads(output.decode('utf-8'))
                if "files" in results and results["files"]:
                    return results["files"][0].get("results", {})
            except json.JSONDecodeError:
                if self.verbose:
                    console.print(f"[yellow]Warning: Could not parse APKiD JSON output[/yellow]")
                
            return {}
        except Exception as e:
            if self.verbose:
                console.print(f"[yellow]Warning: APKiD analysis skipped - {str(e)}[/yellow]")
            else:
                console.print("[yellow]Warning: APKiD analysis skipped (use -v for details)[/yellow]")
            return {}
    
    def _scan_with_quark(self, apk_path):
        """Scan the APK with Quark Engine using the quark-script repository"""
        try:
            console.print("[bold blue]Running Quark Engine analysis...[/bold blue]")
            
            # Get the path to the quark-script directory
            quark_script_dir = "/mnt/c/pentest/research/andro/quark-script"
            results = {}
            
            # Import required modules from quark-script
            import sys
            sys.path.append(quark_script_dir)
            
            # Using the Rule and analysis classes from quark-script
            from quark.script import Rule, _getQuark, QuarkResult
            
            # Find all CWE directories in the quark-script directory
            cwe_dirs = []
            for entry in os.listdir(quark_script_dir):
                if entry.startswith("CWE-") and os.path.isdir(os.path.join(quark_script_dir, entry)):
                    cwe_dirs.append(entry)
            
            console.print(f"[blue]Found {len(cwe_dirs)} CWE vulnerability types to scan[/blue]")
            
            # Find all rule files in each CWE directory
            rule_files = []
            for cwe_dir in cwe_dirs:
                cwe_path = os.path.join(quark_script_dir, cwe_dir)
                for file in os.listdir(cwe_path):
                    if file.endswith('.json'):
                        rule_files.append({
                            "cwe": cwe_dir,  # Store the CWE category
                            "path": os.path.join(cwe_path, file)
                        })
            
            console.print(f"[blue]Found {len(rule_files)} vulnerability rules to apply[/blue]")
            
            # Run analysis with each rule file
            for rule_info in rule_files:
                cwe = rule_info["cwe"]
                rule_file = rule_info["path"]
                
                try:
                    rule_name = os.path.basename(rule_file).replace('.json', '')
                    console.print(f"[blue]Applying rule: {cwe}/{rule_name}[/blue]")
                    
                    # Load the rule
                    rule = Rule(rule_file)
                    
                    # Get Quark instance
                    quark = _getQuark(apk_path)
                    
                    # Run analysis
                    quark_result = QuarkResult(quark, rule)
                    
                    # Extract behavior occurrences
                    behavior_list = quark_result.behaviorOccurList
                    
                    if behavior_list:
                        # If we found any behaviors, add them to the results
                        category = f"{cwe}: {rule_name}"
                        if category not in results:
                            results[category] = []
                        
                        for behavior in behavior_list:
                            param_values = []
                            try:
                                param_values = behavior.getParamValues()
                            except:
                                pass
                            
                            # Add behavior details to results
                            results[category].append({
                                "class1": behavior.invokeClassNode.fullName if hasattr(behavior, 'invokeClassNode') else "",
                                "method1": behavior.invokeMethodNode.name if hasattr(behavior, 'invokeMethodNode') else "",
                                "class2": behavior.sendtoClassNode.fullName if hasattr(behavior, 'sendtoClassNode') else "",
                                "method2": behavior.sendtoMethodNode.name if hasattr(behavior, 'sendtoMethodNode') else "",
                                "params": param_values,
                                "cwe": cwe
                            })
                            
                except Exception as e:
                    console.print(f"[yellow]Warning: Error applying rule {cwe}/{rule_name}: {str(e)}[/yellow]")
            
            # Map CWE numbers to descriptions
            cwe_descriptions = {
                "CWE-117": "Improper Output Neutralization for Logs",
                "CWE-20": "Improper Input Validation",
                "CWE-22": "Path Traversal",
                "CWE-23": "Relative Path Traversal",
                "CWE-295": "Certificate Validation",
                "CWE-312": "Cleartext Storage of Sensitive Information",
                "CWE-319": "Cleartext Transmission of Sensitive Information",
                "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
                "CWE-328": "Weak Hash",
                "CWE-338": "Use of Cryptographically Weak PRNG",
                "CWE-489": "Leftover Debug Code",
                "CWE-502": "Deserialization of Untrusted Data",
                "CWE-532": "Information Exposure Through Log Files",
                "CWE-601": "URL Redirection to Untrusted Site",
                "CWE-73": "External Control of File Name",
                "CWE-749": "Exposed Dangerous Method",
                "CWE-78": "OS Command Injection",
                "CWE-780": "Use of RSA Algorithm without OAEP",
                "CWE-79": "Cross-site Scripting",
                "CWE-798": "Use of Hard-coded Credentials",
                "CWE-88": "Argument Injection",
                "CWE-89": "SQL Injection",
                "CWE-921": "Storage of Sensitive Data in a Mechanism Without Access Control",
                "CWE-925": "Improper Verification of Intent",
                "CWE-926": "Improper Export of Android Application Components",
                "CWE-94": "Code Injection",
                "CWE-940": "Improper Verification of Source of a Communication Channel"
            }
            
            # Augment results with descriptions
            for category, details in results.items():
                cwe = category.split(':')[0].strip()
                if cwe in cwe_descriptions:
                    for detail in details:
                        detail["description"] = cwe_descriptions[cwe]
            
            console.print(f"[green]Completed analysis with vulnerabilities found in {len(results)} categories[/green]")
            return results
            
        except Exception as e:
            console.print(f"[bold red]Quark Engine error: {str(e)}[/bold red]")
            return None
    
    def _analyze_results(self, quark_results, apk):
        """Analyze results from Quark and other scans to identify vulnerabilities"""
        findings = []
        
        # Scan for exported components
        exported_components = []
        for activity in apk.get_activities():
            try:
                activity_xml = apk.get_element('activity', activity)
                exported = activity_xml.get('{http://schemas.android.com/apk/res/android}exported')
                if exported == 'true':
                    exported_components.append({"type": "activity", "name": activity})
            except:
                # If we can't determine if exported, assume it's not
                pass
        
        for service in apk.get_services():
            try:
                service_xml = apk.get_element('service', service)
                exported = service_xml.get('{http://schemas.android.com/apk/res/android}exported')
                if exported == 'true':
                    exported_components.append({"type": "service", "name": service})
            except:
                pass
                
        for receiver in apk.get_receivers():
            try:
                receiver_xml = apk.get_element('receiver', receiver)
                exported = receiver_xml.get('{http://schemas.android.com/apk/res/android}exported')
                if exported == 'true':
                    exported_components.append({"type": "receiver", "name": receiver})
            except:
                pass
                
        for provider in apk.get_providers():
            try:
                provider_xml = apk.get_element('provider', provider)
                exported = provider_xml.get('{http://schemas.android.com/apk/res/android}exported')
                if exported == 'true':
                    exported_components.append({"type": "provider", "name": provider})
            except:
                pass
        
        if exported_components:
            findings.append({
                "type": "exported_components",
                "details": {
                    "name": self.vulnerabilities["exported_components"]["name"],
                    "description": self.vulnerabilities["exported_components"]["description"],
                    "severity": self.vulnerabilities["exported_components"]["severity"],
                    "components": exported_components
                }
            })
        
        # Process Quark results if available
        if quark_results:
            # Map CWE categories to our vulnerability types
            cwe_to_vuln_type = {
                "CWE-89": "sql_injection",
                "CWE-79": "xss",
                "CWE-78": "command_injection", 
                "CWE-94": "code_injection",
                "CWE-798": "hardcoded_secrets",
                "CWE-295": "insecure_ssl",
                "CWE-319": "cleartext_transmission",
                "CWE-312": "cleartext_storage",
                "CWE-327": "weak_crypto",
                "CWE-328": "weak_hash",
                "CWE-326": "insufficient_key_size",
                "CWE-338": "weak_prng",
                "CWE-601": "open_redirect",
                "CWE-532": "information_leakage",
                "CWE-925": "intent_verification",
                "CWE-926": "component_exposure",
                "CWE-749": "exposed_method",
                "CWE-940": "improper_cert_validation"
            }
            
            # Group findings by vulnerability type
            vuln_findings = {}
            
            # Process all CWE findings from Quark
            for category, details in quark_results.items():
                cwe = category.split(':')[0].strip()
                vuln_type = cwe_to_vuln_type.get(cwe)
                
                if not vuln_type:
                    # If we don't have a direct mapping, use a generic mapping
                    if "sql" in category.lower():
                        vuln_type = "sql_injection"
                    elif "javascript" in category.lower() or "webview" in category.lower():
                        vuln_type = "webview_javascript"
                    elif "intent" in category.lower():
                        vuln_type = "intent_redirection"
                    elif "crypto" in category.lower():
                        vuln_type = "weak_crypto"
                    elif "clear" in category.lower() and "text" in category.lower():
                        vuln_type = "insecure_communication"
                    elif "hardcoded" in category.lower() or "credential" in category.lower():
                        vuln_type = "hardcoded_secrets"
                    else:
                        # Default to using the CWE as the type
                        vuln_type = cwe.lower().replace('-', '_')
                
                if vuln_type not in vuln_findings:
                    vuln_findings[vuln_type] = []
                
                # Add all details to the appropriate vulnerability type
                for detail in details:
                    vuln_findings[vuln_type].append({
                        "class": detail.get("class1", "Unknown"),
                        "method": detail.get("method1", "Unknown"),
                        "class2": detail.get("class2", ""),
                        "method2": detail.get("method2", ""),
                        "params": detail.get("params", []),
                        "cwe": detail.get("cwe", ""),
                        "description": detail.get("description", "")
                    })
            
            # Add all findings to our results
            for vuln_type, details in vuln_findings.items():
                if vuln_type in self.vulnerabilities:
                    findings.append({
                        "type": vuln_type,
                        "details": {
                            "name": self.vulnerabilities[vuln_type]["name"],
                            "description": self.vulnerabilities[vuln_type]["description"],
                            "severity": self.vulnerabilities[vuln_type]["severity"],
                            "locations": details
                        }
                    })
                else:
                    # For vulnerabilities not in our predefined list, create a new entry
                    cwe = details[0].get("cwe", "") if details else ""
                    description = details[0].get("description", "") if details else ""
                    
                    # Determine severity based on CWE
                    severity = "Medium"  # Default
                    if cwe in ["CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-798"]:
                        severity = "High"
                    
                    findings.append({
                        "type": vuln_type,
                        "details": {
                            "name": f"{cwe} Vulnerability",
                            "description": description,
                            "severity": severity,
                            "locations": details
                        }
                    })
        
        # Additional checks for MSTG and OVAA specific vulnerabilities
        self._check_for_mstg_vulnerabilities(apk, findings)
        self._check_for_ovaa_vulnerabilities(apk, findings)
        
        return findings
    
    def _check_for_mstg_vulnerabilities(self, apk, findings):
        """Check for vulnerabilities listed in MSTG checklist"""
        # Check for insecure data storage
        if "android.permission.WRITE_EXTERNAL_STORAGE" in apk.get_permissions():
            findings.append({
                "type": "insecure_storage",
                "details": {
                    "name": "Insecure Data Storage",
                    "description": "The app uses external storage which can be accessed by other apps",
                    "severity": "Medium",
                    "locations": ["External storage permission detected"]
                }
            })
            
        # Check for lack of certificate pinning (simplified check)
        # Using the dex analysis to extract strings
        from androguard.core.bytecodes.dvm import DalvikVMFormat
        from androguard.core.analysis.analysis import Analysis
        
        cert_pinning_found = False
        # Get the DVM format
        try:
            dex_file = apk.get_dex()
            if dex_file:
                d = DalvikVMFormat(dex_file)
                dx = Analysis(d)
                
                # Search for cert pinning related strings
                for string in d.get_strings():
                    if (b"certificatepinner" in string.lower() or 
                        b"certificatepin" in string.lower() or
                        b"x509trustmanager" in string.lower()):
                        cert_pinning_found = True
                        break
        except Exception as e:
            console.print(f"[yellow]Warning: Could not analyze DEX for certificate pinning: {str(e)}[/yellow]")
            
        # Check for network permissions without cert pinning
        if not cert_pinning_found and (
            "android.permission.INTERNET" in apk.get_permissions() or
            "android.permission.ACCESS_NETWORK_STATE" in apk.get_permissions()):
            findings.append({
                "type": "missing_cert_pinning",
                "details": {
                    "name": "Missing Certificate Pinning",
                    "description": "The app uses network communication without certificate pinning",
                    "severity": "High",
                    "locations": ["Network permissions without certificate pinning detected"]
                }
            })
    
    def _check_for_ovaa_vulnerabilities(self, apk, findings):
        """Check for vulnerabilities specific to OVAA"""
        # Check for deeplinks
        deeplinks = []
        for activity in apk.get_activities():
            try:
                activity_xml = apk.get_element('activity', activity)
                for intent_filter in activity_xml.findall('./intent-filter'):
                    for data in intent_filter.findall('./data'):
                        scheme = data.get('{http://schemas.android.com/apk/res/android}scheme')
                        host = data.get('{http://schemas.android.com/apk/res/android}host')
                        path = data.get('{http://schemas.android.com/apk/res/android}path')
                        if scheme:
                            deeplinks.append({
                                "activity": activity,
                                "scheme": scheme,
                                "host": host,
                                "path": path
                            })
            except:
                # If we can't determine if exported, assume it's not
                pass
        
        if deeplinks:
            findings.append({
                "type": "insecure_deeplinks",
                "details": {
                    "name": "Potentially Insecure Deeplinks",
                    "description": "The app implements deep links which could be abused if not properly validated",
                    "severity": "Medium",
                    "deeplinks": deeplinks
                }
            })
            
        # Look for Firebase URLs - potential insecure Firebase configuration
        firebase_urls = []
        
        # Use DexVMFormat to extract strings from DEX
        from androguard.core.bytecodes.dvm import DalvikVMFormat
        
        try:
            dex_file = apk.get_dex()
            if dex_file:
                d = DalvikVMFormat(dex_file)
                
                # Search for Firebase URLs in strings
                for string in d.get_strings():
                    if isinstance(string, bytes):
                        string_str = string.decode('utf-8', errors='ignore')
                        if "firebaseio.com" in string_str:
                            firebase_urls.append(string_str)
        except Exception as e:
            console.print(f"[yellow]Warning: Could not analyze DEX for Firebase URLs: {str(e)}[/yellow]")
        
        if firebase_urls:
            findings.append({
                "type": "insecure_firebase",
                "details": {
                    "name": "Potentially Insecure Firebase Configuration",
                    "description": "The app contains Firebase URLs which might not be properly secured",
                    "severity": "High",
                    "urls": firebase_urls
                }
            })
    
    def scan(self):
        """Perform full scanning of the APK file"""
        console.print(f"[bold green]Scanning:[/bold green] {self.apk_path}")
        
        # Validate APK
        try:
            apk = self._validate_apk()
            console.print("[bold green]✓[/bold green] Valid APK file")
        except ValueError as e:
            console.print(f"[bold red]✗[/bold red] {str(e)}")
            return None
        
        # Get APK information
        console.print("[bold blue]Gathering APK information...[/bold blue]")
        apk_info = self._get_apk_info(apk)
        
        # Show APK basic info
        table = Table(title="APK Information")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Package Name", apk_info["package_name"])
        table.add_row("Version", f"{apk_info['version_name']} (code: {apk_info['version_code']})")
        table.add_row("SDK Versions", f"Min: {apk_info['min_sdk']}, Target: {apk_info['target_sdk']}")
        table.add_row("Activities", str(len(apk_info["activities"])))
        table.add_row("Services", str(len(apk_info["services"])))
        table.add_row("Receivers", str(len(apk_info["receivers"])))
        table.add_row("Providers", str(len(apk_info["providers"])))
        table.add_row("Permissions", str(len(apk_info["permissions"])))
        
        console.print(table)
        
        # Identify APK
        console.print("[bold blue]Identifying APK...[/bold blue]")
        apk_identification = self._identify_apk()
        
        # Run Quark Engine analysis
        console.print("[bold blue]Running Quark Engine analysis...[/bold blue]")
        quark_results = self._scan_with_quark(self.apk_path)
        
        # Analyze results to find vulnerabilities
        console.print("[bold blue]Analyzing results for vulnerabilities...[/bold blue]")
        findings = self._analyze_results(quark_results, apk)
        
        # Format final results
        results = {
            "scan_info": {
                "timestamp": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
                "apk_path": self.apk_path,
                "apk_size": os.path.getsize(self.apk_path)
            },
            "apk_info": apk_info,
            "apk_identification": apk_identification,
            "vulnerabilities": findings
        }
        
        # Display results summary
        table = Table(title="Vulnerability Scan Results")
        table.add_column("Type", style="cyan")
        table.add_column("Severity", style="green")
        table.add_column("Description", style="blue")
        
        if findings:
            for finding in findings:
                severity = finding["details"]["severity"]
                severity_color = {
                    "Critical": "[bold red]Critical[/bold red]",
                    "High": "[bold orange]High[/bold orange]",
                    "Medium": "[bold yellow]Medium[/bold yellow]",
                    "Low": "[bold green]Low[/bold green]"
                }.get(severity, severity)
                
                table.add_row(
                    finding["details"]["name"],
                    severity_color,
                    finding["details"]["description"]
                )
        else:
            table.add_row("No vulnerabilities found", "", "")
        
        console.print(table)
        return results
    
    def save_results(self, results, output_path):
        """Save scan results to a JSON file"""
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=4)
        console.print(f"[bold green]Results saved to:[/bold green] {output_path}")

    def generate_html_report(self, apk_info, vulnerabilities, output_file):
        """
        Generate an HTML report with the scan results.
        
        Args:
            apk_info (dict): Dictionary containing APK information
            vulnerabilities (list): List of identified vulnerabilities
            output_file (str): Path to save the HTML report
        """
        try:
            # Get the current date and time
            current_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Get APK information
            package_name = apk_info.get("package_name", "N/A")
            app_name = apk_info.get("app_name", package_name)
            app_version = apk_info.get("version", "N/A")
            min_sdk = apk_info.get("min_sdk", "N/A")
            target_sdk = apk_info.get("target_sdk", "N/A")
            
            # Get activities, services, receivers, and providers
            components = apk_info.get("components", {})
            activities = len(components.get("activities", []))
            services = len(components.get("services", []))
            receivers = len(components.get("receivers", []))
            providers = len(components.get("providers", []))
            
            # Generate vulnerability cards
            vulnerabilities_html = ""
            unique_categories = set()
            
            # Count vulnerabilities by severity
            high_count = 0
            medium_count = 0
            low_count = 0
            total_vulns = len(vulnerabilities)
            
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "Medium")
                if severity == "High" or severity == "Critical":
                    high_count += 1
                elif severity == "Medium":
                    medium_count += 1
                else:
                    low_count += 1
                
                # Add category to unique categories
                category = vuln.get("category", "Unknown")
                if category:
                    unique_categories.add(category)
                
                # Format severity for display
                severity_class = "danger" if severity == "High" or severity == "Critical" else "warning" if severity == "Medium" else "info"
                
                # Extract evidence from vulnerability
                evidence = vuln.get("evidence", "")
                if not evidence and "locations" in vuln:
                    # Try to extract evidence from locations
                    locations = vuln.get("locations", [])
                    evidence_parts = []
                    
                    for loc in locations:
                        if isinstance(loc, dict):
                            loc_evidence = []
                            
                            # Extract class and method information
                            if loc.get("class"):
                                loc_evidence.append(f"Class: {loc['class']}")
                            if loc.get("method"):
                                loc_evidence.append(f"Method: {loc['method']}")
                            
                            # Extract parameters
                            if loc.get("params") and isinstance(loc["params"], list):
                                param_strs = []
                                for i, param in enumerate(loc["params"]):
                                    param_strs.append(f"  {i+1}. {param}")
                                if param_strs:
                                    loc_evidence.append("Parameters:")
                                    loc_evidence.extend(param_strs)
                            
                            # Add CWE and description
                            if loc.get("cwe"):
                                loc_evidence.append(f"CWE: {loc['cwe']}")
                            if loc.get("description"):
                                loc_evidence.append(f"Description: {loc['description']}")
                            
                            if loc_evidence:
                                evidence_parts.append("\n".join(loc_evidence))
                        elif loc:
                            # If location is a string or other non-dict type
                            evidence_parts.append(str(loc))
                    
                    if evidence_parts:
                        evidence = "\n\n".join(evidence_parts)
                
                # Create vulnerability card
                vuln_html = f"""
                <div class="col-md-6 mb-4 vuln-card" data-category="{html.escape(category)}" data-severity="{html.escape(severity)}">
                    <div class="card h-100">
                        <div class="card-header bg-{severity_class} text-white d-flex justify-content-between align-items-center">
                            <h5 class="card-title mb-0">{html.escape(vuln.get('title', 'Unknown Vulnerability'))}</h5>
                            <span class="badge bg-light text-dark">{html.escape(category)}</span>
                        </div>
                        <div class="card-body">
                            <p class="description mb-3">{html.escape(vuln.get('description', 'No description available'))}</p>
                            <div class="mt-3">
                                <h6 class="evidence-title">Evidence:</h6>
                                <pre class="evidence-code">{html.escape(evidence or 'No evidence available')}</pre>
                            </div>
                        </div>
                    </div>
                </div>
                """
                vulnerabilities_html += vuln_html
            
            # Calculate security score (weighted by vulnerability severity)
            total_weight = high_count * 3 + medium_count * 2 + low_count * 1
            max_score = total_vulns * 3  # Assuming all vulns could be high severity
            weighted_score = 0 if max_score == 0 else round(100 - (total_weight / max_score * 100)) if max_score > 0 else 100
            
            # Generate category options for filter
            category_options = ""
            for category in sorted(unique_categories):
                category_options += f'<option value="{html.escape(category)}">{html.escape(category)}</option>\n'
            
            # Read the template file
            template_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates", "report_template.html")
            
            if not os.path.exists(template_path):
                console.print(f"[red]Error: Template file not found at {template_path}[/red]")
                return
                
            with open(template_path, 'r', encoding='utf-8') as f:
                template_content = f.read()
            
            # Prepare template variables
            package_name = apk_info.get('package_name', 'Unknown')
            app_version = apk_info.get('version', 'Unknown')
            min_sdk = apk_info.get('min_sdk', 'Unknown')
            target_sdk = apk_info.get('target_sdk', 'Unknown')
            
            # Get component counts
            activities = len(apk_info.get('activities', []))
            services = len(apk_info.get('services', []))
            receivers = len(apk_info.get('receivers', []))
            providers = len(apk_info.get('providers', []))
            
            # Generate permission rows
            permission_rows = ""
            permissions = apk_info.get('permissions', [])
            
            # Handle permissions whether they're in list or dict format
            if isinstance(permissions, dict):
                # Dictionary format
                for perm, details in permissions.items():
                    risk_level = details.get('risk', 'Medium')
                    risk_class = "danger" if risk_level == "High" else "warning" if risk_level == "Medium" else "info"
                    description = details.get('description', 'No description available')
                    
                    permission_row = f"""
                    <tr>
                        <td><code>{html.escape(perm)}</code></td>
                        <td>{html.escape(description)}</td>
                        <td><span class="badge bg-{risk_class}">{html.escape(risk_level)}</span></td>
                    </tr>
                    """
                    permission_rows += permission_row
            else:
                # List format
                for perm in permissions:
                    # Determine risk level based on permission name (simplified heuristic)
                    if isinstance(perm, dict):
                        perm_name = perm.get('name', 'Unknown Permission')
                        description = perm.get('description', 'No description available')
                        risk_level = perm.get('risk', 'Medium')
                    else:
                        perm_name = str(perm)
                        description = 'No description available'
                        # Simple heuristic for risk level based on permission name
                        if any(keyword in perm_name.lower() for keyword in ['camera', 'location', 'sms', 'phone', 'storage', 'contacts', 'record']):
                            risk_level = 'High'
                        elif any(keyword in perm_name.lower() for keyword in ['internet', 'network', 'wifi', 'bluetooth']):
                            risk_level = 'Medium'
                        else:
                            risk_level = 'Low'
                    
                    risk_class = "danger" if risk_level == "High" else "warning" if risk_level == "Medium" else "info"
                    
                    permission_row = f"""
                    <tr>
                        <td><code>{html.escape(perm_name)}</code></td>
                        <td>{html.escape(description)}</td>
                        <td><span class="badge bg-{risk_class}">{html.escape(risk_level)}</span></td>
                    </tr>
                    """
                    permission_rows += permission_row
            
            # Generate activity rows
            activity_rows = ""
            for activity in apk_info.get('activities', []):
                activity_row = f"""
                <tr>
                    <td><code>{html.escape(activity)}</code></td>
                </tr>
                """
                activity_rows += activity_row
            
            # Generate service rows
            service_rows = ""
            for service in apk_info.get('services', []):
                service_row = f"""
                <tr>
                    <td><code>{html.escape(service)}</code></td>
                </tr>
                """
                service_rows += service_row
            
            # Generate receiver rows
            receiver_rows = ""
            for receiver in apk_info.get('receivers', []):
                receiver_row = f"""
                <tr>
                    <td><code>{html.escape(receiver)}</code></td>
                </tr>
                """
                receiver_rows += receiver_row
            
            # Generate provider rows
            provider_rows = ""
            for provider in apk_info.get('providers', []):
                provider_row = f"""
                <tr>
                    <td><code>{html.escape(provider)}</code></td>
                </tr>
                """
                provider_rows += provider_row
            
            # Replace placeholders in the template
            template_content = template_content.replace("{{title}}", html.escape(app_name))
            template_content = template_content.replace("{{package_name}}", html.escape(package_name))
            template_content = template_content.replace("{{version}}", html.escape(app_version))
            template_content = template_content.replace("{{min_sdk}}", html.escape(str(min_sdk)))
            template_content = template_content.replace("{{target_sdk}}", html.escape(str(target_sdk)))
            template_content = template_content.replace("{{date}}", html.escape(current_date))
            template_content = template_content.replace("{{security_score}}", str(weighted_score))
            template_content = template_content.replace("{{high_count}}", str(high_count))
            template_content = template_content.replace("{{medium_count}}", str(medium_count))
            template_content = template_content.replace("{{low_count}}", str(low_count))
            template_content = template_content.replace("{{total_vulns}}", str(total_vulns))
            template_content = template_content.replace("{{activities}}", str(activities))
            template_content = template_content.replace("{{services}}", str(services))
            template_content = template_content.replace("{{receivers}}", str(receivers))
            template_content = template_content.replace("{{providers}}", str(providers))
            template_content = template_content.replace("{{vulnerability_cards}}", vulnerabilities_html)
            template_content = template_content.replace("{{category_options}}", category_options)
            template_content = template_content.replace("{{permission_rows}}", permission_rows)
            template_content = template_content.replace("{{activity_rows}}", activity_rows)
            template_content = template_content.replace("{{service_rows}}", service_rows)
            template_content = template_content.replace("{{receiver_rows}}", receiver_rows)
            template_content = template_content.replace("{{provider_rows}}", provider_rows)
            
            # Create reports directory structure if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
            
            # Write the HTML report
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(template_content)
            
            console.print(f"[green]Report generated successfully: {output_file}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error generating HTML report: {str(e)}[/red]")
            if self.verbose:
                import traceback
                console.print(traceback.format_exc())
