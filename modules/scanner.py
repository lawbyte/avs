#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Scanner module for AVS
Handles the vulnerability scanning functionality using Quark Engine
"""

import os
import json
import re
import tempfile
import traceback
import time
import hashlib
import html
import magic
from datetime import datetime as dt
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

# Try to import Quark components
try:
    from quark.core.quark import Quark
    from quark.script import runQuarkAnalysis, Rule
    QUARK_AVAILABLE = True
except ImportError:
    QUARK_AVAILABLE = False

from androguard.core.bytecodes.apk import APK
import subprocess

# APKiD imports (optional)
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
        """Validate that the file is a valid APK file"""
        if not os.path.exists(self.apk_path):
            raise ValueError(f"File does not exist: {self.apk_path}")
        
        # Check file type using python-magic
        try:
            file_type = magic.from_file(self.apk_path, mime=True)
            if file_type not in ["application/zip", "application/java-archive", "application/octet-stream", "application/vnd.android.package-archive"]:
                raise ValueError(f"Not a valid APK file. Detected type: {file_type}")
        except Exception as e:
            if self.verbose:
                console.print(f"[yellow]Warning: Magic file type check failed: {str(e)}[/yellow]")
                console.print("[yellow]Continuing with APK validation anyway...[/yellow]")
        
        # Try to parse with Androguard
        try:
            apk = APK(self.apk_path)
            if not apk:
                raise ValueError("Failed to parse APK file with Androguard")
            
            # Further validation
            if not apk.get_package():
                raise ValueError("Invalid APK: Unable to extract package name")
                
            return apk
        except Exception as e:
            raise ValueError(f"Invalid APK file: {str(e)}")
    
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
    
    def _scan_with_quark(self):
        """
        Scan the APK with Quark for vulnerabilities.
        
        Returns:
            list: A list of vulnerabilities found by Quark.
        """
        if not QUARK_AVAILABLE:
            if self.verbose:
                console.print("[yellow]Quark Engine not available. Install it for more comprehensive vulnerability detection.[/yellow]")
            return []
            
        try:
            # Initialize Quark for analysis
            quark = Quark(self.apk_path)
            
            # List to store all the vulnerabilities found
            vulnerabilities = []
            
            # Path to the quark-script directory
            quark_script_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "quark-script")
            
            if not os.path.exists(quark_script_dir):
                if self.verbose:
                    console.print("[yellow]Quark-script directory not found. Skipping advanced vulnerability detection.[/yellow]")
                return vulnerabilities
            
            # Get all CWE directories
            cwe_dirs = [d for d in os.listdir(quark_script_dir) 
                      if os.path.isdir(os.path.join(quark_script_dir, d)) and d.startswith("CWE-")]
            
            cwe_descriptions = {
                "CWE-22": "Path Traversal",
                "CWE-23": "Relative Path Traversal",
                "CWE-78": "OS Command Injection",
                "CWE-79": "Cross-site Scripting (XSS)",
                "CWE-88": "Argument Injection or Modification",
                "CWE-89": "SQL Injection",
                "CWE-94": "Code Injection",
                "CWE-117": "Improper Output Neutralization for Logs",
                "CWE-295": "Improper Certificate Validation",
                "CWE-312": "Cleartext Storage of Sensitive Information",
                "CWE-319": "Cleartext Transmission of Sensitive Information",
                "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
                "CWE-328": "Reversible One-Way Hash",
                "CWE-338": "Use of Cryptographically Weak Pseudo-Random Number Generator",
                "CWE-489": "Leftover Debug Code",
                "CWE-502": "Deserialization of Untrusted Data",
                "CWE-532": "Insertion of Sensitive Information into Log File",
                "CWE-601": "URL Redirection to Untrusted Site",
                "CWE-73": "External Control of File Name or Path",
                "CWE-749": "Exposed Dangerous Method or Function",
                "CWE-780": "Use of RSA Algorithm without OAEP",
                "CWE-798": "Use of Hard-coded Credentials",
                "CWE-921": "Storage of Sensitive Data in a Mechanism without Access Control",
                "CWE-925": "Improper Verification of Intent by Broadcast Receiver",
                "CWE-926": "Improper Export of Android Application Components",
                "CWE-940": "Improper Verification of Source of a Communication Channel"
            }
            
            # For each CWE directory, run the detection algorithm
            for cwe_dir in cwe_dirs:
                cwe_path = os.path.join(quark_script_dir, cwe_dir)
                json_files = [f for f in os.listdir(cwe_path) if f.endswith('.json')]
                
                for json_file in json_files:
                    json_path = os.path.join(cwe_path, json_file)
                    
                    try:
                        # Load the rule
                        with open(json_path, 'r') as f:
                            rule_data = json.load(f)
                        
                        rule_instance = Rule(json_path)
                        
                        # Run Quark analysis with this rule
                        quark_result = runQuarkAnalysis(self.apk_path, rule_instance)
                        
                        # Process the results based on CWE type
                        if quark_result and quark_result.behaviorOccurList:
                            cwe_id = cwe_dir
                            cwe_number = cwe_id.split('-')[1]
                            
                            # Process each behavior occurrence based on CWE type
                            for behavior in quark_result.behaviorOccurList:
                                try:
                                    evidence_details = []
                                    
                                    # Extract method caller information
                                    caller = behavior.methodCaller
                                    caller_class = caller.className
                                    caller_method = caller.methodName
                                    caller_descriptor = caller.descriptor
                                    
                                    # Begin building evidence string
                                    evidence_details.append(f"Found in method: {caller.fullName}")
                                    
                                    # Extract API call information
                                    if behavior.firstAPI:
                                        first_api = behavior.firstAPI
                                        evidence_details.append(f"First API: {first_api.className}.{first_api.methodName}{first_api.descriptor}")
                                    
                                    if behavior.secondAPI:
                                        second_api = behavior.secondAPI
                                        evidence_details.append(f"Second API: {second_api.className}.{second_api.methodName}{second_api.descriptor}")
                                        
                                        # Extract arguments for different CWE types
                                        if cwe_id == "CWE-22" or cwe_id == "CWE-73":
                                            # Path traversal vulnerabilities
                                            try:
                                                file_path = second_api.getArguments()[2]
                                                evidence_details.append(f"File path: {file_path}")
                                                
                                                # Check if path is not hardcoded
                                                if not quark_result.isHardcoded(file_path):
                                                    evidence_details.append("WARNING: Path is user-controlled (not hardcoded)")
                                            except (IndexError, TypeError) as e:
                                                pass
                                                
                                        elif cwe_id == "CWE-798":
                                            # Hardcoded credentials
                                            try:
                                                if len(second_api.getArguments()) > 2:
                                                    first_param = second_api.getArguments()[1]
                                                    second_param = second_api.getArguments()[2]
                                                    
                                                    if second_param == "AES":
                                                        # Try to extract the key value
                                                        match = re.findall(r"\((.*?)\)", first_param)
                                                        if match and len(match) > 1:
                                                            aes_key = match[1]
                                                            evidence_details.append(f"Hardcoded {second_param} key: {aes_key}")
                                            except (IndexError, TypeError) as e:
                                                pass
                                                
                                        elif cwe_id == "CWE-89":
                                            # SQL injection
                                            try:
                                                query = second_api.getArguments()[0]
                                                evidence_details.append(f"SQL Query: {query}")
                                                
                                                # Check if query is not hardcoded
                                                if not quark_result.isHardcoded(query):
                                                    evidence_details.append("WARNING: SQL query is user-controlled (not hardcoded)")
                                            except (IndexError, TypeError) as e:
                                                pass
                                                
                                        elif cwe_id == "CWE-327" or cwe_id == "CWE-328":
                                            # Weak crypto
                                            try:
                                                algorithm = second_api.getArguments()[0]
                                                evidence_details.append(f"Crypto algorithm: {algorithm}")
                                            except (IndexError, TypeError) as e:
                                                pass
                                    
                                    # Create vulnerability entry
                                    title = f"{cwe_id} - {cwe_descriptions.get(cwe_id, 'Vulnerability')}"
                                    description = rule_data.get('crime', f"Potential {cwe_descriptions.get(cwe_id, 'vulnerability')} detected")
                                    
                                    # Determine severity based on CWE
                                    severity = "Medium"  # Default
                                    if cwe_id in ["CWE-78", "CWE-89", "CWE-94", "CWE-798"]:
                                        severity = "High"
                                    elif cwe_id in ["CWE-295", "CWE-327", "CWE-328"]:
                                        severity = "Critical"
                                    
                                    # Add the vulnerability
                                    vulnerability = {
                                        "title": title,
                                        "category": cwe_id,
                                        "description": description,
                                        "severity": severity,
                                        "evidence": "\n".join(evidence_details),
                                        "details": {
                                            "caller_class": caller_class,
                                            "caller_method": caller_method,
                                            "caller_descriptor": caller_descriptor,
                                            "cwe": cwe_number,
                                            "rule_file": os.path.basename(json_file)
                                        }
                                    }
                                    
                                    vulnerabilities.append(vulnerability)
                                    
                                    if self.verbose:
                                        console.print(f"[green]Detected {title}:[/green] {description}")
                                        for line in evidence_details:
                                            console.print(f"  [cyan]{line}[/cyan]")
                                        console.print("")
                                        
                                except Exception as e:
                                    if self.verbose:
                                        console.print(f"[red]Error processing behavior for {cwe_id}:[/red] {str(e)}")
                    
                    except Exception as e:
                        if self.verbose:
                            console.print(f"[red]Error analyzing with rule {json_file}:[/red] {str(e)}")
            
            return vulnerabilities
            
        except Exception as e:
            if self.verbose:
                console.print(f"[red]Error in Quark analysis:[/red] {str(e)}")
                console.print(traceback.format_exc())
            return []
    
    def _analyze_results(self, quark_results, apk):
        """Analyze results from Quark and other scans to identify vulnerabilities"""
        vulnerabilities = []
        
        # Basic vulnerabilities from APK analysis
        vulnerabilities.extend(self._check_basic_vulnerabilities(apk))
        
        # Add vulnerabilities from Quark analysis
        if quark_results:
            # Directly use the vulnerabilities from enhanced Quark scan
            vulnerabilities.extend(quark_results)
            
        # Format and return the results
        return self._format_results(vulnerabilities)
    
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
    
    def _check_basic_vulnerabilities(self, apk):
        """Check for basic vulnerabilities in the APK"""
        vulnerabilities = []
        
        # Check for exported components
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
            vulnerabilities.append({
                "title": "Exported Components",
                "category": "exported_components",
                "description": "The application exposes components to other applications, which may lead to unauthorized access.",
                "severity": "Medium",
                "evidence": self._format_evidence({"components": exported_components})
            })
            
        # Check for backup enabled
        try:
            manifest = apk.get_android_manifest_axml()
            app_node = manifest.getElementsByTagName("application")[0]
            backup_allowed = app_node.getAttribute("android:allowBackup")
            
            if backup_allowed.lower() == "true" or backup_allowed == "":
                vulnerabilities.append({
                    "title": "Backup Enabled",
                    "category": "backup_enabled",
                    "description": "The application allows backup, which may expose sensitive data.",
                    "severity": "Medium",
                    "evidence": "android:allowBackup attribute is set to 'true' or not specified in the AndroidManifest.xml"
                })
        except:
            # If we can't determine if backup is allowed, skip this check
            pass
            
        # Check for debuggable
        try:
            manifest = apk.get_android_manifest_axml()
            app_node = manifest.getElementsByTagName("application")[0]
            debuggable = app_node.getAttribute("android:debuggable")
            
            if debuggable.lower() == "true":
                vulnerabilities.append({
                    "title": "Debuggable Application",
                    "category": "debuggable",
                    "description": "The application is debuggable, which may allow attackers to extract sensitive information.",
                    "severity": "High",
                    "evidence": "android:debuggable attribute is set to 'true' in the AndroidManifest.xml"
                })
        except:
            # If we can't determine if debuggable, skip this check
            pass
            
        # Check for insecure network security configuration
        try:
            network_config = apk.get_android_manifest_axml().getElementsByTagName("network-security-config")
            if network_config:
                # This is a simplified check - in reality, we would need to parse the XML file
                # and check for cleartextTrafficPermitted, etc.
                vulnerabilities.append({
                    "title": "Custom Network Security Configuration",
                    "category": "network_security",
                    "description": "The application uses a custom network security configuration. Verify that it doesn't allow cleartext traffic or insecure connections.",
                    "severity": "Low",
                    "evidence": "The application uses a custom network-security-config. Manual verification recommended."
                })
        except:
            pass
            
        # Check for dangerous permissions
        dangerous_permissions = [
            "android.permission.READ_PHONE_STATE",
            "android.permission.CAMERA",
            "android.permission.READ_CONTACTS",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CALENDAR",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CONTACTS",
            "android.permission.WRITE_CALENDAR",
            "android.permission.WRITE_CALL_LOG"
        ]
        
        requested_dangerous_permissions = []
        for permission in apk.get_permissions():
            if permission in dangerous_permissions:
                requested_dangerous_permissions.append(permission)
                
        if requested_dangerous_permissions:
            vulnerabilities.append({
                "title": "Dangerous Permissions",
                "category": "dangerous_permissions",
                "description": "The application requests dangerous permissions that could potentially compromise user privacy.",
                "severity": "Medium",
                "evidence": "Dangerous permissions requested: " + ", ".join(requested_dangerous_permissions)
            })
            
        return vulnerabilities
    
    def _format_results(self, vulnerabilities):
        """Format the results for output"""
        
        # Make sure our vulnerabilities have a standard format
        normalized_vulns = []
        
        # Currently, we have a mix of vulnerability formats, so let's normalize them
        for vuln in vulnerabilities:
            if isinstance(vuln, dict) and "title" in vuln:
                # Already in the right format from our enhanced Quark analysis
                normalized_vulns.append(vuln)
            elif isinstance(vuln, dict) and "type" in vuln and "details" in vuln:
                # Old format from basic vulnerabilities
                details = vuln["details"]
                normalized_vulns.append({
                    "title": details.get("name", "Unknown Vulnerability"),
                    "category": vuln.get("type", "Unknown"),
                    "description": details.get("description", "No description available"),
                    "severity": details.get("severity", "Medium"),
                    "evidence": self._format_evidence(details)
                })
            else:
                # Unknown format - try our best
                normalized_vulns.append({
                    "title": vuln.get("name", "Unknown Vulnerability"),
                    "category": vuln.get("category", "Unknown"),
                    "description": vuln.get("description", "No description available"),
                    "severity": vuln.get("severity", "Medium"),
                    "evidence": vuln.get("evidence", "No evidence available")
                })
        
        return normalized_vulns
        
    def _format_evidence(self, details):
        """Format the evidence from vulnerability details"""
        evidence_lines = []
        
        # Handle different types of evidence based on vulnerability type
        if "components" in details:
            # For exported components
            evidence_lines.append("Exported Components:")
            for component in details.get("components", []):
                evidence_lines.append(f"  - {component.get('type', 'Unknown')}: {component.get('name', 'Unknown')}")
                
        elif "locations" in details:
            # For code-based vulnerabilities
            evidence_lines.append("Vulnerable Code Locations:")
            for location in details.get("locations", []):
                if "class" in location and "method" in location:
                    evidence_lines.append(f"  - Class: {location.get('class', 'Unknown')}")
                    evidence_lines.append(f"    Method: {location.get('method', 'Unknown')}")
                    if location.get("class2") and location.get("method2"):
                        evidence_lines.append(f"    Target: {location.get('class2', '')}.{location.get('method2', '')}")
                    if "params" in location and location["params"]:
                        evidence_lines.append(f"    Parameters: {', '.join(str(p) for p in location.get('params', []))}")
                    if "cwe" in location:
                        evidence_lines.append(f"    CWE: {location.get('cwe', 'Unknown')}")
                        
        return "\n".join(evidence_lines) if evidence_lines else "No specific evidence available"
    
    def _analyze_permissions(self, apk):
        """Analyze permissions used by the APK and categorize them by risk level"""
        permissions = []
        
        # Dangerous permission groups as defined by Android
        dangerous_permissions = {
            "android.permission.READ_CALENDAR": {
                "description": "Allows reading the user's calendar data",
                "risk": "High"
            },
            "android.permission.WRITE_CALENDAR": {
                "description": "Allows writing to the user's calendar data",
                "risk": "High"
            },
            "android.permission.READ_CALL_LOG": {
                "description": "Allows reading the user's call log",
                "risk": "High"
            },
            "android.permission.WRITE_CALL_LOG": {
                "description": "Allows writing to the user's call log",
                "risk": "High"
            },
            "android.permission.CAMERA": {
                "description": "Allows accessing the camera device",
                "risk": "High"
            },
            "android.permission.READ_CONTACTS": {
                "description": "Allows reading the user's contacts data",
                "risk": "High"
            },
            "android.permission.WRITE_CONTACTS": {
                "description": "Allows writing to the user's contacts data",
                "risk": "High"
            },
            "android.permission.GET_ACCOUNTS": {
                "description": "Allows access to the list of accounts in the Accounts Service",
                "risk": "Medium"
            },
            "android.permission.ACCESS_FINE_LOCATION": {
                "description": "Allows an app to access precise location",
                "risk": "High"
            },
            "android.permission.ACCESS_COARSE_LOCATION": {
                "description": "Allows an app to access approximate location",
                "risk": "Medium"
            },
            "android.permission.RECORD_AUDIO": {
                "description": "Allows an application to record audio",
                "risk": "High"
            },
            "android.permission.READ_PHONE_STATE": {
                "description": "Allows read only access to phone state",
                "risk": "Medium"
            },
            "android.permission.CALL_PHONE": {
                "description": "Allows an application to initiate a phone call without going through the Dialer",
                "risk": "High"
            },
            "android.permission.READ_PHONE_NUMBERS": {
                "description": "Allows read access to the device's phone numbers",
                "risk": "High"
            },
            "android.permission.ANSWER_PHONE_CALLS": {
                "description": "Allows the app to answer an incoming phone call",
                "risk": "High"
            },
            "android.permission.READ_SMS": {
                "description": "Allows an application to read SMS messages",
                "risk": "High"
            },
            "android.permission.RECEIVE_SMS": {
                "description": "Allows an application to receive SMS messages",
                "risk": "High"
            },
            "android.permission.SEND_SMS": {
                "description": "Allows an application to send SMS messages",
                "risk": "High"
            },
            "android.permission.READ_EXTERNAL_STORAGE": {
                "description": "Allows reading from external storage",
                "risk": "Medium"
            },
            "android.permission.WRITE_EXTERNAL_STORAGE": {
                "description": "Allows writing to external storage",
                "risk": "Medium"
            },
            "android.permission.MANAGE_EXTERNAL_STORAGE": {
                "description": "Allows an application to manage all files in external storage",
                "risk": "High"
            }
        }
        
        # Normal permissions with lower risk
        normal_permissions = {
            "android.permission.ACCESS_NETWORK_STATE": {
                "description": "Allows applications to access information about networks",
                "risk": "Low"
            },
            "android.permission.ACCESS_WIFI_STATE": {
                "description": "Allows applications to access information about Wi-Fi networks",
                "risk": "Low"
            },
            "android.permission.INTERNET": {
                "description": "Allows applications to open network sockets",
                "risk": "Low"
            },
            "android.permission.VIBRATE": {
                "description": "Allows access to the vibrator",
                "risk": "Low"
            },
            "android.permission.BLUETOOTH": {
                "description": "Allows applications to connect to paired bluetooth devices",
                "risk": "Low"
            },
            "android.permission.BLUETOOTH_ADMIN": {
                "description": "Allows applications to discover and pair bluetooth devices",
                "risk": "Medium"
            },
            "android.permission.CHANGE_WIFI_STATE": {
                "description": "Allows applications to change Wi-Fi connectivity state",
                "risk": "Medium"
            },
            "android.permission.FOREGROUND_SERVICE": {
                "description": "Allows a regular application to use Service.startForeground",
                "risk": "Low"
            },
            "android.permission.RECEIVE_BOOT_COMPLETED": {
                "description": "Allows an application to receive the ACTION_BOOT_COMPLETED that is broadcast after the system finishes booting",
                "risk": "Low"
            }
        }
        
        # Get all permissions from the APK
        apk_permissions = apk.get_permissions()
        
        # Process each permission
        for permission in apk_permissions:
            if permission in dangerous_permissions:
                info = dangerous_permissions[permission]
                permissions.append({
                    "name": permission,
                    "description": info["description"],
                    "risk": info["risk"]
                })
            elif permission in normal_permissions:
                info = normal_permissions[permission]
                permissions.append({
                    "name": permission,
                    "description": info["description"],
                    "risk": info["risk"]
                })
            else:
                # If permission is not in our list, determine its risk level
                risk = "Low"  # Default risk
                if "SMS" in permission or "CALL" in permission or "LOCATION" in permission:
                    risk = "High"
                elif "READ" in permission or "WRITE" in permission:
                    risk = "Medium"
                    
                # Add custom description
                description = "Custom permission, verify its usage"
                permissions.append({
                    "name": permission,
                    "description": description,
                    "risk": risk
                })
        
        return permissions
    
    def _get_components(self, apk):
        """Extract all components from the APK"""
        components = {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": []
        }
        
        # Process activities
        for activity in apk.get_activities():
            exported = False
            try:
                activity_xml = apk.get_element('activity', activity)
                exported_attr = activity_xml.get('{http://schemas.android.com/apk/res/android}exported')
                if exported_attr and exported_attr.lower() == 'true':
                    exported = True
            except:
                pass
                
            components["activities"].append({
                "name": activity,
                "exported": exported
            })
            
        # Process services
        for service in apk.get_services():
            exported = False
            try:
                service_xml = apk.get_element('service', service)
                exported_attr = service_xml.get('{http://schemas.android.com/apk/res/android}exported')
                if exported_attr and exported_attr.lower() == 'true':
                    exported = True
            except:
                pass
                
            components["services"].append({
                "name": service,
                "exported": exported
            })
            
        # Process receivers
        for receiver in apk.get_receivers():
            exported = False
            try:
                receiver_xml = apk.get_element('receiver', receiver)
                exported_attr = receiver_xml.get('{http://schemas.android.com/apk/res/android}exported')
                if exported_attr and exported_attr.lower() == 'true':
                    exported = True
            except:
                pass
                
            components["receivers"].append({
                "name": receiver,
                "exported": exported
            })
            
        # Process providers
        for provider in apk.get_providers():
            exported = False
            try:
                provider_xml = apk.get_element('provider', provider)
                exported_attr = provider_xml.get('{http://schemas.android.com/apk/res/android}exported')
                if exported_attr and exported_attr.lower() == 'true':
                    exported = True
            except:
                pass
                
            components["providers"].append({
                "name": provider,
                "exported": exported
            })
            
        return components
    
    def scan(self):
        """Perform full scanning of the APK file"""
        console.print(f"[bold green]Scanning:[/bold green] {self.apk_path}")
        
        # Validate APK file
        try:
            apk = self._validate_apk()
        except ValueError as e:
            return {"error": str(e)}
            
        try:
            # Extract basic information
            app_name = apk.get_app_name()
            package_name = apk.get_package()
            version = apk.get_androidversion_name()
            sdk_version = apk.get_target_sdk_version()
            min_sdk = apk.get_min_sdk_version()
            
            # APK identification
            apkid_results = self._identify_apk()
            
            # Run Quark Engine analysis
            console.print("[bold blue]Running Quark Engine analysis...[/bold blue]")
            quark_results = self._scan_with_quark()
            
            # Analyze results to find vulnerabilities
            console.print("[bold blue]Analyzing results for vulnerabilities...[/bold blue]")
            vulnerabilities = self._analyze_results(quark_results, apk)
            
            # Analyze permissions
            permissions = self._analyze_permissions(apk)
            
            # Get components
            components = self._get_components(apk)
            
            # Create the results dictionary
            scan_info = {
                "timestamp": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
                "apk_path": self.apk_path,
                "scan_duration": "0s"  # Will be updated before returning
            }
            
            apk_info = {
                "package_name": package_name,
                "app_name": app_name,
                "version": version,
                "sdk_version": sdk_version,
                "min_sdk": min_sdk,
                "apkid_results": apkid_results,
                "file_size": os.path.getsize(self.apk_path),
                "md5": self._hash_file(self.apk_path, "md5"),
                "sha1": self._hash_file(self.apk_path, "sha1"),
                "sha256": self._hash_file(self.apk_path, "sha256")
            }
            
            results = {
                "scan_info": scan_info,
                "apk_info": apk_info,
                "vulnerabilities": vulnerabilities,
                "permissions": permissions,
                "components": components
            }
            
            return results
            
        except Exception as e:
            console.print(f"[bold red]Error during scanning: {str(e)}[/bold red]")
            if self.verbose:
                console.print(traceback.format_exc())
            return {"error": str(e)}
    
    def _hash_file(self, file_path, algorithm):
        """Calculate the hash of a file"""
        if algorithm == "md5":
            hash_obj = hashlib.md5()
        elif algorithm == "sha1":
            hash_obj = hashlib.sha1()
        elif algorithm == "sha256":
            hash_obj = hashlib.sha256()
        else:
            return None
            
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    
    def save_results(self, results, output_path):
        """Save scan results to a JSON file"""
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=4)

    def generate_html_report(self, apk_info, vulnerabilities, output_file):
        """
        Generate an HTML report of the vulnerabilities.
        
        Args:
            apk_info (dict): Information about the APK.
            vulnerabilities (list): List of vulnerabilities.
            output_file (str): Path to the output file.
        """
        try:
            # Make sure apk_info is a dictionary
            if not isinstance(apk_info, dict):
                if self.verbose:
                    console.print(f"[yellow]Warning: APK info is not a dictionary. Type: {type(apk_info)}[/yellow]")
                console.print("[red]Error generating report: APK info structure is invalid.[/red]")
                return
            
            # Create reports directory if it doesn't exist
            reports_dir = os.path.dirname(output_file)
            os.makedirs(reports_dir, exist_ok=True)
            
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
            current_date = dt.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Count vulnerabilities by severity
            high_count = sum(1 for v in vulnerabilities if v.get('severity', 'Medium').lower() == 'high' or v.get('severity', 'Medium').lower() == 'critical')
            medium_count = sum(1 for v in vulnerabilities if v.get('severity', 'Medium').lower() == 'medium')
            low_count = sum(1 for v in vulnerabilities if v.get('severity', 'Medium').lower() == 'low')
            
            # Calculate security score (100 - weighted vulnerabilities)
            total_vulnerabilities = len(vulnerabilities)
            weighted_score = 100
            if total_vulnerabilities > 0:
                weighted_score = max(0, 100 - (high_count * 10) - (medium_count * 5) - (low_count * 2))
            
            # Get component counts
            activities = len(apk_info.get('activities', []))
            services = len(apk_info.get('services', []))
            receivers = len(apk_info.get('receivers', []))
            providers = len(apk_info.get('providers', []))
            
            # Create vulnerability HTML rows
            vulnerabilities_html = ""
            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    # Skip non-dictionary vulnerabilities
                    continue
                
                # Get vulnerability details with proper fallbacks
                title = vuln.get('title', vuln.get('type', vuln.get('name', 'Unknown Vulnerability')))
                severity = vuln.get('severity', vuln.get('risk', 'Medium'))
                category = vuln.get('category', vuln.get('cwe', 'General'))
                description = vuln.get('description', vuln.get('desc', 'No description available'))
                
                # Extract evidence with fallbacks
                evidence = ""
                if 'evidence' in vuln:
                    evidence = vuln['evidence']
                elif 'details' in vuln and isinstance(vuln['details'], dict) and 'evidence' in vuln['details']:
                    evidence = vuln['details']['evidence']
                elif 'location' in vuln:
                    evidence = vuln['location']
                
                # Convert evidence to HTML-safe string with line breaks
                if evidence:
                    # Replace newlines with <br> tags for HTML display
                    evidence = html.escape(str(evidence)).replace('\n', '<br>')
                
                # Determine severity class for color-coding
                severity_class = "bg-warning"  # Default is warning (Medium)
                if severity.lower() == "high" or severity.lower() == "critical":
                    severity_class = "bg-danger"
                elif severity.lower() == "low":
                    severity_class = "bg-info"
                elif severity.lower() == "info":
                    severity_class = "bg-secondary"
                
                # Create the vulnerability card
                vuln_card = f"""
                <div class="card mb-3">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">{html.escape(title)}</h5>
                        <span class="badge {severity_class}">{html.escape(severity)}</span>
                    </div>
                    <div class="card-body">
                        <h6 class="card-subtitle mb-2 text-muted">Category: {html.escape(category)}</h6>
                        <p class="card-text">{html.escape(description)}</p>
                        {f'<h6 class="mt-3">Evidence:</h6><div class="evidence-box p-2 bg-light rounded"><pre class="mb-0"><code>{evidence}</code></pre></div>' if evidence else ''}
                    </div>
                </div>
                """
                vulnerabilities_html += vuln_card
            
            # Generate category options for filter
            category_options = ""
            for category in sorted(set(vuln.get('category', 'General') for vuln in vulnerabilities)):
                category_options += f'<option value="{category}">{category}</option>'
            
            # Generate permission rows
            permission_rows = ""
            for perm in apk_info.get('permissions', []):
                perm_name = perm
                perm_desc = "No description available"
                risk_level = "Low"
                
                # Determine risk level based on permission name
                if any(danger_term in perm_name.lower() for danger_term in ["camera", "location", "record", "sms", "call", "contacts", "storage"]):
                    risk_level = "High"
                    risk_class = "danger"
                elif any(medium_term in perm_name.lower() for medium_term in ["internet", "bluetooth", "wifi", "account", "vibrate"]):
                    risk_level = "Medium"
                    risk_class = "warning"
                else:
                    risk_class = "success"
                
                permission_rows += f"""
                <tr>
                    <td><code>{perm_name}</code></td>
                    <td>{perm_desc}</td>
                    <td><span class="badge bg-{risk_class}">{risk_level}</span></td>
                </tr>
                """
            
            # Generate component rows (activities, services, etc.)
            activity_rows = ""
            for activity in apk_info.get('activities', []):
                activity_name = activity
                is_exported = "Unknown"
                
                if isinstance(activity, dict):
                    activity_name = activity.get('name', 'Unknown')
                    is_exported = "Yes" if activity.get('exported', False) else "No"
                
                exported_class = "danger" if is_exported == "Yes" else "success"
                
                activity_rows += f"""
                <tr>
                    <td><code>{activity_name}</code></td>
                    <td><span class="badge bg-{exported_class}">{is_exported}</span></td>
                </tr>
                """
            
            service_rows = ""
            for service in apk_info.get('services', []):
                service_name = service
                is_exported = "Unknown"
                
                if isinstance(service, dict):
                    service_name = service.get('name', 'Unknown')
                    is_exported = "Yes" if service.get('exported', False) else "No"
                
                exported_class = "danger" if is_exported == "Yes" else "success"
                
                service_rows += f"""
                <tr>
                    <td><code>{service_name}</code></td>
                    <td><span class="badge bg-{exported_class}">{is_exported}</span></td>
                </tr>
                """
            
            receiver_rows = ""
            for receiver in apk_info.get('receivers', []):
                receiver_name = receiver
                is_exported = "Unknown"
                
                if isinstance(receiver, dict):
                    receiver_name = receiver.get('name', 'Unknown')
                    is_exported = "Yes" if receiver.get('exported', False) else "No"
                
                exported_class = "danger" if is_exported == "Yes" else "success"
                
                receiver_rows += f"""
                <tr>
                    <td><code>{receiver_name}</code></td>
                    <td><span class="badge bg-{exported_class}">{is_exported}</span></td>
                </tr>
                """
            
            provider_rows = ""
            for provider in apk_info.get('providers', []):
                provider_name = provider
                is_exported = "Unknown"
                
                if isinstance(provider, dict):
                    provider_name = provider.get('name', 'Unknown')
                    is_exported = "Yes" if provider.get('exported', False) else "No"
                
                exported_class = "danger" if is_exported == "Yes" else "success"
                
                provider_rows += f"""
                <tr>
                    <td><code>{provider_name}</code></td>
                    <td><span class="badge bg-{exported_class}">{is_exported}</span></td>
                </tr>
                """
            
            # Replace template variables
            template_content = template_content.replace("{{title}}", html.escape(package_name))
            template_content = template_content.replace("{{package_name}}", package_name)
            template_content = template_content.replace("{{version}}", app_version)
            template_content = template_content.replace("{{min_sdk}}", str(min_sdk))
            template_content = template_content.replace("{{target_sdk}}", str(target_sdk))
            template_content = template_content.replace("{{date}}", current_date)
            template_content = template_content.replace("{{security_score}}", str(weighted_score))
            template_content = template_content.replace("{{high_count}}", str(high_count))
            template_content = template_content.replace("{{medium_count}}", str(medium_count))
            template_content = template_content.replace("{{low_count}}", str(low_count))
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
            
        except Exception as e:
            console.print(f"[red]Error generating HTML report: {e}[/red]")
            if self.verbose:
                import traceback
                console.print(f"[red]{traceback.format_exc()}[/red]")
