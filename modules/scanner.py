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
            
            # Process rules from the general rules directory
            rules_dir = os.path.join(quark_script_dir, "rules")
            
            if os.path.exists(rules_dir):
                if self.verbose:
                    console.print(f"[cyan]Scanning rules directory: {rules_dir}[/cyan]")
                
                # Get all JSON files in the rules directory
                rule_files = [f for f in os.listdir(rules_dir) if f.endswith('.json')]
                
                if self.verbose:
                    console.print(f"[cyan]Found {len(rule_files)} rule files in rules directory[/cyan]")
                
                for rule_file in rule_files:
                    rule_path = os.path.join(rules_dir, rule_file)
                    
                    try:
                        # Load the rule metadata
                        with open(rule_path, 'r') as f:
                            rule_data = json.load(f)
                        
                        rule_instance = Rule(rule_path)
                        
                        # Run Quark analysis with this rule
                        quark_result = runQuarkAnalysis(self.apk_path, rule_instance)
                        
                        # Process the results
                        if quark_result and quark_result.behaviorOccurList:
                            crime = rule_data.get('crime', 'Suspicious behavior detected')
                            labels = rule_data.get('label', [])
                            score = rule_data.get('score', 0)
                            
                            # Determine severity based on score and labels
                            severity = "Medium"  # Default
                            
                            # High-risk labels
                            high_risk_labels = ['sms', 'calllog', 'location', 'contacts', 'record', 'camera']
                            if any(label in high_risk_labels for label in labels):
                                severity = "High"
                            
                            # Critical if score is very high
                            if score > 1.0:
                                severity = "High"
                            elif score > 2.0:
                                severity = "Critical"
                            
                            # Low severity for common operations
                            low_risk_labels = ['collection', 'network', 'file']
                            if all(label in low_risk_labels for label in labels) and score < 0.5:
                                severity = "Low"
                            
                            # Create category from labels or use generic
                            category = "_".join(labels) if labels else "general"
                            
                            # Process each behavior occurrence
                            for behavior in quark_result.behaviorOccurList:
                                try:
                                    evidence_details = []
                                    
                                    # Extract method caller information
                                    caller = behavior.methodCaller
                                    caller_class = caller.className
                                    caller_method = caller.methodName
                                    caller_descriptor = caller.descriptor
                                    
                                    evidence_details.append(f"Found in method: {caller.fullName}")
                                    
                                    # Extract API call information
                                    if behavior.firstAPI:
                                        first_api = behavior.firstAPI
                                        evidence_details.append(f"First API: {first_api.className}.{first_api.methodName}{first_api.descriptor}")
                                    
                                    if behavior.secondAPI:
                                        second_api = behavior.secondAPI
                                        evidence_details.append(f"Second API: {second_api.className}.{second_api.methodName}{second_api.descriptor}")
                                    
                                    # Add labels to evidence
                                    if labels:
                                        evidence_details.append(f"Labels: {', '.join(labels)}")
                                    
                                    # Add score to evidence
                                    evidence_details.append(f"Risk Score: {score}")
                                    
                                    # Create vulnerability entry
                                    title = f"{category.upper()} - {crime}"
                                    
                                    vulnerability = {
                                        "title": title,
                                        "category": category,
                                        "description": crime,
                                        "severity": severity,
                                        "evidence": "\n".join(evidence_details),
                                        "details": {
                                            "caller_class": caller_class,
                                            "caller_method": caller_method,
                                            "caller_descriptor": caller_descriptor,
                                            "labels": labels,
                                            "score": score,
                                            "rule_file": os.path.basename(rule_file)
                                        }
                                    }
                                    
                                    vulnerabilities.append(vulnerability)
                                    
                                    if self.verbose:
                                        console.print(f"[green]Detected {title}:[/green] {crime}")
                                        for line in evidence_details:
                                            console.print(f"  [cyan]{line}[/cyan]")
                                        console.print("")
                                        
                                except Exception as e:
                                    if self.verbose:
                                        console.print(f"[red]Error processing behavior for {rule_file}:[/red] {str(e)}")
                    
                    except Exception as e:
                        if self.verbose:
                            console.print(f"[red]Error analyzing with rule {rule_file}:[/red] {str(e)}")
            else:
                if self.verbose:
                    console.print(f"[yellow]Rules directory not found: {rules_dir}[/yellow]")
            
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
                if any(high_term in permission.lower() for high_term in ["SMS", "CALL", "LOCATION", "RECORD", "CONTACTS"]):
                    risk = "High"
                elif any(med_term in permission.lower() for med_term in ["READ", "WRITE", "STORAGE", "NETWORK"]):
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
            
            # Count vulnerabilities by severity
            high_count = sum(1 for v in vulnerabilities if v.get('severity', 'Medium').lower() == 'high' or v.get('severity', 'Medium').lower() == 'critical')
            medium_count = sum(1 for v in vulnerabilities if v.get('severity', 'Medium').lower() == 'medium')
            low_count = sum(1 for v in vulnerabilities if v.get('severity', 'Medium').lower() == 'low')
            total_count = len(vulnerabilities)
            
            # Process simple template variables
            template_variables = {
                # APK Info
                "{{app_name}}": html.escape(apk_info.get('app_name', 'Unknown')),
                "{{package_name}}": html.escape(apk_info.get('package_name', 'Unknown')),
                "{{version}}": html.escape(str(apk_info.get('version', 'Unknown'))),
                "{{min_sdk}}": html.escape(str(apk_info.get('min_sdk', 'Unknown'))),
                "{{target_sdk}}": html.escape(str(apk_info.get('target_sdk', 'Unknown'))),
                "{{size}}": html.escape(str(apk_info.get('file_size', 'Unknown'))),
                "{{md5}}": html.escape(apk_info.get('md5', 'Unknown')),
                "{{sha256}}": html.escape(apk_info.get('sha256', 'Unknown')),
                "{{timestamp}}": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
                
                # Statistics
                "{{high_count}}": str(high_count),
                "{{medium_count}}": str(medium_count),
                "{{low_count}}": str(low_count),
                "{{total_count}}": str(total_count)
            }
            
            # Replace simple variables
            for var, value in template_variables.items():
                template_content = template_content.replace(var, value)
            
            # Process vulnerability section
            vulnerabilities_section = self._process_vulnerabilities_section(template_content, vulnerabilities)
            
            if vulnerabilities_section:
                template_content = vulnerabilities_section
            
            # Process component sections
            template_content = self._process_components_section(template_content, apk_info)
            
            # Process permissions section
            template_content = self._process_permissions_section(template_content, apk_info)
            
            # Final cleanup of any remaining template tags
            template_content = self._cleanup_template_tags(template_content)
            
            # Write the report
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(template_content)
            
        except Exception as e:
            console.print(f"[red]Error generating HTML report: {e}[/red]")
            if self.verbose:
                import traceback
                console.print(traceback.format_exc())
    
    def _process_vulnerabilities_section(self, template_content, vulnerabilities):
        """Process the vulnerabilities section of the template"""
        try:
            # Find the vulnerabilities section pattern
            vuln_pattern = re.search(
                r'{{#vulnerabilities}}(.*?){{/vulnerabilities}}',
                template_content,
                re.DOTALL
            )
            
            if not vuln_pattern:
                return None
            
            vuln_template = vuln_pattern.group(1)
            processed_vulns = []
            
            # Count vulnerabilities by severity
            severity_counts = {
                'Critical': 0,
                'High': 0,
                'Medium': 0,
                'Low': 0,
                'Info': 0
            }
            
            # Check if we have actual vulnerabilities
            if vulnerabilities and len(vulnerabilities) > 0:
                # Process each vulnerability
                for vuln in vulnerabilities:
                    # Create a copy of the template for this vulnerability
                    vuln_html = vuln_template
                    
                    # Extract the evidence section
                    evidence_pattern = re.search(
                        r'{{#has_evidence}}(.*?){{/has_evidence}}',
                        vuln_html,
                        re.DOTALL
                    )
                    
                    # Get vulnerability details
                    title = vuln.get('title', vuln.get('type', vuln.get('name', 'Unknown')))
                    severity = vuln.get('severity', vuln.get('risk', 'Medium'))
                    category = vuln.get('category', vuln.get('cwe', 'Vulnerability'))
                    description = vuln.get('description', vuln.get('desc', 'No description available'))
                    evidence = vuln.get('evidence', '')
                    
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                    
                    # Replace title, severity, category, and description
                    vuln_html = vuln_html.replace('{{title}}', html.escape(str(title)))
                    vuln_html = vuln_html.replace('{{severity}}', html.escape(str(severity)))
                    vuln_html = vuln_html.replace('{{category}}', html.escape(str(category)))
                    vuln_html = vuln_html.replace('{{description}}', html.escape(str(description)))
                    
                    # Set severity class
                    severity_class = self._get_severity_class(severity)
                    vuln_html = vuln_html.replace('{{severity_class}}', severity_class)
                    
                    # Handle evidence
                    if evidence:
                        # Evidence exists
                        if evidence_pattern:
                            evidence_html = evidence_pattern.group(1)
                            evidence_html = evidence_html.replace('{{evidence}}', html.escape(str(evidence)))
                            
                            # Replace has_evidence section
                            vuln_html = re.sub(
                                r'{{#has_evidence}}.*?{{/has_evidence}}',
                                evidence_html,
                                vuln_html,
                                flags=re.DOTALL
                            )
                    else:
                        # No evidence
                        vuln_html = re.sub(
                            r'{{#has_evidence}}.*?{{/has_evidence}}',
                            '',
                            vuln_html,
                            flags=re.DOTALL
                        )
                    
                    processed_vulns.append(vuln_html)
                
                # Calculate total count
                total_count = sum(severity_counts.values())
                
                # Replace the vulnerability section with processed content
                vuln_section = "\n".join(processed_vulns)
                template_content = re.sub(
                    r'{{#vulnerabilities}}.*?{{/vulnerabilities}}',
                    vuln_section,
                    template_content,
                    flags=re.DOTALL
                )
                
                # Since we have vulnerabilities, remove the "No vulnerabilities detected" message
                template_content = re.sub(
                    r'{{^vulnerabilities}}.*?{{/vulnerabilities}}',
                    '',
                    template_content,
                    flags=re.DOTALL
                )
                
                # Replace severity counts
                template_content = template_content.replace('{{high_count}}', str(severity_counts['High'] + severity_counts['Critical']))
                template_content = template_content.replace('{{medium_count}}', str(severity_counts['Medium']))
                template_content = template_content.replace('{{low_count}}', str(severity_counts['Low'] + severity_counts['Info']))
                template_content = template_content.replace('{{total_count}}', str(total_count))
            else:
                # No vulnerabilities detected
                template_content = re.sub(
                    r'{{#vulnerabilities}}.*?{{/vulnerabilities}}',
                    '',
                    template_content,
                    flags=re.DOTALL
                )
                
                # Find and keep the "No vulnerabilities detected" message
                no_vulns_pattern = re.search(
                    r'{{^vulnerabilities}}(.*?){{/vulnerabilities}}',
                    template_content,
                    re.DOTALL
                )
                
                if no_vulns_pattern:
                    no_vulns_html = no_vulns_pattern.group(1)
                    template_content = re.sub(
                        r'{{^vulnerabilities}}.*?{{/vulnerabilities}}',
                        no_vulns_html,
                        template_content,
                        flags=re.DOTALL
                    )
                
                # Set all counts to 0
                template_content = template_content.replace('{{high_count}}', '0')
                template_content = template_content.replace('{{medium_count}}', '0')
                template_content = template_content.replace('{{low_count}}', '0')
                template_content = template_content.replace('{{total_count}}', '0')
            
            return template_content
            
        except Exception as e:
            console.print(f"[red]Error processing vulnerabilities section:[/red] {str(e)}")
            if self.verbose:
                import traceback
                console.print(traceback.format_exc())
            return template_content
    
    def _process_components_section(self, template_content, apk_info):
        """Process the components section of the template"""
        try:
            # Initialize default values - components might be nested under 'components' or directly in apk_info
            components = {}
            
            # Check if components are in the nested structure
            if 'components' in apk_info and isinstance(apk_info['components'], dict):
                components = {
                    'activities': apk_info['components'].get('activities', []),
                    'services': apk_info['components'].get('services', []),
                    'receivers': apk_info['components'].get('receivers', []),
                    'providers': apk_info['components'].get('providers', [])
                }
            else:
                # Fall back to flat structure
                components = {
                    'activities': apk_info.get('activities', []),
                    'services': apk_info.get('services', []),
                    'receivers': apk_info.get('receivers', []),
                    'providers': apk_info.get('providers', [])
                }
            
            # Process each component type
            for component_type in components.keys():
                # Extract the component template pattern
                comp_pattern = re.search(
                    r'{{#components\.' + component_type + r'}}(.*?){{/components\.' + component_type + r'}}',
                    template_content,
                    re.DOTALL
                )
                
                if not comp_pattern:
                    continue
                
                comp_template = comp_pattern.group(1)
                processed_comps = []
                
                component_list = components[component_type]
                
                # Check if there are components to process
                if not component_list:
                    # No components - process the empty message
                    template_content = re.sub(
                        r'{{#components\.' + component_type + r'}}.*?{{/components\.' + component_type + r'}}',
                        '',
                        template_content,
                        flags=re.DOTALL
                    )
                    # Keep the empty message
                    continue
                
                # Components exist - process them
                for comp in component_list:
                    # Create a copy of the template for this component
                    comp_html = comp_template
                    
                    # Get component details
                    if isinstance(comp, dict):
                        name = comp.get('name', 'Unknown')
                        exported = comp.get('exported', False)
                    else:
                        name = comp
                        exported = False
                    
                    # Replace the name
                    comp_html = comp_html.replace('{{name}}', html.escape(str(name)))
                    
                    # Handle exported conditional
                    if exported:
                        comp_html = re.sub(
                            r'{{#exported}}(.*?){{/exported}}',
                            r'\1',
                            comp_html,
                            flags=re.DOTALL
                        )
                        comp_html = re.sub(
                            r'{{^exported}}.*?{{/exported}}',
                            '',
                            comp_html,
                            flags=re.DOTALL
                        )
                    else:
                        comp_html = re.sub(
                            r'{{#exported}}.*?{{/exported}}',
                            '',
                            comp_html,
                            flags=re.DOTALL
                        )
                        comp_html = re.sub(
                            r'{{^exported}}(.*?){{/exported}}',
                            r'\1',
                            comp_html,
                            flags=re.DOTALL
                        )
                    
                    processed_comps.append(comp_html)
                
                # Replace the component section with processed content
                comp_section = "\n".join(processed_comps)
                template_content = re.sub(
                    r'{{#components\.' + component_type + r'}}.*?{{/components\.' + component_type + r'}}',
                    comp_section,
                    template_content,
                    flags=re.DOTALL
                )
                
                # Since we have components, remove the "No X found" message
                template_content = re.sub(
                    r'{{^components\.' + component_type + r'}}.*?{{/components\.' + component_type + r'}}',
                    '',
                    template_content,
                    flags=re.DOTALL
                )
            
            return template_content
            
        except Exception as e:
            console.print(f"[red]Error processing components section:[/red] {str(e)}")
            if self.verbose:
                import traceback
                console.print(traceback.format_exc())
            return template_content
    
    def _process_permissions_section(self, template_content, apk_info):
        """Process the permissions section of the template"""
        try:
            # Get permissions list from apk_info
            permissions = apk_info.get('permissions', [])
            
            # Extract the permissions template pattern
            perm_pattern = re.search(
                r'{{#permissions}}(.*?){{/permissions}}',
                template_content,
                re.DOTALL
            )
            
            if not perm_pattern:
                return template_content
            
            perm_template = perm_pattern.group(1)
            processed_perms = []
            
            # Check if we have any permissions
            if permissions and len(permissions) > 0:
                # Process each permission
                for perm in permissions:
                    # Create a copy of the template for this permission
                    perm_html = perm_template
                    
                    # Get permission details
                    if isinstance(perm, dict):
                        name = perm.get('name', 'Unknown Permission')
                        description = perm.get('description', 'No description available')
                        risk = perm.get('risk', 'Low')
                    else:
                        # If it's just a string, assume it's the name
                        name = perm
                        description = 'No description available'
                        risk = 'Low'
                    
                    # Replace name and description
                    perm_html = perm_html.replace('{{name}}', html.escape(str(name)))
                    perm_html = perm_html.replace('{{description}}', html.escape(str(description)))
                    perm_html = perm_html.replace('{{risk}}', html.escape(str(risk)))
                    
                    # Handle risk level conditionals
                    is_high_risk = risk.lower() == 'high' or risk.lower() == 'critical'
                    is_medium_risk = risk.lower() == 'medium'
                    is_low_risk = risk.lower() == 'low' or risk.lower() == 'info'
                    
                    if is_high_risk:
                        perm_html = re.sub(
                            r'{{#is_high_risk}}(.*?){{/is_high_risk}}',
                            r'\1',
                            perm_html,
                            flags=re.DOTALL
                        )
                        perm_html = re.sub(
                            r'{{#is_medium_risk}}.*?{{/is_medium_risk}}',
                            '',
                            perm_html,
                            flags=re.DOTALL
                        )
                        perm_html = re.sub(
                            r'{{#is_low_risk}}.*?{{/is_low_risk}}',
                            '',
                            perm_html,
                            flags=re.DOTALL
                        )
                    elif is_medium_risk:
                        perm_html = re.sub(
                            r'{{#is_high_risk}}.*?{{/is_high_risk}}',
                            '',
                            perm_html,
                            flags=re.DOTALL
                        )
                        perm_html = re.sub(
                            r'{{#is_medium_risk}}(.*?){{/is_medium_risk}}',
                            r'\1',
                            perm_html,
                            flags=re.DOTALL
                        )
                        perm_html = re.sub(
                            r'{{#is_low_risk}}.*?{{/is_low_risk}}',
                            '',
                            perm_html,
                            flags=re.DOTALL
                        )
                    else:  # Low risk
                        perm_html = re.sub(
                            r'{{#is_high_risk}}.*?{{/is_high_risk}}',
                            '',
                            perm_html,
                            flags=re.DOTALL
                        )
                        perm_html = re.sub(
                            r'{{#is_medium_risk}}.*?{{/is_medium_risk}}',
                            '',
                            perm_html,
                            flags=re.DOTALL
                        )
                        perm_html = re.sub(
                            r'{{#is_low_risk}}(.*?){{/is_low_risk}}',
                            r'\1',
                            perm_html,
                            flags=re.DOTALL
                        )
                    
                    processed_perms.append(perm_html)
                
                # Replace the permissions section with processed content
                perm_section = "\n".join(processed_perms)
                template_content = re.sub(
                    r'{{#permissions}}.*?{{/permissions}}',
                    perm_section,
                    template_content,
                    flags=re.DOTALL
                )
                
                # Since we have permissions, remove the "No permissions found" message
                template_content = re.sub(
                    r'{{^permissions}}.*?{{/permissions}}',
                    '',
                    template_content,
                    flags=re.DOTALL
                )
            else:
                # No permissions - process the empty message
                template_content = re.sub(
                    r'{{#permissions}}.*?{{/permissions}}',
                    '',
                    template_content,
                    flags=re.DOTALL
                )
                # Keep the empty message
            
            return template_content
            
        except Exception as e:
            console.print(f"[red]Error processing permissions section:[/red] {str(e)}")
            if self.verbose:
                import traceback
                console.print(traceback.format_exc())
            return template_content
    
    def _cleanup_template_tags(self, content):
        """Remove any remaining template tags from the content"""
        # Remove any remaining template variables
        content = re.sub(r'{{\w+}}', '', content)
        
        # Remove any remaining conditional blocks
        content = re.sub(r'{{#.*?}}.*?{{/.*?}}', '', content, flags=re.DOTALL)
        content = re.sub(r'{{^.*?}}.*?{{/.*?}}', '', content, flags=re.DOTALL)
        
        # Remove any remaining template tags
        content = re.sub(r'{{.*?}}', '', content)
        
        return content
    
    def _get_severity_class(self, severity):
        """Get CSS class for severity level"""
        severity = str(severity).lower()
        if severity in ["critical", "high"]:
            return "high"
        elif severity == "medium":
            return "medium"
        elif severity == "low":
            return "low"
        else:
            return "info"
