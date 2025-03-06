#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mitigator module for AVS
Provides mitigation strategies for identified vulnerabilities
"""

import os
import json
from rich.console import Console
from rich.table import Table
from rich.markdown import Markdown

console = Console()

class Mitigator:
    """Class to handle vulnerability mitigation strategies"""
    
    def __init__(self):
        """Initialize Mitigator with mitigation strategies"""
        self.results = None
        self.mitigation_strategies = {
            "intent_redirection": {
                "title": "Intent Redirection Mitigation",
                "description": "Mitigation strategies for Intent Redirection vulnerabilities",
                "strategies": [
                    "Always use explicit intents when sensitive data is being transferred",
                    "Implement proper validation of incoming intents",
                    "Use signature-level permissions for sensitive activities",
                    "Avoid putting sensitive data in intents that can be intercepted"
                ]
            },
            "insecure_file_permissions": {
                "title": "Insecure File Permissions Mitigation",
                "description": "Mitigation strategies for Insecure File Permissions",
                "strategies": [
                    "Use internal storage instead of external storage for sensitive data",
                    "Use the Context.MODE_PRIVATE flag when creating files",
                    "Avoid using MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE flags",
                    "Implement proper file access controls using FileProvider"
                ]
            },
            "sql_injection": {
                "title": "SQL Injection Mitigation",
                "description": "Mitigation strategies for SQL Injection vulnerabilities",
                "strategies": [
                    "Use parameterized queries with prepared statements",
                    "Avoid raw SQL queries with user-supplied input",
                    "Use SQLiteQueryBuilder instead of directly concatenating strings",
                    "Apply input validation and sanitization"
                ]
            },
            "webview_javascript": {
                "title": "WebView JavaScript Mitigation",
                "description": "Mitigation strategies for WebView JavaScript vulnerabilities",
                "strategies": [
                    "Disable JavaScript if not necessary: webView.getSettings().setJavaScriptEnabled(false)",
                    "Implement proper URL validation before loading content in WebViews",
                    "Use addJavascriptInterface() with caution and only on Android 4.2 (API 17) or higher",
                    "Implement a restrictive WebViewClient.shouldOverrideUrlLoading() method",
                    "Consider using SafeBrowsing API to protect against malicious URLs"
                ]
            },
            "weak_crypto": {
                "title": "Weak Cryptography Mitigation",
                "description": "Mitigation strategies for Weak Cryptography vulnerabilities",
                "strategies": [
                    "Use strong cryptographic algorithms (AES-256, RSA-2048 or higher)",
                    "Avoid MD5 and SHA-1 as they are considered broken",
                    "Use Android Keystore System to store cryptographic keys",
                    "Consider using the Security library in Jetpack for easier cryptography implementation",
                    "Use secure random number generators (SecureRandom)"
                ]
            },
            "hardcoded_secrets": {
                "title": "Hardcoded Secrets Mitigation",
                "description": "Mitigation strategies for Hardcoded Secrets vulnerabilities",
                "strategies": [
                    "Do not hardcode sensitive information in your application code",
                    "Use Android Keystore System to store sensitive keys",
                    "Consider using server-side authentication mechanisms",
                    "Implement obfuscation techniques for any API keys that must be included",
                    "Use BuildConfig or Gradle properties for API keys with proper obfuscation"
                ]
            },
            "data_leakage": {
                "title": "Data Leakage Mitigation",
                "description": "Mitigation strategies for Data Leakage vulnerabilities",
                "strategies": [
                    "Avoid logging sensitive information, especially in production builds",
                    "Use secure storage options for storing sensitive data",
                    "Implement proper clipboard handling for sensitive data",
                    "Clear sensitive data from memory when no longer needed",
                    "Use FLAG_SECURE for screens displaying sensitive information"
                ]
            },
            "broadcast_theft": {
                "title": "Broadcast Theft Mitigation",
                "description": "Mitigation strategies for Broadcast Theft vulnerabilities",
                "strategies": [
                    "Use LocalBroadcastManager for internal app communication",
                    "Implement proper permissions for sensitive broadcasts",
                    "Use explicit intents when broadcasting sensitive information",
                    "Consider using direct component-to-component communication instead of broadcasts",
                    "Encrypt sensitive data before broadcasting"
                ]
            },
            "exported_components": {
                "title": "Exported Components Mitigation",
                "description": "Mitigation strategies for Exported Components vulnerabilities",
                "strategies": [
                    "Set android:exported=\"false\" for components that don't need to be accessed by other apps",
                    "For components that must be exported, implement proper permission checks",
                    "Validate all inputs received by exported components",
                    "Use custom permissions with protectionLevel=\"signature\" for sensitive components",
                    "Consider using Intent filters only when absolutely necessary"
                ]
            },
            "path_traversal": {
                "title": "Path Traversal Mitigation",
                "description": "Mitigation strategies for Path Traversal vulnerabilities",
                "strategies": [
                    "Validate and sanitize all file paths provided by users or external sources",
                    "Use ContentProvider or FileProvider instead of direct file access",
                    "Restrict file operations to a specific directory",
                    "Implement proper input validation to prevent path manipulation",
                    "Avoid using user input directly in file operations"
                ]
            }
        }
    
    def load_from_file(self, file_path):
        """Load vulnerability results from a file"""
        try:
            with open(file_path, 'r') as f:
                self.results = json.load(f)
            console.print(f"[bold green]Loaded results from:[/bold green] {file_path}")
        except Exception as e:
            console.print(f"[bold red]Error loading results file: {str(e)}[/bold red]")
    
    def show_mitigation(self, vulnerability_type):
        """Show mitigation strategies for a specific vulnerability type"""
        if vulnerability_type not in self.mitigation_strategies:
            console.print(f"[bold red]Error:[/bold red] Unknown vulnerability type: {vulnerability_type}")
            console.print(f"[bold blue]Available vulnerability types:[/bold blue] {', '.join(self.mitigation_strategies.keys())}")
            return
        
        mitigation = self.mitigation_strategies[vulnerability_type]
        
        console.print(f"[bold green]{mitigation['title']}[/bold green]")
        console.print(f"[italic]{mitigation['description']}[/italic]\n")
        
        table = Table(title="Mitigation Strategies")
        table.add_column("Strategy", style="cyan")
        
        for strategy in mitigation['strategies']:
            table.add_row(strategy)
        
        console.print(table)
        
        # Show code examples if available (not implemented in this version)
        console.print("\n[bold blue]For more detailed guidance, please refer to OWASP Mobile Top 10 and Android Security Best Practices.[/bold blue]")
    
    def show_all_mitigations(self):
        """Show mitigation strategies for all vulnerabilities identified in results"""
        if not self.results:
            console.print("[bold yellow]No scan results loaded. Please provide a results file or specify a vulnerability type.[/bold yellow]")
            return
        
        found_vulnerabilities = []
        
        # Extract vulnerability types from results
        if "vulnerabilities" in self.results:
            for vulnerability in self.results["vulnerabilities"]:
                if "type" in vulnerability:
                    found_vulnerabilities.append(vulnerability["type"])
        
        if not found_vulnerabilities:
            console.print("[bold yellow]No vulnerabilities found in the results file.[/bold yellow]")
            return
        
        # Show mitigation for each found vulnerability
        for vuln_type in found_vulnerabilities:
            self.show_mitigation(vuln_type)
            console.print("\n" + "-" * 80 + "\n")
