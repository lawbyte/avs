# APK Vulnerability Scanner (AVS)

![Version](https://img.shields.io/badge/version-1.1.0-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-brightgreen)
![License](https://img.shields.io/badge/license-MIT-orange)

A comprehensive Android application security testing tool designed to identify vulnerabilities in APK files. The tool performs deep analysis using the Quark Engine and custom security checks to detect common security issues.

## Features

- **Comprehensive Vulnerability Scanning**: Analyzes APK files to identify potential security weaknesses
- **Detailed Evidence Collection**: Provides specific evidence of vulnerabilities, including method calls and parameters
- **Customizable HTML Reports**: Generates professional HTML reports with detailed findings and evidence
- **Basic Security Checks**: Identifies common security misconfigurations in Android apps
- **Permission Analysis**: Reviews and categorizes app permissions by security risk
- **Component Analysis**: Identifies potentially insecure app components

## Vulnerability Types Detected

The scanner detects numerous vulnerability types, including:

| Vulnerability Type | Description |
|-------------------|-------------|
| Path Traversal (CWE-22) | File access vulnerabilities that allow accessing files outside intended directories |
| Hardcoded Credentials (CWE-798) | Applications with embedded authentication credentials in source code |
| SSL/TLS Validation Issues (CWE-295) | Improper certificate validation leading to potential MITM attacks |
| Weak Encryption (CWE-327) | Usage of broken or weak cryptographic algorithms |
| Information Exposure (CWE-200) | Revealing sensitive information to unauthorized actors |
| Exported Components | Components with `exported=true` that could be accessed from other applications |
| Insecure Backup Configuration | Applications allowing backups that may expose sensitive data |
| Debuggable Applications | Apps with the `android:debuggable` flag enabled |
| Insecure Network Configuration | Applications with cleartext traffic enabled |
| Dangerous Permissions | High-risk permissions that could lead to privacy issues |

*Additional vulnerabilities are detected based on Quark Engine's rule set*

## Requirements

- Python 3.8 or higher
- Androguard
- Quark-Engine (optional, for enhanced detection)
- Rich (for console output styling)
- Other dependencies as specified in requirements.txt

## Installation

1. Clone the repository:
```bash
git clone https://github.com/lawbyte/avs.git
cd avs
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

3. (Optional) Install Quark Engine for advanced vulnerability detection:
```bash
pip install -U quark-engine
```

## Usage

### Scanning an APK for Vulnerabilities

```bash
python avs.py scan -f path/to/application.apk [-v]
```

Options:
- `-f, --file`: Path to the APK file (required)
- `-a, --json`: Custom output file for results in JSON format (optional)
- `-v, --verbose`: Enable verbose output (optional)

### Example Session

```bash
# Perform a basic scan
python avs.py scan -f target.apk

# Perform a scan with verbose output
python avs.py scan -f target.apk -v

# Specify a custom output file
python avs.py scan -f target.apk -a custom_output.json
```

## Reports

After scanning, the tool generates:

1. A JSON file with detailed scan results
2. An HTML report with an organized view of all findings
   - APK information (package name, version, etc.)
   - Summary of detected vulnerabilities
   - Detailed evidence for each vulnerability
   - Component analysis
   - Permission analysis

HTML reports are saved in the `reports` directory.

## Upcoming Features

- **Exploit Generator**: Create proof-of-concept exploits for detected vulnerabilities
- **Mitigation Advisor**: Get detailed remediation advice for identified issues
- **Dynamic Analysis**: Runtime behavior analysis for more accurate detection

## Note

This tool is designed for security researchers, penetration testers, and app developers. Please use it responsibly and only on applications you have permission to test.

## Acknowledgments

- [Androguard](https://github.com/androguard/androguard) for APK parsing and analysis
- [Quark Engine](https://github.com/quark-engine/quark-engine) for rule-based vulnerability detection
- [Rich](https://github.com/Textualize/rich) for beautiful terminal output

## License

MIT License

## Disclaimer

APK Vulnerability Scanner is a security tool designed for legitimate security research and testing. Users are responsible for complying with applicable laws and regulations. The authors assume no liability for misuse or damage caused by this tool.
