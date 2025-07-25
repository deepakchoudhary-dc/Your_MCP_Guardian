# MCP Comprehensive Security Scanner

A complete security testing suite for Model Context Protocol (MCP) servers that addresses all major vulnerability categories including runtime, network, and application logic flaws.

## 🚀 Features

### Static Analysis
- **CVE Detection**: Identifies known vulnerabilities (CVE-2025-49596, CVE-2025-6514, etc.)
- **Tool Poisoning Detection**: Detects malicious functionality in tool descriptions
- **Command Injection**: Identifies dangerous `child_process.exec` usage
- **SSRF Vulnerabilities**: Finds unvalidated URL parameters
- **SQL Injection**: Detects unsafe database query patterns
- **OAuth Security**: Validates permission scopes and privilege escalation risks

### Runtime Vulnerability Testing
- **Buffer Overflow Detection**: Tests with various payload sizes and formats
- **Race Condition Testing**: Concurrent request analysis for state corruption
- **Insecure Deserialization**: Tests multiple serialization attack vectors
- **Error Handling Analysis**: Identifies information disclosure in error messages

### Network & Infrastructure Security
- **Man-in-the-Middle (MitM) Protection**: SSL/TLS configuration testing
- **DoS/Rate Limiting**: Stress testing and rate limit validation
- **HTTP Security Headers**: Comprehensive header security analysis
- **DNS Security**: DNSSEC and DNS-over-HTTPS testing
- **Database Backup Security**: Exposed backup file detection
- **Server Configuration**: Information disclosure and debug endpoint testing

### Application Logic Security
- **Clickjacking Protection**: Frame options and CSP validation
- **Session Management**: Cookie security, fixation, and timeout testing
- **Authentication Security**: Brute force protection and MFA validation
- **Password Policies**: Strength requirements and recovery mechanisms
- **Business Logic Flaws**: Price manipulation, workflow bypass, privilege escalation

## 📁 File Structure

```
e:\MCP\
├── mcp_security_hub.html              # Main web interface
├── runtime_security_scanner.js        # Runtime vulnerability testing
├── network_security_scanner.js        # Network and infrastructure testing
├── application_logic_scanner.js       # Application logic flaw testing
├── dast_scanner.js                    # Dynamic Application Security Testing
├── sca_scanner.js                     # Software Composition Analysis
├── secret_scanner.js                  # Secret and credential detection
├── iac_scanner.js                     # Infrastructure as Code scanning
├── security_dashboard.js              # Centralized dashboard and database
├── comprehensive_security_scanner.js  # Integrated scanner coordinator
└── README.md                          # This documentation
```

## 🛠️ Usage

### Quick Start
1. Open `mcp_security_hub.html` in a web browser
2. Configure your MCP server details:
   - **Server Name**: Identifier for your server
   - **Tools JSON**: Your MCP tool definitions
   - **OAuth Scopes**: Space-separated permission scopes
3. Click "Analyze Server" to run comprehensive scan
4. Review findings and generate AI-powered solutions

### Example Tool Configuration
```json
[{
    "name": "run_command",
    "description": "Executes a system command using child_process.exec",
    "parameters": { "cmd": "string" }
}, {
    "name": "fetch_internal_data",
    "description": "Fetches data from an internal URL",
    "parameters": { "url": "string" }
}, {
    "name": "update_user_settings",
    "description": "Updates user profile settings",
    "parameters": { "settings": "object" }
}]
```

## 🔍 Vulnerability Categories Tested

### Critical Vulnerabilities
- **Command Injection** (CVE-2025-53818)
- **Tool Poisoning** (CVE-2025-49596)
- **SQL Injection** (GHSA-sqlite-MCP-issue)
- **Remote Code Execution** (GEN-RCE)
- **Insecure Deserialization** (GEN-Deserialization)
- **Buffer Overflow** (Runtime testing)
- **Excessive Permissions** (AUTH-ExcessivePerms)

### High Severity Issues
- **SSRF** (CVE-2025-53355)
- **Path Traversal** (CVE-2025-53109)
- **Cross-Site Scripting** (GEN-XSS)
- **Privilege Escalation** (AUTH-PrivEscalation)
- **Race Conditions** (Runtime testing)
- **Weak TLS Configuration** (Network testing)
- **Session Management Flaws** (Logic testing)

### Medium/Low Priority
- **Information Disclosure** (GEN-InfoDisclosure)
- **Missing Security Headers** (Network testing)
- **Weak Password Policies** (Logic testing)
- **DNS Security Issues** (Network testing)

## 📊 Report Features

### Executive Summary
- **Risk Score**: 0-100 scale with severity classification
- **Vulnerability Breakdown**: Count by severity level
- **Category Analysis**: Issues grouped by type
- **Executive Summary**: High-level assessment narrative

### Compliance Reporting
- **OWASP Top 10**: Compliance percentage and violations
- **NIST Cybersecurity Framework**: Control assessment
- **ISO 27001**: Security control evaluation
- **PCI DSS**: Payment security requirements

### Detailed Findings
- **Vulnerability Details**: Description, evidence, recommendations
- **AI-Powered Solutions**: Generated mitigation strategies
- **Priority Recommendations**: Actionable remediation steps
- **Trend Analysis**: Historical comparison and focus areas

## 🔧 Technical Implementation

### Scanner Architecture
```
ComprehensiveSecurityScanner
├── RuntimeSecurityScanner
│   ├── Buffer Overflow Testing
│   ├── Race Condition Detection
│   ├── Deserialization Testing
│   └── Error Handling Analysis
├── NetworkSecurityScanner
│   ├── TLS/SSL Testing
│   ├── DoS Protection Testing
│   ├── Security Headers Analysis
│   ├── DNS Security Testing
│   └── Server Configuration Review
└── ApplicationLogicScanner
    ├── Clickjacking Protection
    ├── Session Management Testing
    ├── Authentication Security
    ├── Password Policy Validation
    └── Business Logic Testing
```

### Key Testing Methods

#### Runtime Testing
- **Concurrent Requests**: 50+ simultaneous requests for race conditions
- **Payload Fuzzing**: 1KB to 1MB payloads for buffer overflows
- **Serialization Attacks**: JSON, XML, Python pickle, PHP objects
- **Error Injection**: Null, undefined, malformed inputs

#### Network Testing
- **SSL/TLS Analysis**: Protocol versions, cipher suites, certificates
- **Rate Limiting**: Burst testing with 100+ requests
- **Header Analysis**: 6+ critical security headers
- **Backup Discovery**: 12+ common backup file patterns

#### Logic Testing
- **Session Analysis**: Cookie security, fixation, timeouts
- **Authentication**: Brute force, MFA, password policies
- **Business Logic**: Price manipulation, workflow bypass
- **Authorization**: Horizontal/vertical privilege escalation

## 🛡️ Security Best Practices

### Immediate Actions for Critical Findings
1. **Command Injection**: Remove `child_process.exec` usage
2. **SQL Injection**: Implement parameterized queries
3. **Tool Poisoning**: Review all tool descriptions for malicious content
4. **Buffer Overflow**: Add input length validation
5. **Excessive Permissions**: Apply principle of least privilege

### Network Security Hardening
1. **Enable HTTPS**: Use TLS 1.2+ with strong cipher suites
2. **Security Headers**: Implement HSTS, CSP, X-Frame-Options
3. **Rate Limiting**: 10 requests/second per IP recommended
4. **DNS Security**: Enable DNSSEC and DNS-over-HTTPS

### Application Security
1. **Session Management**: HttpOnly, Secure, SameSite cookies
2. **Authentication**: Multi-factor authentication required
3. **Input Validation**: Server-side validation for all inputs
4. **Error Handling**: Generic error messages, detailed server logs

## 🔄 Continuous Security

### Integration Options
- **CI/CD Pipeline**: Automated security testing
- **Monitoring**: Real-time vulnerability detection
- **Dependency Scanning**: Regular library vulnerability checks
- **Penetration Testing**: Quarterly manual security assessments

### Recommended Tools
- **SAST**: SonarQube, Checkmarx, Veracode
- **DAST**: OWASP ZAP, Burp Suite, Nessus
- **Dependency**: Snyk, Dependabot, Safety CLI
- **Infrastructure**: Nmap, SSLyze, Qualys SSL Labs

## 📈 Metrics and KPIs

### Security Metrics
- **Vulnerability Density**: Issues per 1000 lines of code
- **Mean Time to Remediation**: Average fix time by severity
- **Security Test Coverage**: Percentage of code/endpoints tested
- **Compliance Score**: Percentage compliance with standards

### Trending Analysis
- **Vulnerability Trends**: Month-over-month comparison
- **Risk Score Evolution**: Historical risk assessment
- **Category Focus**: Most common vulnerability types
- **Remediation Effectiveness**: Fix success rates

## 🤝 Contributing

This security scanner is designed to be extensible. To add new vulnerability checks:

1. **Static Checks**: Add to `VULNERABILITY_CHECKS` array
2. **Runtime Tests**: Extend `RuntimeSecurityScanner` class
3. **Network Tests**: Add methods to `NetworkSecurityScanner`
4. **Logic Tests**: Implement in `ApplicationLogicScanner`

## 📄 License

This security testing suite is provided for educational and security assessment purposes. Use responsibly and only on systems you own or have explicit permission to test.

## 🆘 Support

For security issues or questions:
- Review the generated recommendations
- Use the AI-powered solution generator
- Consult OWASP guidelines for specific vulnerabilities
- Consider professional security assessment for critical systems

---

**⚠️ Important**: This tool performs simulated attacks and security testing. Only use on systems you own or have explicit permission to test. The authors are not responsible for any misuse or damage caused by this tool.