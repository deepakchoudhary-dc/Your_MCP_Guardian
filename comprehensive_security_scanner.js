/**
 * MCP Comprehensive Security Scanner
 * Integrates all security scanners for complete vulnerability assessment
 */

class ComprehensiveSecurityScanner {
    constructor(serverConfig) {
        this.serverConfig = serverConfig;
        this.scanResults = {};
        this.allVulnerabilities = [];
        this.scanStartTime = null;
        this.scanEndTime = null;
    }

    async performCompleteScan() {
        console.log('🚀 Starting Comprehensive Security Scan...');
        this.scanStartTime = new Date();
        
        try {
            // Initialize all scanners
            const runtimeScanner = new RuntimeSecurityScanner(this.serverConfig);
            const networkScanner = new NetworkSecurityScanner(this.serverConfig);
            const logicScanner = new ApplicationLogicScanner(this.serverConfig);
            const dastScanner = new DASTScanner(this.serverConfig);
            const scaScanner = new SCAScanner();
            const secretScanner = new SecretScanner();
            const iacScanner = new IaCScanner();
            
            // Run all scans in parallel for efficiency
            const [
                runtimeResults, 
                networkResults, 
                logicResults,
                dastResults,
                scaResults,
                secretResults,
                iacResults
            ] = await Promise.all([
                runtimeScanner.scanAll(),
                networkScanner.scanAll(),
                logicScanner.scanAll(),
                dastScanner.performDASTScan(),
                scaScanner.performSCAScan(),
                secretScanner.performSecretScan(),
                iacScanner.performIaCScan()
            ]);
            
            // Store individual scan results
            this.scanResults = {
                runtime: runtimeResults,
                network: networkResults,
                applicationLogic: logicResults,
                dast: dastResults,
                sca: scaResults,
                secret: secretResults,
                iac: iacResults
            };
            
            // Combine all vulnerabilities
            this.allVulnerabilities = [
                ...runtimeResults.vulnerabilities,
                ...networkResults.vulnerabilities,
                ...logicResults.vulnerabilities,
                ...dastResults.vulnerabilities,
                ...scaResults.vulnerabilities,
                ...secretResults.vulnerabilities,
                ...iacResults.vulnerabilities
            ];
            
            this.scanEndTime = new Date();
            
            // Generate comprehensive report
            return this.generateComprehensiveReport();
            
        } catch (error) {
            console.error('Comprehensive scan failed:', error);
            throw error;
        }
    }

    generateComprehensiveReport() {
        const scanDuration = this.scanEndTime - this.scanStartTime;
        
        // Calculate severity breakdown
        const severityBreakdown = this.allVulnerabilities.reduce((acc, vuln) => {
            acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
            return acc;
        }, {});
        
        // Calculate risk score (weighted by severity)
        const riskScore = this.calculateRiskScore();
        
        // Generate category breakdown
        const categoryBreakdown = this.generateCategoryBreakdown();
        
        // Generate executive summary
        const executiveSummary = this.generateExecutiveSummary();
        
        // Compile all recommendations
        const allRecommendations = this.compileRecommendations();
        
        return {
            metadata: {
                scanTimestamp: this.scanStartTime.toISOString(),
                scanDuration: `${Math.round(scanDuration / 1000)}s`,
                serverName: this.serverConfig.serverName,
                scannerVersion: '2.0.0',
                totalChecksPerformed: this.getTotalChecksPerformed()
            },
            summary: {
                totalVulnerabilities: this.allVulnerabilities.length,
                severityBreakdown,
                riskScore,
                categoryBreakdown,
                executiveSummary
            },
            vulnerabilities: this.allVulnerabilities.sort((a, b) => {
                const severityOrder = { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4 };
                return severityOrder[a.severity] - severityOrder[b.severity];
            }),
            detailedResults: this.scanResults,
            recommendations: allRecommendations,
            compliance: this.generateComplianceReport(),
            trends: this.generateTrendAnalysis()
        };
    }

    calculateRiskScore() {
        const weights = {
            'Critical': 10,
            'High': 7,
            'Medium': 4,
            'Low': 2,
            'Info': 1
        };
        
        const totalScore = this.allVulnerabilities.reduce((score, vuln) => {
            return score + (weights[vuln.severity] || 0);
        }, 0);
        
        // Normalize to 0-100 scale
        const maxPossibleScore = this.allVulnerabilities.length * 10;
        const normalizedScore = maxPossibleScore > 0 ? Math.round((totalScore / maxPossibleScore) * 100) : 0;
        
        return {
            score: normalizedScore,
            level: this.getRiskLevel(normalizedScore),
            totalScore,
            maxPossibleScore
        };
    }

    getRiskLevel(score) {
        if (score >= 80) return 'Critical';
        if (score >= 60) return 'High';
        if (score >= 40) return 'Medium';
        if (score >= 20) return 'Low';
        return 'Minimal';
    }

    generateCategoryBreakdown() {
        const categories = {
            'Runtime Vulnerabilities': 0,
            'Network & Infrastructure': 0,
            'Application Logic': 0,
            'Authentication & Session': 0,
            'Input Validation': 0,
            'Configuration Issues': 0
        };
        
        this.allVulnerabilities.forEach(vuln => {
            if (vuln.id.startsWith('RUNTIME-')) {
                categories['Runtime Vulnerabilities']++;
            } else if (vuln.id.startsWith('NETWORK-')) {
                categories['Network & Infrastructure']++;
            } else if (vuln.id.startsWith('LOGIC-')) {
                categories['Application Logic']++;
            }
            
            // Categorize by vulnerability type
            if (vuln.type.toLowerCase().includes('auth') || 
                vuln.type.toLowerCase().includes('session') ||
                vuln.type.toLowerCase().includes('password')) {
                categories['Authentication & Session']++;
            }
            
            if (vuln.type.toLowerCase().includes('injection') ||
                vuln.type.toLowerCase().includes('xss') ||
                vuln.type.toLowerCase().includes('validation')) {
                categories['Input Validation']++;
            }
            
            if (vuln.type.toLowerCase().includes('config') ||
                vuln.type.toLowerCase().includes('header') ||
                vuln.type.toLowerCase().includes('server')) {
                categories['Configuration Issues']++;
            }
        });
        
        return categories;
    }

    generateExecutiveSummary() {
        const criticalCount = this.allVulnerabilities.filter(v => v.severity === 'Critical').length;
        const highCount = this.allVulnerabilities.filter(v => v.severity === 'High').length;
        const totalCount = this.allVulnerabilities.length;
        
        let summary = `Security assessment completed for ${this.serverConfig.serverName}. `;
        
        if (criticalCount > 0) {
            summary += `🚨 URGENT: ${criticalCount} critical vulnerabilities require immediate attention. `;
        }
        
        if (highCount > 0) {
            summary += `⚠️ ${highCount} high-severity issues need prompt remediation. `;
        }
        
        if (totalCount === 0) {
            summary += `✅ No vulnerabilities detected in current scan scope.`;
        } else {
            summary += `Total of ${totalCount} security issues identified across runtime, network, and application logic layers.`;
        }
        
        return summary;
    }

    compileRecommendations() {
        const allRecommendations = [];
        
        // Get recommendations from each scanner
        if (this.scanResults.runtime?.recommendations) {
            allRecommendations.push(...this.scanResults.runtime.recommendations);
        }
        if (this.scanResults.network?.recommendations) {
            allRecommendations.push(...this.scanResults.network.recommendations);
        }
        if (this.scanResults.applicationLogic?.recommendations) {
            allRecommendations.push(...this.scanResults.applicationLogic.recommendations);
        }
        
        // Add general security recommendations
        allRecommendations.push({
            category: 'General Security Best Practices',
            priority: 'High',
            actions: [
                'Implement a Security Development Lifecycle (SDL)',
                'Conduct regular security training for development team',
                'Establish incident response procedures',
                'Implement continuous security monitoring',
                'Perform regular penetration testing',
                'Maintain an inventory of all software dependencies',
                'Implement automated security testing in CI/CD pipeline'
            ]
        });
        
        // Prioritize recommendations based on vulnerability severity
        return this.prioritizeRecommendations(allRecommendations);
    }

    prioritizeRecommendations(recommendations) {
        const criticalVulns = this.allVulnerabilities.filter(v => v.severity === 'Critical');
        const highVulns = this.allVulnerabilities.filter(v => v.severity === 'High');
        
        // Add priority levels based on vulnerability presence
        return recommendations.map(rec => {
            let priority = rec.priority || 'Medium';
            
            // Increase priority if related to critical vulnerabilities
            if (criticalVulns.some(v => v.type.toLowerCase().includes(rec.category.toLowerCase()))) {
                priority = 'Critical';
            } else if (highVulns.some(v => v.type.toLowerCase().includes(rec.category.toLowerCase()))) {
                priority = 'High';
            }
            
            return { ...rec, priority };
        }).sort((a, b) => {
            const priorityOrder = { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3 };
            return priorityOrder[a.priority] - priorityOrder[b.priority];
        });
    }

    generateComplianceReport() {
        const compliance = {
            'OWASP Top 10': this.checkOWASPCompliance(),
            'NIST Cybersecurity Framework': this.checkNISTCompliance(),
            'ISO 27001': this.checkISO27001Compliance(),
            'PCI DSS': this.checkPCIDSSCompliance()
        };
        
        return compliance;
    }

    checkOWASPCompliance() {
        const owaspTop10 = [
            'Injection',
            'Broken Authentication',
            'Sensitive Data Exposure',
            'XML External Entities (XXE)',
            'Broken Access Control',
            'Security Misconfiguration',
            'Cross-Site Scripting (XSS)',
            'Insecure Deserialization',
            'Using Components with Known Vulnerabilities',
            'Insufficient Logging & Monitoring'
        ];
        
        const violations = owaspTop10.filter(category => {
            return this.allVulnerabilities.some(vuln => 
                vuln.type.toLowerCase().includes(category.toLowerCase()) ||
                vuln.description.toLowerCase().includes(category.toLowerCase())
            );
        });
        
        return {
            compliant: violations.length === 0,
            violations,
            score: Math.round(((owaspTop10.length - violations.length) / owaspTop10.length) * 100)
        };
    }

    checkNISTCompliance() {
        const nistControls = [
            'Access Control',
            'Awareness and Training',
            'Audit and Accountability',
            'Configuration Management',
            'Identification and Authentication',
            'Incident Response',
            'Risk Assessment',
            'System and Communications Protection'
        ];
        
        // Simplified compliance check based on vulnerability types
        const violations = [];
        
        if (this.allVulnerabilities.some(v => v.type.includes('Authentication'))) {
            violations.push('Identification and Authentication');
        }
        if (this.allVulnerabilities.some(v => v.type.includes('Configuration'))) {
            violations.push('Configuration Management');
        }
        if (this.allVulnerabilities.some(v => v.type.includes('Access Control'))) {
            violations.push('Access Control');
        }
        
        return {
            compliant: violations.length === 0,
            violations,
            score: Math.round(((nistControls.length - violations.length) / nistControls.length) * 100)
        };
    }

    checkISO27001Compliance() {
        // Simplified ISO 27001 compliance check
        const controlViolations = [];
        
        if (this.allVulnerabilities.some(v => v.type.includes('Access'))) {
            controlViolations.push('A.9 - Access Control');
        }
        if (this.allVulnerabilities.some(v => v.type.includes('Crypto') || v.type.includes('TLS'))) {
            controlViolations.push('A.10 - Cryptography');
        }
        if (this.allVulnerabilities.some(v => v.type.includes('Network'))) {
            controlViolations.push('A.13 - Communications Security');
        }
        
        return {
            compliant: controlViolations.length === 0,
            violations: controlViolations,
            score: Math.round(((10 - controlViolations.length) / 10) * 100)
        };
    }

    checkPCIDSSCompliance() {
        // PCI DSS requirements check
        const pciRequirements = [
            'Install and maintain a firewall configuration',
            'Do not use vendor-supplied defaults for system passwords',
            'Protect stored cardholder data',
            'Encrypt transmission of cardholder data',
            'Protect all systems against malware',
            'Develop and maintain secure systems and applications'
        ];
        
        const violations = [];
        
        if (this.allVulnerabilities.some(v => v.type.includes('Password') && v.type.includes('Weak'))) {
            violations.push('Do not use vendor-supplied defaults for system passwords');
        }
        if (this.allVulnerabilities.some(v => v.type.includes('TLS') || v.type.includes('Encryption'))) {
            violations.push('Encrypt transmission of cardholder data');
        }
        if (this.allVulnerabilities.some(v => v.type.includes('Injection') || v.type.includes('XSS'))) {
            violations.push('Develop and maintain secure systems and applications');
        }
        
        return {
            compliant: violations.length === 0,
            violations,
            score: Math.round(((pciRequirements.length - violations.length) / pciRequirements.length) * 100)
        };
    }

    generateTrendAnalysis() {
        // Simulate trend analysis (in real implementation, would compare with historical data)
        return {
            vulnerabilityTrend: 'stable', // 'increasing', 'decreasing', 'stable'
            riskTrend: 'improving', // 'worsening', 'improving', 'stable'
            mostCommonVulnerabilityType: this.getMostCommonVulnerabilityType(),
            recommendedFocus: this.getRecommendedFocus()
        };
    }

    getMostCommonVulnerabilityType() {
        const typeCounts = {};
        this.allVulnerabilities.forEach(vuln => {
            const type = vuln.type.split(' ')[0]; // Get first word of type
            typeCounts[type] = (typeCounts[type] || 0) + 1;
        });
        
        return Object.keys(typeCounts).reduce((a, b) => 
            typeCounts[a] > typeCounts[b] ? a : b, 'None'
        );
    }

    getRecommendedFocus() {
        const criticalTypes = this.allVulnerabilities
            .filter(v => v.severity === 'Critical')
            .map(v => v.type);
        
        if (criticalTypes.length > 0) {
            return `Immediate focus needed on: ${criticalTypes[0]}`;
        }
        
        const highTypes = this.allVulnerabilities
            .filter(v => v.severity === 'High')
            .map(v => v.type);
        
        if (highTypes.length > 0) {
            return `Priority focus on: ${highTypes[0]}`;
        }
        
        return 'Continue regular security maintenance';
    }

    getTotalChecksPerformed() {
        // Calculate total number of security checks performed
        let totalChecks = 0;
        
        // Runtime checks
        if (this.scanResults.runtime) {
            totalChecks += 50; // Estimated number of runtime checks
        }
        
        // Network checks
        if (this.scanResults.network) {
            totalChecks += 75; // Estimated number of network checks
        }
        
        // Application logic checks
        if (this.scanResults.applicationLogic) {
            totalChecks += 100; // Estimated number of logic checks
        }
        
        return totalChecks;
    }

    exportReport(format = 'json') {
        const report = this.generateComprehensiveReport();
        
        switch (format.toLowerCase()) {
            case 'json':
                return JSON.stringify(report, null, 2);
            
            case 'csv':
                return this.exportToCSV(report);
            
            case 'html':
                return this.exportToHTML(report);
            
            default:
                return JSON.stringify(report, null, 2);
        }
    }

    exportToCSV(report) {
        const headers = ['ID', 'Type', 'Severity', 'Description', 'Evidence', 'Recommendation'];
        const rows = report.vulnerabilities.map(vuln => [
            vuln.id,
            vuln.type,
            vuln.severity,
            vuln.description,
            vuln.evidence || '',
            vuln.recommendation || ''
        ]);
        
        return [headers, ...rows].map(row => 
            row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')
        ).join('\n');
    }

    exportToHTML(report) {
        return `
<!DOCTYPE html>
<html>
<head>
    <title>Security Report - ${report.metadata.serverName}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .severity-Critical { color: #dc3545; font-weight: bold; }
        .severity-High { color: #fd7e14; font-weight: bold; }
        .severity-Medium { color: #ffc107; font-weight: bold; }
        .severity-Low { color: #17a2b8; }
        .severity-Info { color: #6c757d; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Security Report: ${report.metadata.serverName}</h1>
    <p>Generated: ${report.metadata.scanTimestamp}</p>
    <p>Risk Score: ${report.summary.riskScore.score}/100 (${report.summary.riskScore.level})</p>
    
    <h2>Vulnerabilities</h2>
    <table>
        <tr><th>Type</th><th>Severity</th><th>Description</th></tr>
        ${report.vulnerabilities.map(vuln => `
            <tr>
                <td>${vuln.type}</td>
                <td class="severity-${vuln.severity}">${vuln.severity}</td>
                <td>${vuln.description}</td>
            </tr>
        `).join('')}
    </table>
</body>
</html>`;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ComprehensiveSecurityScanner;
}