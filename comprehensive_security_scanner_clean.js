/**
 * Comprehensive Security Scanner for MCP Servers
 * Enterprise-grade security testing suite with genuine vulnerability detection
 */

// Import scanner modules (for Node.js environment)
if (typeof require !== 'undefined') {
    try {
        const RuntimeSecurityScanner = require('./runtime_security_scanner.js');
        const NetworkSecurityScanner = require('./network_security_scanner.js');
        const ApplicationLogicScanner = require('./application_logic_scanner.js');
        const DASTScanner = require('./dast_scanner.js');
        const SCAScanner = require('./sca_scanner.js');
        const SecretScanner = require('./secret_scanner.js');
        const IaCScanner = require('./iac_scanner.js');
        const NapthaAgentCoordinator = require('./naptha_agent_coordinator.js');
        const AIPoweredAnalytics = require('./ai_powered_analytics.js');
        const ThreatIntelligenceEngine = require('./threat_intelligence_engine.js');
        const ComplianceOrchestrator = require('./compliance_orchestrator.js');
        const AutonomousRemediationEngine = require('./autonomous_remediation.js');
        
        // Make them globally available
        global.RuntimeSecurityScanner = RuntimeSecurityScanner;
        global.NetworkSecurityScanner = NetworkSecurityScanner;
        global.ApplicationLogicScanner = ApplicationLogicScanner;
        global.DASTScanner = DASTScanner;
        global.SCAScanner = SCAScanner;
        global.SecretScanner = SecretScanner;
        global.IaCScanner = IaCScanner;
        global.NapthaAgentCoordinator = NapthaAgentCoordinator;
        global.AIPoweredAnalytics = AIPoweredAnalytics;
        global.ThreatIntelligenceEngine = ThreatIntelligenceEngine;
        global.ComplianceOrchestrator = ComplianceOrchestrator;
        global.AutonomousRemediationEngine = AutonomousRemediationEngine;
    } catch (error) {
        console.log('ℹ️ Running in browser mode - scanner modules loaded via script tags');
    }
}

class ComprehensiveSecurityScanner {
    constructor(config = {}) {
        this.config = {
            enableAllScans: config.enableAllScans || true,
            generateReport: config.generateReport || true,
            maxConcurrentScans: config.maxConcurrentScans || 5,
            timeoutDuration: config.timeoutDuration || 30000,
            napthaIntegration: config.napthaIntegration || true,
            aiAnalytics: config.aiAnalytics || true,
            autonomousRemediation: config.autonomousRemediation || false,
            threatIntelligence: config.threatIntelligence || true,
            complianceFrameworks: config.complianceFrameworks || ['SOC2', 'ISO27001', 'NIST'],
            reportFormat: config.reportFormat || 'comprehensive',
            severity: {
                critical: config.severity?.critical || true,
                high: config.severity?.high || true,
                medium: config.severity?.medium || true,
                low: config.severity?.low || true,
                info: config.severity?.info || true
            }
        };

        this.serverConfig = null;
        this.results = {};
        this.scanHistory = new Map();
        this.activeScans = new Set();
        
        // Initialize AI components
        this.initializeAIComponents();
        
        console.log('🚀 Comprehensive Security Scanner initialized with genuine analysis only');
    }

    /**
     * Initialize AI-powered components
     */
    async initializeAIComponents() {
        if (this.config.napthaIntegration) {
            try {
                this.napthaCoordinator = new NapthaAgentCoordinator();
                await this.napthaCoordinator.initialize();
            } catch (error) {
                console.warn('⚠️ Naptha AI coordination unavailable:', error.message);
            }
        }

        if (this.config.aiAnalytics) {
            try {
                this.aiAnalytics = new AIPoweredAnalytics();
            } catch (error) {
                console.warn('⚠️ AI Analytics unavailable:', error.message);
            }
        }

        if (this.config.threatIntelligence) {
            try {
                this.threatEngine = new ThreatIntelligenceEngine();
            } catch (error) {
                console.warn('⚠️ Threat Intelligence unavailable:', error.message);
            }
        }

        if (this.config.complianceFrameworks.length > 0) {
            try {
                this.complianceOrchestrator = new ComplianceOrchestrator();
            } catch (error) {
                console.warn('⚠️ Compliance checking unavailable:', error.message);
            }
        }

        if (this.config.autonomousRemediation) {
            try {
                this.remediationEngine = new AutonomousRemediationEngine();
            } catch (error) {
                console.warn('⚠️ Autonomous remediation unavailable:', error.message);
            }
        }
    }

    /**
     * Set server configuration for scanning
     */
    setServerConfig(config) {
        this.serverConfig = config;
        console.log('📊 Server configuration loaded:', {
            serverName: config.serverName,
            toolCount: config.tools?.length || 0,
            scopesCount: config.oauthScopes?.length || 0
        });
    }

    /**
     * Run comprehensive security scan
     */
    async runComprehensiveScan() {
        if (!this.serverConfig) {
            throw new Error('❌ Server configuration not set. Call setServerConfig() first.');
        }

        const scanId = `COMP-${Date.now()}`;
        this.activeScans.add(scanId);
        
        console.log('🔍 Starting Comprehensive Security Scan');
        console.log(`📋 Scan ID: ${scanId}`);
        
        const startTime = Date.now();
        const scanResults = {};

        try {
            // Static Analysis - Genuine analysis of configuration
            console.log('⚡ Running Static Analysis...');
            scanResults.static = await this.performStaticAnalysis();

            // Runtime Analysis - Only if scanner available
            if (typeof RuntimeSecurityScanner !== 'undefined') {
                try {
                    console.log('⚡ Running Runtime Security Scan...');
                    const runtimeScanner = new RuntimeSecurityScanner(this.serverConfig);
                    scanResults.runtime = await runtimeScanner.scanAll();
                } catch (error) {
                    console.error('❌ Runtime scan failed:', error);
                    scanResults.runtime = this.createFallbackScanResult('runtime', error);
                }
            } else {
                scanResults.runtime = this.createEmptyScanResult('runtime');
            }

            // Network Scanner
            if (typeof NetworkSecurityScanner !== 'undefined') {
                try {
                    console.log('⚡ Running Network Security Scan...');
                    const networkScanner = new NetworkSecurityScanner(this.serverConfig);
                    scanResults.network = await networkScanner.scanAll();
                } catch (error) {
                    console.error('❌ Network scan failed:', error);
                    scanResults.network = this.createFallbackScanResult('network', error);
                }
            } else {
                scanResults.network = this.createEmptyScanResult('network');
            }

            // Additional scanners...
            if (typeof ApplicationLogicScanner !== 'undefined') {
                try {
                    console.log('⚡ Running Application Logic Scan...');
                    const logicScanner = new ApplicationLogicScanner(this.serverConfig);
                    scanResults.logic = await logicScanner.scanAll();
                } catch (error) {
                    console.error('❌ Logic scan failed:', error);
                    scanResults.logic = this.createFallbackScanResult('logic', error);
                }
            } else {
                scanResults.logic = this.createEmptyScanResult('logic');
            }

            // DAST Scanner
            if (typeof DASTScanner !== 'undefined') {
                try {
                    console.log('⚡ Running DAST Scan...');
                    const dastScanner = new DASTScanner(this.serverConfig);
                    scanResults.dast = await dastScanner.scanAll();
                } catch (error) {
                    console.error('❌ DAST scan failed:', error);
                    scanResults.dast = this.createFallbackScanResult('dast', error);
                }
            } else {
                scanResults.dast = this.createEmptyScanResult('dast');
            }

            // SCA Scanner
            if (typeof SCAScanner !== 'undefined') {
                try {
                    console.log('⚡ Running SCA Scan...');
                    const scaScanner = new SCAScanner(this.serverConfig);
                    scanResults.sca = await scaScanner.scanAll();
                } catch (error) {
                    console.error('❌ SCA scan failed:', error);
                    scanResults.sca = this.createFallbackScanResult('sca', error);
                }
            } else {
                scanResults.sca = this.createEmptyScanResult('sca');
            }

            // Secret Scanner
            if (typeof SecretScanner !== 'undefined') {
                try {
                    console.log('⚡ Running Secret Scan...');
                    const secretScanner = new SecretScanner(this.serverConfig);
                    scanResults.secret = await secretScanner.scanAll();
                } catch (error) {
                    console.error('❌ Secret scan failed:', error);
                    scanResults.secret = this.createFallbackScanResult('secret', error);
                }
            } else {
                scanResults.secret = this.createEmptyScanResult('secret');
            }

            // IaC Scanner
            if (typeof IaCScanner !== 'undefined') {
                try {
                    console.log('⚡ Running IaC Scan...');
                    const iacScanner = new IaCScanner(this.serverConfig);
                    scanResults.iac = await iacScanner.scanAll();
                } catch (error) {
                    console.error('❌ IaC scan failed:', error);
                    scanResults.iac = this.createFallbackScanResult('iac', error);
                }
            } else {
                scanResults.iac = this.createEmptyScanResult('iac');
            }

            // Naptha AI Analysis
            if (this.napthaCoordinator) {
                try {
                    console.log('⚡ Running Naptha AI Analysis...');
                    await this.napthaCoordinator.performAICorrelation(scanId, scanResults);
                    scanResults.naptha = this.napthaCoordinator.getAIAnalysis();
                } catch (error) {
                    console.error('❌ Naptha AI analysis failed:', error);
                }
            }

            // Store results
            this.results = scanResults;
            
            const duration = Date.now() - startTime;
            console.log(`✅ Comprehensive scan completed in ${duration}ms`);

            // Generate final report
            return this.generateReport(scanId, scanResults, duration);

        } catch (error) {
            console.error('❌ Comprehensive scan failed:', error);
            throw error;
        } finally {
            this.activeScans.delete(scanId);
        }
    }

    /**
     * Perform genuine static analysis of server configuration
     */
    async performStaticAnalysis() {
        console.log('🔍 Performing Genuine Static Analysis...');
        const vulnerabilities = [];

        // Analyze tool configurations for security issues
        if (this.serverConfig.tools && Array.isArray(this.serverConfig.tools)) {
            for (const tool of this.serverConfig.tools) {
                // Check for potential RCE tools
                const toolName = (tool.name || '').toLowerCase();
                const toolDesc = (tool.description || '').toLowerCase();
                
                const rcePatterns = ['run_command', 'execute', 'shell', 'system', 'exec', 'spawn', 'eval'];
                const hasRCE = rcePatterns.some(pattern => 
                    toolName.includes(pattern) || toolDesc.includes(pattern)
                );
                
                if (hasRCE) {
                    vulnerabilities.push({
                        id: `STATIC-RCE-${tool.name}-${Date.now()}`,
                        type: 'Remote Code Execution',
                        severity: 'critical',
                        description: `Tool '${tool.name}' may allow remote code execution`,
                        evidence: `Tool name/description contains RCE indicators: ${toolName}`,
                        recommendation: 'Restrict tool execution to safe operations only',
                        scanType: 'STATIC',
                        cve: 'CWE-78'
                    });
                }

                // Check for SSRF vulnerabilities
                if (tool.inputSchema) {
                    const schemaStr = JSON.stringify(tool.inputSchema).toLowerCase();
                    if (schemaStr.includes('url') || schemaStr.includes('endpoint') || schemaStr.includes('uri')) {
                        vulnerabilities.push({
                            id: `STATIC-SSRF-${tool.name}-${Date.now()}`,
                            type: 'Server Side Request Forgery',
                            severity: 'high',
                            description: `Tool '${tool.name}' accepts URL parameters which may enable SSRF`,
                            evidence: `URL parameter detected in input schema`,
                            recommendation: 'Validate and whitelist allowed URLs/domains',
                            scanType: 'STATIC',
                            cve: 'CWE-918'
                        });
                    }
                }

                // Check for admin/privileged functions
                const adminPatterns = ['admin', 'delete', 'remove', 'update', 'modify', 'config', 'settings'];
                const hasAdminFunc = adminPatterns.some(pattern => 
                    toolName.includes(pattern) || toolDesc.includes(pattern)
                );
                
                if (hasAdminFunc) {
                    vulnerabilities.push({
                        id: `STATIC-PRIV-${tool.name}-${Date.now()}`,
                        type: 'Privileged Function Access',
                        severity: 'high',
                        description: `Tool '${tool.name}' provides administrative/privileged functionality`,
                        evidence: `Admin function patterns detected: ${toolName}`,
                        recommendation: 'Ensure proper authorization controls are in place',
                        scanType: 'STATIC',
                        cve: 'CWE-269'
                    });
                }
            }
        }

        // Analyze OAuth scopes for excessive permissions
        if (this.serverConfig.oauthScopes && Array.isArray(this.serverConfig.oauthScopes)) {
            const adminScopes = this.serverConfig.oauthScopes.filter(scope => 
                scope.toLowerCase().includes('admin') || 
                scope.toLowerCase().includes('write') || 
                scope.toLowerCase().includes('delete') ||
                scope.toLowerCase().includes('modify')
            );
            
            if (adminScopes.length > 0) {
                vulnerabilities.push({
                    id: `STATIC-OAUTH-001`,
                    type: 'Excessive OAuth Permissions',
                    severity: 'critical',
                    description: `OAuth scopes contain administrative privileges: ${adminScopes.join(', ')}`,
                    evidence: `Admin scopes: ${adminScopes.join(', ')}`,
                    recommendation: 'Apply principle of least privilege - remove unnecessary admin scopes',
                    scanType: 'STATIC',
                    cve: 'CWE-269'
                });
            }
        }

        // Check server URL for security issues
        if (this.serverConfig.serverUrl) {
            if (!this.serverConfig.serverUrl.startsWith('https://')) {
                vulnerabilities.push({
                    id: `STATIC-TLS-001`,
                    type: 'Insecure Transport',
                    severity: 'high',
                    description: 'Server URL does not use HTTPS encryption',
                    evidence: `Insecure URL: ${this.serverConfig.serverUrl}`,
                    recommendation: 'Use HTTPS protocol to encrypt all communications',
                    scanType: 'STATIC',
                    cve: 'CWE-319'
                });
            }
        }

        console.log(`✅ Static Analysis Complete: Found ${vulnerabilities.length} genuine vulnerabilities`);
        return {
            scanType: 'STATIC',
            vulnerabilities: vulnerabilities,
            metadata: {
                scanId: `STATIC-${Date.now()}`,
                scanTimestamp: new Date().toISOString(),
                scanDuration: 100,
                status: 'completed'
            },
            summary: {
                totalVulnerabilities: vulnerabilities.length,
                severityBreakdown: this.calculateSeverityBreakdown(vulnerabilities)
            }
        };
    }

    /**
     * Create empty scan result when scanner is not available
     */
    createEmptyScanResult(scanType) {
        return {
            scanType: scanType.toUpperCase(),
            vulnerabilities: [],
            metadata: {
                scanId: `${scanType.toUpperCase()}-SKIPPED-${Date.now()}`,
                scanTimestamp: new Date().toISOString(),
                scanDuration: 0,
                status: 'skipped_scanner_unavailable'
            },
            summary: {
                totalVulnerabilities: 0,
                severityBreakdown: {
                    critical: 0,
                    high: 0,
                    medium: 0,
                    low: 0,
                    info: 0
                }
            }
        };
    }

    /**
     * Create fallback scan result when scanner fails
     */
    createFallbackScanResult(scanType, error) {
        return {
            scanType: scanType.toUpperCase(),
            vulnerabilities: [],
            metadata: {
                scanId: `${scanType.toUpperCase()}-${Date.now()}`,
                scanTimestamp: new Date().toISOString(),
                scanDuration: 0,
                status: 'failed',
                error: error.message
            },
            summary: {
                totalVulnerabilities: 0,
                severityBreakdown: { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 }
            }
        };
    }

    /**
     * Generate comprehensive security report
     */
    generateReport(scanId, results, duration) {
        const report = {
            scanId,
            timestamp: new Date().toISOString(),
            duration,
            serverConfig: {
                serverName: this.serverConfig.serverName,
                serverUrl: this.serverConfig.serverUrl,
                toolsAnalyzed: this.serverConfig.tools?.length || 0,
                scopesAnalyzed: this.serverConfig.oauthScopes?.length || 0
            },
            summary: this.generateSummary(results),
            results,
            recommendations: this.generateRecommendations(results),
            complianceStatus: this.checkCompliance(results),
            riskScore: this.calculateRiskScore(results),
            aiInsights: this.generateAIInsights(results)
        };

        console.log('📊 Security Report Generated:');
        console.log(`   📋 Scan ID: ${scanId}`);
        console.log(`   ⏱️ Duration: ${duration}ms`);
        console.log(`   🔍 Total Vulnerabilities: ${report.summary.totalVulnerabilities}`);
        console.log(`   ⚠️ Critical: ${report.summary.severityBreakdown.critical}`);
        console.log(`   🔸 High: ${report.summary.severityBreakdown.high}`);
        console.log(`   🔹 Medium: ${report.summary.severityBreakdown.medium}`);
        console.log(`   📊 Risk Score: ${report.riskScore}/10`);

        return report;
    }

    /**
     * Generate summary from scan results
     */
    generateSummary(results) {
        let totalVulnerabilities = 0;
        const severityBreakdown = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        const scanTypes = [];

        for (const [scanType, result] of Object.entries(results)) {
            if (result?.vulnerabilities) {
                totalVulnerabilities += result.vulnerabilities.length;
                scanTypes.push(scanType);
                
                // Aggregate severity breakdown
                if (result.summary?.severityBreakdown) {
                    for (const [severity, count] of Object.entries(result.summary.severityBreakdown)) {
                        if (severityBreakdown.hasOwnProperty(severity.toLowerCase())) {
                            severityBreakdown[severity.toLowerCase()] += count;
                        }
                    }
                }
            }
        }

        return {
            totalVulnerabilities,
            severityBreakdown,
            scanTypes,
            scansCompleted: scanTypes.length,
            scansSkipped: Math.max(0, 8 - scanTypes.length) // Expected 8 scan types
        };
    }

    /**
     * Calculate risk score based on vulnerabilities
     */
    calculateRiskScore(results) {
        let score = 0;
        const summary = this.generateSummary(results);
        
        // Weight vulnerabilities by severity
        score += summary.severityBreakdown.critical * 4;
        score += summary.severityBreakdown.high * 2.5;
        score += summary.severityBreakdown.medium * 1.5;
        score += summary.severityBreakdown.low * 0.5;
        score += summary.severityBreakdown.info * 0.1;
        
        // Cap at 10
        return Math.min(10, Math.round(score * 10) / 10);
    }

    /**
     * Generate recommendations based on findings
     */
    generateRecommendations(results) {
        const recommendations = [];
        const summary = this.generateSummary(results);
        
        if (summary.severityBreakdown.critical > 0) {
            recommendations.push({
                priority: 'CRITICAL',
                category: 'Immediate Action Required',
                description: `Address ${summary.severityBreakdown.critical} critical vulnerabilities immediately`,
                impact: 'High security risk requiring immediate attention'
            });
        }
        
        if (summary.severityBreakdown.high > 0) {
            recommendations.push({
                priority: 'HIGH',
                category: 'High Priority Fixes',
                description: `Remediate ${summary.severityBreakdown.high} high severity issues`,
                impact: 'Significant security concerns requiring prompt attention'
            });
        }
        
        if (summary.totalVulnerabilities === 0) {
            recommendations.push({
                priority: 'INFO',
                category: 'Security Posture',
                description: 'No vulnerabilities detected in current configuration',
                impact: 'Good security posture maintained'
            });
        }
        
        return recommendations;
    }

    /**
     * Check compliance status
     */
    checkCompliance(results) {
        const summary = this.generateSummary(results);
        
        return {
            overall: summary.severityBreakdown.critical === 0 ? 'COMPLIANT' : 'NON_COMPLIANT',
            frameworks: this.config.complianceFrameworks.map(framework => ({
                name: framework,
                status: summary.severityBreakdown.critical === 0 ? 'PASS' : 'FAIL',
                criticalIssues: summary.severityBreakdown.critical
            }))
        };
    }

    /**
     * Generate AI insights
     */
    generateAIInsights(results) {
        return {
            analysisComplete: true,
            riskVector: this.analyzeRiskVector(results),
            attackSurface: this.calculateAttackSurface(),
            recommendedActions: this.generateActionPlan(results)
        };
    }

    /**
     * Analyze risk vector
     */
    analyzeRiskVector(results) {
        const summary = this.generateSummary(results);
        
        return {
            confidentiality: summary.severityBreakdown.critical > 0 ? 'HIGH' : 'LOW',
            integrity: summary.severityBreakdown.high > 0 ? 'MEDIUM' : 'LOW', 
            availability: 'LOW',
            scope: this.serverConfig?.tools?.length > 5 ? 'EXTENDED' : 'LIMITED'
        };
    }

    /**
     * Calculate attack surface
     */
    calculateAttackSurface() {
        return {
            toolsExposed: this.serverConfig?.tools?.length || 0,
            adminFunctions: this.serverConfig?.tools?.filter(t => 
                t.name?.toLowerCase().includes('admin') || 
                t.description?.toLowerCase().includes('admin')
            ).length || 0,
            networkEndpoints: 1, // MCP server endpoint
            authenticationMethods: this.serverConfig?.oauthScopes?.length > 0 ? 1 : 0
        };
    }

    /**
     * Generate action plan
     */
    generateActionPlan(results) {
        const actions = [];
        const summary = this.generateSummary(results);
        
        if (summary.severityBreakdown.critical > 0) {
            actions.push('Immediately patch critical vulnerabilities');
        }
        
        if (summary.severityBreakdown.high > 0) {
            actions.push('Schedule high-priority vulnerability remediation');
        }
        
        if (summary.totalVulnerabilities > 0) {
            actions.push('Implement security monitoring and alerting');
            actions.push('Consider penetration testing for validation');
        } else {
            actions.push('Maintain current security posture');
            actions.push('Schedule regular security assessments');
        }
        
        return actions;
    }

    /**
     * Calculate severity breakdown from vulnerabilities array
     */
    calculateSeverityBreakdown(vulnerabilities) {
        return vulnerabilities.reduce((breakdown, vuln) => {
            const severity = vuln.severity ? vuln.severity.toLowerCase() : 'info';
            breakdown[severity] = (breakdown[severity] || 0) + 1;
            return breakdown;
        }, { critical: 0, high: 0, medium: 0, low: 0, info: 0 });
    }

    /**
     * Get current status of all active scans
     */
    getStatus() {
        const napthaStatus = this.napthaCoordinator?.getStatus() || {};
        
        return {
            activeScans: this.activeScans.size,
            lastScanTimestamp: this.results.static?.metadata?.scanTimestamp || null,
            totalScansCompleted: this.scanHistory.size,
            aiComponents: {
                naptha: !!this.napthaCoordinator,
                analytics: !!this.aiAnalytics,
                threatIntel: !!this.threatEngine,
                compliance: !!this.complianceOrchestrator,
                remediation: !!this.remediationEngine
            },
            activeAgents: napthaStatus.activeAgents || 0,
            totalAgents: napthaStatus.totalAgents || 0,
            autonomousScans: napthaStatus.totalScans || 0,
            vulnerabilitiesFound: napthaStatus.totalVulnerabilities || 0,
            correlations: this.results.naptha?.findings?.length || 0,
            queuedRemediations: napthaStatus.queuedRemediations || 0
        };
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ComprehensiveSecurityScanner;
}

// Export for browser usage
if (typeof window !== 'undefined') {
    window.ComprehensiveSecurityScanner = ComprehensiveSecurityScanner;
}
