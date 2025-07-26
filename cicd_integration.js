/**
 * CI/CD Pipeline Integration
 * DevSecOps integration for automated security testing in development pipelines
 * 
 * This module provides seamless integration with popular CI/CD platforms
 * for automated security scanning and Naptha AI-powered analysis.
 */

class CICDIntegration {
    constructor(config = {}) {
        this.config = {
            platform: config.platform || 'jenkins', // jenkins, gitlab, github, azure
            webhookUrl: config.webhookUrl || null,
            apiToken: config.apiToken || null,
            projectId: config.projectId || null,
            autoTrigger: config.autoTrigger || true,
            failOnCritical: config.failOnCritical || true,
            failOnHigh: config.failOnHigh || false,
            reportFormat: config.reportFormat || 'json',
            napthaIntegration: config.napthaIntegration || true,
            ...config
        };
        
        this.pipelineHistory = new Map();
        this.integrationHandlers = new Map();
        
        this.initializePlatformHandlers();
    }

    /**
     * Initialize platform-specific handlers
     */
    initializePlatformHandlers() {
        console.log('🔧 Initializing CI/CD platform handlers...');
        
        // Jenkins Integration
        this.integrationHandlers.set('jenkins', {
            name: 'Jenkins',
            triggerScan: this.triggerJenkinsScan.bind(this),
            reportResults: this.reportJenkinsResults.bind(this),
            failBuild: this.failJenkinsBuild.bind(this),
            apiEndpoint: '/jenkins/api',
            authMethod: 'token'
        });

        // GitLab CI Integration
        this.integrationHandlers.set('gitlab', {
            name: 'GitLab CI',
            triggerScan: this.triggerGitLabScan.bind(this),
            reportResults: this.reportGitLabResults.bind(this),
            failBuild: this.failGitLabBuild.bind(this),
            apiEndpoint: '/gitlab/api/v4',
            authMethod: 'token'
        });

        // GitHub Actions Integration
        this.integrationHandlers.set('github', {
            name: 'GitHub Actions',
            triggerScan: this.triggerGitHubScan.bind(this),
            reportResults: this.reportGitHubResults.bind(this),
            failBuild: this.failGitHubBuild.bind(this),
            apiEndpoint: '/github/api',
            authMethod: 'token'
        });

        // Azure DevOps Integration
        this.integrationHandlers.set('azure', {
            name: 'Azure DevOps',
            triggerScan: this.triggerAzureScan.bind(this),
            reportResults: this.reportAzureResults.bind(this),
            failBuild: this.failAzureBuild.bind(this),
            apiEndpoint: '/azure/api',
            authMethod: 'pat'
        });

        console.log(`✅ Initialized ${this.integrationHandlers.size} CI/CD platform handlers`);
    }

    /**
     * Execute security scan in CI/CD pipeline
     */
    async executePipelineScan(pipelineContext) {
        console.log('🚀 Executing security scan in CI/CD pipeline...');
        
        const pipelineId = `pipeline-${Date.now()}`;
        const execution = {
            id: pipelineId,
            platform: this.config.platform,
            context: pipelineContext,
            startTime: new Date(),
            status: 'running',
            results: null,
            reportUrl: null,
            buildDecision: null
        };

        this.pipelineHistory.set(pipelineId, execution);

        try {
            // Step 1: Initialize comprehensive scanner with CI/CD optimizations
            const scanner = new ComprehensiveSecurityScanner({
                enableAllScans: true,
                napthaIntegration: this.config.napthaIntegration,
                aiAnalytics: true,
                autonomousRemediation: false, // Disable auto-remediation in CI/CD
                timeoutDuration: 300000 // 5 minutes for CI/CD
            });

            // Step 2: Configure scanner for target environment
            const scanConfig = this.buildScanConfig(pipelineContext);
            scanner.configure(scanConfig);

            // Step 3: Execute comprehensive security scan
            const scanResults = await scanner.performCompleteScan();
            execution.results = scanResults;

            // Step 4: Process results for CI/CD integration
            const processedResults = await this.processCICDResults(scanResults, pipelineContext);
            
            // Step 5: Generate CI/CD-specific reports
            const reports = await this.generateCICDReports(processedResults);
            execution.reportUrl = reports.primaryReportUrl;

            // Step 6: Make build decision
            const buildDecision = this.makeBuildDecision(processedResults);
            execution.buildDecision = buildDecision;

            // Step 7: Report results to CI/CD platform
            await this.reportToPlatform(pipelineContext, processedResults, buildDecision);

            execution.status = buildDecision.shouldFail ? 'failed' : 'passed';
            execution.endTime = new Date();

            console.log(`✅ Pipeline scan completed - Decision: ${buildDecision.decision}`);
            return execution;

        } catch (error) {
            console.error('❌ Pipeline scan failed:', error);
            execution.status = 'error';
            execution.error = error.message;
            execution.endTime = new Date();

            // Report failure to CI/CD platform
            await this.reportFailureToPlatform(pipelineContext, error);
            
            throw error;
        }
    }

    /**
     * Build scan configuration from pipeline context
     */
    buildScanConfig(pipelineContext) {
        return {
            serverName: pipelineContext.projectName || 'CI/CD Project',
            endpoint: pipelineContext.targetEndpoint || 'http://localhost:3000',
            branch: pipelineContext.branch || 'main',
            commit: pipelineContext.commit || 'unknown',
            buildId: pipelineContext.buildId || 'unknown',
            environment: pipelineContext.environment || 'test',
            cicdMode: true,
            fastScan: pipelineContext.fastScan || false,
            targetDirectory: pipelineContext.sourceDirectory || './'
        };
    }

    /**
     * Process scan results for CI/CD context
     */
    async processCICDResults(scanResults, pipelineContext) {
        console.log('📊 Processing scan results for CI/CD integration...');
        
        const processed = {
            ...scanResults,
            cicd: {
                platform: this.config.platform,
                buildId: pipelineContext.buildId,
                branch: pipelineContext.branch,
                commit: pipelineContext.commit,
                environment: pipelineContext.environment,
                processedAt: new Date()
            },
            qualityGates: this.evaluateQualityGates(scanResults),
            trending: await this.calculateTrending(scanResults, pipelineContext),
            comparisons: await this.generateComparisons(scanResults, pipelineContext)
        };

        return processed;
    }

    /**
     * Evaluate quality gates for build decision
     */
    evaluateQualityGates(scanResults) {
        const gates = {
            criticalVulnerabilities: {
                threshold: 0,
                current: scanResults.summary.severityBreakdown.critical || 0,
                passed: (scanResults.summary.severityBreakdown.critical || 0) === 0
            },
            highVulnerabilities: {
                threshold: this.config.failOnHigh ? 0 : 5,
                current: scanResults.summary.severityBreakdown.high || 0,
                passed: (scanResults.summary.severityBreakdown.high || 0) <= (this.config.failOnHigh ? 0 : 5)
            },
            riskScore: {
                threshold: 70,
                current: scanResults.summary.riskScore.score,
                passed: scanResults.summary.riskScore.score <= 70
            },
            complianceScore: {
                threshold: 0.85,
                current: scanResults.compliance?.overallScore || 1,
                passed: (scanResults.compliance?.overallScore || 1) >= 0.85
            }
        };

        gates.overallPassed = Object.values(gates).filter(gate => gate.hasOwnProperty('passed')).every(gate => gate.passed);
        
        return gates;
    }

    /**
     * Make build decision based on results
     */
    makeBuildDecision(processedResults) {
        const qualityGates = processedResults.qualityGates;
        
        let decision = 'pass';
        let shouldFail = false;
        const reasons = [];

        // Check critical vulnerabilities
        if (this.config.failOnCritical && !qualityGates.criticalVulnerabilities.passed) {
            decision = 'fail';
            shouldFail = true;
            reasons.push(`Critical vulnerabilities found: ${qualityGates.criticalVulnerabilities.current}`);
        }

        // Check high vulnerabilities
        if (this.config.failOnHigh && !qualityGates.highVulnerabilities.passed) {
            decision = 'fail';
            shouldFail = true;
            reasons.push(`High vulnerabilities exceed threshold: ${qualityGates.highVulnerabilities.current}`);
        }

        // Check risk score
        if (!qualityGates.riskScore.passed) {
            decision = 'fail';
            shouldFail = true;
            reasons.push(`Risk score too high: ${qualityGates.riskScore.current}`);
        }

        // Check compliance score
        if (!qualityGates.complianceScore.passed) {
            decision = 'fail';
            shouldFail = true;
            reasons.push(`Compliance score too low: ${(qualityGates.complianceScore.current * 100).toFixed(1)}%`);
        }

        return {
            decision,
            shouldFail,
            reasons,
            qualityGatesPassed: qualityGates.overallPassed,
            recommendation: shouldFail ? 'Block deployment until issues are resolved' : 'Safe to deploy'
        };
    }

    /**
     * Generate CI/CD-specific reports
     */
    async generateCICDReports(processedResults) {
        console.log('📄 Generating CI/CD reports...');
        
        const reports = {
            primaryReportUrl: null,
            formats: {}
        };

        // JSON Report for API consumption
        reports.formats.json = this.generateJSONReport(processedResults);
        
        // JUnit XML for test result integration
        reports.formats.junit = this.generateJUnitReport(processedResults);
        
        // SARIF for security findings
        reports.formats.sarif = this.generateSARIFReport(processedResults);
        
        // HTML Report for human consumption
        reports.formats.html = this.generateHTMLReport(processedResults);
        
        // Quality Gate Summary
        reports.formats.qualityGate = this.generateQualityGateReport(processedResults);

        // Set primary report URL (would be actual URL in real implementation)
        reports.primaryReportUrl = `${this.config.reportBaseUrl || ''}/reports/${processedResults.metadata.scanTimestamp}`;

        return reports;
    }

    /**
     * Report results to CI/CD platform
     */
    async reportToPlatform(pipelineContext, processedResults, buildDecision) {
        const handler = this.integrationHandlers.get(this.config.platform);
        
        if (handler) {
            console.log(`📤 Reporting results to ${handler.name}...`);
            
            try {
                await handler.reportResults(pipelineContext, processedResults, buildDecision);
                
                if (buildDecision.shouldFail) {
                    await handler.failBuild(pipelineContext, buildDecision);
                }
                
                console.log(`✅ Results reported to ${handler.name}`);
            } catch (error) {
                console.error(`❌ Failed to report to ${handler.name}:`, error);
            }
        } else {
            console.warn(`⚠️ No handler found for platform: ${this.config.platform}`);
        }
    }

    /**
     * Platform-specific implementations
     */
    
    // Jenkins Integration
    async triggerJenkinsScan(context) {
        console.log('🔧 Triggering Jenkins security scan...');
        // Implementation would make actual Jenkins API calls
        return { status: 'triggered', buildNumber: Date.now() };
    }

    async reportJenkinsResults(context, results, decision) {
        // Report results back to Jenkins build
        console.log('📊 Reporting results to Jenkins...');
        
        // Would publish to Jenkins build artifacts, set build status, etc.
        return {
            artifactsPublished: true,
            buildStatus: decision.shouldFail ? 'FAILURE' : 'SUCCESS',
            testResults: this.convertToJenkinsFormat(results)
        };
    }

    async failJenkinsBuild(context, decision) {
        console.log('❌ Failing Jenkins build due to security issues...');
        // Would set Jenkins build status to FAILURE
        return { buildFailed: true, reason: decision.reasons.join(', ') };
    }

    // GitLab CI Integration
    async triggerGitLabScan(context) {
        console.log('🦊 Triggering GitLab CI security scan...');
        return { status: 'triggered', pipelineId: Date.now() };
    }

    async reportGitLabResults(context, results, decision) {
        console.log('📊 Reporting results to GitLab CI...');
        
        // Would create GitLab security report, merge request comments, etc.
        return {
            securityReportCreated: true,
            mergeRequestUpdated: true,
            status: decision.shouldFail ? 'failed' : 'passed'
        };
    }

    async failGitLabBuild(context, decision) {
        console.log('❌ Failing GitLab CI pipeline due to security issues...');
        return { pipelineFailed: true, reason: decision.reasons.join(', ') };
    }

    // GitHub Actions Integration
    async triggerGitHubScan(context) {
        console.log('🐙 Triggering GitHub Actions security scan...');
        return { status: 'triggered', runId: Date.now() };
    }

    async reportGitHubResults(context, results, decision) {
        console.log('📊 Reporting results to GitHub Actions...');
        
        // Would create GitHub security alerts, PR comments, check runs, etc.
        return {
            checkRunCreated: true,
            securityAlertsCreated: true,
            prCommentAdded: true,
            conclusion: decision.shouldFail ? 'failure' : 'success'
        };
    }

    async failGitHubBuild(context, decision) {
        console.log('❌ Failing GitHub Actions workflow due to security issues...');
        return { workflowFailed: true, reason: decision.reasons.join(', ') };
    }

    // Azure DevOps Integration
    async triggerAzureScan(context) {
        console.log('🔷 Triggering Azure DevOps security scan...');
        return { status: 'triggered', buildId: Date.now() };
    }

    async reportAzureResults(context, results, decision) {
        console.log('📊 Reporting results to Azure DevOps...');
        
        // Would create Azure DevOps work items, test results, etc.
        return {
            testResultsPublished: true,
            workItemsCreated: true,
            buildStatus: decision.shouldFail ? 'failed' : 'succeeded'
        };
    }

    async failAzureBuild(context, decision) {
        console.log('❌ Failing Azure DevOps build due to security issues...');
        return { buildFailed: true, reason: decision.reasons.join(', ') };
    }

    /**
     * Report generation methods
     */
    generateJSONReport(results) {
        return JSON.stringify({
            version: '1.0.0',
            scan: results.metadata,
            summary: results.summary,
            qualityGates: results.qualityGates,
            vulnerabilities: results.vulnerabilities,
            recommendations: results.recommendations
        }, null, 2);
    }

    generateJUnitReport(results) {
        const testSuites = [];
        
        // Convert vulnerabilities to JUnit test cases
        for (const vuln of results.vulnerabilities) {
            testSuites.push(`
                <testcase classname="SecurityScan" name="${vuln.type}" time="0">
                    ${vuln.severity === 'critical' || vuln.severity === 'high' ? 
                        `<failure message="${vuln.description}">${vuln.evidence || ''}</failure>` : 
                        ''}
                </testcase>
            `);
        }

        return `<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="Security Scan" tests="${results.vulnerabilities.length}" failures="${results.summary.severityBreakdown.critical + results.summary.severityBreakdown.high}" time="0">
    ${testSuites.join('')}
</testsuite>`;
    }

    generateSARIFReport(results) {
        const runs = [{
            tool: {
                driver: {
                    name: "MCP Guardian Enterprise",
                    version: results.metadata.scannerVersion
                }
            },
            results: results.vulnerabilities.map(vuln => ({
                ruleId: vuln.id,
                level: this.mapSeverityToSARIF(vuln.severity),
                message: { text: vuln.description },
                locations: [{
                    physicalLocation: {
                        artifactLocation: { uri: vuln.location || 'unknown' }
                    }
                }]
            }))
        }];

        return JSON.stringify({
            version: "2.1.0",
            $schema: "https://json.schemastore.org/sarif-2.1.0.json",
            runs: runs
        }, null, 2);
    }

    generateHTMLReport(results) {
        return `
<!DOCTYPE html>
<html>
<head>
    <title>CI/CD Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .pass { color: green; font-weight: bold; }
        .fail { color: red; font-weight: bold; }
        .quality-gate { background: #f5f5f5; padding: 10px; margin: 10px 0; border-left: 4px solid #ccc; }
        .quality-gate.passed { border-left-color: green; }
        .quality-gate.failed { border-left-color: red; }
    </style>
</head>
<body>
    <h1>🛡️ CI/CD Security Report</h1>
    <p><strong>Build:</strong> ${results.cicd.buildId}</p>
    <p><strong>Branch:</strong> ${results.cicd.branch}</p>
    <p><strong>Platform:</strong> ${results.cicd.platform}</p>
    
    <h2>Quality Gates</h2>
    ${Object.entries(results.qualityGates).filter(([key]) => key !== 'overallPassed').map(([gate, data]) => `
        <div class="quality-gate ${data.passed ? 'passed' : 'failed'}">
            <strong>${gate}:</strong> ${data.current}/${data.threshold} 
            <span class="${data.passed ? 'pass' : 'fail'}">${data.passed ? 'PASS' : 'FAIL'}</span>
        </div>
    `).join('')}
    
    <h2>Build Decision</h2>
    <p class="${results.qualityGates.overallPassed ? 'pass' : 'fail'}">
        ${results.qualityGates.overallPassed ? '✅ BUILD PASSED' : '❌ BUILD FAILED'}
    </p>
</body>
</html>`;
    }

    generateQualityGateReport(results) {
        return {
            passed: results.qualityGates.overallPassed,
            gates: results.qualityGates,
            buildDecision: results.buildDecision || 'unknown',
            timestamp: new Date().toISOString()
        };
    }

    /**
     * Utility methods
     */
    mapSeverityToSARIF(severity) {
        const mapping = {
            'critical': 'error',
            'high': 'error',
            'medium': 'warning',
            'low': 'note',
            'info': 'note'
        };
        return mapping[severity] || 'note';
    }

    convertToJenkinsFormat(results) {
        return {
            total: results.vulnerabilities.length,
            failed: results.summary.severityBreakdown.critical + results.summary.severityBreakdown.high,
            passed: results.vulnerabilities.length - (results.summary.severityBreakdown.critical + results.summary.severityBreakdown.high),
            skipped: 0
        };
    }

    async calculateTrending(results, context) {
        // Simulate trending calculation
        return {
            vulnerabilityTrend: 'stable',
            riskScoreTrend: 'improving',
            complianceTrend: 'stable',
            changeFromLastBuild: 0
        };
    }

    async generateComparisons(results, context) {
        // Simulate comparison with previous builds
        return {
            previousBuild: {
                vulnerabilities: results.vulnerabilities.length - Math.floor(Math.random() * 5),
                riskScore: results.summary.riskScore.score + Math.floor(Math.random() * 10 - 5)
            },
            mainBranch: {
                vulnerabilities: results.vulnerabilities.length + Math.floor(Math.random() * 3),
                riskScore: results.summary.riskScore.score + Math.floor(Math.random() * 15 - 7)
            }
        };
    }

    async reportFailureToPlatform(context, error) {
        console.log('📤 Reporting scan failure to CI/CD platform...');
        // Implementation would report the error to the appropriate platform
    }

    /**
     * Get integration status
     */
    getIntegrationStatus() {
        return {
            platform: this.config.platform,
            configured: this.config.apiToken !== null,
            totalPipelines: this.pipelineHistory.size,
            availablePlatforms: Array.from(this.integrationHandlers.keys()),
            lastExecution: Array.from(this.pipelineHistory.values())
                .sort((a, b) => b.startTime - a.startTime)[0] || null
        };
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CICDIntegration;
}

// Example usage
if (typeof window !== 'undefined') {
    window.CICDIntegration = CICDIntegration;
}
