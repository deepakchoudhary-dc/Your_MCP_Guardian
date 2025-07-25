/**
 * Centralized Security Dashboard
 * Manages scan configurations, historical data, and provides comprehensive reporting
 */

class SecurityDashboard {
    constructor() {
        this.database = new SecurityDatabase();
        this.scanConfigurations = new Map();
        this.activeScans = new Map();
        this.scanHistory = [];
        this.projects = new Map();
        this.vulnerabilityTracking = new Map();
        
        // Initialize dashboard
        this.initializeDashboard();
    }

    async initializeDashboard() {
        // Load saved configurations and data
        await this.loadSavedData();
        
        // Set up periodic tasks
        this.setupPeriodicTasks();
        
        console.log('🎛️ Security Dashboard initialized');
    }

    // Project Management
    async createProject(projectConfig) {
        const projectId = this.generateId('PROJECT');
        const project = {
            id: projectId,
            name: projectConfig.name,
            description: projectConfig.description || '',
            environment: projectConfig.environment || 'development',
            serverUrl: projectConfig.serverUrl,
            tools: projectConfig.tools || [],
            oauthScopes: projectConfig.oauthScopes || [],
            scanSchedule: projectConfig.scanSchedule || null,
            notifications: projectConfig.notifications || {},
            created: new Date().toISOString(),
            lastScan: null,
            status: 'active'
        };
        
        this.projects.set(projectId, project);
        await this.database.saveProject(project);
        
        return projectId;
    }

    async updateProject(projectId, updates) {
        const project = this.projects.get(projectId);
        if (!project) throw new Error('Project not found');
        
        const updatedProject = { ...project, ...updates, updated: new Date().toISOString() };
        this.projects.set(projectId, updatedProject);
        await this.database.updateProject(projectId, updatedProject);
        
        return updatedProject;
    }

    async deleteProject(projectId) {
        const project = this.projects.get(projectId);
        if (!project) throw new Error('Project not found');
        
        // Archive instead of delete to preserve history
        project.status = 'archived';
        project.archived = new Date().toISOString();
        
        this.projects.set(projectId, project);
        await this.database.updateProject(projectId, project);
        
        return true;
    }

    async getProjects(filter = {}) {
        let projects = Array.from(this.projects.values());
        
        if (filter.environment) {
            projects = projects.filter(p => p.environment === filter.environment);
        }
        
        if (filter.status) {
            projects = projects.filter(p => p.status === filter.status);
        }
        
        return projects;
    }

    // Scan Configuration Management
    async saveScanConfiguration(name, config) {
        const configId = this.generateId('CONFIG');
        const scanConfig = {
            id: configId,
            name,
            projectId: config.projectId,
            scanTypes: config.scanTypes || ['static', 'dast', 'sca', 'secret', 'iac'],
            schedule: config.schedule || null,
            notifications: config.notifications || {},
            parameters: config.parameters || {},
            created: new Date().toISOString(),
            lastUsed: null
        };
        
        this.scanConfigurations.set(configId, scanConfig);
        await this.database.saveScanConfiguration(scanConfig);
        
        return configId;
    }

    async getScanConfigurations(projectId = null) {
        let configs = Array.from(this.scanConfigurations.values());
        
        if (projectId) {
            configs = configs.filter(c => c.projectId === projectId);
        }
        
        return configs;
    }

    async deleteScanConfiguration(configId) {
        this.scanConfigurations.delete(configId);
        await this.database.deleteScanConfiguration(configId);
        return true;
    }

    // Comprehensive Scan Execution
    async executeComprehensiveScan(projectId, scanTypes = null) {
        const project = this.projects.get(projectId);
        if (!project) throw new Error('Project not found');
        
        const scanId = this.generateId('SCAN');
        const scanTypes_ = scanTypes || ['static', 'dast', 'sca', 'secret', 'iac'];
        
        const scanExecution = {
            id: scanId,
            projectId,
            scanTypes: scanTypes_,
            status: 'running',
            started: new Date().toISOString(),
            progress: 0,
            results: {},
            vulnerabilities: [],
            errors: []
        };
        
        this.activeScans.set(scanId, scanExecution);
        
        try {
            // Execute all scan types
            const scanResults = await this.runAllScanners(project, scanTypes_);
            
            // Combine results
            const combinedResults = this.combineResults(scanResults);
            
            // Update scan execution
            scanExecution.status = 'completed';
            scanExecution.completed = new Date().toISOString();
            scanExecution.duration = Date.now() - new Date(scanExecution.started).getTime();
            scanExecution.results = combinedResults;
            scanExecution.vulnerabilities = combinedResults.vulnerabilities || [];
            
            // Save to database
            await this.database.saveScanResult(scanExecution);
            
            // Update project last scan
            project.lastScan = scanExecution.completed;
            await this.updateProject(projectId, { lastScan: scanExecution.completed });
            
            // Track vulnerabilities
            await this.trackVulnerabilities(projectId, scanExecution.vulnerabilities);
            
            // Send notifications if configured
            await this.sendNotifications(project, scanExecution);
            
            return scanExecution;
            
        } catch (error) {
            scanExecution.status = 'failed';
            scanExecution.error = error.message;
            scanExecution.completed = new Date().toISOString();
            
            console.error('Scan execution failed:', error);
            return scanExecution;
        } finally {
            this.activeScans.delete(scanId);
        }
    }

    async runAllScanners(project, scanTypes) {
        const results = {};
        const serverConfig = {
            serverName: project.name,
            serverUrl: project.serverUrl,
            tools: project.tools,
            oauthScopes: project.oauthScopes
        };
        
        // Static Analysis (always included)
        if (scanTypes.includes('static')) {
            console.log('Running static analysis...');
            results.static = await this.runStaticAnalysis(serverConfig);
        }
        
        // Dynamic Application Security Testing
        if (scanTypes.includes('dast')) {
            console.log('Running DAST scan...');
            const DASTScanner = require('./dast_scanner.js');
            const dastScanner = new DASTScanner(serverConfig);
            results.dast = await dastScanner.performDASTScan();
        }
        
        // Software Composition Analysis
        if (scanTypes.includes('sca')) {
            console.log('Running SCA scan...');
            const SCAScanner = require('./sca_scanner.js');
            const scaScanner = new SCAScanner();
            results.sca = await scaScanner.performSCAScan();
        }
        
        // Secret Scanning
        if (scanTypes.includes('secret')) {
            console.log('Running secret scan...');
            const SecretScanner = require('./secret_scanner.js');
            const secretScanner = new SecretScanner();
            results.secret = await secretScanner.performSecretScan();
        }
        
        // Infrastructure as Code Scanning
        if (scanTypes.includes('iac')) {
            console.log('Running IaC scan...');
            const IaCScanner = require('./iac_scanner.js');
            const iacScanner = new IaCScanner();
            results.iac = await iacScanner.performIaCScan();
        }
        
        // Runtime and Network Testing
        if (scanTypes.includes('runtime')) {
            console.log('Running runtime tests...');
            const RuntimeSecurityScanner = require('./runtime_security_scanner.js');
            const runtimeScanner = new RuntimeSecurityScanner(serverConfig);
            results.runtime = await runtimeScanner.scanAll();
        }
        
        if (scanTypes.includes('network')) {
            console.log('Running network tests...');
            const NetworkSecurityScanner = require('./network_security_scanner.js');
            const networkScanner = new NetworkSecurityScanner(serverConfig);
            results.network = await networkScanner.scanAll();
        }
        
        if (scanTypes.includes('logic')) {
            console.log('Running application logic tests...');
            const ApplicationLogicScanner = require('./application_logic_scanner.js');
            const logicScanner = new ApplicationLogicScanner(serverConfig);
            results.logic = await logicScanner.scanAll();
        }
        
        return results;
    }

    async runStaticAnalysis(serverConfig) {
        // Run the existing static analysis
        const VULNERABILITY_CHECKS = [
            // Include all the existing static checks from the original code
            { id: 'CVE-2025-49596', severity: 'Critical', title: 'Tool Poisoning (TPA/ATPA/FSP)', check: (tools) => {
                const tool = tools.find(t => /(poison|malicious|hidden|backdoor)/i.test(t.description));
                return tool ? "Detected keywords suggesting hidden malicious functionality in tool descriptions." : null;
            }},
            // ... (include all other checks from the original code)
        ];
        
        const vulnerabilities = [];
        const tools = serverConfig.tools || [];
        const scopes = (serverConfig.oauthScopes || []).map(s => s.toLowerCase());
        
        VULNERABILITY_CHECKS.forEach(vuln => {
            const result = vuln.check(tools, scopes);
            if (result) {
                vulnerabilities.push({
                    id: vuln.id,
                    severity: vuln.severity,
                    title: vuln.title,
                    description: result,
                    scanType: 'static'
                });
            }
        });
        
        return { vulnerabilities };
    }

    combineResults(scanResults) {
        const combined = {
            vulnerabilities: [],
            summary: {
                totalVulnerabilities: 0,
                severityBreakdown: {},
                scanTypeBreakdown: {},
                riskScore: 0
            },
            scanResults: scanResults
        };
        
        // Combine vulnerabilities from all scans
        for (const [scanType, result] of Object.entries(scanResults)) {
            if (result.vulnerabilities) {
                for (const vuln of result.vulnerabilities) {
                    vuln.scanType = scanType;
                    combined.vulnerabilities.push(vuln);
                }
            }
        }
        
        // Calculate summary statistics
        combined.summary.totalVulnerabilities = combined.vulnerabilities.length;
        
        // Severity breakdown
        for (const vuln of combined.vulnerabilities) {
            const severity = vuln.severity || 'Unknown';
            combined.summary.severityBreakdown[severity] = (combined.summary.severityBreakdown[severity] || 0) + 1;
        }
        
        // Scan type breakdown
        for (const vuln of combined.vulnerabilities) {
            const scanType = vuln.scanType || 'Unknown';
            combined.summary.scanTypeBreakdown[scanType] = (combined.summary.scanTypeBreakdown[scanType] || 0) + 1;
        }
        
        // Calculate risk score
        combined.summary.riskScore = this.calculateRiskScore(combined.vulnerabilities);
        
        return combined;
    }

    calculateRiskScore(vulnerabilities) {
        const weights = { 'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 2, 'Info': 1 };
        const totalScore = vulnerabilities.reduce((score, vuln) => {
            return score + (weights[vuln.severity] || 0);
        }, 0);
        
        const maxPossibleScore = vulnerabilities.length * 10;
        return maxPossibleScore > 0 ? Math.round((totalScore / maxPossibleScore) * 100) : 0;
    }

    // Vulnerability Tracking
    async trackVulnerabilities(projectId, vulnerabilities) {
        for (const vuln of vulnerabilities) {
            const vulnKey = `${projectId}-${vuln.type}-${vuln.file || 'global'}`;
            
            if (this.vulnerabilityTracking.has(vulnKey)) {
                // Update existing vulnerability
                const tracked = this.vulnerabilityTracking.get(vulnKey);
                tracked.lastSeen = new Date().toISOString();
                tracked.occurrences++;
                
                if (tracked.status === 'fixed' && vuln.severity) {
                    tracked.status = 'reopened';
                    tracked.reopened = new Date().toISOString();
                }
            } else {
                // New vulnerability
                const tracked = {
                    id: this.generateId('VULN'),
                    projectId,
                    type: vuln.type,
                    severity: vuln.severity,
                    file: vuln.file,
                    firstSeen: new Date().toISOString(),
                    lastSeen: new Date().toISOString(),
                    status: 'open',
                    occurrences: 1,
                    assignee: null,
                    notes: []
                };
                
                this.vulnerabilityTracking.set(vulnKey, tracked);
                await this.database.saveVulnerability(tracked);
            }
        }
    }

    async updateVulnerabilityStatus(vulnId, status, assignee = null, notes = null) {
        for (const [key, vuln] of this.vulnerabilityTracking.entries()) {
            if (vuln.id === vulnId) {
                vuln.status = status;
                vuln.updated = new Date().toISOString();
                
                if (assignee) vuln.assignee = assignee;
                if (notes) vuln.notes.push({ text: notes, timestamp: new Date().toISOString() });
                
                await this.database.updateVulnerability(vulnId, vuln);
                return vuln;
            }
        }
        throw new Error('Vulnerability not found');
    }

    // Historical Analysis and Trends
    async getTrendAnalysis(projectId, timeRange = '30d') {
        const scans = await this.database.getScanHistory(projectId, timeRange);
        
        const trends = {
            vulnerabilityTrend: [],
            riskScoreTrend: [],
            scanTypeTrends: {},
            severityTrends: {}
        };
        
        for (const scan of scans) {
            const date = scan.completed.split('T')[0];
            
            trends.vulnerabilityTrend.push({
                date,
                count: scan.vulnerabilities.length
            });
            
            trends.riskScoreTrend.push({
                date,
                score: scan.results.summary?.riskScore || 0
            });
            
            // Analyze by scan type
            for (const [scanType, count] of Object.entries(scan.results.summary?.scanTypeBreakdown || {})) {
                if (!trends.scanTypeTrends[scanType]) trends.scanTypeTrends[scanType] = [];
                trends.scanTypeTrends[scanType].push({ date, count });
            }
            
            // Analyze by severity
            for (const [severity, count] of Object.entries(scan.results.summary?.severityBreakdown || {})) {
                if (!trends.severityTrends[severity]) trends.severityTrends[severity] = [];
                trends.severityTrends[severity].push({ date, count });
            }
        }
        
        return trends;
    }

    async getComplianceReport(projectId) {
        const latestScan = await this.database.getLatestScan(projectId);
        if (!latestScan) return null;
        
        const vulnerabilities = latestScan.vulnerabilities;
        
        const compliance = {
            'OWASP Top 10': this.checkOWASPCompliance(vulnerabilities),
            'NIST Cybersecurity Framework': this.checkNISTCompliance(vulnerabilities),
            'ISO 27001': this.checkISO27001Compliance(vulnerabilities),
            'PCI DSS': this.checkPCIDSSCompliance(vulnerabilities),
            'SOC 2': this.checkSOC2Compliance(vulnerabilities)
        };
        
        return compliance;
    }

    // Notification System
    async sendNotifications(project, scanExecution) {
        const notifications = project.notifications || {};
        
        if (notifications.email && notifications.email.enabled) {
            await this.sendEmailNotification(notifications.email, project, scanExecution);
        }
        
        if (notifications.slack && notifications.slack.enabled) {
            await this.sendSlackNotification(notifications.slack, project, scanExecution);
        }
        
        if (notifications.webhook && notifications.webhook.enabled) {
            await this.sendWebhookNotification(notifications.webhook, project, scanExecution);
        }
    }

    async sendEmailNotification(emailConfig, project, scanExecution) {
        const criticalCount = scanExecution.vulnerabilities.filter(v => v.severity === 'Critical').length;
        const highCount = scanExecution.vulnerabilities.filter(v => v.severity === 'High').length;
        
        const subject = `Security Scan Complete: ${project.name} - ${criticalCount} Critical, ${highCount} High`;
        const body = this.generateEmailBody(project, scanExecution);
        
        // In real implementation, would send actual email
        console.log(`📧 Email notification sent: ${subject}`);
    }

    async sendSlackNotification(slackConfig, project, scanExecution) {
        const message = this.generateSlackMessage(project, scanExecution);
        
        // In real implementation, would send to Slack webhook
        console.log(`💬 Slack notification sent: ${message}`);
    }

    async sendWebhookNotification(webhookConfig, project, scanExecution) {
        const payload = {
            project: project.name,
            scanId: scanExecution.id,
            status: scanExecution.status,
            vulnerabilities: scanExecution.vulnerabilities.length,
            riskScore: scanExecution.results.summary?.riskScore || 0,
            timestamp: scanExecution.completed
        };
        
        // In real implementation, would POST to webhook URL
        console.log(`🔗 Webhook notification sent: ${JSON.stringify(payload)}`);
    }

    // Scheduled Scanning
    setupPeriodicTasks() {
        // Check for scheduled scans every hour
        setInterval(async () => {
            await this.checkScheduledScans();
        }, 60 * 60 * 1000); // 1 hour
        
        // Cleanup old data daily
        setInterval(async () => {
            await this.cleanupOldData();
        }, 24 * 60 * 60 * 1000); // 24 hours
    }

    async checkScheduledScans() {
        const projects = await this.getProjects({ status: 'active' });
        
        for (const project of projects) {
            if (project.scanSchedule) {
                const shouldRun = this.shouldRunScheduledScan(project);
                if (shouldRun) {
                    console.log(`🕐 Running scheduled scan for project: ${project.name}`);
                    await this.executeComprehensiveScan(project.id);
                }
            }
        }
    }

    shouldRunScheduledScan(project) {
        if (!project.scanSchedule || !project.lastScan) return true;
        
        const lastScan = new Date(project.lastScan);
        const now = new Date();
        const schedule = project.scanSchedule;
        
        switch (schedule.frequency) {
            case 'daily':
                return (now - lastScan) >= 24 * 60 * 60 * 1000;
            case 'weekly':
                return (now - lastScan) >= 7 * 24 * 60 * 60 * 1000;
            case 'monthly':
                return (now - lastScan) >= 30 * 24 * 60 * 60 * 1000;
            default:
                return false;
        }
    }

    async cleanupOldData() {
        // Remove scan results older than 90 days
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - 90);
        
        await this.database.cleanupOldScans(cutoffDate);
        console.log('🧹 Cleaned up old scan data');
    }

    // Utility Methods
    generateId(prefix) {
        return `${prefix}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    }

    async loadSavedData() {
        // Load projects, configurations, and vulnerability tracking from database
        const projects = await this.database.loadProjects();
        const configs = await this.database.loadScanConfigurations();
        const vulnerabilities = await this.database.loadVulnerabilities();
        
        for (const project of projects) {
            this.projects.set(project.id, project);
        }
        
        for (const config of configs) {
            this.scanConfigurations.set(config.id, config);
        }
        
        for (const vuln of vulnerabilities) {
            const key = `${vuln.projectId}-${vuln.type}-${vuln.file || 'global'}`;
            this.vulnerabilityTracking.set(key, vuln);
        }
    }

    // Compliance checking methods (simplified)
    checkOWASPCompliance(vulnerabilities) {
        const owaspCategories = [
            'Injection', 'Broken Authentication', 'Sensitive Data Exposure',
            'XML External Entities', 'Broken Access Control', 'Security Misconfiguration',
            'Cross-Site Scripting', 'Insecure Deserialization', 'Known Vulnerabilities',
            'Insufficient Logging'
        ];
        
        const violations = owaspCategories.filter(category => 
            vulnerabilities.some(v => v.type.toLowerCase().includes(category.toLowerCase()))
        );
        
        return {
            compliant: violations.length === 0,
            violations,
            score: Math.round(((owaspCategories.length - violations.length) / owaspCategories.length) * 100)
        };
    }

    checkNISTCompliance(vulnerabilities) {
        // Simplified NIST compliance check
        const violations = [];
        if (vulnerabilities.some(v => v.type.includes('Authentication'))) violations.push('Access Control');
        if (vulnerabilities.some(v => v.type.includes('Configuration'))) violations.push('Configuration Management');
        
        return {
            compliant: violations.length === 0,
            violations,
            score: Math.round(((5 - violations.length) / 5) * 100)
        };
    }

    checkISO27001Compliance(vulnerabilities) {
        // Simplified ISO 27001 compliance check
        const violations = [];
        if (vulnerabilities.some(v => v.type.includes('Access'))) violations.push('A.9 - Access Control');
        if (vulnerabilities.some(v => v.type.includes('Crypto'))) violations.push('A.10 - Cryptography');
        
        return {
            compliant: violations.length === 0,
            violations,
            score: Math.round(((10 - violations.length) / 10) * 100)
        };
    }

    checkPCIDSSCompliance(vulnerabilities) {
        // Simplified PCI DSS compliance check
        const violations = [];
        if (vulnerabilities.some(v => v.type.includes('Password'))) violations.push('Strong Passwords');
        if (vulnerabilities.some(v => v.type.includes('Encryption'))) violations.push('Data Encryption');
        
        return {
            compliant: violations.length === 0,
            violations,
            score: Math.round(((6 - violations.length) / 6) * 100)
        };
    }

    checkSOC2Compliance(vulnerabilities) {
        // Simplified SOC 2 compliance check
        const violations = [];
        if (vulnerabilities.some(v => v.type.includes('Access'))) violations.push('Security');
        if (vulnerabilities.some(v => v.type.includes('Availability'))) violations.push('Availability');
        
        return {
            compliant: violations.length === 0,
            violations,
            score: Math.round(((5 - violations.length) / 5) * 100)
        };
    }

    generateEmailBody(project, scanExecution) {
        return `
Security Scan Report for ${project.name}

Scan ID: ${scanExecution.id}
Duration: ${Math.round(scanExecution.duration / 1000)}s
Status: ${scanExecution.status}

Summary:
- Total Vulnerabilities: ${scanExecution.vulnerabilities.length}
- Critical: ${scanExecution.vulnerabilities.filter(v => v.severity === 'Critical').length}
- High: ${scanExecution.vulnerabilities.filter(v => v.severity === 'High').length}
- Medium: ${scanExecution.vulnerabilities.filter(v => v.severity === 'Medium').length}
- Low: ${scanExecution.vulnerabilities.filter(v => v.severity === 'Low').length}

Risk Score: ${scanExecution.results.summary?.riskScore || 0}/100

View full report in the Security Dashboard.
        `;
    }

    generateSlackMessage(project, scanExecution) {
        const criticalCount = scanExecution.vulnerabilities.filter(v => v.severity === 'Critical').length;
        const emoji = criticalCount > 0 ? '🚨' : scanExecution.vulnerabilities.length > 0 ? '⚠️' : '✅';
        
        return `${emoji} Security scan completed for *${project.name}*\n` +
               `Vulnerabilities: ${scanExecution.vulnerabilities.length} total\n` +
               `Risk Score: ${scanExecution.results.summary?.riskScore || 0}/100`;
    }
}

// Simple in-memory database (in production, would use real database)
class SecurityDatabase {
    constructor() {
        this.projects = new Map();
        this.scanConfigurations = new Map();
        this.scanResults = new Map();
        this.vulnerabilities = new Map();
    }

    async saveProject(project) {
        this.projects.set(project.id, { ...project });
        return true;
    }

    async updateProject(projectId, project) {
        this.projects.set(projectId, { ...project });
        return true;
    }

    async loadProjects() {
        return Array.from(this.projects.values());
    }

    async saveScanConfiguration(config) {
        this.scanConfigurations.set(config.id, { ...config });
        return true;
    }

    async deleteScanConfiguration(configId) {
        this.scanConfigurations.delete(configId);
        return true;
    }

    async loadScanConfigurations() {
        return Array.from(this.scanConfigurations.values());
    }

    async saveScanResult(scanResult) {
        this.scanResults.set(scanResult.id, { ...scanResult });
        return true;
    }

    async getScanHistory(projectId, timeRange) {
        const scans = Array.from(this.scanResults.values())
            .filter(scan => scan.projectId === projectId)
            .sort((a, b) => new Date(b.completed) - new Date(a.completed));
        
        // Apply time range filter
        const cutoffDate = new Date();
        const days = parseInt(timeRange.replace('d', ''));
        cutoffDate.setDate(cutoffDate.getDate() - days);
        
        return scans.filter(scan => new Date(scan.completed) >= cutoffDate);
    }

    async getLatestScan(projectId) {
        const scans = Array.from(this.scanResults.values())
            .filter(scan => scan.projectId === projectId)
            .sort((a, b) => new Date(b.completed) - new Date(a.completed));
        
        return scans[0] || null;
    }

    async saveVulnerability(vulnerability) {
        this.vulnerabilities.set(vulnerability.id, { ...vulnerability });
        return true;
    }

    async updateVulnerability(vulnId, vulnerability) {
        this.vulnerabilities.set(vulnId, { ...vulnerability });
        return true;
    }

    async loadVulnerabilities() {
        return Array.from(this.vulnerabilities.values());
    }

    async cleanupOldScans(cutoffDate) {
        for (const [id, scan] of this.scanResults.entries()) {
            if (new Date(scan.completed) < cutoffDate) {
                this.scanResults.delete(id);
            }
        }
        return true;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { SecurityDashboard, SecurityDatabase };
}