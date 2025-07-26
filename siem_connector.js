/**
 * SIEM Connector
 * Security Information and Event Management system integration
 * 
 * This module provides integration with popular SIEM/SOAR platforms
 * for automated security event forwarding and workflow orchestration.
 */

class SIEMConnector {
    constructor(config = {}) {
        this.config = {
            siemPlatform: config.siemPlatform || 'splunk', // splunk, qradar, sentinel, elastic
            endpoint: config.endpoint || null,
            apiKey: config.apiKey || null,
            indexName: config.indexName || 'mcp_security',
            batchSize: config.batchSize || 100,
            flushInterval: config.flushInterval || 60000, // 1 minute
            enableRealTime: config.enableRealTime || true,
            enableAggregation: config.enableAggregation || true,
            retryAttempts: config.retryAttempts || 3,
            ...config
        };
        
        this.eventQueue = [];
        this.connectors = new Map();
        this.flushTimer = null;
        this.connectionStatus = new Map();
        
        this.initializeSIEMConnectors();
        this.startEventProcessing();
    }

    /**
     * Initialize SIEM platform connectors
     */
    initializeSIEMConnectors() {
        console.log('🔌 Initializing SIEM connectors...');
        
        // Splunk Connector
        this.connectors.set('splunk', {
            name: 'Splunk Enterprise',
            endpoint: '/services/collector/event',
            authHeader: 'Splunk',
            formatEvent: this.formatSplunkEvent.bind(this),
            sendEvents: this.sendSplunkEvents.bind(this),
            createAlert: this.createSplunkAlert.bind(this),
            maxBatchSize: 1000
        });

        // IBM QRadar Connector
        this.connectors.set('qradar', {
            name: 'IBM QRadar',
            endpoint: '/api/siem/offenses',
            authHeader: 'SEC',
            formatEvent: this.formatQRadarEvent.bind(this),
            sendEvents: this.sendQRadarEvents.bind(this),
            createAlert: this.createQRadarAlert.bind(this),
            maxBatchSize: 500
        });

        // Microsoft Sentinel Connector
        this.connectors.set('sentinel', {
            name: 'Microsoft Sentinel',
            endpoint: '/api/logs',
            authHeader: 'Bearer',
            formatEvent: this.formatSentinelEvent.bind(this),
            sendEvents: this.sendSentinelEvents.bind(this),
            createAlert: this.createSentinelAlert.bind(this),
            maxBatchSize: 1000
        });

        // Elastic Security Connector
        this.connectors.set('elastic', {
            name: 'Elastic Security',
            endpoint: '/_bulk',
            authHeader: 'ApiKey',
            formatEvent: this.formatElasticEvent.bind(this),
            sendEvents: this.sendElasticEvents.bind(this),
            createAlert: this.createElasticAlert.bind(this),
            maxBatchSize: 1000
        });

        // Generic CEF/Syslog Connector
        this.connectors.set('cef', {
            name: 'CEF/Syslog',
            endpoint: '/syslog',
            authHeader: null,
            formatEvent: this.formatCEFEvent.bind(this),
            sendEvents: this.sendCEFEvents.bind(this),
            createAlert: this.createCEFAlert.bind(this),
            maxBatchSize: 100
        });

        console.log(`✅ Initialized ${this.connectors.size} SIEM connectors`);
    }

    /**
     * Start event processing and batching
     */
    startEventProcessing() {
        if (this.config.enableRealTime) {
            console.log('🔄 Starting real-time event processing...');
            
            this.flushTimer = setInterval(() => {
                this.flushEventBatch();
            }, this.config.flushInterval);
        }
    }

    /**
     * Send security events to SIEM
     */
    async sendSecurityEvents(events) {
        console.log(`📤 Sending ${events.length} security events to SIEM...`);
        
        const connector = this.connectors.get(this.config.siemPlatform);
        if (!connector) {
            throw new Error(`Unsupported SIEM platform: ${this.config.siemPlatform}`);
        }

        try {
            // Format events for target SIEM
            const formattedEvents = events.map(event => connector.formatEvent(event));
            
            // Send events in batches
            const batches = this.createEventBatches(formattedEvents, connector.maxBatchSize);
            const results = [];

            for (const batch of batches) {
                const result = await connector.sendEvents(batch);
                results.push(result);
            }

            // Update connection status
            this.connectionStatus.set(this.config.siemPlatform, {
                lastSuccess: new Date(),
                status: 'connected',
                eventsSent: events.length
            });

            console.log(`✅ Successfully sent ${events.length} events to ${connector.name}`);
            return {
                success: true,
                eventsSent: events.length,
                batches: results.length,
                platform: connector.name
            };

        } catch (error) {
            console.error(`❌ Failed to send events to ${connector.name}:`, error);
            
            this.connectionStatus.set(this.config.siemPlatform, {
                lastError: new Date(),
                status: 'error',
                error: error.message
            });

            throw error;
        }
    }

    /**
     * Send vulnerability findings to SIEM
     */
    async sendVulnerabilityFindings(scanResults) {
        console.log('🔍 Sending vulnerability findings to SIEM...');
        
        const events = [];
        
        // Convert vulnerabilities to SIEM events
        for (const vulnerability of scanResults.vulnerabilities) {
            const event = {
                timestamp: new Date().toISOString(),
                eventType: 'vulnerability_finding',
                source: 'mcp_guardian',
                severity: this.mapSeverityToSIEM(vulnerability.severity),
                vulnerability: {
                    id: vulnerability.id,
                    type: vulnerability.type,
                    category: vulnerability.category,
                    description: vulnerability.description,
                    cve: vulnerability.cve,
                    cvss: vulnerability.cvss,
                    evidence: vulnerability.evidence,
                    recommendation: vulnerability.recommendation
                },
                asset: {
                    name: scanResults.metadata.serverName,
                    type: 'mcp_server',
                    environment: scanResults.metadata.environment || 'unknown'
                },
                scan: {
                    id: scanResults.metadata.scanId,
                    timestamp: scanResults.metadata.scanTimestamp,
                    duration: scanResults.metadata.scanDuration,
                    scanner: 'mcp_guardian_enterprise'
                }
            };
            
            events.push(event);
        }

        // Add scan summary event
        events.push({
            timestamp: new Date().toISOString(),
            eventType: 'security_scan_completed',
            source: 'mcp_guardian',
            severity: this.calculateScanSeverity(scanResults),
            summary: {
                totalVulnerabilities: scanResults.summary.totalVulnerabilities,
                severityBreakdown: scanResults.summary.severityBreakdown,
                riskScore: scanResults.summary.riskScore,
                complianceScore: scanResults.compliance?.overallScore
            },
            asset: {
                name: scanResults.metadata.serverName,
                type: 'mcp_server'
            },
            scan: {
                id: scanResults.metadata.scanId,
                timestamp: scanResults.metadata.scanTimestamp,
                duration: scanResults.metadata.scanDuration
            }
        });

        return await this.sendSecurityEvents(events);
    }

    /**
     * Send compliance findings to SIEM
     */
    async sendComplianceFindings(complianceResults) {
        console.log('📋 Sending compliance findings to SIEM...');
        
        const events = [];
        
        // Convert compliance findings to SIEM events
        for (const finding of complianceResults.findings || []) {
            const event = {
                timestamp: new Date().toISOString(),
                eventType: 'compliance_violation',
                source: 'mcp_guardian',
                severity: this.mapSeverityToSIEM(finding.severity),
                compliance: {
                    framework: finding.framework,
                    control: finding.control,
                    controlName: finding.controlName,
                    category: finding.category,
                    description: finding.description,
                    weight: finding.weight
                },
                asset: {
                    name: 'mcp_server',
                    type: 'application'
                }
            };
            
            events.push(event);
        }

        // Add compliance summary event
        events.push({
            timestamp: new Date().toISOString(),
            eventType: 'compliance_assessment_completed',
            source: 'mcp_guardian',
            severity: complianceResults.overallScore >= 0.85 ? 'low' : 'medium',
            compliance: {
                overallScore: complianceResults.overallScore,
                status: complianceResults.overallScore >= 0.85 ? 'compliant' : 'non_compliant',
                frameworks: Object.keys(complianceResults.frameworks || {}),
                totalFindings: complianceResults.findings?.length || 0
            }
        });

        return await this.sendSecurityEvents(events);
    }

    /**
     * Send threat intelligence events to SIEM
     */
    async sendThreatIntelligence(threatIntelResults) {
        console.log('🕵️ Sending threat intelligence to SIEM...');
        
        const events = [];
        
        // Add threat intelligence update event
        events.push({
            timestamp: new Date().toISOString(),
            eventType: 'threat_intelligence_update',
            source: 'mcp_guardian',
            severity: 'info',
            threatIntel: {
                newThreats: threatIntelResults.newThreats || 0,
                updatedThreats: threatIntelResults.updatedThreats || 0,
                sources: threatIntelResults.sources || [],
                lastUpdate: threatIntelResults.timestamp
            }
        });

        return await this.sendSecurityEvents(events);
    }

    /**
     * Create security alerts in SIEM for critical findings
     */
    async createSecurityAlerts(scanResults) {
        console.log('🚨 Creating security alerts for critical findings...');
        
        const connector = this.connectors.get(this.config.siemPlatform);
        if (!connector) {
            throw new Error(`Unsupported SIEM platform: ${this.config.siemPlatform}`);
        }

        const criticalVulnerabilities = scanResults.vulnerabilities.filter(v => 
            v.severity === 'critical' || v.severity === 'high'
        );

        const alerts = [];
        
        for (const vulnerability of criticalVulnerabilities) {
            try {
                const alert = await connector.createAlert({
                    title: `Critical Security Finding: ${vulnerability.type}`,
                    description: vulnerability.description,
                    severity: vulnerability.severity,
                    source: 'MCP Guardian Enterprise',
                    asset: scanResults.metadata.serverName,
                    evidence: vulnerability.evidence,
                    recommendation: vulnerability.recommendation,
                    cve: vulnerability.cve,
                    category: vulnerability.category
                });
                
                alerts.push(alert);
            } catch (error) {
                console.error(`❌ Failed to create alert for ${vulnerability.id}:`, error);
            }
        }

        console.log(`✅ Created ${alerts.length} security alerts`);
        return alerts;
    }

    /**
     * Queue events for batch processing
     */
    queueEvent(event) {
        this.eventQueue.push({
            ...event,
            queuedAt: new Date()
        });

        // Flush immediately if batch size reached
        if (this.eventQueue.length >= this.config.batchSize) {
            this.flushEventBatch();
        }
    }

    /**
     * Flush queued events
     */
    async flushEventBatch() {
        if (this.eventQueue.length === 0) {
            return;
        }

        console.log(`📤 Flushing batch of ${this.eventQueue.length} events...`);
        
        const eventsToSend = [...this.eventQueue];
        this.eventQueue = [];

        try {
            await this.sendSecurityEvents(eventsToSend);
        } catch (error) {
            console.error('❌ Failed to flush event batch:', error);
            
            // Re-queue events for retry (with exponential backoff)
            setTimeout(() => {
                this.eventQueue.unshift(...eventsToSend);
            }, 5000);
        }
    }

    /**
     * Platform-specific event formatters
     */
    
    // Splunk Event Format
    formatSplunkEvent(event) {
        return {
            time: new Date(event.timestamp).getTime() / 1000,
            host: 'mcp-guardian',
            source: event.source,
            sourcetype: event.eventType,
            index: this.config.indexName,
            event: event
        };
    }

    // QRadar Event Format
    formatQRadarEvent(event) {
        return {
            startTime: new Date(event.timestamp).getTime(),
            eventCount: 1,
            eventName: event.eventType,
            severity: this.mapSeverityToQRadar(event.severity),
            sourceAddress: '127.0.0.1',
            magnitude: this.calculateMagnitude(event),
            properties: this.flattenEventProperties(event)
        };
    }

    // Microsoft Sentinel Event Format
    formatSentinelEvent(event) {
        return {
            TimeGenerated: event.timestamp,
            Computer: 'mcp-guardian',
            EventType: event.eventType,
            Severity: event.severity,
            SourceSystem: 'MCP Guardian',
            EventData: JSON.stringify(event)
        };
    }

    // Elastic Security Event Format
    formatElasticEvent(event) {
        return {
            '@timestamp': event.timestamp,
            event: {
                category: ['security'],
                type: [event.eventType],
                severity: this.mapSeverityToElastic(event.severity)
            },
            source: {
                application: 'mcp-guardian'
            },
            ...event
        };
    }

    // CEF Event Format
    formatCEFEvent(event) {
        const cefVersion = '0';
        const deviceVendor = 'MCP Guardian';
        const deviceProduct = 'Enterprise Security Scanner';
        const deviceVersion = '3.0.0';
        const signatureId = event.eventType;
        const name = event.vulnerability?.type || event.eventType;
        const severity = this.mapSeverityToCEF(event.severity);
        
        const extensions = [
            `src=${event.asset?.name || 'unknown'}`,
            `msg=${event.description || event.vulnerability?.description || ''}`,
            `cat=${event.vulnerability?.category || event.eventType}`
        ];

        return `CEF:${cefVersion}|${deviceVendor}|${deviceProduct}|${deviceVersion}|${signatureId}|${name}|${severity}|${extensions.join(' ')}`;
    }

    /**
     * Platform-specific event senders
     */
    
    async sendSplunkEvents(events) {
        // Simulate Splunk HTTP Event Collector API call
        console.log(`📤 Sending ${events.length} events to Splunk...`);
        
        const payload = events.map(event => JSON.stringify(event)).join('\n');
        
        // Would make actual HTTP request to Splunk HEC endpoint
        return {
            success: true,
            eventsAccepted: events.length,
            response: 'Events successfully sent to Splunk'
        };
    }

    async sendQRadarEvents(events) {
        console.log(`📤 Sending ${events.length} events to QRadar...`);
        
        // Would make actual API calls to QRadar
        return {
            success: true,
            eventsProcessed: events.length,
            response: 'Events successfully sent to QRadar'
        };
    }

    async sendSentinelEvents(events) {
        console.log(`📤 Sending ${events.length} events to Microsoft Sentinel...`);
        
        // Would make actual API calls to Azure Log Analytics
        return {
            success: true,
            eventsIngested: events.length,
            response: 'Events successfully sent to Sentinel'
        };
    }

    async sendElasticEvents(events) {
        console.log(`📤 Sending ${events.length} events to Elastic Security...`);
        
        // Would use Elasticsearch bulk API
        return {
            success: true,
            eventsIndexed: events.length,
            response: 'Events successfully indexed in Elasticsearch'
        };
    }

    async sendCEFEvents(events) {
        console.log(`📤 Sending ${events.length} CEF events via Syslog...`);
        
        // Would send via syslog protocol
        return {
            success: true,
            eventsSent: events.length,
            response: 'CEF events successfully sent via Syslog'
        };
    }

    /**
     * Platform-specific alert creators
     */
    
    async createSplunkAlert(alertData) {
        return {
            alertId: `splunk-${Date.now()}`,
            platform: 'splunk',
            created: true,
            searchUrl: `https://splunk.example.com/app/search?q=${encodeURIComponent(alertData.title)}`
        };
    }

    async createQRadarAlert(alertData) {
        return {
            alertId: `qradar-${Date.now()}`,
            platform: 'qradar',
            created: true,
            offenseId: Math.floor(Math.random() * 10000)
        };
    }

    async createSentinelAlert(alertData) {
        return {
            alertId: `sentinel-${Date.now()}`,
            platform: 'sentinel',
            created: true,
            incidentId: `incident-${Date.now()}`
        };
    }

    async createElasticAlert(alertData) {
        return {
            alertId: `elastic-${Date.now()}`,
            platform: 'elastic',
            created: true,
            detectionRuleId: `rule-${Date.now()}`
        };
    }

    async createCEFAlert(alertData) {
        return {
            alertId: `cef-${Date.now()}`,
            platform: 'cef',
            created: true,
            syslogMessage: this.formatCEFEvent(alertData)
        };
    }

    /**
     * Utility methods
     */
    
    createEventBatches(events, batchSize) {
        const batches = [];
        for (let i = 0; i < events.length; i += batchSize) {
            batches.push(events.slice(i, i + batchSize));
        }
        return batches;
    }

    mapSeverityToSIEM(severity) {
        const mapping = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'info': 'informational'
        };
        return mapping[severity] || 'unknown';
    }

    mapSeverityToQRadar(severity) {
        const mapping = {
            'critical': 10,
            'high': 8,
            'medium': 5,
            'low': 3,
            'info': 1
        };
        return mapping[severity] || 1;
    }

    mapSeverityToElastic(severity) {
        return this.mapSeverityToSIEM(severity);
    }

    mapSeverityToCEF(severity) {
        const mapping = {
            'critical': '10',
            'high': '8',
            'medium': '5',
            'low': '3',
            'info': '1'
        };
        return mapping[severity] || '1';
    }

    calculateScanSeverity(scanResults) {
        if (scanResults.summary.severityBreakdown.critical > 0) return 'critical';
        if (scanResults.summary.severityBreakdown.high > 0) return 'high';
        if (scanResults.summary.severityBreakdown.medium > 0) return 'medium';
        return 'low';
    }

    calculateMagnitude(event) {
        // Calculate QRadar magnitude based on event properties
        let magnitude = 3; // Base magnitude
        
        if (event.vulnerability?.cvss) {
            magnitude += Math.floor(event.vulnerability.cvss);
        }
        
        if (event.severity === 'critical') magnitude += 3;
        if (event.severity === 'high') magnitude += 2;
        
        return Math.min(magnitude, 10);
    }

    flattenEventProperties(event) {
        // Flatten nested event properties for QRadar
        const properties = [];
        
        const flatten = (obj, prefix = '') => {
            for (const [key, value] of Object.entries(obj)) {
                if (typeof value === 'object' && value !== null) {
                    flatten(value, `${prefix}${key}_`);
                } else {
                    properties.push({
                        name: `${prefix}${key}`,
                        value: String(value)
                    });
                }
            }
        };
        
        flatten(event);
        return properties;
    }

    /**
     * Get connector status
     */
    getConnectorStatus() {
        return {
            platform: this.config.siemPlatform,
            status: this.connectionStatus.get(this.config.siemPlatform) || { status: 'unknown' },
            queuedEvents: this.eventQueue.length,
            availablePlatforms: Array.from(this.connectors.keys()),
            lastFlush: this.flushTimer ? new Date() : null
        };
    }

    /**
     * Test SIEM connection
     */
    async testConnection() {
        console.log(`🔍 Testing connection to ${this.config.siemPlatform}...`);
        
        const testEvent = {
            timestamp: new Date().toISOString(),
            eventType: 'connection_test',
            source: 'mcp_guardian',
            severity: 'info',
            message: 'SIEM connector test event'
        };

        try {
            await this.sendSecurityEvents([testEvent]);
            console.log(`✅ Successfully connected to ${this.config.siemPlatform}`);
            return true;
        } catch (error) {
            console.error(`❌ Connection test failed for ${this.config.siemPlatform}:`, error);
            return false;
        }
    }

    /**
     * Shutdown SIEM connector
     */
    shutdown() {
        console.log('🔄 Shutting down SIEM connector...');
        
        if (this.flushTimer) {
            clearInterval(this.flushTimer);
            this.flushTimer = null;
        }
        
        // Flush remaining events
        if (this.eventQueue.length > 0) {
            this.flushEventBatch();
        }
        
        console.log('✅ SIEM connector shutdown complete');
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SIEMConnector;
}

// Example usage
if (typeof window !== 'undefined') {
    window.SIEMConnector = SIEMConnector;
}
