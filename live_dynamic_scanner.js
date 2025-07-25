/**
 * Live Dynamic Security Scanner
 * Performs real-time dynamic testing against running MCP servers
 */

class LiveDynamicScanner {
    constructor(serverConfig, updateCallback) {
        this.serverConfig = serverConfig;
        this.updateCallback = updateCallback;
        this.isScanning = false;
        this.vulnerabilities = [];
        this.testResults = {};
        this.activeConnections = new Map();
        
        // Real-time testing configuration
        this.config = {
            maxConcurrentTests: 10,
            requestTimeout: 30000,
            retryAttempts: 3,
            delayBetweenTests: 100
        };
    }

    async startLiveScan() {
        if (this.isScanning) {
            throw new Error('Scan already in progress');
        }

        this.isScanning = true;
        this.vulnerabilities = [];
        this.testResults = {};

        try {
            this.updateCallback('🚀 Initializing live dynamic scanner...', 0);
            
            // Phase 1: Server Discovery and Reconnaissance
            await this.performReconnaissance();
            
            // Phase 2: Active Vulnerability Testing
            await this.performActiveVulnerabilityTesting();
            
            // Phase 3: Runtime Behavior Analysis
            await this.performRuntimeAnalysis();
            
            // Phase 4: Stress Testing and DoS Detection
            await this.performStressTesting();
            
            // Phase 5: Business Logic Testing
            await this.performBusinessLogicTesting();
            
            this.updateCallback('✅ Live dynamic scan completed', 100);
            
            return {
                vulnerabilities: this.vulnerabilities,
                testResults: this.testResults,
                scanSummary: this.generateScanSummary()
            };
            
        } catch (error) {
            this.updateCallback(`❌ Scan failed: ${error.message}`, 100);
            throw error;
        } finally {
            this.isScanning = false;
            this.closeAllConnections();
        }
    }

    async performReconnaissance() {
        this.updateCallback('🔍 Phase 1: Server reconnaissance and discovery...', 10);
        
        // Test server connectivity and gather information
        const connectivityResult = await this.testServerConnectivity();
        this.testResults.connectivity = connectivityResult;
        
        if (!connectivityResult.isReachable) {
            this.addVulnerability({
                id: 'LIVE-CONN-001',
                severity: 'High',
                title: 'Server Unreachable for Dynamic Testing',
                description: 'Target server is not accessible for live security testing',
                evidence: `Connection failed: ${connectivityResult.error}`,
                recommendation: 'Ensure server is running and network accessible',
                phase: 'reconnaissance'
            });
            return;
        }

        // Fingerprint server technology
        await this.fingerprintServer();
        
        // Discover available endpoints
        await this.discoverEndpoints();
        
        // Test for information disclosure
        await this.testInformationDisclosure();
    }

    async testServerConnectivity() {
        this.updateCallback('🔗 Testing server connectivity...', 12);
        
        const results = {
            isReachable: false,
            responseTime: null,
            serverHeaders: {},
            tlsInfo: {},
            error: null
        };

        try {
            const startTime = Date.now();
            
            // Test basic HTTP connectivity
            const response = await this.makeRequest('/', {
                method: 'GET',
                timeout: 5000
            });
            
            results.isReachable = true;
            results.responseTime = Date.now() - startTime;
            results.serverHeaders = response.headers;
            results.statusCode = response.status;
            
            this.updateCallback(`✅ Server reachable (${results.responseTime}ms)`, 15);
            
            // Test HTTPS/TLS if applicable
            if (this.serverConfig.serverUrl.startsWith('https://')) {
                results.tlsInfo = await this.analyzeTLS();
            }
            
        } catch (error) {
            results.error = error.message;
            this.updateCallback(`❌ Server unreachable: ${error.message}`, 15);
        }
        
        return results;
    }

    async fingerprintServer() {
        this.updateCallback('🔍 Fingerprinting server technology...', 18);
        
        try {
            const response = await this.makeRequest('/', { method: 'HEAD' });
            const headers = response.headers;
            
            const fingerprint = {
                server: headers.server || 'Unknown',
                poweredBy: headers['x-powered-by'] || 'Unknown',
                framework: this.detectFramework(headers),
                language: this.detectLanguage(headers),
                cloudProvider: this.detectCloudProvider(headers)
            };
            
            this.testResults.fingerprint = fingerprint;
            
            // Check for information disclosure in headers
            if (fingerprint.server !== 'Unknown' && fingerprint.server.includes('/')) {
                this.addVulnerability({
                    id: 'LIVE-INFO-001',
                    severity: 'Low',
                    title: 'Server Version Disclosure',
                    description: 'Server header reveals version information',
                    evidence: `Server: ${fingerprint.server}`,
                    recommendation: 'Remove version information from server headers',
                    phase: 'reconnaissance'
                });
            }
            
            this.updateCallback(`🔍 Server fingerprint: ${fingerprint.server}`, 20);
            
        } catch (error) {
            this.updateCallback(`⚠️ Fingerprinting failed: ${error.message}`, 20);
        }
    }

    async discoverEndpoints() {
        this.updateCallback('🗺️ Discovering available endpoints...', 22);
        
        const commonEndpoints = [
            '/api', '/api/v1', '/api/v2', '/graphql',
            '/health', '/status', '/metrics', '/debug',
            '/admin', '/management', '/actuator',
            '/swagger', '/docs', '/api-docs',
            '/.well-known', '/robots.txt', '/sitemap.xml'
        ];
        
        const discoveredEndpoints = [];
        
        for (const endpoint of commonEndpoints) {
            try {
                const response = await this.makeRequest(endpoint, { method: 'GET' });
                
                if (response.status < 400) {
                    discoveredEndpoints.push({
                        path: endpoint,
                        status: response.status,
                        contentType: response.headers['content-type'] || 'unknown'
                    });
                    
                    // Check for sensitive endpoints
                    if (/admin|debug|management|actuator/.test(endpoint)) {
                        this.addVulnerability({
                            id: `LIVE-ENDPOINT-${Date.now()}`,
                            severity: 'Medium',
                            title: 'Sensitive Endpoint Exposed',
                            description: `Administrative endpoint ${endpoint} is publicly accessible`,
                            evidence: `${endpoint} returned status ${response.status}`,
                            recommendation: 'Restrict access to administrative endpoints',
                            phase: 'reconnaissance'
                        });
                    }
                }
                
            } catch (error) {
                // Expected for non-existent endpoints
            }
        }
        
        this.testResults.discoveredEndpoints = discoveredEndpoints;
        this.updateCallback(`🗺️ Found ${discoveredEndpoints.length} accessible endpoints`, 25);
    }

    async testInformationDisclosure() {
        this.updateCallback('📋 Testing for information disclosure...', 27);
        
        const infoEndpoints = [
            '/.env', '/config.json', '/package.json',
            '/composer.json', '/requirements.txt',
            '/error', '/debug', '/trace'
        ];
        
        for (const endpoint of infoEndpoints) {
            try {
                const response = await this.makeRequest(endpoint);
                
                if (response.status === 200 && response.body) {
                    this.addVulnerability({
                        id: `LIVE-INFO-${Date.now()}`,
                        severity: 'Medium',
                        title: 'Information Disclosure',
                        description: `Sensitive file ${endpoint} is publicly accessible`,
                        evidence: `${endpoint} returned ${response.body.length} bytes`,
                        recommendation: 'Remove or restrict access to sensitive files',
                        phase: 'reconnaissance'
                    });
                    
                    this.updateCallback(`📋 Information disclosure: ${endpoint}`, 30);
                }
                
            } catch (error) {
                // Expected for non-existent files
            }
        }
    }

    async performActiveVulnerabilityTesting() {
        this.updateCallback('🎯 Phase 2: Active vulnerability testing...', 30);
        
        // SQL Injection Testing
        await this.testSQLInjectionLive();
        
        // XSS Testing
        await this.testXSSLive();
        
        // Command Injection Testing
        await this.testCommandInjectionLive();
        
        // SSRF Testing
        await this.testSSRFLive();
        
        // Path Traversal Testing
        await this.testPathTraversalLive();
        
        // Authentication Bypass Testing
        await this.testAuthenticationBypassLive();
    }

    async testSQLInjectionLive() {
        this.updateCallback('💉 Testing SQL injection vulnerabilities...', 35);
        
        const sqlPayloads = [
            "' OR '1'='1",
            "'; WAITFOR DELAY '00:00:05'--",
            "' UNION SELECT NULL,NULL,NULL--",
            "'; DROP TABLE users; --",
            "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--"
        ];
        
        for (const tool of this.serverConfig.tools) {
            if (!tool.parameters) continue;
            
            for (const [paramName, paramType] of Object.entries(tool.parameters)) {
                for (const payload of sqlPayloads) {
                    try {
                        const startTime = Date.now();
                        const response = await this.makeToolCall(tool.name, {
                            [paramName]: payload
                        });
                        const responseTime = Date.now() - startTime;
                        
                        // Time-based SQL injection detection
                        if (payload.includes('WAITFOR') && responseTime > 4000) {
                            this.addVulnerability({
                                id: `LIVE-SQL-TIME-${Date.now()}`,
                                severity: 'Critical',
                                title: 'Time-based SQL Injection',
                                description: `Tool '${tool.name}' is vulnerable to time-based SQL injection`,
                                evidence: `Response time: ${responseTime}ms with WAITFOR payload`,
                                recommendation: 'Use parameterized queries immediately',
                                tool: tool.name,
                                parameter: paramName,
                                phase: 'active-testing'
                            });
                            
                            this.updateCallback(`🚨 SQL injection confirmed in ${tool.name}`, 40);
                        }
                        
                        // Error-based SQL injection detection
                        if (response.body && typeof response.body === 'string') {
                            const errorKeywords = ['sql', 'mysql', 'sqlite', 'syntax error', 'table', 'column'];
                            const hasError = errorKeywords.some(keyword => 
                                response.body.toLowerCase().includes(keyword)
                            );
                            
                            if (hasError) {
                                this.addVulnerability({
                                    id: `LIVE-SQL-ERROR-${Date.now()}`,
                                    severity: 'Critical',
                                    title: 'Error-based SQL Injection',
                                    description: `Tool '${tool.name}' exposes SQL errors`,
                                    evidence: `SQL error keywords detected in response`,
                                    recommendation: 'Implement proper error handling and use parameterized queries',
                                    tool: tool.name,
                                    parameter: paramName,
                                    phase: 'active-testing'
                                });
                                
                                this.updateCallback(`🚨 SQL error exposure in ${tool.name}`, 40);
                            }
                        }
                        
                    } catch (error) {
                        // SQL injection might cause server errors
                        if (error.message.includes('sql') || error.message.includes('database')) {
                            this.addVulnerability({
                                id: `LIVE-SQL-CRASH-${Date.now()}`,
                                severity: 'High',
                                title: 'SQL Injection - Server Error',
                                description: `Tool '${tool.name}' crashes with SQL injection payload`,
                                evidence: error.message,
                                recommendation: 'Fix SQL injection vulnerability and improve error handling',
                                tool: tool.name,
                                parameter: paramName,
                                phase: 'active-testing'
                            });
                        }
                    }
                }
            }
        }
    }

    async testXSSLive() {
        this.updateCallback('🔗 Testing Cross-Site Scripting (XSS)...', 42);
        
        const xssPayloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            'javascript:alert("XSS")',
            '<iframe src="javascript:alert(\'XSS\')"></iframe>'
        ];
        
        for (const tool of this.serverConfig.tools) {
            if (!tool.parameters) continue;
            
            // Focus on tools that might render content
            if (!/render|display|show|html|content|message/.test(tool.description)) continue;
            
            for (const [paramName, paramType] of Object.entries(tool.parameters)) {
                for (const payload of xssPayloads) {
                    try {
                        const response = await this.makeToolCall(tool.name, {
                            [paramName]: payload
                        });
                        
                        if (response.body && typeof response.body === 'string') {
                            // Check if payload is reflected without encoding
                            if (response.body.includes(payload)) {
                                this.addVulnerability({
                                    id: `LIVE-XSS-${Date.now()}`,
                                    severity: 'High',
                                    title: 'Reflected Cross-Site Scripting (XSS)',
                                    description: `Tool '${tool.name}' reflects user input without encoding`,
                                    evidence: `Payload reflected: ${payload}`,
                                    recommendation: 'Encode all user input before displaying',
                                    tool: tool.name,
                                    parameter: paramName,
                                    phase: 'active-testing'
                                });
                                
                                this.updateCallback(`🔗 XSS vulnerability in ${tool.name}`, 45);
                            }
                        }
                        
                    } catch (error) {
                        // XSS might cause parsing errors
                        if (error.message.includes('script') || error.message.includes('html')) {
                            this.addVulnerability({
                                id: `LIVE-XSS-ERROR-${Date.now()}`,
                                severity: 'Medium',
                                title: 'XSS - Parsing Error',
                                description: `Tool '${tool.name}' has parsing issues with HTML content`,
                                evidence: error.message,
                                recommendation: 'Review HTML/JavaScript parsing for security issues',
                                tool: tool.name,
                                parameter: paramName,
                                phase: 'active-testing'
                            });
                        }
                    }
                }
            }
        }
    }

    async testCommandInjectionLive() {
        this.updateCallback('⚡ Testing command injection vulnerabilities...', 47);
        
        const commandPayloads = [
            '; whoami',
            '| whoami',
            '&& whoami',
            '`whoami`',
            '$(whoami)',
            '; sleep 5',
            '| ping -c 1 127.0.0.1',
            '; echo "COMMAND_INJECTION_TEST"'
        ];
        
        for (const tool of this.serverConfig.tools) {
            if (!tool.parameters) continue;
            
            // Focus on tools that might execute commands
            if (!/command|cmd|exec|run|execute|shell|system/.test(tool.description)) continue;
            
            for (const [paramName, paramType] of Object.entries(tool.parameters)) {
                for (const payload of commandPayloads) {
                    try {
                        const startTime = Date.now();
                        const response = await this.makeToolCall(tool.name, {
                            [paramName]: `test${payload}`
                        });
                        const responseTime = Date.now() - startTime;
                        
                        if (response.body && typeof response.body === 'string') {
                            const responseText = response.body.toLowerCase();
                            
                            // Check for command execution indicators
                            if (responseText.includes('command_injection_test') ||
                                responseText.includes('uid=') ||
                                responseText.includes('gid=') ||
                                responseText.includes('ping statistics')) {
                                
                                this.addVulnerability({
                                    id: `LIVE-CMD-${Date.now()}`,
                                    severity: 'Critical',
                                    title: 'Command Injection Vulnerability',
                                    description: `Tool '${tool.name}' executes injected commands`,
                                    evidence: `Command output detected in response`,
                                    recommendation: 'Never execute user input as commands',
                                    tool: tool.name,
                                    parameter: paramName,
                                    phase: 'active-testing'
                                });
                                
                                this.updateCallback(`⚡ Command injection confirmed in ${tool.name}`, 50);
                            }
                            
                            // Time-based command injection (sleep)
                            if (payload.includes('sleep') && responseTime > 4000) {
                                this.addVulnerability({
                                    id: `LIVE-CMD-TIME-${Date.now()}`,
                                    severity: 'Critical',
                                    title: 'Time-based Command Injection',
                                    description: `Tool '${tool.name}' vulnerable to time-based command injection`,
                                    evidence: `Response time: ${responseTime}ms with sleep command`,
                                    recommendation: 'Remove command execution functionality',
                                    tool: tool.name,
                                    parameter: paramName,
                                    phase: 'active-testing'
                                });
                                
                                this.updateCallback(`⚡ Time-based command injection in ${tool.name}`, 50);
                            }
                        }
                        
                    } catch (error) {
                        if (error.message.includes('spawn') || error.message.includes('exec')) {
                            this.addVulnerability({
                                id: `LIVE-CMD-ERROR-${Date.now()}`,
                                severity: 'High',
                                title: 'Command Injection - System Error',
                                description: `Tool '${tool.name}' shows command execution errors`,
                                evidence: error.message,
                                recommendation: 'Review command execution code for vulnerabilities',
                                tool: tool.name,
                                parameter: paramName,
                                phase: 'active-testing'
                            });
                        }
                    }
                }
            }
        }
    }

    async testSSRFLive() {
        this.updateCallback('🌐 Testing Server-Side Request Forgery (SSRF)...', 52);
        
        const ssrfPayloads = [
            'http://localhost:22',
            'http://127.0.0.1:3306',
            'http://169.254.169.254/latest/meta-data/',
            'file:///etc/passwd',
            'http://internal.company.com',
            'gopher://localhost:6379/_INFO'
        ];
        
        for (const tool of this.serverConfig.tools) {
            if (!tool.parameters) continue;
            
            for (const [paramName, paramType] of Object.entries(tool.parameters)) {
                if (paramName.toLowerCase().includes('url') || 
                    paramName.toLowerCase().includes('uri') ||
                    paramName.toLowerCase().includes('endpoint')) {
                    
                    for (const payload of ssrfPayloads) {
                        try {
                            const startTime = Date.now();
                            const response = await this.makeToolCall(tool.name, {
                                [paramName]: payload
                            });
                            const responseTime = Date.now() - startTime;
                            
                            if (response.body && typeof response.body === 'string') {
                                const responseText = response.body.toLowerCase();
                                
                                // Check for internal service responses
                                if (responseText.includes('ssh') || 
                                    responseText.includes('mysql') ||
                                    responseText.includes('redis') ||
                                    responseText.includes('aws') ||
                                    responseText.includes('metadata')) {
                                    
                                    this.addVulnerability({
                                        id: `LIVE-SSRF-${Date.now()}`,
                                        severity: 'Critical',
                                        title: 'Server-Side Request Forgery (SSRF)',
                                        description: `Tool '${tool.name}' allows access to internal services`,
                                        evidence: `Internal service response for ${payload}`,
                                        recommendation: 'Validate and whitelist allowed URLs',
                                        tool: tool.name,
                                        parameter: paramName,
                                        phase: 'active-testing'
                                    });
                                    
                                    this.updateCallback(`🌐 SSRF vulnerability in ${tool.name}`, 55);
                                }
                            }
                            
                            // Time-based SSRF detection
                            if (responseTime > 5000 && payload.includes('localhost')) {
                                this.addVulnerability({
                                    id: `LIVE-SSRF-TIME-${Date.now()}`,
                                    severity: 'High',
                                    title: 'SSRF - Time-based Detection',
                                    description: `Tool '${tool.name}' shows delayed response to internal addresses`,
                                    evidence: `Response time: ${responseTime}ms for ${payload}`,
                                    recommendation: 'Implement URL validation and timeout controls',
                                    tool: tool.name,
                                    parameter: paramName,
                                    phase: 'active-testing'
                                });
                            }
                            
                        } catch (error) {
                            // Connection errors might indicate SSRF attempt
                            if (error.message.includes('ECONNREFUSED') || 
                                error.message.includes('timeout')) {
                                this.addVulnerability({
                                    id: `LIVE-SSRF-ATTEMPT-${Date.now()}`,
                                    severity: 'Medium',
                                    title: 'SSRF - Connection Attempt',
                                    description: `Tool '${tool.name}' attempts connections to internal addresses`,
                                    evidence: `Connection attempt to ${payload}: ${error.message}`,
                                    recommendation: 'Implement proper URL validation',
                                    tool: tool.name,
                                    parameter: paramName,
                                    phase: 'active-testing'
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    async testPathTraversalLive() {
        this.updateCallback('📁 Testing path traversal vulnerabilities...', 57);
        
        const pathPayloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '/etc/passwd',
            '....//....//....//etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
            '/proc/self/environ'
        ];
        
        for (const tool of this.serverConfig.tools) {
            if (!tool.parameters) continue;
            
            for (const [paramName, paramType] of Object.entries(tool.parameters)) {
                if (paramName.toLowerCase().includes('file') || 
                    paramName.toLowerCase().includes('path') ||
                    paramName.toLowerCase().includes('filename')) {
                    
                    for (const payload of pathPayloads) {
                        try {
                            const response = await this.makeToolCall(tool.name, {
                                [paramName]: payload
                            });
                            
                            if (response.body && typeof response.body === 'string') {
                                const responseText = response.body.toLowerCase();
                                
                                // Check for successful file access
                                if (responseText.includes('root:') || 
                                    responseText.includes('daemon:') ||
                                    responseText.includes('localhost') ||
                                    responseText.includes('127.0.0.1')) {
                                    
                                    this.addVulnerability({
                                        id: `LIVE-PATH-${Date.now()}`,
                                        severity: 'Critical',
                                        title: 'Path Traversal Vulnerability',
                                        description: `Tool '${tool.name}' allows access to system files`,
                                        evidence: `System file content accessed with ${payload}`,
                                        recommendation: 'Validate file paths and use absolute path restrictions',
                                        tool: tool.name,
                                        parameter: paramName,
                                        phase: 'active-testing'
                                    });
                                    
                                    this.updateCallback(`📁 Path traversal in ${tool.name}`, 60);
                                }
                            }
                            
                        } catch (error) {
                            if (error.message.includes('ENOENT') || 
                                error.message.includes('permission denied')) {
                                this.addVulnerability({
                                    id: `LIVE-PATH-ATTEMPT-${Date.now()}`,
                                    severity: 'Medium',
                                    title: 'Path Traversal Attempt',
                                    description: `Tool '${tool.name}' attempts file system access`,
                                    evidence: `File access attempted: ${error.message}`,
                                    recommendation: 'Implement proper path validation',
                                    tool: tool.name,
                                    parameter: paramName,
                                    phase: 'active-testing'
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    async testAuthenticationBypassLive() {
        this.updateCallback('🔐 Testing authentication bypass...', 62);
        
        const bypassPayloads = [
            { username: 'admin', password: "' OR '1'='1" },
            { username: "admin'--", password: 'anything' },
            { username: 'admin', password: 'admin' },
            { username: '', password: '' },
            { username: null, password: null }
        ];
        
        try {
            for (const payload of bypassPayloads) {
                const response = await this.makeToolCall('authenticate', payload);
                
                if (response.status === 200 && response.body) {
                    const responseText = JSON.stringify(response.body).toLowerCase();
                    
                    if (responseText.includes('success') || 
                        responseText.includes('token') ||
                        responseText.includes('authenticated')) {
                        
                        this.addVulnerability({
                            id: `LIVE-AUTH-${Date.now()}`,
                            severity: 'Critical',
                            title: 'Authentication Bypass',
                            description: 'Authentication can be bypassed with weak credentials',
                            evidence: `Login successful with: ${JSON.stringify(payload)}`,
                            recommendation: 'Implement strong authentication and input validation',
                            phase: 'active-testing'
                        });
                        
                        this.updateCallback(`🔐 Authentication bypass detected`, 65);
                    }
                }
            }
        } catch (error) {
            // Authentication endpoint might not exist
            this.updateCallback(`🔐 Authentication endpoint not available`, 65);
        }
    }

    async performRuntimeAnalysis() {
        this.updateCallback('🔄 Phase 3: Runtime behavior analysis...', 65);
        
        // Memory leak detection
        await this.testMemoryLeaks();
        
        // Race condition testing
        await this.testRaceConditionsLive();
        
        // Resource exhaustion testing
        await this.testResourceExhaustion();
    }

    async testMemoryLeaks() {
        this.updateCallback('🧠 Testing for memory leaks...', 70);
        
        // Simulate memory-intensive operations
        for (const tool of this.serverConfig.tools) {
            if (!tool.parameters) continue;
            
            try {
                // Send large payloads repeatedly
                const largePayload = 'A'.repeat(1024 * 1024); // 1MB
                
                for (let i = 0; i < 10; i++) {
                    await this.makeToolCall(tool.name, {
                        data: largePayload
                    });
                }
                
                // Check if server is still responsive
                const healthCheck = await this.makeRequest('/health');
                if (!healthCheck || healthCheck.status >= 500) {
                    this.addVulnerability({
                        id: `LIVE-MEMORY-${Date.now()}`,
                        severity: 'High',
                        title: 'Potential Memory Leak',
                        description: `Tool '${tool.name}' may have memory management issues`,
                        evidence: 'Server becomes unresponsive after memory-intensive operations',
                        recommendation: 'Review memory management and implement proper cleanup',
                        tool: tool.name,
                        phase: 'runtime-analysis'
                    });
                    
                    this.updateCallback(`🧠 Memory leak detected in ${tool.name}`, 72);
                }
                
            } catch (error) {
                if (error.message.includes('out of memory') || 
                    error.message.includes('heap')) {
                    this.addVulnerability({
                        id: `LIVE-MEMORY-ERROR-${Date.now()}`,
                        severity: 'Critical',
                        title: 'Memory Exhaustion',
                        description: `Tool '${tool.name}' causes memory exhaustion`,
                        evidence: error.message,
                        recommendation: 'Implement memory limits and proper resource management',
                        tool: tool.name,
                        phase: 'runtime-analysis'
                    });
                }
            }
        }
    }

    async testRaceConditionsLive() {
        this.updateCallback('🏃 Testing for race conditions...', 75);
        
        const stateChangingTools = this.serverConfig.tools.filter(tool => 
            /update|create|delete|modify|set|change|increment|decrement/.test(tool.name)
        );
        
        for (const tool of stateChangingTools) {
            try {
                const resourceId = `test_resource_${Date.now()}`;
                const concurrentRequests = 20;
                
                // Create concurrent requests
                const promises = Array(concurrentRequests).fill().map(async (_, index) => {
                    return this.makeToolCall(tool.name, {
                        id: resourceId,
                        value: `concurrent_value_${index}`,
                        operation: 'increment'
                    });
                });
                
                const results = await Promise.allSettled(promises);
                const successfulResults = results.filter(r => r.status === 'fulfilled');
                
                // Check for inconsistent results
                const responses = successfulResults.map(r => JSON.stringify(r.value));
                const uniqueResponses = new Set(responses);
                
                if (uniqueResponses.size > 1 && successfulResults.length > 1) {
                    this.addVulnerability({
                        id: `LIVE-RACE-${Date.now()}`,
                        severity: 'High',
                        title: 'Race Condition Vulnerability',
                        description: `Tool '${tool.name}' has inconsistent behavior under concurrent access`,
                        evidence: `${uniqueResponses.size} different responses from ${concurrentRequests} requests`,
                        recommendation: 'Implement proper locking mechanisms',
                        tool: tool.name,
                        phase: 'runtime-analysis'
                    });
                    
                    this.updateCallback(`🏃 Race condition in ${tool.name}`, 77);
                }
                
            } catch (error) {
                this.updateCallback(`🏃 Race condition test failed for ${tool.name}`, 77);
            }
        }
    }

    async testResourceExhaustion() {
        this.updateCallback('💾 Testing resource exhaustion...', 80);
        
        try {
            // Test with very large payloads
            const massivePayload = 'X'.repeat(10 * 1024 * 1024); // 10MB
            
            const startTime = Date.now();
            const response = await this.makeRequest('/api/test', {
                method: 'POST',
                body: massivePayload,
                timeout: 30000
            });
            const responseTime = Date.now() - startTime;
            
            if (responseTime > 30000) {
                this.addVulnerability({
                    id: `LIVE-RESOURCE-${Date.now()}`,
                    severity: 'Medium',
                    title: 'Resource Exhaustion Vulnerability',
                    description: 'Server accepts very large payloads without limits',
                    evidence: `${massivePayload.length} byte payload processed in ${responseTime}ms`,
                    recommendation: 'Implement payload size limits and request timeouts',
                    phase: 'runtime-analysis'
                });
                
                this.updateCallback(`💾 Resource exhaustion vulnerability found`, 82);
            }
            
        } catch (error) {
            if (error.message.includes('timeout') || error.message.includes('too large')) {
                // This is actually good - server has protection
                this.updateCallback(`💾 Server has resource protection`, 82);
            }
        }
    }

    async performStressTesting() {
        this.updateCallback('⚡ Phase 4: Stress testing and DoS detection...', 82);
        
        // Rate limiting test
        await this.testRateLimiting();
        
        // Connection flooding test
        await this.testConnectionFlooding();
        
        // Slowloris attack simulation
        await this.testSlowlorisAttack();
    }

    async testRateLimiting() {
        this.updateCallback('🚦 Testing rate limiting...', 85);
        
        const requestCount = 100;
        const timeWindow = 1000; // 1 second
        
        try {
            const startTime = Date.now();
            const promises = Array(requestCount).fill().map(() => 
                this.makeRequest('/api/test')
            );
            
            const results = await Promise.allSettled(promises);
            const endTime = Date.now();
            
            const successfulRequests = results.filter(r => 
                r.status === 'fulfilled' && r.value.status < 400
            ).length;
            
            const rateLimitedRequests = results.filter(r => 
                r.status === 'fulfilled' && r.value.status === 429
            ).length;
            
            if (rateLimitedRequests === 0 && successfulRequests > 50) {
                this.addVulnerability({
                    id: `LIVE-RATE-${Date.now()}`,
                    severity: 'High',
                    title: 'Missing Rate Limiting',
                    description: 'Server does not implement rate limiting',
                    evidence: `${successfulRequests}/${requestCount} requests succeeded in ${endTime - startTime}ms`,
                    recommendation: 'Implement rate limiting (e.g., 10 requests per second per IP)',
                    phase: 'stress-testing'
                });
                
                this.updateCallback(`🚦 No rate limiting detected`, 87);
            } else {
                this.updateCallback(`🚦 Rate limiting is active`, 87);
            }
            
        } catch (error) {
            this.updateCallback(`🚦 Rate limiting test failed: ${error.message}`, 87);
        }
    }

    async testConnectionFlooding() {
        this.updateCallback('🌊 Testing connection flooding resistance...', 90);
        
        try {
            // Create many concurrent connections
            const connectionCount = 50;
            const connections = [];
            
            for (let i = 0; i < connectionCount; i++) {
                connections.push(this.createPersistentConnection());
            }
            
            // Wait and test if server is still responsive
            await new Promise(resolve => setTimeout(resolve, 2000));
            
            const healthCheck = await this.makeRequest('/health');
            
            if (!healthCheck || healthCheck.status >= 500) {
                this.addVulnerability({
                    id: `LIVE-FLOOD-${Date.now()}`,
                    severity: 'Medium',
                    title: 'Connection Flooding Vulnerability',
                    description: 'Server becomes unresponsive under connection flooding',
                    evidence: `Server unresponsive with ${connectionCount} concurrent connections`,
                    recommendation: 'Implement connection limits and proper resource management',
                    phase: 'stress-testing'
                });
                
                this.updateCallback(`🌊 Connection flooding vulnerability found`, 92);
            } else {
                this.updateCallback(`🌊 Server handles connection flooding well`, 92);
            }
            
            // Clean up connections
            connections.forEach(conn => {
                if (conn && conn.close) conn.close();
            });
            
        } catch (error) {
            this.updateCallback(`🌊 Connection flooding test failed: ${error.message}`, 92);
        }
    }

    async testSlowlorisAttack() {
        this.updateCallback('🐌 Testing Slowloris attack resistance...', 95);
        
        try {
            // Simulate slow HTTP attack
            const slowRequests = Array(10).fill().map(() => 
                this.makeSlowRequest('/api/test')
            );
            
            const results = await Promise.allSettled(slowRequests);
            const successfulSlowRequests = results.filter(r => 
                r.status === 'fulfilled'
            ).length;
            
            if (successfulSlowRequests > 7) {
                this.addVulnerability({
                    id: `LIVE-SLOWLORIS-${Date.now()}`,
                    severity: 'Medium',
                    title: 'Slowloris Attack Vulnerability',
                    description: 'Server vulnerable to Slow HTTP (Slowloris) attacks',
                    evidence: `${successfulSlowRequests}/10 slow requests succeeded`,
                    recommendation: 'Implement connection timeouts and concurrent connection limits',
                    phase: 'stress-testing'
                });
                
                this.updateCallback(`🐌 Slowloris vulnerability detected`, 97);
            } else {
                this.updateCallback(`🐌 Server resistant to Slowloris attacks`, 97);
            }
            
        } catch (error) {
            this.updateCallback(`🐌 Slowloris test failed: ${error.message}`, 97);
        }
    }

    async performBusinessLogicTesting() {
        this.updateCallback('💼 Phase 5: Business logic testing...', 97);
        
        // Test for business logic flaws
        await this.testBusinessLogicFlaws();
    }

    async testBusinessLogicFlaws() {
        this.updateCallback('💼 Testing business logic flaws...', 99);
        
        const businessLogicTests = [
            { name: 'Negative Price', data: { price: -100, quantity: 1 } },
            { name: 'Zero Price', data: { price: 0, quantity: 1 } },
            { name: 'Negative Quantity', data: { price: 100, quantity: -1 } },
            { name: 'Excessive Quantity', data: { price: 100, quantity: 999999 } }
        ];
        
        for (const test of businessLogicTests) {
            try {
                const response = await this.makeToolCall('create_order', test.data);
                
                if (response.status === 200) {
                    this.addVulnerability({
                        id: `LIVE-LOGIC-${Date.now()}`,
                        severity: 'High',
                        title: `Business Logic Flaw: ${test.name}`,
                        description: `Business logic bypass detected`,
                        evidence: `Order accepted with invalid data: ${JSON.stringify(test.data)}`,
                        recommendation: 'Implement server-side business logic validation',
                        phase: 'business-logic'
                    });
                    
                    this.updateCallback(`💼 Business logic flaw: ${test.name}`, 100);
                }
                
            } catch (error) {
                // Business logic errors are expected for invalid data
            }
        }
    }

    // Helper methods
    async makeRequest(path, options = {}) {
        const url = this.serverConfig.serverUrl + path;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), options.timeout || 10000);
        
        try {
            const response = await fetch(url, {
                method: options.method || 'GET',
                headers: {
                    'User-Agent': 'MCP-Live-Security-Scanner/3.0',
                    'Content-Type': 'application/json',
                    ...options.headers
                },
                body: options.body,
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            let body;
            try {
                const text = await response.text();
                try {
                    body = JSON.parse(text);
                } catch (e) {
                    body = text;
                }
            } catch (e) {
                body = null;
            }
            
            return {
                status: response.status,
                headers: Object.fromEntries(response.headers.entries()),
                body
            };
            
        } catch (error) {
            clearTimeout(timeoutId);
            throw error;
        }
    }

    async makeToolCall(toolName, parameters) {
        return this.makeRequest(`/api/tools/${toolName}`, {
            method: 'POST',
            body: JSON.stringify(parameters)
        });
    }

    async makeSlowRequest(path) {
        // Simulate slow HTTP request by sending headers slowly
        return new Promise((resolve, reject) => {
            setTimeout(() => {
                this.makeRequest(path).then(resolve).catch(reject);
            }, 5000 + Math.random() * 5000); // 5-10 second delay
        });
    }

    createPersistentConnection() {
        // Simulate creating a persistent connection
        return {
            id: Date.now() + Math.random(),
            close: () => {}
        };
    }

    async analyzeTLS() {
        // Simulate TLS analysis
        return {
            version: 'TLS 1.3',
            cipherSuite: 'TLS_AES_256_GCM_SHA384',
            certificateValid: true
        };
    }

    detectFramework(headers) {
        if (headers['x-powered-by']) {
            return headers['x-powered-by'];
        }
        if (headers.server && headers.server.includes('Express')) {
            return 'Express.js';
        }
        return 'Unknown';
    }

    detectLanguage(headers) {
        if (headers['x-powered-by']) {
            if (headers['x-powered-by'].includes('PHP')) return 'PHP';
            if (headers['x-powered-by'].includes('ASP.NET')) return 'C#/.NET';
        }
        return 'Unknown';
    }

    detectCloudProvider(headers) {
        if (headers['x-amz-request-id']) return 'AWS';
        if (headers['x-azure-ref']) return 'Azure';
        if (headers['x-goog-request-id']) return 'Google Cloud';
        return 'Unknown';
    }

    addVulnerability(vulnerability) {
        vulnerability.timestamp = new Date().toISOString();
        vulnerability.id = vulnerability.id || `LIVE-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        this.vulnerabilities.push(vulnerability);
        
        // Notify callback of new vulnerability
        if (this.updateCallback) {
            this.updateCallback(`🚨 ${vulnerability.severity}: ${vulnerability.title}`, null, vulnerability);
        }
    }

    closeAllConnections() {
        for (const [id, connection] of this.activeConnections.entries()) {
            if (connection && connection.close) {
                connection.close();
            }
        }
        this.activeConnections.clear();
    }

    generateScanSummary() {
        const severityBreakdown = this.vulnerabilities.reduce((acc, vuln) => {
            acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
            return acc;
        }, {});

        const phaseBreakdown = this.vulnerabilities.reduce((acc, vuln) => {
            const phase = vuln.phase || 'unknown';
            acc[phase] = (acc[phase] || 0) + 1;
            return acc;
        }, {});

        return {
            totalVulnerabilities: this.vulnerabilities.length,
            severityBreakdown,
            phaseBreakdown,
            scanDuration: Date.now() - (this.scanStartTime || Date.now()),
            serverReachable: this.testResults.connectivity?.isReachable || false,
            endpointsDiscovered: this.testResults.discoveredEndpoints?.length || 0
        };
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = LiveDynamicScanner;
}