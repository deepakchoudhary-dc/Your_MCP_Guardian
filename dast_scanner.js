/**
 * Dynamic Application Security Testing (DAST) Scanner
 * Performs active testing against running MCP servers
 */

class DASTScanner {
    constructor(serverConfig) {
        this.serverConfig = serverConfig;
        this.vulnerabilities = [];
        this.testResults = {};
        this.baseUrl = this.normalizeUrl(serverConfig.serverUrl || 'http://localhost:3000');
        this.timeout = 30000; // 30 seconds
    }

    /**
     * Normalize URL to handle HTTP/HTTPS issues
     */
    normalizeUrl(url) {
        // If localhost and HTTPS, try HTTP instead for local testing
        if (url.includes('localhost') && url.startsWith('https://')) {
            console.log(`🔄 Converting localhost HTTPS to HTTP for testing: ${url}`);
            return url.replace('https://', 'http://');
        }
        return url;
    }

    async performDASTScan() {
        console.log('🎯 Starting Dynamic Application Security Testing (DAST)...');
        
        try {
            // Check if server is reachable
            const isReachable = await this.checkServerReachability();
            if (!isReachable) {
                this.addVulnerability({
                    type: 'Server Unreachable',
                    severity: 'Info',
                    description: 'Cannot reach target server for dynamic testing',
                    evidence: `Failed to connect to ${this.baseUrl}`,
                    recommendation: 'Ensure server is running and accessible'
                });
                return { vulnerabilities: this.vulnerabilities, testResults: this.testResults };
            }

            // Perform active security tests
            await Promise.all([
                this.testActiveBufferOverflow(),
                this.testActiveRaceConditions(),
                this.testActiveDeserialization(),
                this.testActiveSQLInjection(),
                this.testActiveXSS(),
                this.testActiveCSRF(),
                this.testActiveSSRF(),
                this.testActivePathTraversal(),
                this.testActiveCommandInjection(),
                this.testActiveAuthenticationBypass(),
                this.testActiveSessionManagement(),
                this.testActiveInputValidation(),
                this.testActiveBusinessLogic()
            ]);

            return {
                vulnerabilities: this.vulnerabilities,
                testResults: this.testResults
            };

        } catch (error) {
            console.error('DAST scan failed:', error);
            this.addVulnerability({
                type: 'DAST Scan Error',
                severity: 'Medium',
                description: 'Dynamic testing encountered errors',
                evidence: error.message,
                recommendation: 'Review server configuration and network connectivity'
            });
            return { vulnerabilities: this.vulnerabilities, testResults: this.testResults };
        }
    }

    async checkServerReachability() {
        try {
            console.log(`🔍 Testing server reachability: ${this.baseUrl}`);
            
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5000);
            
            // Try the configured URL first
            let response;
            try {
                response = await fetch(`${this.baseUrl}/health`, {
                    method: 'GET',
                    signal: controller.signal,
                    headers: { 'User-Agent': 'MCP-Security-Scanner/2.0' }
                });
                clearTimeout(timeoutId);
                console.log(`✅ Server reachable at ${this.baseUrl}`);
                return response.status < 500;
            } catch (fetchError) {
                clearTimeout(timeoutId);
                
                // If HTTPS failed on localhost, try HTTP
                if (this.baseUrl.includes('localhost') && this.baseUrl.startsWith('https://')) {
                    const httpUrl = this.baseUrl.replace('https://', 'http://');
                    console.log(`🔄 HTTPS failed, trying HTTP: ${httpUrl}`);
                    
                    try {
                        const controller2 = new AbortController();
                        const timeoutId2 = setTimeout(() => controller2.abort(), 5000);
                        
                        response = await fetch(`${httpUrl}/health`, {
                            method: 'GET',
                            signal: controller2.signal,
                            headers: { 'User-Agent': 'MCP-Security-Scanner/2.0' }
                        });
                        
                        clearTimeout(timeoutId2);
                        this.baseUrl = httpUrl; // Update to working URL
                        console.log(`✅ Server reachable at ${httpUrl}`);
                        return response.status < 500;
                    } catch (httpError) {
                        console.warn(`⚠️ Server not reachable at either HTTPS or HTTP, continuing with simulated tests...`);
                        return false;
                    }
                }
                
                throw fetchError;
            }
            
        } catch (error) {
            console.warn(`⚠️ Server not reachable at ${this.baseUrl}, continuing with simulated tests...`);
            return false; // Return false but don't throw error
        }
    }

    async testActiveBufferOverflow() {
        console.log('Testing active buffer overflow vulnerabilities...');
        
        const payloads = [
            'A'.repeat(1024),      // 1KB
            'A'.repeat(8192),      // 8KB
            'A'.repeat(65536),     // 64KB
            'A'.repeat(1048576),   // 1MB
            '\x00'.repeat(1000),   // Null bytes
            '%n%n%n%n%n%n%n%n',    // Format string
            'AAAA' + '\x41'.repeat(1000) + '\x42\x42\x42\x42', // Pattern
        ];

        for (const tool of this.serverConfig.tools || []) {
            if (!tool.parameters) continue;

            for (const [paramName, paramType] of Object.entries(tool.parameters)) {
                if (paramType === 'string') {
                    for (const payload of payloads) {
                        try {
                            const startTime = Date.now();
                            const response = await this.makeToolCall(tool.name, {
                                [paramName]: payload
                            });
                            const endTime = Date.now();
                            
                            // Check for signs of buffer overflow
                            if (endTime - startTime > 10000) { // Took more than 10 seconds
                                this.addVulnerability({
                                    type: 'Active Buffer Overflow',
                                    severity: 'Critical',
                                    tool: tool.name,
                                    parameter: paramName,
                                    description: `Tool ${tool.name} shows signs of buffer overflow with large payloads`,
                                    evidence: `Response time: ${endTime - startTime}ms with ${payload.length} byte payload`,
                                    recommendation: 'Implement input length validation and use safe string handling functions'
                                });
                            }

                            // Check response for crash indicators
                            if (response.status === 500 && response.body?.includes('segmentation fault')) {
                                this.addVulnerability({
                                    type: 'Active Buffer Overflow - Crash',
                                    severity: 'Critical',
                                    tool: tool.name,
                                    parameter: paramName,
                                    description: `Buffer overflow caused application crash`,
                                    evidence: 'Segmentation fault detected in response',
                                    recommendation: 'Immediate fix required - implement bounds checking'
                                });
                            }

                        } catch (error) {
                            if (error.name === 'AbortError' || error.message.includes('timeout')) {
                                this.addVulnerability({
                                    type: 'Active Buffer Overflow - Timeout',
                                    severity: 'High',
                                    tool: tool.name,
                                    parameter: paramName,
                                    description: `Request timeout with large payload suggests buffer overflow`,
                                    evidence: `Timeout with ${payload.length} byte payload`,
                                    recommendation: 'Implement input size limits and proper error handling'
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    async testActiveRaceConditions() {
        console.log('Testing active race condition vulnerabilities...');
        
        const stateChangingTools = (this.serverConfig.tools || []).filter(tool => 
            /update|create|delete|modify|set|change|increment|decrement/i.test(tool.name)
        );

        for (const tool of stateChangingTools) {
            try {
                const resourceId = `test_resource_${Date.now()}`;
                const concurrentRequests = 20;
                
                // Create concurrent requests that modify the same resource
                const promises = Array(concurrentRequests).fill().map(async (_, index) => {
                    return this.makeToolCall(tool.name, {
                        id: resourceId,
                        value: `concurrent_value_${index}`,
                        operation: 'increment',
                        amount: 1
                    });
                });

                const results = await Promise.allSettled(promises);
                const successfulResults = results.filter(r => r.status === 'fulfilled' && r.value.status === 200);
                
                // Analyze for race condition indicators
                if (successfulResults.length > 1) {
                    // Check for inconsistent final state
                    const finalStateResponse = await this.makeToolCall('get_resource', { id: resourceId });
                    
                    if (finalStateResponse.status === 200) {
                        const expectedValue = concurrentRequests;
                        const actualValue = finalStateResponse.data?.value || 0;
                        
                        if (Math.abs(actualValue - expectedValue) > 2) { // Allow small variance
                            this.addVulnerability({
                                type: 'Active Race Condition',
                                severity: 'High',
                                tool: tool.name,
                                description: `Race condition detected in ${tool.name} - inconsistent state after concurrent operations`,
                                evidence: `Expected: ${expectedValue}, Actual: ${actualValue}, Successful requests: ${successfulResults.length}`,
                                recommendation: 'Implement proper locking mechanisms or atomic operations'
                            });
                        }
                    }
                }

                this.testResults.raceConditions = {
                    tool: tool.name,
                    concurrentRequests,
                    successfulRequests: successfulResults.length,
                    testPassed: successfulResults.length <= 1
                };

            } catch (error) {
                console.error(`Race condition test failed for ${tool.name}:`, error);
            }
        }
    }

    async testActiveDeserialization() {
        console.log('Testing active deserialization vulnerabilities...');
        
        const maliciousPayloads = [
            // Java serialized object (base64)
            'rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAABdAAEY2FsYw==',
            
            // Python pickle (base64)
            'gASVKAAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwGX19pbXBvcnRfX5STlIwCb3OUhZRSlIwGc3lzdGVtlIwEY2FsY5STlFKULg==',
            
            // PHP serialized object
            'O:8:"stdClass":1:{s:4:"exec";s:6:"whoami";}',
            
            // .NET BinaryFormatter
            'AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BQEAAAAhU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBwAACAkCAAAACQMAAAALCw==',
            
            // YAML unsafe load
            '!!python/object/apply:os.system ["whoami"]',
            
            // JSON with prototype pollution
            '{"__proto__": {"isAdmin": true, "role": "admin"}}',
            '{"constructor": {"prototype": {"isAdmin": true}}}',
            
            // XML with external entity
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
        ];

        for (const tool of this.serverConfig.tools || []) {
            if (!tool.parameters) continue;

            for (const [paramName, paramType] of Object.entries(tool.parameters)) {
                if (paramType === 'object' || paramType === 'string') {
                    for (const payload of maliciousPayloads) {
                        try {
                            const response = await this.makeToolCall(tool.name, {
                                [paramName]: payload
                            });
                            
                            // Check for successful deserialization attack indicators
                            if (response.status === 200 && response.body) {
                                const responseText = JSON.stringify(response.body).toLowerCase();
                                
                                if (responseText.includes('whoami') || 
                                    responseText.includes('admin') ||
                                    responseText.includes('root') ||
                                    responseText.includes('/etc/passwd') ||
                                    responseText.includes('system')) {
                                    
                                    this.addVulnerability({
                                        type: 'Active Insecure Deserialization',
                                        severity: 'Critical',
                                        tool: tool.name,
                                        parameter: paramName,
                                        description: `Successful deserialization attack on ${tool.name}`,
                                        evidence: `Response contains: ${responseText.substring(0, 200)}...`,
                                        recommendation: 'Never deserialize untrusted data. Use safe serialization formats like JSON with validation.'
                                    });
                                }
                            }

                        } catch (error) {
                            // Some deserialization attacks cause exceptions
                            if (error.message.includes('pickle') || 
                                error.message.includes('serialize') ||
                                error.message.includes('eval')) {
                                
                                this.addVulnerability({
                                    type: 'Active Deserialization Error',
                                    severity: 'High',
                                    tool: tool.name,
                                    parameter: paramName,
                                    description: `Deserialization error suggests vulnerable code path`,
                                    evidence: error.message,
                                    recommendation: 'Review deserialization code for security vulnerabilities'
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    async testActiveSQLInjection() {
        console.log('Testing active SQL injection vulnerabilities...');
        
        const sqlPayloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT username, password FROM users --",
            "1' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
            "'; WAITFOR DELAY '00:00:05' --",
            "' OR SLEEP(5) --",
            "1' AND (SELECT SUBSTRING(@@version,1,1)) = '5' --",
            "' OR 1=1 LIMIT 1 OFFSET 1 --",
            "'; INSERT INTO users (username, password) VALUES ('hacker', 'password') --"
        ];

        for (const tool of this.serverConfig.tools || []) {
            if (!tool.parameters) continue;
            
            // Focus on tools that likely interact with databases
            if (!/query|search|get|find|select|database|db/i.test(tool.name)) continue;

            for (const [paramName, paramType] of Object.entries(tool.parameters)) {
                for (const payload of sqlPayloads) {
                    try {
                        const startTime = Date.now();
                        const response = await this.makeToolCall(tool.name, {
                            [paramName]: payload
                        });
                        const endTime = Date.now();
                        
                        // Check for SQL injection indicators
                        if (response.status === 200 && response.body) {
                            const responseText = JSON.stringify(response.body).toLowerCase();
                            
                            // Time-based SQL injection detection
                            if (payload.includes('SLEEP') || payload.includes('WAITFOR')) {
                                if (endTime - startTime > 4000) { // More than 4 seconds
                                    this.addVulnerability({
                                        type: 'Active SQL Injection - Time-based',
                                        severity: 'Critical',
                                        tool: tool.name,
                                        parameter: paramName,
                                        description: `Time-based SQL injection confirmed in ${tool.name}`,
                                        evidence: `Response time: ${endTime - startTime}ms with SLEEP payload`,
                                        recommendation: 'Use parameterized queries immediately'
                                    });
                                }
                            }
                            
                            // Error-based SQL injection detection
                            if (responseText.includes('sql') || 
                                responseText.includes('mysql') ||
                                responseText.includes('sqlite') ||
                                responseText.includes('syntax error') ||
                                responseText.includes('table') ||
                                responseText.includes('column')) {
                                
                                this.addVulnerability({
                                    type: 'Active SQL Injection - Error-based',
                                    severity: 'Critical',
                                    tool: tool.name,
                                    parameter: paramName,
                                    description: `SQL error messages exposed in ${tool.name}`,
                                    evidence: `Response contains SQL-related errors`,
                                    recommendation: 'Implement proper error handling and use parameterized queries'
                                });
                            }
                            
                            // Union-based SQL injection detection
                            if (payload.includes('UNION') && responseText.includes('username')) {
                                this.addVulnerability({
                                    type: 'Active SQL Injection - Union-based',
                                    severity: 'Critical',
                                    tool: tool.name,
                                    parameter: paramName,
                                    description: `Union-based SQL injection successful in ${tool.name}`,
                                    evidence: `UNION query returned user data`,
                                    recommendation: 'Critical: Use parameterized queries and validate all inputs'
                                });
                            }
                        }

                    } catch (error) {
                        if (error.message.includes('sql') || error.message.includes('database')) {
                            this.addVulnerability({
                                type: 'Active SQL Injection - Exception',
                                severity: 'High',
                                tool: tool.name,
                                parameter: paramName,
                                description: `SQL injection caused database exception`,
                                evidence: error.message,
                                recommendation: 'Implement proper input validation and error handling'
                            });
                        }
                    }
                }
            }
        }
    }

    async testActiveXSS() {
        console.log('Testing active XSS vulnerabilities...');
        
        const xssPayloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            'javascript:alert("XSS")',
            '<iframe src="javascript:alert(\'XSS\')"></iframe>',
            '<body onload=alert("XSS")>',
            '<input onfocus=alert("XSS") autofocus>',
            '<select onfocus=alert("XSS") autofocus>',
            '<textarea onfocus=alert("XSS") autofocus>',
            '<keygen onfocus=alert("XSS") autofocus>',
            '<video><source onerror="alert(\'XSS\')">',
            '<audio src=x onerror=alert("XSS")>',
            '<details open ontoggle=alert("XSS")>',
            '<marquee onstart=alert("XSS")>',
            '"><script>alert("XSS")</script>',
            '\';alert("XSS");//',
            '<script>fetch("/admin").then(r=>r.text()).then(d=>alert(d))</script>'
        ];

        for (const tool of this.serverConfig.tools || []) {
            if (!tool.parameters) continue;
            
            // Focus on tools that might render or display content
            if (!/render|display|show|html|content|message|output/i.test(tool.name)) continue;

            for (const [paramName, paramType] of Object.entries(tool.parameters)) {
                for (const payload of xssPayloads) {
                    try {
                        const response = await this.makeToolCall(tool.name, {
                            [paramName]: payload
                        });
                        
                        if (response.status === 200 && response.body) {
                            const responseText = response.body;
                            
                            // Check if payload is reflected without encoding
                            if (typeof responseText === 'string' && responseText.includes(payload)) {
                                this.addVulnerability({
                                    type: 'Active Cross-Site Scripting (XSS)',
                                    severity: 'High',
                                    tool: tool.name,
                                    parameter: paramName,
                                    description: `Reflected XSS vulnerability in ${tool.name}`,
                                    evidence: `Payload reflected unencoded: ${payload}`,
                                    recommendation: 'Encode all user input before displaying. Use Content Security Policy.'
                                });
                            }
                            
                            // Check for stored XSS by making a second request
                            const secondResponse = await this.makeToolCall(tool.name, { [paramName]: 'test' });
                            if (secondResponse.body && secondResponse.body.includes(payload)) {
                                this.addVulnerability({
                                    type: 'Active Stored XSS',
                                    severity: 'Critical',
                                    tool: tool.name,
                                    parameter: paramName,
                                    description: `Stored XSS vulnerability in ${tool.name}`,
                                    evidence: `Payload persisted and reflected: ${payload}`,
                                    recommendation: 'Critical: Sanitize and validate all stored user input'
                                });
                            }
                        }

                    } catch (error) {
                        // XSS might cause parsing errors
                        if (error.message.includes('script') || error.message.includes('html')) {
                            this.addVulnerability({
                                type: 'Active XSS - Parsing Error',
                                severity: 'Medium',
                                tool: tool.name,
                                parameter: paramName,
                                description: `XSS payload caused parsing error`,
                                evidence: error.message,
                                recommendation: 'Review HTML/JavaScript parsing for security issues'
                            });
                        }
                    }
                }
            }
        }
    }

    async testActiveCSRF() {
        console.log('Testing active CSRF vulnerabilities...');
        
        const stateChangingTools = (this.serverConfig.tools || []).filter(tool => 
            /update|create|delete|modify|set|change|transfer|payment|admin/i.test(tool.name)
        );

        for (const tool of stateChangingTools) {
            try {
                // Test without CSRF token
                const response1 = await this.makeToolCall(tool.name, {
                    action: 'test_action',
                    value: 'csrf_test'
                });

                // Test with invalid CSRF token
                const response2 = await this.makeToolCall(tool.name, {
                    action: 'test_action',
                    value: 'csrf_test',
                    csrf_token: 'invalid_token_12345'
                });

                // Test with missing referrer
                const response3 = await this.makeToolCall(tool.name, {
                    action: 'test_action',
                    value: 'csrf_test'
                }, { 'Referer': '' });

                if (response1.status === 200 || response2.status === 200 || response3.status === 200) {
                    this.addVulnerability({
                        type: 'Active CSRF Vulnerability',
                        severity: 'High',
                        tool: tool.name,
                        description: `CSRF protection missing or bypassable in ${tool.name}`,
                        evidence: `State-changing operation succeeded without proper CSRF protection`,
                        recommendation: 'Implement CSRF tokens and validate referrer headers'
                    });
                }

            } catch (error) {
                console.error(`CSRF test failed for ${tool.name}:`, error);
            }
        }
    }

    async testActiveSSRF() {
        console.log('Testing active SSRF vulnerabilities...');
        
        const ssrfPayloads = [
            'http://localhost:22',
            'http://127.0.0.1:3306',
            'http://169.254.169.254/latest/meta-data/',
            'file:///etc/passwd',
            'ftp://localhost:21',
            'http://internal.company.com',
            'http://192.168.1.1',
            'http://10.0.0.1',
            'gopher://localhost:6379/_INFO',
            'dict://localhost:11211/stats'
        ];

        for (const tool of this.serverConfig.tools || []) {
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
                            const endTime = Date.now();
                            
                            // Check for SSRF indicators
                            if (response.status === 200 && response.body) {
                                const responseText = JSON.stringify(response.body).toLowerCase();
                                
                                // Check for internal service responses
                                if (responseText.includes('ssh') || 
                                    responseText.includes('mysql') ||
                                    responseText.includes('redis') ||
                                    responseText.includes('memcached') ||
                                    responseText.includes('aws') ||
                                    responseText.includes('metadata')) {
                                    
                                    this.addVulnerability({
                                        type: 'Active Server-Side Request Forgery (SSRF)',
                                        severity: 'Critical',
                                        tool: tool.name,
                                        parameter: paramName,
                                        description: `SSRF vulnerability allows access to internal services`,
                                        evidence: `Internal service response detected for ${payload}`,
                                        recommendation: 'Validate and whitelist allowed URLs. Block internal IP ranges.'
                                    });
                                }
                            }
                            
                            // Time-based SSRF detection
                            if (endTime - startTime > 5000 && payload.includes('localhost')) {
                                this.addVulnerability({
                                    type: 'Active SSRF - Time-based',
                                    severity: 'High',
                                    tool: tool.name,
                                    parameter: paramName,
                                    description: `Possible SSRF - long response time to internal address`,
                                    evidence: `Response time: ${endTime - startTime}ms for ${payload}`,
                                    recommendation: 'Implement URL validation and timeout controls'
                                });
                            }

                        } catch (error) {
                            // Connection errors might indicate SSRF attempt
                            if (error.message.includes('ECONNREFUSED') || 
                                error.message.includes('timeout')) {
                                this.addVulnerability({
                                    type: 'Active SSRF - Connection Attempt',
                                    severity: 'Medium',
                                    tool: tool.name,
                                    parameter: paramName,
                                    description: `SSRF attempt detected - connection to internal address`,
                                    evidence: `Connection attempt to ${payload}: ${error.message}`,
                                    recommendation: 'Implement proper URL validation and network controls'
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    async testActivePathTraversal() {
        console.log('Testing active path traversal vulnerabilities...');
        
        const pathPayloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '/etc/passwd',
            'C:\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
            '..%252F..%252F..%252Fetc%252Fpasswd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
            '/var/log/apache2/access.log',
            '/proc/self/environ',
            '/proc/version',
            '/etc/hosts',
            '/etc/shadow'
        ];

        for (const tool of this.serverConfig.tools || []) {
            if (!tool.parameters) continue;
            
            for (const [paramName, paramType] of Object.entries(tool.parameters)) {
                if (paramName.toLowerCase().includes('file') || 
                    paramName.toLowerCase().includes('path') ||
                    paramName.toLowerCase().includes('filename') ||
                    paramName.toLowerCase().includes('document')) {
                    
                    for (const payload of pathPayloads) {
                        try {
                            const response = await this.makeToolCall(tool.name, {
                                [paramName]: payload
                            });
                            
                            if (response.status === 200 && response.body) {
                                const responseText = JSON.stringify(response.body).toLowerCase();
                                
                                // Check for successful file access
                                if (responseText.includes('root:') || 
                                    responseText.includes('daemon:') ||
                                    responseText.includes('localhost') ||
                                    responseText.includes('127.0.0.1') ||
                                    responseText.includes('windows') ||
                                    responseText.includes('system32')) {
                                    
                                    this.addVulnerability({
                                        type: 'Active Path Traversal',
                                        severity: 'Critical',
                                        tool: tool.name,
                                        parameter: paramName,
                                        description: `Path traversal allows access to system files`,
                                        evidence: `System file content detected for ${payload}`,
                                        recommendation: 'Validate file paths and use absolute path restrictions'
                                    });
                                }
                            }

                        } catch (error) {
                            if (error.message.includes('ENOENT') || 
                                error.message.includes('permission denied')) {
                                // File system access attempted
                                this.addVulnerability({
                                    type: 'Active Path Traversal Attempt',
                                    severity: 'Medium',
                                    tool: tool.name,
                                    parameter: paramName,
                                    description: `Path traversal attempt detected`,
                                    evidence: `File system access attempted: ${error.message}`,
                                    recommendation: 'Implement proper path validation and sandboxing'
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    async testActiveCommandInjection() {
        console.log('Testing active command injection vulnerabilities...');
        
        const commandPayloads = [
            '; whoami',
            '| whoami',
            '& whoami',
            '&& whoami',
            '|| whoami',
            '`whoami`',
            '$(whoami)',
            '; ls -la',
            '; cat /etc/passwd',
            '; ping -c 1 127.0.0.1',
            '; sleep 5',
            '\n whoami',
            '\r\n whoami',
            '; echo "COMMAND_INJECTION_TEST"',
            '| echo "COMMAND_INJECTION_TEST"'
        ];

        for (const tool of this.serverConfig.tools || []) {
            if (!tool.parameters) continue;
            
            // Focus on tools that might execute commands
            if (!/command|cmd|exec|run|execute|shell|system/i.test(tool.name)) continue;

            for (const [paramName, paramType] of Object.entries(tool.parameters)) {
                for (const payload of commandPayloads) {
                    try {
                        const startTime = Date.now();
                        const response = await this.makeToolCall(tool.name, {
                            [paramName]: `test${payload}`
                        });
                        const endTime = Date.now();
                        
                        if (response.status === 200 && response.body) {
                            const responseText = JSON.stringify(response.body).toLowerCase();
                            
                            // Check for command execution indicators
                            if (responseText.includes('command_injection_test') ||
                                responseText.includes('root') ||
                                responseText.includes('uid=') ||
                                responseText.includes('gid=') ||
                                responseText.includes('total ') ||
                                responseText.includes('ping statistics')) {
                                
                                this.addVulnerability({
                                    type: 'Active Command Injection',
                                    severity: 'Critical',
                                    tool: tool.name,
                                    parameter: paramName,
                                    description: `Command injection successful in ${tool.name}`,
                                    evidence: `Command output detected: ${responseText.substring(0, 200)}`,
                                    recommendation: 'Never execute user input as commands. Use parameterized APIs.'
                                });
                            }
                            
                            // Time-based command injection (sleep)
                            if (payload.includes('sleep') && endTime - startTime > 4000) {
                                this.addVulnerability({
                                    type: 'Active Command Injection - Time-based',
                                    severity: 'Critical',
                                    tool: tool.name,
                                    parameter: paramName,
                                    description: `Time-based command injection confirmed`,
                                    evidence: `Response time: ${endTime - startTime}ms with sleep command`,
                                    recommendation: 'Critical: Remove command execution functionality or implement strict validation'
                                });
                            }
                        }

                    } catch (error) {
                        if (error.message.includes('spawn') || 
                            error.message.includes('exec') ||
                            error.message.includes('command')) {
                            this.addVulnerability({
                                type: 'Active Command Injection Error',
                                severity: 'High',
                                tool: tool.name,
                                parameter: paramName,
                                description: `Command injection attempt caused system error`,
                                evidence: error.message,
                                recommendation: 'Review command execution code for injection vulnerabilities'
                            });
                        }
                    }
                }
            }
        }
    }

    async testActiveAuthenticationBypass() {
        console.log('Testing active authentication bypass vulnerabilities...');
        
        const bypassPayloads = [
            { username: 'admin', password: "' OR '1'='1" },
            { username: "admin'--", password: 'anything' },
            { username: 'admin', password: 'admin' },
            { username: 'administrator', password: 'administrator' },
            { username: 'root', password: 'root' },
            { username: 'test', password: 'test' },
            { username: '', password: '' },
            { username: 'admin', password: '' },
            { username: null, password: null }
        ];

        try {
            for (const payload of bypassPayloads) {
                const response = await this.makeToolCall('authenticate', payload);
                
                if (response.status === 200 && response.body) {
                    const responseText = JSON.stringify(response.body).toLowerCase();
                    
                    if (responseText.includes('success') || 
                        responseText.includes('token') ||
                        responseText.includes('authenticated') ||
                        responseText.includes('welcome')) {
                        
                        this.addVulnerability({
                            type: 'Active Authentication Bypass',
                            severity: 'Critical',
                            description: `Authentication bypass successful with weak credentials`,
                            evidence: `Login successful with: ${JSON.stringify(payload)}`,
                            recommendation: 'Implement strong authentication and input validation'
                        });
                    }
                }
            }
        } catch (error) {
            // Authentication endpoint might not exist
            console.log('Authentication endpoint not available for testing');
        }
    }

    async testActiveSessionManagement() {
        console.log('Testing active session management vulnerabilities...');
        
        try {
            // Test session fixation
            const preAuthResponse = await this.makeRequest('/session');
            const preAuthSessionId = this.extractSessionId(preAuthResponse);
            
            if (preAuthSessionId) {
                // Attempt login with existing session
                const loginResponse = await this.makeToolCall('authenticate', {
                    username: 'testuser',
                    password: 'testpass'
                }, { 'Cookie': `sessionid=${preAuthSessionId}` });
                
                const postAuthSessionId = this.extractSessionId(loginResponse);
                
                if (preAuthSessionId === postAuthSessionId) {
                    this.addVulnerability({
                        type: 'Active Session Fixation',
                        severity: 'High',
                        description: 'Session ID not regenerated after authentication',
                        evidence: `Session ID ${preAuthSessionId} remained same after login`,
                        recommendation: 'Regenerate session ID upon authentication'
                    });
                }
            }
            
            // Test session timeout
            const sessionResponse = await this.makeRequest('/protected');
            if (sessionResponse.status === 200) {
                // Wait and test again
                await new Promise(resolve => setTimeout(resolve, 2000));
                const timeoutResponse = await this.makeRequest('/protected');
                
                if (timeoutResponse.status === 200) {
                    this.addVulnerability({
                        type: 'Active Session Timeout Issue',
                        severity: 'Medium',
                        description: 'Session does not timeout appropriately',
                        evidence: 'Session remained valid after extended period',
                        recommendation: 'Implement proper session timeout mechanisms'
                    });
                }
            }
            
        } catch (error) {
            console.log('Session management endpoints not available for testing');
        }
    }

    async testActiveInputValidation() {
        console.log('Testing active input validation vulnerabilities...');
        
        const invalidInputs = [
            null,
            undefined,
            '',
            ' ',
            '\n\r\t',
            'A'.repeat(10000),
            -1,
            999999999,
            -999999999,
            0.1,
            '0.1',
            'true',
            'false',
            '[]',
            '{}',
            'NaN',
            'Infinity',
            '-Infinity'
        ];

        for (const tool of this.serverConfig.tools || []) {
            if (!tool.parameters) continue;
            
            for (const [paramName, paramType] of Object.entries(tool.parameters)) {
                for (const invalidInput of invalidInputs) {
                    try {
                        const response = await this.makeToolCall(tool.name, {
                            [paramName]: invalidInput
                        });
                        
                        // Check if invalid input was accepted
                        if (response.status === 200) {
                            this.addVulnerability({
                                type: 'Active Input Validation Bypass',
                                severity: 'Medium',
                                tool: tool.name,
                                parameter: paramName,
                                description: `Invalid input accepted without proper validation`,
                                evidence: `Input ${JSON.stringify(invalidInput)} was accepted`,
                                recommendation: 'Implement comprehensive input validation'
                            });
                        }

                    } catch (error) {
                        // Errors are expected for invalid input
                        continue;
                    }
                }
            }
        }
    }

    async testActiveBusinessLogic() {
        console.log('Testing active business logic vulnerabilities...');
        
        // Test negative values
        const businessLogicTests = [
            { name: 'Negative Price', data: { price: -100, quantity: 1 } },
            { name: 'Zero Price', data: { price: 0, quantity: 1 } },
            { name: 'Negative Quantity', data: { price: 100, quantity: -1 } },
            { name: 'Excessive Quantity', data: { price: 100, quantity: 999999 } },
            { name: 'Decimal Quantity', data: { price: 100, quantity: 1.5 } },
            { name: 'String Price', data: { price: 'free', quantity: 1 } },
            { name: 'Boolean Values', data: { price: true, quantity: false } }
        ];

        for (const test of businessLogicTests) {
            try {
                const response = await this.makeToolCall('create_order', test.data);
                
                if (response.status === 200) {
                    this.addVulnerability({
                        type: 'Active Business Logic Flaw',
                        severity: 'High',
                        description: `Business logic bypass: ${test.name}`,
                        evidence: `Order accepted with invalid data: ${JSON.stringify(test.data)}`,
                        recommendation: 'Implement server-side business logic validation'
                    });
                }

            } catch (error) {
                // Business logic errors are expected
                continue;
            }
        }
    }

    // Helper methods
    async makeToolCall(toolName, parameters, headers = {}) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        
        try {
            const response = await fetch(`${this.baseUrl}/api/tools/${toolName}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'User-Agent': 'MCP-Security-Scanner/2.0',
                    ...headers
                },
                body: JSON.stringify(parameters),
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            let body;
            try {
                body = await response.text();
                try {
                    body = JSON.parse(body);
                } catch (e) {
                    // Keep as text if not JSON
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

    async makeRequest(path, options = {}) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        
        try {
            const response = await fetch(`${this.baseUrl}${path}`, {
                method: options.method || 'GET',
                headers: {
                    'User-Agent': 'MCP-Security-Scanner/2.0',
                    ...options.headers
                },
                body: options.body,
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            let body;
            try {
                body = await response.text();
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

    extractSessionId(response) {
        const cookies = response.headers?.['set-cookie'] || [];
        for (const cookie of cookies) {
            const match = cookie.match(/sessionid=([^;]+)/);
            if (match) return match[1];
        }
        return null;
    }

    addVulnerability(vuln) {
        this.vulnerabilities.push({
            ...vuln,
            timestamp: new Date().toISOString(),
            id: `DAST-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            scanType: 'DAST'
        });
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = DASTScanner;
}