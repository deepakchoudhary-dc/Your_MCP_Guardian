/**
 * MCP Runtime Security Scanner
 * Detects runtime vulnerabilities through dynamic testing
 */

class RuntimeSecurityScanner {
    constructor(serverConfig) {
        this.serverConfig = serverConfig;
        this.vulnerabilities = [];
        this.testResults = {};
    }

    async scanAll() {
        console.log('🔍 Starting Runtime Security Scan...');
        
        await this.testBufferOverflow();
        await this.testRaceConditions();
        await this.testInsecureDeserialization();
        await this.testErrorHandling();
        
        return {
            vulnerabilities: this.vulnerabilities,
            testResults: this.testResults
        };
    }

    // Buffer Overflow Detection
    async testBufferOverflow() {
        console.log('Testing for Buffer Overflow vulnerabilities...');
        
        const testCases = [
            'A'.repeat(1000),      // 1KB payload
            'A'.repeat(10000),     // 10KB payload
            'A'.repeat(100000),    // 100KB payload
            'A'.repeat(1000000),   // 1MB payload
            '\x00'.repeat(1000),   // Null bytes
            '%s%s%s%s%s%s%s%s',    // Format string
            '../'.repeat(100),     // Path traversal
            '\n'.repeat(1000),     // Newline flood
        ];

        for (const tool of this.serverConfig.tools) {
            if (!tool.parameters) continue;

            for (const [paramName, paramType] of Object.entries(tool.parameters)) {
                if (paramType === 'string') {
                    for (const payload of testCases) {
                        try {
                            const result = await this.simulateToolCall(tool.name, {
                                [paramName]: payload
                            });
                            
                            // Check for signs of buffer overflow
                            if (this.detectBufferOverflowSigns(result)) {
                                this.addVulnerability({
                                    type: 'Buffer Overflow',
                                    severity: 'Critical',
                                    tool: tool.name,
                                    parameter: paramName,
                                    payload: payload.substring(0, 50) + '...',
                                    description: `Tool ${tool.name} parameter ${paramName} may be vulnerable to buffer overflow attacks`,
                                    evidence: result.error || result.response
                                });
                            }
                        } catch (error) {
                            // Crashes or exceptions might indicate buffer overflow
                            if (error.message.includes('segmentation fault') || 
                                error.message.includes('stack overflow') ||
                                error.message.includes('memory')) {
                                this.addVulnerability({
                                    type: 'Buffer Overflow',
                                    severity: 'Critical',
                                    tool: tool.name,
                                    parameter: paramName,
                                    description: `Buffer overflow detected - application crashed with payload`,
                                    evidence: error.message
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // Race Condition Detection
    async testRaceConditions() {
        console.log('Testing for Race Condition vulnerabilities...');
        
        const concurrentRequests = 50;
        const stateChangingTools = this.serverConfig.tools.filter(tool => 
            /update|create|delete|modify|set|change/i.test(tool.name)
        );

        for (const tool of stateChangingTools) {
            try {
                // Create multiple concurrent requests
                const promises = Array(concurrentRequests).fill().map(async (_, index) => {
                    return this.simulateToolCall(tool.name, {
                        id: 'test_resource_123',
                        value: `concurrent_value_${index}`,
                        timestamp: Date.now()
                    });
                });

                const results = await Promise.allSettled(promises);
                
                // Analyze results for race condition indicators
                const successfulResults = results.filter(r => r.status === 'fulfilled');
                const uniqueResponses = new Set(successfulResults.map(r => JSON.stringify(r.value)));
                
                if (uniqueResponses.size > 1) {
                    this.addVulnerability({
                        type: 'Race Condition',
                        severity: 'High',
                        tool: tool.name,
                        description: `Race condition detected in ${tool.name} - concurrent requests produced inconsistent results`,
                        evidence: `${uniqueResponses.size} different responses from ${concurrentRequests} concurrent requests`
                    });
                }

                // Check for data corruption indicators
                const corruptionSigns = successfulResults.some(result => 
                    result.value && (
                        result.value.includes('undefined') ||
                        result.value.includes('null') ||
                        result.value.includes('NaN') ||
                        /corrupted|invalid|error/i.test(result.value)
                    )
                );

                if (corruptionSigns) {
                    this.addVulnerability({
                        type: 'Race Condition - Data Corruption',
                        severity: 'Critical',
                        tool: tool.name,
                        description: `Data corruption detected during concurrent access to ${tool.name}`,
                        evidence: 'Responses contained corruption indicators'
                    });
                }

            } catch (error) {
                console.error(`Race condition test failed for ${tool.name}:`, error);
            }
        }
    }

    // Insecure Deserialization Detection
    async testInsecureDeserialization() {
        console.log('Testing for Insecure Deserialization vulnerabilities...');
        
        const maliciousPayloads = [
            // JSON-based payloads
            '{"__proto__": {"isAdmin": true}}',
            '{"constructor": {"prototype": {"isAdmin": true}}}',
            
            // Serialized object payloads
            'rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAABdAAEY2FsYw==',
            
            // Python pickle payloads (base64 encoded)
            'gASVKAAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwGX19pbXBvcnRfX5STlIwCb3OUhZRSlIwGc3lzdGVtlIwEY2FsY5STlFKULg==',
            
            // PHP serialized object
            'O:8:"stdClass":1:{s:4:"exec";s:6:"whoami";}',
            
            // XML with external entity
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            
            // YAML unsafe load
            '!!python/object/apply:os.system ["whoami"]',
            
            // JavaScript function serialization
            '{"rce": {"__js_function": "function(){return require(\'child_process\').exec(\'whoami\')}"}}',
        ];

        for (const tool of this.serverConfig.tools) {
            if (!tool.parameters) continue;

            for (const [paramName, paramType] of Object.entries(tool.parameters)) {
                if (paramType === 'object' || paramType === 'string') {
                    for (const payload of maliciousPayloads) {
                        try {
                            const result = await this.simulateToolCall(tool.name, {
                                [paramName]: payload
                            });
                            
                            // Check for signs of successful deserialization attack
                            if (this.detectDeserializationAttack(result)) {
                                this.addVulnerability({
                                    type: 'Insecure Deserialization',
                                    severity: 'Critical',
                                    tool: tool.name,
                                    parameter: paramName,
                                    description: `Tool ${tool.name} appears vulnerable to deserialization attacks`,
                                    evidence: result.response || result.error,
                                    payload: payload.substring(0, 100) + '...'
                                });
                            }
                        } catch (error) {
                            // Some deserialization attacks cause exceptions
                            if (error.message.includes('eval') || 
                                error.message.includes('exec') ||
                                error.message.includes('system')) {
                                this.addVulnerability({
                                    type: 'Insecure Deserialization',
                                    severity: 'Critical',
                                    tool: tool.name,
                                    parameter: paramName,
                                    description: `Deserialization vulnerability detected - dangerous function execution attempted`,
                                    evidence: error.message
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // Error & Exception Handling Testing
    async testErrorHandling() {
        console.log('Testing Error & Exception Handling...');
        
        const errorTriggers = [
            null,
            undefined,
            '',
            '{}',
            '[]',
            'null',
            'undefined',
            '1/0',
            'throw new Error("test")',
            '${7*7}',
            '#{7*7}',
            '{{7*7}}',
            '<script>alert(1)</script>',
            'SELECT * FROM users',
            '../../../etc/passwd',
            'file:///etc/passwd',
            'http://evil.com/callback',
            '\x00\x01\x02\x03',
            '🚀💥🔥',
            'ÿÿÿÿ',
        ];

        for (const tool of this.serverConfig.tools) {
            if (!tool.parameters) continue;

            for (const [paramName, paramType] of Object.entries(tool.parameters)) {
                for (const trigger of errorTriggers) {
                    try {
                        const result = await this.simulateToolCall(tool.name, {
                            [paramName]: trigger
                        });
                        
                        // Check for information disclosure in error messages
                        if (this.detectInformationDisclosure(result)) {
                            this.addVulnerability({
                                type: 'Improper Error Handling - Information Disclosure',
                                severity: 'Medium',
                                tool: tool.name,
                                parameter: paramName,
                                description: `Tool ${tool.name} exposes sensitive information in error messages`,
                                evidence: result.error || result.response,
                                trigger: String(trigger)
                            });
                        }
                    } catch (error) {
                        // Check if error messages reveal sensitive information
                        if (this.detectSensitiveInfoInError(error.message)) {
                            this.addVulnerability({
                                type: 'Improper Error Handling - Stack Trace Exposure',
                                severity: 'Medium',
                                tool: tool.name,
                                parameter: paramName,
                                description: `Tool ${tool.name} exposes stack traces or system information`,
                                evidence: error.message,
                                trigger: String(trigger)
                            });
                        }
                    }
                }
            }
        }
    }

    // Helper Methods
    async simulateToolCall(toolName, parameters) {
        // Simulate MCP tool call - in real implementation, this would make actual calls
        return new Promise((resolve) => {
            setTimeout(() => {
                // Simulate various response types
                const responses = [
                    { response: `Tool ${toolName} executed with params: ${JSON.stringify(parameters)}` },
                    { error: `Invalid parameter: ${Object.keys(parameters)[0]}` },
                    { response: 'Success', data: parameters },
                    { error: 'Internal server error at line 42 in /app/handlers/tool.js' },
                    { response: JSON.stringify(parameters) }
                ];
                resolve(responses[Math.floor(Math.random() * responses.length)]);
            }, Math.random() * 100);
        });
    }

    detectBufferOverflowSigns(result) {
        if (!result) return false;
        const text = JSON.stringify(result).toLowerCase();
        return text.includes('segmentation') || 
               text.includes('stack overflow') || 
               text.includes('memory') ||
               text.includes('buffer') ||
               text.includes('heap') ||
               text.length > 10000; // Unusually long response
    }

    detectDeserializationAttack(result) {
        if (!result) return false;
        const text = JSON.stringify(result).toLowerCase();
        return text.includes('whoami') ||
               text.includes('system') ||
               text.includes('exec') ||
               text.includes('eval') ||
               text.includes('isadmin') ||
               text.includes('__proto__') ||
               text.includes('constructor');
    }

    detectInformationDisclosure(result) {
        if (!result) return false;
        const text = JSON.stringify(result).toLowerCase();
        return text.includes('password') ||
               text.includes('secret') ||
               text.includes('token') ||
               text.includes('api_key') ||
               text.includes('database') ||
               text.includes('connection') ||
               text.includes('config') ||
               text.includes('/etc/') ||
               text.includes('c:\\') ||
               text.includes('localhost') ||
               text.includes('127.0.0.1');
    }

    detectSensitiveInfoInError(errorMessage) {
        if (!errorMessage) return false;
        const text = errorMessage.toLowerCase();
        return text.includes('at ') && text.includes('.js:') ||
               text.includes('traceback') ||
               text.includes('stack trace') ||
               text.includes('file not found') ||
               text.includes('permission denied') ||
               text.includes('access denied') ||
               text.includes('database') ||
               text.includes('connection') ||
               text.includes('/app/') ||
               text.includes('/home/') ||
               text.includes('/var/') ||
               text.includes('c:\\');
    }

    addVulnerability(vuln) {
        this.vulnerabilities.push({
            ...vuln,
            timestamp: new Date().toISOString(),
            id: `RUNTIME-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
        });
    }

    generateReport() {
        const severityCounts = this.vulnerabilities.reduce((acc, vuln) => {
            acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
            return acc;
        }, {});

        return {
            summary: {
                totalVulnerabilities: this.vulnerabilities.length,
                severityBreakdown: severityCounts,
                scanTimestamp: new Date().toISOString()
            },
            vulnerabilities: this.vulnerabilities,
            recommendations: this.generateRecommendations()
        };
    }

    generateRecommendations() {
        const recommendations = [];
        
        if (this.vulnerabilities.some(v => v.type.includes('Buffer Overflow'))) {
            recommendations.push({
                category: 'Buffer Overflow Prevention',
                actions: [
                    'Implement input length validation for all string parameters',
                    'Use safe string handling functions (e.g., strncpy instead of strcpy)',
                    'Enable stack canaries and ASLR in your runtime environment',
                    'Conduct regular static analysis with tools like Valgrind or AddressSanitizer'
                ]
            });
        }

        if (this.vulnerabilities.some(v => v.type.includes('Race Condition'))) {
            recommendations.push({
                category: 'Race Condition Mitigation',
                actions: [
                    'Implement proper locking mechanisms (mutexes, semaphores)',
                    'Use atomic operations for shared data access',
                    'Design stateless operations where possible',
                    'Implement database transactions with proper isolation levels'
                ]
            });
        }

        if (this.vulnerabilities.some(v => v.type.includes('Deserialization'))) {
            recommendations.push({
                category: 'Secure Deserialization',
                actions: [
                    'Never deserialize untrusted data',
                    'Use safe serialization formats like JSON instead of binary formats',
                    'Implement whitelist-based deserialization',
                    'Use digital signatures to verify serialized data integrity'
                ]
            });
        }

        if (this.vulnerabilities.some(v => v.type.includes('Error Handling'))) {
            recommendations.push({
                category: 'Secure Error Handling',
                actions: [
                    'Implement generic error messages for users',
                    'Log detailed errors securely on the server side',
                    'Never expose stack traces to end users',
                    'Implement proper exception handling for all code paths'
                ]
            });
        }

        return recommendations;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = RuntimeSecurityScanner;
}