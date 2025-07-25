/**
 * MCP Network & Infrastructure Security Scanner
 * Tests for network-level vulnerabilities and misconfigurations
 */

class NetworkSecurityScanner {
    constructor(serverConfig) {
        this.serverConfig = serverConfig;
        this.vulnerabilities = [];
        this.networkTests = {};
        this.serverUrl = serverConfig.serverUrl || 'https://localhost:3000';
    }

    async scanAll() {
        console.log('🌐 Starting Network Security Scan...');
        
        await this.testMITMVulnerabilities();
        await this.testDOSVulnerabilities();
        await this.testUnsecuredCommunication();
        await this.testHTTPSecurityHeaders();
        await this.testDNSConfiguration();
        await this.testDatabaseBackupSecurity();
        await this.testServerConfiguration();
        
        return {
            vulnerabilities: this.vulnerabilities,
            networkTests: this.networkTests
        };
    }

    // Man-in-the-Middle Attack Testing
    async testMITMVulnerabilities() {
        console.log('Testing for Man-in-the-Middle vulnerabilities...');
        
        try {
            // Test SSL/TLS Configuration
            const sslTests = await this.testSSLConfiguration();
            this.networkTests.ssl = sslTests;
            
            // Test Certificate Validation
            const certTests = await this.testCertificateValidation();
            this.networkTests.certificates = certTests;
            
            // Test for weak cipher suites
            const cipherTests = await this.testCipherSuites();
            this.networkTests.ciphers = cipherTests;
            
        } catch (error) {
            console.error('MITM testing failed:', error);
        }
    }

    async testSSLConfiguration() {
        const tests = [];
        
        // Test for HTTP instead of HTTPS
        if (this.serverUrl.startsWith('http://')) {
            this.addVulnerability({
                type: 'Unsecured Communication',
                severity: 'Critical',
                description: 'Server is using HTTP instead of HTTPS, making it vulnerable to MITM attacks',
                evidence: `Server URL: ${this.serverUrl}`,
                recommendation: 'Implement HTTPS with valid SSL/TLS certificates'
            });
            tests.push({ test: 'HTTPS_REQUIRED', result: 'FAIL', details: 'HTTP detected' });
        } else {
            tests.push({ test: 'HTTPS_REQUIRED', result: 'PASS', details: 'HTTPS detected' });
        }

        // Test for SSL/TLS version
        try {
            const response = await this.makeSecureRequest('/health');
            const tlsVersion = response.headers?.['tls-version'] || 'unknown';
            
            if (tlsVersion.includes('1.0') || tlsVersion.includes('1.1')) {
                this.addVulnerability({
                    type: 'Weak TLS Version',
                    severity: 'High',
                    description: 'Server is using outdated TLS version vulnerable to attacks',
                    evidence: `TLS Version: ${tlsVersion}`,
                    recommendation: 'Upgrade to TLS 1.2 or higher'
                });
                tests.push({ test: 'TLS_VERSION', result: 'FAIL', details: tlsVersion });
            } else {
                tests.push({ test: 'TLS_VERSION', result: 'PASS', details: tlsVersion });
            }
        } catch (error) {
            tests.push({ test: 'TLS_VERSION', result: 'ERROR', details: error.message });
        }

        return tests;
    }

    async testCertificateValidation() {
        const tests = [];
        
        try {
            // Test for self-signed certificates
            const response = await this.makeSecureRequest('/');
            
            // Simulate certificate checks
            const certInfo = {
                selfSigned: Math.random() > 0.7, // Simulate detection
                expired: Math.random() > 0.9,
                weakSignature: Math.random() > 0.8,
                invalidHostname: Math.random() > 0.85
            };

            if (certInfo.selfSigned) {
                this.addVulnerability({
                    type: 'Self-Signed Certificate',
                    severity: 'High',
                    description: 'Server is using a self-signed certificate',
                    evidence: 'Certificate validation failed',
                    recommendation: 'Use certificates from a trusted Certificate Authority'
                });
                tests.push({ test: 'CERT_AUTHORITY', result: 'FAIL', details: 'Self-signed certificate' });
            } else {
                tests.push({ test: 'CERT_AUTHORITY', result: 'PASS', details: 'Valid CA certificate' });
            }

            if (certInfo.expired) {
                this.addVulnerability({
                    type: 'Expired Certificate',
                    severity: 'Critical',
                    description: 'Server certificate has expired',
                    evidence: 'Certificate expiration date passed',
                    recommendation: 'Renew SSL certificate immediately'
                });
                tests.push({ test: 'CERT_EXPIRY', result: 'FAIL', details: 'Certificate expired' });
            } else {
                tests.push({ test: 'CERT_EXPIRY', result: 'PASS', details: 'Certificate valid' });
            }

            if (certInfo.weakSignature) {
                this.addVulnerability({
                    type: 'Weak Certificate Signature',
                    severity: 'Medium',
                    description: 'Certificate uses weak signature algorithm (SHA-1)',
                    evidence: 'SHA-1 signature detected',
                    recommendation: 'Use certificates with SHA-256 or stronger signatures'
                });
                tests.push({ test: 'CERT_SIGNATURE', result: 'FAIL', details: 'Weak signature algorithm' });
            } else {
                tests.push({ test: 'CERT_SIGNATURE', result: 'PASS', details: 'Strong signature algorithm' });
            }

        } catch (error) {
            tests.push({ test: 'CERT_VALIDATION', result: 'ERROR', details: error.message });
        }

        return tests;
    }

    async testCipherSuites() {
        const tests = [];
        const weakCiphers = [
            'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT',
            'ADH', 'AECDH', 'PSK', 'SRP', 'KRB5'
        ];

        // Simulate cipher suite detection
        const detectedCiphers = [
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_RSA_WITH_RC4_128_SHA', // Weak cipher
            'TLS_RSA_WITH_3DES_EDE_CBC_SHA' // Weak cipher
        ];

        const foundWeakCiphers = detectedCiphers.filter(cipher => 
            weakCiphers.some(weak => cipher.includes(weak))
        );

        if (foundWeakCiphers.length > 0) {
            this.addVulnerability({
                type: 'Weak Cipher Suites',
                severity: 'High',
                description: 'Server supports weak cipher suites vulnerable to attacks',
                evidence: `Weak ciphers: ${foundWeakCiphers.join(', ')}`,
                recommendation: 'Disable weak cipher suites and use only strong encryption'
            });
            tests.push({ test: 'CIPHER_STRENGTH', result: 'FAIL', details: foundWeakCiphers });
        } else {
            tests.push({ test: 'CIPHER_STRENGTH', result: 'PASS', details: 'Strong ciphers only' });
        }

        return tests;
    }

    // Denial of Service Testing
    async testDOSVulnerabilities() {
        console.log('Testing for DoS vulnerabilities...');
        
        await this.testRateLimiting();
        await this.testResourceExhaustion();
        await this.testSlowLoris();
    }

    async testRateLimiting() {
        const requestCount = 100;
        const timeWindow = 1000; // 1 second
        
        try {
            const startTime = Date.now();
            const promises = Array(requestCount).fill().map(() => 
                this.makeRequest('/api/test')
            );
            
            const results = await Promise.allSettled(promises);
            const endTime = Date.now();
            
            const successfulRequests = results.filter(r => r.status === 'fulfilled').length;
            const rateLimitedRequests = results.filter(r => 
                r.status === 'rejected' && r.reason?.status === 429
            ).length;
            
            if (rateLimitedRequests === 0 && successfulRequests > 50) {
                this.addVulnerability({
                    type: 'Missing Rate Limiting',
                    severity: 'High',
                    description: 'Server does not implement rate limiting, vulnerable to DoS attacks',
                    evidence: `${successfulRequests}/${requestCount} requests succeeded in ${endTime - startTime}ms`,
                    recommendation: 'Implement rate limiting (e.g., 10 requests per second per IP)'
                });
            }
            
            this.networkTests.rateLimiting = {
                totalRequests: requestCount,
                successfulRequests,
                rateLimitedRequests,
                timeElapsed: endTime - startTime
            };
            
        } catch (error) {
            console.error('Rate limiting test failed:', error);
        }
    }

    async testResourceExhaustion() {
        const largePayloads = [
            'A'.repeat(1024 * 1024),      // 1MB
            'A'.repeat(10 * 1024 * 1024), // 10MB
            'A'.repeat(100 * 1024 * 1024) // 100MB
        ];

        for (const payload of largePayloads) {
            try {
                const startTime = Date.now();
                const response = await this.makeRequest('/api/upload', {
                    method: 'POST',
                    body: payload,
                    headers: { 'Content-Type': 'text/plain' }
                });
                const endTime = Date.now();
                
                if (response.ok && endTime - startTime > 30000) {
                    this.addVulnerability({
                        type: 'Resource Exhaustion',
                        severity: 'Medium',
                        description: 'Server accepts very large payloads without proper limits',
                        evidence: `${payload.length} byte payload accepted in ${endTime - startTime}ms`,
                        recommendation: 'Implement payload size limits and request timeouts'
                    });
                }
            } catch (error) {
                // Timeout or rejection is actually good here
                console.log(`Large payload rejected: ${error.message}`);
            }
        }
    }

    async testSlowLoris() {
        // Simulate slow HTTP attack
        try {
            const slowRequests = Array(20).fill().map(() => 
                this.makeSlowRequest('/api/test')
            );
            
            const results = await Promise.allSettled(slowRequests);
            const successfulSlowRequests = results.filter(r => r.status === 'fulfilled').length;
            
            if (successfulSlowRequests > 15) {
                this.addVulnerability({
                    type: 'Slow HTTP Attack Vulnerability',
                    severity: 'Medium',
                    description: 'Server vulnerable to Slow HTTP (Slowloris) attacks',
                    evidence: `${successfulSlowRequests}/20 slow requests succeeded`,
                    recommendation: 'Implement connection timeouts and concurrent connection limits'
                });
            }
        } catch (error) {
            console.error('Slowloris test failed:', error);
        }
    }

    // HTTP Security Headers Testing
    async testHTTPSecurityHeaders() {
        console.log('Testing HTTP Security Headers...');
        
        try {
            const response = await this.makeRequest('/');
            const headers = response.headers || {};
            
            const requiredHeaders = {
                'strict-transport-security': {
                    name: 'HSTS',
                    severity: 'High',
                    description: 'Missing HTTP Strict Transport Security header'
                },
                'content-security-policy': {
                    name: 'CSP',
                    severity: 'High',
                    description: 'Missing Content Security Policy header'
                },
                'x-frame-options': {
                    name: 'X-Frame-Options',
                    severity: 'Medium',
                    description: 'Missing X-Frame-Options header (Clickjacking protection)'
                },
                'x-content-type-options': {
                    name: 'X-Content-Type-Options',
                    severity: 'Medium',
                    description: 'Missing X-Content-Type-Options header'
                },
                'referrer-policy': {
                    name: 'Referrer-Policy',
                    severity: 'Low',
                    description: 'Missing Referrer-Policy header'
                },
                'permissions-policy': {
                    name: 'Permissions-Policy',
                    severity: 'Low',
                    description: 'Missing Permissions-Policy header'
                }
            };

            for (const [headerName, config] of Object.entries(requiredHeaders)) {
                if (!headers[headerName] && !headers[headerName.toLowerCase()]) {
                    this.addVulnerability({
                        type: 'Missing Security Header',
                        severity: config.severity,
                        description: config.description,
                        evidence: `${config.name} header not found in response`,
                        recommendation: `Add ${config.name} header to all responses`
                    });
                }
            }

            // Check for insecure header values
            const hstsHeader = headers['strict-transport-security'];
            if (hstsHeader && !hstsHeader.includes('includeSubDomains')) {
                this.addVulnerability({
                    type: 'Weak HSTS Configuration',
                    severity: 'Medium',
                    description: 'HSTS header does not include subdomains',
                    evidence: `HSTS: ${hstsHeader}`,
                    recommendation: 'Add includeSubDomains directive to HSTS header'
                });
            }

            this.networkTests.securityHeaders = {
                detected: Object.keys(headers),
                missing: Object.keys(requiredHeaders).filter(h => !headers[h] && !headers[h.toLowerCase()])
            };

        } catch (error) {
            console.error('Security headers test failed:', error);
        }
    }

    // DNS Configuration Testing
    async testDNSConfiguration() {
        console.log('Testing DNS Configuration...');
        
        try {
            // Test for DNS over HTTPS (DoH) support
            const dohTest = await this.testDNSOverHTTPS();
            
            // Test for DNSSEC
            const dnssecTest = await this.testDNSSEC();
            
            // Test for DNS cache poisoning resistance
            const cachePoisoningTest = await this.testDNSCachePoisoning();
            
            this.networkTests.dns = {
                doh: dohTest,
                dnssec: dnssecTest,
                cachePoisoning: cachePoisoningTest
            };
            
        } catch (error) {
            console.error('DNS testing failed:', error);
        }
    }

    async testDNSOverHTTPS() {
        // Simulate DoH testing
        const supportsDoH = Math.random() > 0.6; // Simulate detection
        
        if (!supportsDoH) {
            this.addVulnerability({
                type: 'Missing DNS over HTTPS',
                severity: 'Medium',
                description: 'DNS queries are not encrypted, vulnerable to eavesdropping',
                evidence: 'DoH not detected',
                recommendation: 'Implement DNS over HTTPS (DoH) or DNS over TLS (DoT)'
            });
        }
        
        return { supported: supportsDoH };
    }

    async testDNSSEC() {
        // Simulate DNSSEC testing
        const supportsDNSSEC = Math.random() > 0.5;
        
        if (!supportsDNSSEC) {
            this.addVulnerability({
                type: 'Missing DNSSEC',
                severity: 'Medium',
                description: 'DNS responses are not cryptographically signed',
                evidence: 'DNSSEC validation failed',
                recommendation: 'Enable DNSSEC for domain authentication'
            });
        }
        
        return { enabled: supportsDNSSEC };
    }

    async testDNSCachePoisoning() {
        // Simulate cache poisoning resistance test
        const resistant = Math.random() > 0.4;
        
        if (!resistant) {
            this.addVulnerability({
                type: 'DNS Cache Poisoning Vulnerability',
                severity: 'High',
                description: 'DNS resolver vulnerable to cache poisoning attacks',
                evidence: 'Predictable query IDs or insufficient randomization',
                recommendation: 'Use secure DNS resolvers with proper randomization'
            });
        }
        
        return { resistant };
    }

    // Database Backup Security Testing
    async testDatabaseBackupSecurity() {
        console.log('Testing Database Backup Security...');
        
        const commonBackupPaths = [
            '/backup/',
            '/backups/',
            '/db_backup/',
            '/database/',
            '/dump/',
            '/sql/',
            '/.backup/',
            '/backup.sql',
            '/database.sql',
            '/dump.sql',
            '/backup.tar.gz',
            '/db.tar.gz'
        ];

        for (const path of commonBackupPaths) {
            try {
                const response = await this.makeRequest(path);
                
                if (response.ok || response.status === 403) {
                    this.addVulnerability({
                        type: 'Exposed Database Backup',
                        severity: 'Critical',
                        description: 'Database backup files are accessible via web',
                        evidence: `Backup found at ${path} (Status: ${response.status})`,
                        recommendation: 'Move backup files outside web root and restrict access'
                    });
                }
            } catch (error) {
                // 404 is expected and good
                continue;
            }
        }

        // Test for backup file naming patterns
        const backupPatterns = [
            'backup_' + new Date().toISOString().split('T')[0],
            'db_backup_' + Date.now(),
            'database_dump_latest',
            'prod_backup',
            'mysql_backup'
        ];

        for (const pattern of backupPatterns) {
            try {
                const response = await this.makeRequest(`/${pattern}.sql`);
                if (response.ok) {
                    this.addVulnerability({
                        type: 'Predictable Backup Naming',
                        severity: 'High',
                        description: 'Database backups use predictable naming patterns',
                        evidence: `Backup accessible at /${pattern}.sql`,
                        recommendation: 'Use random, non-guessable backup file names'
                    });
                }
            } catch (error) {
                continue;
            }
        }
    }

    // Server Configuration Testing
    async testServerConfiguration() {
        console.log('Testing Server Configuration...');
        
        try {
            const response = await this.makeRequest('/');
            const headers = response.headers || {};
            
            // Test for server information disclosure
            const serverHeader = headers.server || headers.Server;
            if (serverHeader) {
                this.addVulnerability({
                    type: 'Server Information Disclosure',
                    severity: 'Low',
                    description: 'Server header reveals software version information',
                    evidence: `Server: ${serverHeader}`,
                    recommendation: 'Remove or obfuscate server version information'
                });
            }

            // Test for powered-by headers
            const poweredBy = headers['x-powered-by'] || headers['X-Powered-By'];
            if (poweredBy) {
                this.addVulnerability({
                    type: 'Technology Stack Disclosure',
                    severity: 'Low',
                    description: 'X-Powered-By header reveals technology stack',
                    evidence: `X-Powered-By: ${poweredBy}`,
                    recommendation: 'Remove X-Powered-By header'
                });
            }

            // Test for debug endpoints
            const debugEndpoints = [
                '/debug',
                '/admin',
                '/test',
                '/dev',
                '/api/debug',
                '/api/admin',
                '/.env',
                '/config',
                '/status',
                '/health'
            ];

            for (const endpoint of debugEndpoints) {
                try {
                    const debugResponse = await this.makeRequest(endpoint);
                    if (debugResponse.ok) {
                        this.addVulnerability({
                            type: 'Debug Endpoint Exposed',
                            severity: 'Medium',
                            description: 'Debug or administrative endpoints are publicly accessible',
                            evidence: `${endpoint} returns status ${debugResponse.status}`,
                            recommendation: 'Restrict access to debug endpoints or remove them in production'
                        });
                    }
                } catch (error) {
                    continue;
                }
            }

            this.networkTests.serverConfig = {
                serverHeader,
                poweredBy,
                debugEndpointsFound: []
            };

        } catch (error) {
            console.error('Server configuration test failed:', error);
        }
    }

    // Helper Methods
    async makeRequest(path, options = {}) {
        // Simulate HTTP request - in real implementation, use fetch or axios
        return new Promise((resolve) => {
            setTimeout(() => {
                const responses = [
                    { ok: true, status: 200, headers: { 'server': 'nginx/1.18.0' } },
                    { ok: false, status: 404, headers: {} },
                    { ok: false, status: 403, headers: {} },
                    { ok: false, status: 429, headers: {} },
                    { ok: true, status: 200, headers: { 'x-powered-by': 'Express' } }
                ];
                resolve(responses[Math.floor(Math.random() * responses.length)]);
            }, Math.random() * 200);
        });
    }

    async makeSecureRequest(path) {
        // Simulate HTTPS request with TLS info
        return new Promise((resolve) => {
            setTimeout(() => {
                resolve({
                    ok: true,
                    status: 200,
                    headers: {
                        'tls-version': 'TLSv1.3',
                        'strict-transport-security': 'max-age=31536000; includeSubDomains'
                    }
                });
            }, Math.random() * 300);
        });
    }

    async makeSlowRequest(path) {
        // Simulate slow HTTP request
        return new Promise((resolve) => {
            setTimeout(() => {
                resolve({ ok: true, status: 200 });
            }, 5000 + Math.random() * 5000); // 5-10 second delay
        });
    }

    addVulnerability(vuln) {
        this.vulnerabilities.push({
            ...vuln,
            timestamp: new Date().toISOString(),
            id: `NETWORK-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
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
            networkTests: this.networkTests,
            recommendations: this.generateRecommendations()
        };
    }

    generateRecommendations() {
        const recommendations = [];
        
        if (this.vulnerabilities.some(v => v.type.includes('MITM') || v.type.includes('TLS'))) {
            recommendations.push({
                category: 'Transport Security',
                actions: [
                    'Implement HTTPS with TLS 1.2 or higher',
                    'Use certificates from trusted Certificate Authorities',
                    'Enable HTTP Strict Transport Security (HSTS)',
                    'Disable weak cipher suites and protocols'
                ]
            });
        }

        if (this.vulnerabilities.some(v => v.type.includes('DoS') || v.type.includes('Rate'))) {
            recommendations.push({
                category: 'DoS Protection',
                actions: [
                    'Implement rate limiting (e.g., 10 requests/second per IP)',
                    'Set maximum payload size limits',
                    'Configure connection timeouts',
                    'Use a Web Application Firewall (WAF)'
                ]
            });
        }

        if (this.vulnerabilities.some(v => v.type.includes('Header'))) {
            recommendations.push({
                category: 'HTTP Security Headers',
                actions: [
                    'Add Content Security Policy (CSP) header',
                    'Enable X-Frame-Options for clickjacking protection',
                    'Set X-Content-Type-Options: nosniff',
                    'Configure Referrer-Policy appropriately'
                ]
            });
        }

        if (this.vulnerabilities.some(v => v.type.includes('DNS'))) {
            recommendations.push({
                category: 'DNS Security',
                actions: [
                    'Enable DNSSEC for domain validation',
                    'Use DNS over HTTPS (DoH) or DNS over TLS (DoT)',
                    'Implement DNS filtering for malicious domains',
                    'Use secure, reputable DNS resolvers'
                ]
            });
        }

        if (this.vulnerabilities.some(v => v.type.includes('Backup'))) {
            recommendations.push({
                category: 'Backup Security',
                actions: [
                    'Store backups outside the web-accessible directory',
                    'Encrypt all database backups',
                    'Use non-predictable backup file names',
                    'Implement proper access controls for backup files'
                ]
            });
        }

        return recommendations;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = NetworkSecurityScanner;
}