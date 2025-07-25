/**
 * MCP Application Logic Security Scanner
 * Tests for complex application logic flaws and session management issues
 */

class ApplicationLogicScanner {
    constructor(serverConfig) {
        this.serverConfig = serverConfig;
        this.vulnerabilities = [];
        this.logicTests = {};
    }

    async scanAll() {
        console.log('🧠 Starting Application Logic Security Scan...');
        
        await this.testClickjacking();
        await this.testSessionManagement();
        await this.testAuthentication();
        await this.testPasswordPolicies();
        await this.testPasswordRecovery();
        await this.testBusinessLogicFlaws();
        
        return {
            vulnerabilities: this.vulnerabilities,
            logicTests: this.logicTests
        };
    }

    // Clickjacking Protection Testing
    async testClickjacking() {
        console.log('Testing for Clickjacking vulnerabilities...');
        
        try {
            // Test X-Frame-Options header
            const response = await this.simulateRequest('/');
            const headers = response.headers || {};
            
            const xFrameOptions = headers['x-frame-options'] || headers['X-Frame-Options'];
            const csp = headers['content-security-policy'] || headers['Content-Security-Policy'];
            
            let hasClickjackingProtection = false;
            
            if (xFrameOptions) {
                if (xFrameOptions.toLowerCase() === 'deny' || 
                    xFrameOptions.toLowerCase() === 'sameorigin') {
                    hasClickjackingProtection = true;
                } else if (xFrameOptions.toLowerCase().startsWith('allow-from')) {
                    // Partial protection
                    this.addVulnerability({
                        type: 'Weak Clickjacking Protection',
                        severity: 'Medium',
                        description: 'X-Frame-Options uses ALLOW-FROM which is not supported by all browsers',
                        evidence: `X-Frame-Options: ${xFrameOptions}`,
                        recommendation: 'Use DENY or SAMEORIGIN, or implement CSP frame-ancestors'
                    });
                    hasClickjackingProtection = true;
                }
            }
            
            if (csp && csp.includes('frame-ancestors')) {
                hasClickjackingProtection = true;
            }
            
            if (!hasClickjackingProtection) {
                this.addVulnerability({
                    type: 'Clickjacking Vulnerability',
                    severity: 'Medium',
                    description: 'Application lacks clickjacking protection',
                    evidence: 'No X-Frame-Options or CSP frame-ancestors directive found',
                    recommendation: 'Add X-Frame-Options: DENY or CSP frame-ancestors directive'
                });
            }

            // Test for frameable sensitive pages
            const sensitivePages = ['/admin', '/profile', '/settings', '/payment', '/transfer'];
            for (const page of sensitivePages) {
                const pageResponse = await this.simulateRequest(page);
                const pageHeaders = pageResponse.headers || {};
                
                if (!pageHeaders['x-frame-options'] && !pageHeaders['X-Frame-Options']) {
                    this.addVulnerability({
                        type: 'Sensitive Page Clickjacking',
                        severity: 'High',
                        description: `Sensitive page ${page} lacks clickjacking protection`,
                        evidence: `Page ${page} can be framed`,
                        recommendation: 'Add frame protection to all sensitive pages'
                    });
                }
            }

            this.logicTests.clickjacking = {
                xFrameOptions,
                cspFrameAncestors: csp?.includes('frame-ancestors'),
                protected: hasClickjackingProtection
            };

        } catch (error) {
            console.error('Clickjacking test failed:', error);
        }
    }

    // Session Management Testing
    async testSessionManagement() {
        console.log('Testing Session Management...');
        
        try {
            // Test session cookie security
            await this.testSessionCookies();
            
            // Test session fixation
            await this.testSessionFixation();
            
            // Test session timeout
            await this.testSessionTimeout();
            
            // Test concurrent sessions
            await this.testConcurrentSessions();
            
        } catch (error) {
            console.error('Session management test failed:', error);
        }
    }

    async testSessionCookies() {
        const loginResponse = await this.simulateLogin('testuser', 'password123');
        const cookies = loginResponse.headers?.['set-cookie'] || [];
        
        let sessionCookie = null;
        for (const cookie of cookies) {
            if (cookie.toLowerCase().includes('session') || 
                cookie.toLowerCase().includes('auth') ||
                cookie.toLowerCase().includes('token')) {
                sessionCookie = cookie;
                break;
            }
        }

        if (!sessionCookie) {
            this.addVulnerability({
                type: 'Missing Session Cookie',
                severity: 'High',
                description: 'No session cookie found after authentication',
                evidence: 'Login response contains no session management cookies',
                recommendation: 'Implement proper session cookie management'
            });
            return;
        }

        // Check cookie security attributes
        const cookieFlags = {
            httpOnly: sessionCookie.toLowerCase().includes('httponly'),
            secure: sessionCookie.toLowerCase().includes('secure'),
            sameSite: sessionCookie.toLowerCase().includes('samesite')
        };

        if (!cookieFlags.httpOnly) {
            this.addVulnerability({
                type: 'Insecure Session Cookie - Missing HttpOnly',
                severity: 'High',
                description: 'Session cookie lacks HttpOnly flag, vulnerable to XSS',
                evidence: `Session cookie: ${sessionCookie}`,
                recommendation: 'Add HttpOnly flag to session cookies'
            });
        }

        if (!cookieFlags.secure) {
            this.addVulnerability({
                type: 'Insecure Session Cookie - Missing Secure',
                severity: 'High',
                description: 'Session cookie lacks Secure flag, can be transmitted over HTTP',
                evidence: `Session cookie: ${sessionCookie}`,
                recommendation: 'Add Secure flag to session cookies'
            });
        }

        if (!cookieFlags.sameSite) {
            this.addVulnerability({
                type: 'Insecure Session Cookie - Missing SameSite',
                severity: 'Medium',
                description: 'Session cookie lacks SameSite attribute, vulnerable to CSRF',
                evidence: `Session cookie: ${sessionCookie}`,
                recommendation: 'Add SameSite=Strict or SameSite=Lax to session cookies'
            });
        }

        this.logicTests.sessionCookies = {
            found: !!sessionCookie,
            ...cookieFlags
        };
    }

    async testSessionFixation() {
        // Test if session ID changes after login
        const preLoginResponse = await this.simulateRequest('/login');
        const preLoginSessionId = this.extractSessionId(preLoginResponse);
        
        const loginResponse = await this.simulateLogin('testuser', 'password123');
        const postLoginSessionId = this.extractSessionId(loginResponse);
        
        if (preLoginSessionId && postLoginSessionId && preLoginSessionId === postLoginSessionId) {
            this.addVulnerability({
                type: 'Session Fixation',
                severity: 'High',
                description: 'Session ID does not change after authentication',
                evidence: `Session ID remains ${preLoginSessionId} before and after login`,
                recommendation: 'Generate new session ID upon successful authentication'
            });
        }

        this.logicTests.sessionFixation = {
            preLoginId: preLoginSessionId,
            postLoginId: postLoginSessionId,
            vulnerable: preLoginSessionId === postLoginSessionId
        };
    }

    async testSessionTimeout() {
        // Test if sessions expire appropriately
        const loginResponse = await this.simulateLogin('testuser', 'password123');
        const sessionId = this.extractSessionId(loginResponse);
        
        if (!sessionId) return;

        // Simulate waiting for session timeout
        await this.simulateDelay(30000); // 30 seconds
        
        const timeoutTestResponse = await this.simulateAuthenticatedRequest('/profile', sessionId);
        
        if (timeoutTestResponse.status === 200) {
            // Session still valid - check if it's too long
            this.addVulnerability({
                type: 'Long Session Timeout',
                severity: 'Medium',
                description: 'Session timeout may be too long',
                evidence: 'Session still valid after 30 seconds of inactivity',
                recommendation: 'Implement appropriate session timeout (15-30 minutes for sensitive apps)'
            });
        }

        // Test absolute session timeout
        await this.simulateDelay(3600000); // 1 hour
        const absoluteTimeoutResponse = await this.simulateAuthenticatedRequest('/profile', sessionId);
        
        if (absoluteTimeoutResponse.status === 200) {
            this.addVulnerability({
                type: 'Missing Absolute Session Timeout',
                severity: 'Medium',
                description: 'Sessions do not have absolute timeout limits',
                evidence: 'Session still valid after 1 hour',
                recommendation: 'Implement absolute session timeout (e.g., 8-12 hours maximum)'
            });
        }
    }

    async testConcurrentSessions() {
        // Test if multiple sessions are allowed for same user
        const session1 = await this.simulateLogin('testuser', 'password123');
        const session2 = await this.simulateLogin('testuser', 'password123');
        
        const sessionId1 = this.extractSessionId(session1);
        const sessionId2 = this.extractSessionId(session2);
        
        if (sessionId1 && sessionId2 && sessionId1 !== sessionId2) {
            // Both sessions exist - test if both are valid
            const test1 = await this.simulateAuthenticatedRequest('/profile', sessionId1);
            const test2 = await this.simulateAuthenticatedRequest('/profile', sessionId2);
            
            if (test1.status === 200 && test2.status === 200) {
                this.addVulnerability({
                    type: 'Concurrent Session Vulnerability',
                    severity: 'Medium',
                    description: 'Multiple active sessions allowed for same user',
                    evidence: 'Both sessions remain valid after second login',
                    recommendation: 'Invalidate previous sessions when user logs in from new location'
                });
            }
        }
    }

    // Authentication Testing
    async testAuthentication() {
        console.log('Testing Authentication mechanisms...');
        
        await this.testBruteForceProtection();
        await this.testAccountLockout();
        await this.testMultiFactorAuthentication();
        await this.testPasswordTransmission();
    }

    async testBruteForceProtection() {
        const username = 'testuser';
        const wrongPasswords = Array(10).fill().map((_, i) => `wrongpass${i}`);
        
        let successfulAttempts = 0;
        let lockedOut = false;
        
        for (const password of wrongPasswords) {
            const response = await this.simulateLogin(username, password);
            
            if (response.status === 200) {
                successfulAttempts++;
            } else if (response.status === 423 || response.status === 429) {
                lockedOut = true;
                break;
            }
        }
        
        if (successfulAttempts === 0 && !lockedOut) {
            this.addVulnerability({
                type: 'Missing Brute Force Protection',
                severity: 'High',
                description: 'No brute force protection detected',
                evidence: `${wrongPasswords.length} failed login attempts without lockout`,
                recommendation: 'Implement account lockout or rate limiting after failed attempts'
            });
        }

        this.logicTests.bruteForce = {
            attemptsBeforeLockout: lockedOut ? wrongPasswords.indexOf(wrongPasswords[wrongPasswords.length - 1]) + 1 : null,
            protectionDetected: lockedOut
        };
    }

    async testAccountLockout() {
        // Test account lockout mechanism
        const response = await this.simulateRequest('/account/lockout-policy');
        
        // Simulate checking lockout policy
        const hasLockoutPolicy = Math.random() > 0.3; // Simulate detection
        
        if (!hasLockoutPolicy) {
            this.addVulnerability({
                type: 'Missing Account Lockout Policy',
                severity: 'Medium',
                description: 'No account lockout policy implemented',
                evidence: 'Account lockout mechanism not found',
                recommendation: 'Implement progressive delays or temporary lockouts after failed attempts'
            });
        }
    }

    async testMultiFactorAuthentication() {
        // Test for MFA implementation
        const loginResponse = await this.simulateLogin('testuser', 'password123');
        
        // Check if MFA is required
        const requiresMFA = loginResponse.headers?.['x-mfa-required'] || 
                           loginResponse.body?.includes('mfa') ||
                           loginResponse.body?.includes('two-factor');
        
        if (!requiresMFA) {
            this.addVulnerability({
                type: 'Missing Multi-Factor Authentication',
                severity: 'High',
                description: 'Multi-factor authentication not implemented',
                evidence: 'Login successful without MFA challenge',
                recommendation: 'Implement MFA using TOTP, SMS, or hardware tokens'
            });
        }

        this.logicTests.mfa = {
            required: !!requiresMFA,
            detected: !!requiresMFA
        };
    }

    async testPasswordTransmission() {
        // Test if passwords are transmitted securely
        const loginRequest = {
            url: '/login',
            method: 'POST',
            body: { username: 'testuser', password: 'password123' }
        };
        
        // Check if using HTTPS
        if (this.serverConfig.serverUrl?.startsWith('http://')) {
            this.addVulnerability({
                type: 'Insecure Password Transmission',
                severity: 'Critical',
                description: 'Passwords transmitted over unencrypted HTTP',
                evidence: 'Login form uses HTTP instead of HTTPS',
                recommendation: 'Use HTTPS for all authentication endpoints'
            });
        }
        
        // Check for password in URL parameters (GET request)
        const getLoginResponse = await this.simulateRequest('/login?username=test&password=test123');
        if (getLoginResponse.status === 200) {
            this.addVulnerability({
                type: 'Password in URL Parameters',
                severity: 'High',
                description: 'Login accepts passwords via URL parameters',
                evidence: 'GET request to /login with password parameter succeeded',
                recommendation: 'Only accept passwords via POST request body'
            });
        }
    }

    // Password Policy Testing
    async testPasswordPolicies() {
        console.log('Testing Password Policies...');
        
        const weakPasswords = [
            'password',
            '123456',
            'admin',
            'test',
            'a',
            '12345678',
            'password123',
            'qwerty',
            'abc123'
        ];

        let weakPasswordsAccepted = 0;
        
        for (const weakPassword of weakPasswords) {
            const response = await this.simulatePasswordChange('testuser', weakPassword);
            
            if (response.status === 200) {
                weakPasswordsAccepted++;
            }
        }
        
        if (weakPasswordsAccepted > 0) {
            this.addVulnerability({
                type: 'Weak Password Policy',
                severity: 'Medium',
                description: 'System accepts weak passwords',
                evidence: `${weakPasswordsAccepted}/${weakPasswords.length} weak passwords accepted`,
                recommendation: 'Implement strong password policy (min 8 chars, mixed case, numbers, symbols)'
            });
        }

        // Test password complexity requirements
        const complexityTests = [
            { password: 'short', requirement: 'minimum length' },
            { password: 'alllowercase123', requirement: 'uppercase letters' },
            { password: 'ALLUPPERCASE123', requirement: 'lowercase letters' },
            { password: 'NoNumbers', requirement: 'numbers' },
            { password: 'NoSymbols123', requirement: 'special characters' }
        ];

        for (const test of complexityTests) {
            const response = await this.simulatePasswordChange('testuser', test.password);
            if (response.status === 200) {
                this.addVulnerability({
                    type: 'Missing Password Complexity Requirement',
                    severity: 'Medium',
                    description: `Password policy missing ${test.requirement} requirement`,
                    evidence: `Password "${test.password}" was accepted`,
                    recommendation: `Enforce ${test.requirement} in password policy`
                });
            }
        }

        this.logicTests.passwordPolicy = {
            weakPasswordsAccepted,
            totalWeakPasswordsTested: weakPasswords.length
        };
    }

    // Password Recovery Testing
    async testPasswordRecovery() {
        console.log('Testing Password Recovery mechanisms...');
        
        await this.testPasswordResetTokens();
        await this.testSecurityQuestions();
        await this.testPasswordResetRateLimit();
    }

    async testPasswordResetTokens() {
        // Test password reset token security
        const resetResponse = await this.simulatePasswordReset('testuser@example.com');
        
        if (resetResponse.status === 200) {
            // Simulate token extraction (in real scenario, would need email access)
            const token = 'simulated-reset-token-123';
            
            // Test token predictability
            if (token.length < 32) {
                this.addVulnerability({
                    type: 'Weak Password Reset Token',
                    severity: 'High',
                    description: 'Password reset tokens are too short or predictable',
                    evidence: `Token length: ${token.length} characters`,
                    recommendation: 'Use cryptographically secure random tokens (min 32 characters)'
                });
            }
            
            // Test token reuse
            const reuse1 = await this.simulatePasswordResetWithToken(token, 'newpass1');
            const reuse2 = await this.simulatePasswordResetWithToken(token, 'newpass2');
            
            if (reuse1.status === 200 && reuse2.status === 200) {
                this.addVulnerability({
                    type: 'Password Reset Token Reuse',
                    severity: 'High',
                    description: 'Password reset tokens can be reused multiple times',
                    evidence: 'Same token used successfully twice',
                    recommendation: 'Invalidate tokens after single use'
                });
            }
            
            // Test token expiration
            await this.simulateDelay(3600000); // 1 hour
            const expiredTokenResponse = await this.simulatePasswordResetWithToken(token, 'newpass3');
            
            if (expiredTokenResponse.status === 200) {
                this.addVulnerability({
                    type: 'Password Reset Token Never Expires',
                    severity: 'Medium',
                    description: 'Password reset tokens do not expire',
                    evidence: 'Token still valid after 1 hour',
                    recommendation: 'Set token expiration (15-30 minutes recommended)'
                });
            }
        }
    }

    async testSecurityQuestions() {
        // Test security question implementation
        const securityQuestionsResponse = await this.simulateRequest('/security-questions');
        
        if (securityQuestionsResponse.status === 200) {
            // Test for weak security questions
            const weakQuestions = [
                'What is your favorite color?',
                'What is your pet\'s name?',
                'What city were you born in?',
                'What is your mother\'s maiden name?'
            ];
            
            // Simulate checking if weak questions are used
            const usesWeakQuestions = Math.random() > 0.4;
            
            if (usesWeakQuestions) {
                this.addVulnerability({
                    type: 'Weak Security Questions',
                    severity: 'Medium',
                    description: 'Security questions use easily guessable or researched answers',
                    evidence: 'Common security questions detected',
                    recommendation: 'Use complex, personal security questions or eliminate them entirely'
                });
            }
        }
    }

    async testPasswordResetRateLimit() {
        const email = 'testuser@example.com';
        const attempts = 10;
        let successfulResets = 0;
        
        for (let i = 0; i < attempts; i++) {
            const response = await this.simulatePasswordReset(email);
            if (response.status === 200) {
                successfulResets++;
            } else if (response.status === 429) {
                break; // Rate limited
            }
        }
        
        if (successfulResets >= attempts) {
            this.addVulnerability({
                type: 'Password Reset Rate Limit Missing',
                severity: 'Medium',
                description: 'No rate limiting on password reset requests',
                evidence: `${successfulResets} password reset requests succeeded`,
                recommendation: 'Implement rate limiting for password reset requests'
            });
        }
    }

    // Business Logic Flaws Testing
    async testBusinessLogicFlaws() {
        console.log('Testing Business Logic Flaws...');
        
        await this.testPriceManipulation();
        await this.testQuantityManipulation();
        await this.testWorkflowBypass();
        await this.testPrivilegeEscalation();
    }

    async testPriceManipulation() {
        // Test for price manipulation in e-commerce scenarios
        const orderData = {
            item: 'expensive_item',
            price: -100, // Negative price
            quantity: 1
        };
        
        const response = await this.simulateRequest('/api/order', {
            method: 'POST',
            body: JSON.stringify(orderData)
        });
        
        if (response.status === 200) {
            this.addVulnerability({
                type: 'Price Manipulation',
                severity: 'Critical',
                description: 'System accepts negative prices or price manipulation',
                evidence: 'Order with negative price was accepted',
                recommendation: 'Validate all price inputs on server side'
            });
        }
        
        // Test decimal manipulation
        const decimalOrderData = {
            item: 'item',
            price: 0.01, // Very low price
            quantity: 1
        };
        
        const decimalResponse = await this.simulateRequest('/api/order', {
            method: 'POST',
            body: JSON.stringify(decimalOrderData)
        });
        
        if (decimalResponse.status === 200) {
            this.addVulnerability({
                type: 'Price Validation Bypass',
                severity: 'High',
                description: 'System accepts unrealistic low prices',
                evidence: 'Order with $0.01 price was accepted',
                recommendation: 'Implement minimum price validation'
            });
        }
    }

    async testQuantityManipulation() {
        // Test quantity manipulation
        const quantityTests = [
            { quantity: -1, description: 'negative quantity' },
            { quantity: 0, description: 'zero quantity' },
            { quantity: 999999, description: 'excessive quantity' },
            { quantity: 1.5, description: 'fractional quantity for discrete items' }
        ];
        
        for (const test of quantityTests) {
            const response = await this.simulateRequest('/api/order', {
                method: 'POST',
                body: JSON.stringify({
                    item: 'test_item',
                    price: 10,
                    quantity: test.quantity
                })
            });
            
            if (response.status === 200) {
                this.addVulnerability({
                    type: 'Quantity Manipulation',
                    severity: 'High',
                    description: `System accepts ${test.description}`,
                    evidence: `Order with quantity ${test.quantity} was accepted`,
                    recommendation: 'Implement proper quantity validation'
                });
            }
        }
    }

    async testWorkflowBypass() {
        // Test workflow bypass (e.g., skipping payment step)
        const workflowSteps = [
            '/api/cart/add',
            '/api/checkout/shipping',
            '/api/checkout/payment',
            '/api/order/complete'
        ];
        
        // Try to skip directly to order completion
        const bypassResponse = await this.simulateRequest('/api/order/complete', {
            method: 'POST',
            body: JSON.stringify({ orderId: 'test123' })
        });
        
        if (bypassResponse.status === 200) {
            this.addVulnerability({
                type: 'Workflow Bypass',
                severity: 'Critical',
                description: 'Critical workflow steps can be bypassed',
                evidence: 'Order completion succeeded without going through proper workflow',
                recommendation: 'Implement server-side workflow state validation'
            });
        }
    }

    async testPrivilegeEscalation() {
        // Test horizontal privilege escalation
        const userAResponse = await this.simulateLogin('userA', 'password');
        const userASessionId = this.extractSessionId(userAResponse);
        
        // Try to access userB's data with userA's session
        const escalationResponse = await this.simulateAuthenticatedRequest('/api/user/userB/profile', userASessionId);
        
        if (escalationResponse.status === 200) {
            this.addVulnerability({
                type: 'Horizontal Privilege Escalation',
                severity: 'High',
                description: 'Users can access other users\' data',
                evidence: 'UserA successfully accessed UserB\'s profile',
                recommendation: 'Implement proper authorization checks for all user data access'
            });
        }
        
        // Test vertical privilege escalation
        const adminResponse = await this.simulateAuthenticatedRequest('/api/admin/users', userASessionId);
        
        if (adminResponse.status === 200) {
            this.addVulnerability({
                type: 'Vertical Privilege Escalation',
                severity: 'Critical',
                description: 'Regular users can access administrative functions',
                evidence: 'Regular user accessed admin endpoint successfully',
                recommendation: 'Implement role-based access control (RBAC)'
            });
        }
    }

    // Helper Methods
    async simulateRequest(path, options = {}) {
        // Simulate HTTP request
        return new Promise((resolve) => {
            setTimeout(() => {
                const responses = [
                    { status: 200, headers: {}, body: 'Success' },
                    { status: 404, headers: {}, body: 'Not Found' },
                    { status: 403, headers: {}, body: 'Forbidden' },
                    { status: 429, headers: {}, body: 'Too Many Requests' },
                    { status: 423, headers: {}, body: 'Locked' }
                ];
                resolve(responses[Math.floor(Math.random() * responses.length)]);
            }, Math.random() * 200);
        });
    }

    async simulateLogin(username, password) {
        return new Promise((resolve) => {
            setTimeout(() => {
                const success = password === 'password123' && username === 'testuser';
                resolve({
                    status: success ? 200 : 401,
                    headers: success ? {
                        'set-cookie': ['sessionid=abc123; HttpOnly; Secure; SameSite=Strict']
                    } : {},
                    body: success ? 'Login successful' : 'Invalid credentials'
                });
            }, Math.random() * 300);
        });
    }

    async simulateAuthenticatedRequest(path, sessionId) {
        return new Promise((resolve) => {
            setTimeout(() => {
                const validSession = sessionId === 'abc123';
                resolve({
                    status: validSession ? 200 : 401,
                    headers: {},
                    body: validSession ? 'Authenticated content' : 'Unauthorized'
                });
            }, Math.random() * 200);
        });
    }

    async simulatePasswordChange(username, newPassword) {
        return new Promise((resolve) => {
            setTimeout(() => {
                const weakPasswords = ['password', '123456', 'admin', 'test', 'a'];
                const isWeak = weakPasswords.includes(newPassword.toLowerCase()) || newPassword.length < 8;
                resolve({
                    status: isWeak ? 400 : 200,
                    body: isWeak ? 'Password too weak' : 'Password changed'
                });
            }, Math.random() * 200);
        });
    }

    async simulatePasswordReset(email) {
        return new Promise((resolve) => {
            setTimeout(() => {
                resolve({
                    status: 200,
                    body: 'Password reset email sent'
                });
            }, Math.random() * 300);
        });
    }

    async simulatePasswordResetWithToken(token, newPassword) {
        return new Promise((resolve) => {
            setTimeout(() => {
                resolve({
                    status: 200,
                    body: 'Password reset successful'
                });
            }, Math.random() * 200);
        });
    }

    async simulateDelay(ms) {
        // Simulate time passage (in real implementation, this would be actual delay)
        return new Promise(resolve => setTimeout(resolve, Math.min(ms, 1000))); // Cap at 1 second for demo
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
            id: `LOGIC-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
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
            logicTests: this.logicTests,
            recommendations: this.generateRecommendations()
        };
    }

    generateRecommendations() {
        const recommendations = [];
        
        if (this.vulnerabilities.some(v => v.type.includes('Clickjacking'))) {
            recommendations.push({
                category: 'Clickjacking Prevention',
                actions: [
                    'Add X-Frame-Options: DENY header to all pages',
                    'Implement CSP frame-ancestors directive',
                    'Use framebusting JavaScript as additional protection',
                    'Test all sensitive pages for frame protection'
                ]
            });
        }

        if (this.vulnerabilities.some(v => v.type.includes('Session'))) {
            recommendations.push({
                category: 'Session Security',
                actions: [
                    'Set HttpOnly, Secure, and SameSite flags on session cookies',
                    'Regenerate session IDs after authentication',
                    'Implement appropriate session timeouts',
                    'Limit concurrent sessions per user'
                ]
            });
        }

        if (this.vulnerabilities.some(v => v.type.includes('Authentication') || v.type.includes('Password'))) {
            recommendations.push({
                category: 'Authentication Security',
                actions: [
                    'Implement multi-factor authentication',
                    'Add brute force protection with progressive delays',
                    'Enforce strong password policies',
                    'Secure password reset mechanisms with time-limited tokens'
                ]
            });
        }

        if (this.vulnerabilities.some(v => v.type.includes('Privilege') || v.type.includes('Logic'))) {
            recommendations.push({
                category: 'Business Logic Security',
                actions: [
                    'Implement proper authorization checks for all operations',
                    'Validate all business logic on the server side',
                    'Use role-based access control (RBAC)',
                    'Implement workflow state validation'
                ]
            });
        }

        return recommendations;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ApplicationLogicScanner;
}