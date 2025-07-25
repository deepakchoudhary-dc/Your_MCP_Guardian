/**
 * Secret Scanner
 * Detects hardcoded secrets, API keys, passwords, and credentials in code
 */

class SecretScanner {
    constructor(projectPath = '.') {
        this.projectPath = projectPath;
        this.vulnerabilities = [];
        this.scanResults = {};
        this.scannedFiles = [];
        
        // Secret detection patterns
        this.secretPatterns = {
            // API Keys
            'AWS Access Key': {
                pattern: /AKIA[0-9A-Z]{16}/g,
                severity: 'Critical',
                description: 'AWS Access Key ID detected'
            },
            'AWS Secret Key': {
                pattern: /[A-Za-z0-9/+=]{40}/g,
                severity: 'Critical',
                description: 'AWS Secret Access Key detected',
                context: ['aws', 'secret', 'key']
            },
            'Google API Key': {
                pattern: /AIza[0-9A-Za-z\\-_]{35}/g,
                severity: 'High',
                description: 'Google API Key detected'
            },
            'GitHub Token': {
                pattern: /gh[pousr]_[A-Za-z0-9_]{36,255}/g,
                severity: 'High',
                description: 'GitHub Personal Access Token detected'
            },
            'GitHub OAuth': {
                pattern: /gho_[A-Za-z0-9_]{36}/g,
                severity: 'High',
                description: 'GitHub OAuth Token detected'
            },
            'Slack Token': {
                pattern: /xox[baprs]-([0-9a-zA-Z]{10,48})?/g,
                severity: 'High',
                description: 'Slack Token detected'
            },
            'Discord Token': {
                pattern: /[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/g,
                severity: 'High',
                description: 'Discord Bot Token detected'
            },
            'Stripe API Key': {
                pattern: /sk_live_[0-9a-zA-Z]{24}/g,
                severity: 'Critical',
                description: 'Stripe Live API Key detected'
            },
            'PayPal Token': {
                pattern: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g,
                severity: 'Critical',
                description: 'PayPal Access Token detected'
            },
            'Twilio API Key': {
                pattern: /SK[a-z0-9]{32}/g,
                severity: 'High',
                description: 'Twilio API Key detected'
            },
            'SendGrid API Key': {
                pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
                severity: 'High',
                description: 'SendGrid API Key detected'
            },
            'Mailgun API Key': {
                pattern: /key-[a-zA-Z0-9]{32}/g,
                severity: 'High',
                description: 'Mailgun API Key detected'
            },
            'Firebase Token': {
                pattern: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/g,
                severity: 'High',
                description: 'Firebase Cloud Messaging Token detected'
            },
            'Azure Storage Key': {
                pattern: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}/g,
                severity: 'Critical',
                description: 'Azure Storage Account Key detected'
            },
            'Heroku API Key': {
                pattern: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g,
                severity: 'High',
                description: 'Heroku API Key detected',
                context: ['heroku']
            },
            
            // Database Credentials
            'MongoDB Connection String': {
                pattern: /mongodb(\+srv)?:\/\/[^\s]+/g,
                severity: 'Critical',
                description: 'MongoDB connection string with credentials detected'
            },
            'MySQL Connection String': {
                pattern: /mysql:\/\/[^\s]+:[^\s]+@[^\s]+/g,
                severity: 'Critical',
                description: 'MySQL connection string with credentials detected'
            },
            'PostgreSQL Connection String': {
                pattern: /postgres(ql)?:\/\/[^\s]+:[^\s]+@[^\s]+/g,
                severity: 'Critical',
                description: 'PostgreSQL connection string with credentials detected'
            },
            'Redis Connection String': {
                pattern: /redis:\/\/[^\s]*:[^\s]*@[^\s]+/g,
                severity: 'High',
                description: 'Redis connection string with credentials detected'
            },
            
            // Generic Patterns
            'Generic API Key': {
                pattern: /['"](api[_-]?key|apikey)['"]\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"]/gi,
                severity: 'Medium',
                description: 'Generic API key pattern detected'
            },
            'Generic Secret': {
                pattern: /['"](secret|password|passwd|pwd)['"]\s*[:=]\s*['"][^'"]{8,}['"]/gi,
                severity: 'Medium',
                description: 'Generic secret pattern detected'
            },
            'Generic Token': {
                pattern: /['"](token|auth[_-]?token|access[_-]?token)['"]\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"]/gi,
                severity: 'Medium',
                description: 'Generic token pattern detected'
            },
            'Private Key': {
                pattern: /-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----/g,
                severity: 'Critical',
                description: 'Private key detected'
            },
            'SSH Private Key': {
                pattern: /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----/g,
                severity: 'Critical',
                description: 'SSH private key detected'
            },
            'JWT Token': {
                pattern: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g,
                severity: 'Medium',
                description: 'JWT token detected'
            },
            'Base64 Encoded Secret': {
                pattern: /['"](secret|password|key|token)['"]\s*[:=]\s*['"][A-Za-z0-9+/]{20,}={0,2}['"]/gi,
                severity: 'Medium',
                description: 'Base64 encoded secret detected'
            },
            
            // Cloud Provider Specific
            'GCP Service Account': {
                pattern: /"type":\s*"service_account"[\s\S]*?"private_key":\s*"-----BEGIN PRIVATE KEY-----/g,
                severity: 'Critical',
                description: 'Google Cloud Platform service account key detected'
            },
            'Azure Client Secret': {
                pattern: /['"](client[_-]?secret|clientsecret)['"]\s*[:=]\s*['"][a-zA-Z0-9_\-~.]{34,}['"]/gi,
                severity: 'Critical',
                description: 'Azure client secret detected'
            },
            
            // Cryptocurrency
            'Bitcoin Private Key': {
                pattern: /[5KL][1-9A-HJ-NP-Za-km-z]{50,51}/g,
                severity: 'Critical',
                description: 'Bitcoin private key detected'
            },
            'Ethereum Private Key': {
                pattern: /0x[a-fA-F0-9]{64}/g,
                severity: 'Critical',
                description: 'Ethereum private key detected',
                context: ['private', 'key', 'ethereum', 'wallet']
            },
            
            // Email and Communication
            'SMTP Credentials': {
                pattern: /smtp:\/\/[^\s]+:[^\s]+@[^\s]+/g,
                severity: 'High',
                description: 'SMTP credentials detected'
            },
            'Email with Password': {
                pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}:[^\s]{6,}/g,
                severity: 'Medium',
                description: 'Email with password detected'
            },
            
            // Generic High Entropy Strings
            'High Entropy String': {
                pattern: /['"]\w*[a-zA-Z0-9+/]{32,}={0,2}['"]/g,
                severity: 'Low',
                description: 'High entropy string detected (possible secret)',
                entropy: true
            }
        };
        
        // File extensions to scan
        this.scanExtensions = [
            '.js', '.ts', '.jsx', '.tsx', '.vue',
            '.py', '.rb', '.php', '.java', '.cs', '.cpp', '.c', '.h',
            '.go', '.rs', '.swift', '.kt', '.scala',
            '.json', '.yaml', '.yml', '.xml', '.toml', '.ini', '.cfg', '.conf',
            '.env', '.properties', '.config',
            '.sh', '.bash', '.zsh', '.fish', '.ps1', '.bat', '.cmd',
            '.sql', '.md', '.txt', '.log'
        ];
        
        // Files to exclude
        this.excludePatterns = [
            /node_modules/,
            /\.git/,
            /\.vscode/,
            /\.idea/,
            /dist/,
            /build/,
            /target/,
            /bin/,
            /obj/,
            /\.min\./,
            /\.bundle\./,
            /vendor/,
            /coverage/,
            /\.nyc_output/,
            /test.*fixtures/,
            /mock/,
            /example/,
            /demo/
        ];
    }

    async performSecretScan() {
        console.log('🔍 Starting Secret Scanning...');
        
        try {
            // Get list of files to scan
            const filesToScan = await this.getFilesToScan();
            
            // Scan each file
            for (const filePath of filesToScan) {
                await this.scanFile(filePath);
            }
            
            // Scan environment variables
            await this.scanEnvironmentVariables();
            
            // Scan configuration files
            await this.scanConfigurationFiles();
            
            // Analyze findings
            await this.analyzeFindings();

            return {
                vulnerabilities: this.vulnerabilities,
                scanResults: this.scanResults,
                scannedFiles: this.scannedFiles
            };

        } catch (error) {
            console.error('Secret scan failed:', error);
            this.addVulnerability({
                type: 'Secret Scan Error',
                severity: 'Medium',
                description: 'Secret scanning encountered errors',
                evidence: error.message,
                recommendation: 'Review project structure and file permissions'
            });
            return { vulnerabilities: this.vulnerabilities, scanResults: this.scanResults };
        }
    }

    async getFilesToScan() {
        // Simulate file discovery (in real implementation, would use fs.readdir recursively)
        const mockFiles = [
            'src/config.js',
            'src/database.js',
            'src/auth.js',
            'config/database.yml',
            'config/secrets.json',
            '.env',
            '.env.local',
            'docker-compose.yml',
            'package.json',
            'requirements.txt',
            'application.properties',
            'settings.py',
            'config.php',
            'appsettings.json',
            'credentials.json',
            'keys.pem',
            'private.key',
            'id_rsa',
            'backup.sql',
            'deploy.sh',
            'README.md'
        ];
        
        return mockFiles.filter(file => {
            // Check if file should be excluded
            for (const pattern of this.excludePatterns) {
                if (pattern.test(file)) return false;
            }
            
            // Check if file extension should be scanned
            const ext = file.substring(file.lastIndexOf('.'));
            return this.scanExtensions.includes(ext) || file.startsWith('.env');
        });
    }

    async scanFile(filePath) {
        try {
            const content = await this.readFile(filePath);
            if (!content) return;
            
            this.scannedFiles.push(filePath);
            
            // Scan for each secret pattern
            for (const [secretType, config] of Object.entries(this.secretPatterns)) {
                const matches = content.match(config.pattern);
                
                if (matches) {
                    for (const match of matches) {
                        // Skip if it's a false positive
                        if (this.isFalsePositive(match, content, config)) continue;
                        
                        // Check entropy if required
                        if (config.entropy && !this.hasHighEntropy(match)) continue;
                        
                        // Check context if required
                        if (config.context && !this.hasContext(match, content, config.context)) continue;
                        
                        const lineNumber = this.getLineNumber(content, match);
                        
                        this.addVulnerability({
                            type: 'Hardcoded Secret',
                            secretType: secretType,
                            severity: config.severity,
                            file: filePath,
                            line: lineNumber,
                            description: `${config.description} in ${filePath}`,
                            evidence: this.maskSecret(match),
                            recommendation: 'Remove hardcoded secret and use environment variables or secure secret management'
                        });
                    }
                }
            }
            
            // Additional checks for this file
            await this.checkFileSpecificPatterns(filePath, content);
            
        } catch (error) {
            console.error(`Error scanning file ${filePath}:`, error);
        }
    }

    async checkFileSpecificPatterns(filePath, content) {
        // Check for .env files with suspicious content
        if (filePath.includes('.env')) {
            await this.scanEnvFile(filePath, content);
        }
        
        // Check for configuration files
        if (filePath.includes('config') || filePath.includes('settings')) {
            await this.scanConfigFile(filePath, content);
        }
        
        // Check for database files
        if (filePath.includes('database') || filePath.includes('db')) {
            await this.scanDatabaseFile(filePath, content);
        }
        
        // Check for deployment scripts
        if (filePath.includes('deploy') || filePath.includes('script')) {
            await this.scanDeploymentFile(filePath, content);
        }
    }

    async scanEnvFile(filePath, content) {
        const lines = content.split('\n');
        
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line || line.startsWith('#')) continue;
            
            const [key, value] = line.split('=', 2);
            if (!key || !value) continue;
            
            // Check for suspicious environment variable names
            const suspiciousKeys = [
                'password', 'passwd', 'pwd', 'secret', 'key', 'token',
                'api_key', 'apikey', 'auth_token', 'access_token',
                'private_key', 'client_secret', 'database_password'
            ];
            
            const keyLower = key.toLowerCase();
            for (const suspicious of suspiciousKeys) {
                if (keyLower.includes(suspicious)) {
                    // Check if value looks like a real secret (not placeholder)
                    if (!this.isPlaceholder(value)) {
                        this.addVulnerability({
                            type: 'Environment Variable Secret',
                            severity: 'High',
                            file: filePath,
                            line: i + 1,
                            description: `Suspicious environment variable: ${key}`,
                            evidence: `${key}=${this.maskSecret(value)}`,
                            recommendation: 'Use secure secret management instead of .env files for production'
                        });
                    }
                }
            }
        }
    }

    async scanConfigFile(filePath, content) {
        // Look for configuration-specific patterns
        const configPatterns = [
            {
                pattern: /database.*password.*['"]\w+['"]/gi,
                type: 'Database Password in Config',
                severity: 'Critical'
            },
            {
                pattern: /smtp.*password.*['"]\w+['"]/gi,
                type: 'SMTP Password in Config',
                severity: 'High'
            },
            {
                pattern: /admin.*password.*['"]\w+['"]/gi,
                type: 'Admin Password in Config',
                severity: 'Critical'
            }
        ];
        
        for (const pattern of configPatterns) {
            const matches = content.match(pattern.pattern);
            if (matches) {
                for (const match of matches) {
                    const lineNumber = this.getLineNumber(content, match);
                    this.addVulnerability({
                        type: 'Configuration Secret',
                        severity: pattern.severity,
                        file: filePath,
                        line: lineNumber,
                        description: `${pattern.type} in configuration file`,
                        evidence: this.maskSecret(match),
                        recommendation: 'Move credentials to secure configuration management'
                    });
                }
            }
        }
    }

    async scanDatabaseFile(filePath, content) {
        // Look for database connection strings and credentials
        const dbPatterns = [
            /CREATE USER.*IDENTIFIED BY.*['"]\w+['"]/gi,
            /GRANT.*TO.*IDENTIFIED BY.*['"]\w+['"]/gi,
            /INSERT INTO.*users.*password.*['"]\w+['"]/gi,
            /UPDATE.*users.*password.*['"]\w+['"]/gi
        ];
        
        for (const pattern of dbPatterns) {
            const matches = content.match(pattern);
            if (matches) {
                for (const match of matches) {
                    const lineNumber = this.getLineNumber(content, match);
                    this.addVulnerability({
                        type: 'Database Credential',
                        severity: 'High',
                        file: filePath,
                        line: lineNumber,
                        description: 'Database credentials in SQL file',
                        evidence: this.maskSecret(match),
                        recommendation: 'Remove hardcoded credentials from database scripts'
                    });
                }
            }
        }
    }

    async scanDeploymentFile(filePath, content) {
        // Look for deployment-specific secrets
        const deployPatterns = [
            /export.*[A-Z_]*PASSWORD.*=.*['"]\w+['"]/gi,
            /export.*[A-Z_]*SECRET.*=.*['"]\w+['"]/gi,
            /export.*[A-Z_]*KEY.*=.*['"]\w+['"]/gi,
            /docker.*-e.*[A-Z_]*PASSWORD.*=.*\w+/gi,
            /kubectl.*secret.*--from-literal.*=.*\w+/gi
        ];
        
        for (const pattern of deployPatterns) {
            const matches = content.match(pattern);
            if (matches) {
                for (const match of matches) {
                    const lineNumber = this.getLineNumber(content, match);
                    this.addVulnerability({
                        type: 'Deployment Secret',
                        severity: 'High',
                        file: filePath,
                        line: lineNumber,
                        description: 'Hardcoded secret in deployment script',
                        evidence: this.maskSecret(match),
                        recommendation: 'Use secure deployment practices with secret injection'
                    });
                }
            }
        }
    }

    async scanEnvironmentVariables() {
        // Simulate scanning environment variables
        const mockEnvVars = {
            'DATABASE_PASSWORD': 'super_secret_password_123',
            'API_KEY': 'EXAMPLE_API_KEY_HERE',
            'JWT_SECRET': 'my_jwt_secret_key_2023',
            'STRIPE_SECRET_KEY': 'EXAMPLE_STRIPE_KEY_HERE',
            'AWS_SECRET_ACCESS_KEY': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        };
        
        for (const [key, value] of Object.entries(mockEnvVars)) {
            if (!this.isPlaceholder(value)) {
                this.addVulnerability({
                    type: 'Environment Variable Secret',
                    severity: 'Medium',
                    description: `Suspicious environment variable: ${key}`,
                    evidence: `${key}=${this.maskSecret(value)}`,
                    recommendation: 'Review environment variable security and use proper secret management'
                });
            }
        }
    }

    async scanConfigurationFiles() {
        // Scan common configuration file patterns
        const configFiles = [
            { name: 'aws/credentials', content: '[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' },
            { name: '.gitconfig', content: '[user]\n\tname = John Doe\n\temail = john@example.com\n[credential]\n\thelper = store\n\tusername = john\n\tpassword = secret123' },
            { name: 'docker-compose.yml', content: 'services:\n  db:\n    environment:\n      MYSQL_ROOT_PASSWORD: rootpassword123\n      MYSQL_PASSWORD: userpassword456' }
        ];
        
        for (const configFile of configFiles) {
            await this.scanFile(configFile.name);
        }
    }

    async analyzeFindings() {
        // Group findings by type
        const findingsByType = {};
        for (const vuln of this.vulnerabilities) {
            const type = vuln.secretType || vuln.type;
            if (!findingsByType[type]) {
                findingsByType[type] = [];
            }
            findingsByType[type].push(vuln);
        }
        
        // Check for patterns that might indicate a compromised system
        const criticalPatterns = [
            'AWS Access Key',
            'AWS Secret Key',
            'Private Key',
            'SSH Private Key',
            'Stripe API Key'
        ];
        
        const criticalFindings = criticalPatterns.filter(pattern => findingsByType[pattern]);
        
        if (criticalFindings.length > 0) {
            this.addVulnerability({
                type: 'Critical Secret Exposure',
                severity: 'Critical',
                description: 'Multiple critical secrets detected in codebase',
                evidence: `Critical secret types found: ${criticalFindings.join(', ')}`,
                recommendation: 'Immediate action required: rotate all exposed credentials and implement proper secret management'
            });
        }
        
        // Check for secret sprawl (same secret in multiple places)
        await this.checkSecretSprawl();
        
        this.scanResults.summary = {
            totalSecrets: this.vulnerabilities.length,
            criticalSecrets: this.vulnerabilities.filter(v => v.severity === 'Critical').length,
            filesScanned: this.scannedFiles.length,
            secretTypes: Object.keys(findingsByType).length
        };
    }

    async checkSecretSprawl() {
        // Group secrets by their masked value to find duplicates
        const secretGroups = {};
        
        for (const vuln of this.vulnerabilities) {
            if (vuln.evidence) {
                const maskedSecret = vuln.evidence;
                if (!secretGroups[maskedSecret]) {
                    secretGroups[maskedSecret] = [];
                }
                secretGroups[maskedSecret].push(vuln);
            }
        }
        
        // Find secrets that appear in multiple places
        for (const [secret, occurrences] of Object.entries(secretGroups)) {
            if (occurrences.length > 1) {
                const files = occurrences.map(o => o.file).filter(f => f).join(', ');
                this.addVulnerability({
                    type: 'Secret Sprawl',
                    severity: 'High',
                    description: 'Same secret found in multiple locations',
                    evidence: `Secret appears in: ${files}`,
                    recommendation: 'Centralize secret management and remove duplicate secrets'
                });
            }
        }
    }

    // Helper methods
    async readFile(filename) {
        // Simulate file reading with mock content
        const mockFileContents = {
            'src/config.js': `
const config = {
    database: {
        host: 'localhost',
        user: 'admin',
        password: 'super_secret_password_123',
        port: 3306
    },
    apiKey: 'EXAMPLE_API_KEY_HERE',
    jwtSecret: 'my_jwt_secret_key_2023_very_long',
    stripeKey: 'EXAMPLE_STRIPE_KEY_HERE'
};
module.exports = config;`,
            
            'src/auth.js': `
const jwt = require('jsonwebtoken');
const SECRET = 'hardcoded_jwt_secret_123';
const AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

function generateToken(user) {
    return jwt.sign(user, SECRET);
}`,
            
            '.env': `
DATABASE_URL=postgresql://user:password123@localhost:5432/mydb
API_KEY=EXAMPLE_API_KEY_HERE
JWT_SECRET=my_super_secret_jwt_key
STRIPE_SECRET_KEY=EXAMPLE_STRIPE_KEY_HERE
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef12345678
`,
            
            'config/database.yml': `
production:
  adapter: postgresql
  database: myapp_production
  username: postgres
  password: production_password_123
  host: localhost
  port: 5432`,
            
            'keys.pem': `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB
wQNneCjmrSueCiDHVWHdGP91brVNNt6fdmzAzFvW0XnI0YKBOUtVUnMjP/L6M4wX
-----END PRIVATE KEY-----`,
            
            'docker-compose.yml': `
version: '3.8'
services:
  db:
    image: postgres:13
    environment:
      POSTGRES_PASSWORD: docker_postgres_password_123
      POSTGRES_USER: postgres
      POSTGRES_DB: myapp
  redis:
    image: redis:6
    command: redis-server --requirepass redis_password_456`,
            
            'backup.sql': `
CREATE USER 'backup_user'@'localhost' IDENTIFIED BY 'backup_password_789';
GRANT SELECT ON *.* TO 'backup_user'@'localhost';
INSERT INTO users (username, password) VALUES ('admin', 'admin_password_123');`,
            
            'deploy.sh': `
#!/bin/bash
export DATABASE_PASSWORD="deployment_password_456"
export API_SECRET="deployment_api_secret_789"
kubectl create secret generic app-secrets --from-literal=db-password=k8s_secret_123`,
            
            'README.md': `
# My App

## Configuration

Set the following environment variables:
- DATABASE_PASSWORD=your_password_here
- API_KEY=your_api_key_here

## Testing

Use test credentials:
- Username: test@example.com
- Password: test_password_123 (don't use in production!)

## API Keys

Development API key: EXAMPLE_DEV_KEY_HERE
Production API key: EXAMPLE_PROD_KEY_HERE (example only!)
`
        };
        
        return mockFileContents[filename] || null;
    }

    isFalsePositive(match, content, config) {
        // Common false positive patterns
        const falsePositives = [
            /example/i,
            /test/i,
            /demo/i,
            /placeholder/i,
            /your_.*_here/i,
            /replace.*with/i,
            /\*{3,}/,
            /x{3,}/i,
            /\.{3,}/,
            /123456/,
            /password/i,
            /secret/i,
            /key/i
        ];
        
        // Check if the match itself is a false positive
        for (const fp of falsePositives) {
            if (fp.test(match)) return true;
        }
        
        // Check surrounding context for false positive indicators
        const matchIndex = content.indexOf(match);
        const contextStart = Math.max(0, matchIndex - 100);
        const contextEnd = Math.min(content.length, matchIndex + match.length + 100);
        const context = content.substring(contextStart, contextEnd).toLowerCase();
        
        const contextFalsePositives = [
            'example',
            'test',
            'demo',
            'placeholder',
            'replace',
            'your_key_here',
            'todo',
            'fixme',
            'comment'
        ];
        
        for (const fp of contextFalsePositives) {
            if (context.includes(fp)) return true;
        }
        
        return false;
    }

    hasHighEntropy(str) {
        // Calculate Shannon entropy
        const chars = {};
        for (const char of str) {
            chars[char] = (chars[char] || 0) + 1;
        }
        
        let entropy = 0;
        const length = str.length;
        
        for (const count of Object.values(chars)) {
            const probability = count / length;
            entropy -= probability * Math.log2(probability);
        }
        
        return entropy > 4.5; // Threshold for high entropy
    }

    hasContext(match, content, contextWords) {
        const matchIndex = content.indexOf(match);
        const contextStart = Math.max(0, matchIndex - 200);
        const contextEnd = Math.min(content.length, matchIndex + match.length + 200);
        const context = content.substring(contextStart, contextEnd).toLowerCase();
        
        return contextWords.some(word => context.includes(word.toLowerCase()));
    }

    isPlaceholder(value) {
        const placeholderPatterns = [
            /^(your_.*_here|replace.*|example.*|test.*|demo.*|placeholder.*)$/i,
            /^[x*]{3,}$/,
            /^\.{3,}$/,
            /^(password|secret|key|token)$/i,
            /^(123456|password123|secret123)$/i,
            /^[a-z]{1,8}$/i // Very simple passwords
        ];
        
        return placeholderPatterns.some(pattern => pattern.test(value.trim()));
    }

    getLineNumber(content, match) {
        const beforeMatch = content.substring(0, content.indexOf(match));
        return beforeMatch.split('\n').length;
    }

    maskSecret(secret) {
        if (secret.length <= 8) {
            return '*'.repeat(secret.length);
        }
        
        const visibleChars = 4;
        const start = secret.substring(0, visibleChars);
        const end = secret.substring(secret.length - visibleChars);
        const masked = '*'.repeat(Math.max(0, secret.length - (visibleChars * 2)));
        
        return start + masked + end;
    }

    addVulnerability(vuln) {
        this.vulnerabilities.push({
            ...vuln,
            timestamp: new Date().toISOString(),
            id: `SECRET-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            scanType: 'Secret'
        });
    }

    generateReport() {
        const severityCounts = this.vulnerabilities.reduce((acc, vuln) => {
            acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
            return acc;
        }, {});

        const secretTypeCounts = {};
        for (const vuln of this.vulnerabilities) {
            const type = vuln.secretType || vuln.type;
            secretTypeCounts[type] = (secretTypeCounts[type] || 0) + 1;
        }

        return {
            summary: {
                totalSecrets: this.vulnerabilities.length,
                severityBreakdown: severityCounts,
                secretTypeBreakdown: secretTypeCounts,
                filesScanned: this.scannedFiles.length,
                scanTimestamp: new Date().toISOString()
            },
            vulnerabilities: this.vulnerabilities,
            scannedFiles: this.scannedFiles,
            scanResults: this.scanResults,
            recommendations: this.generateRecommendations()
        };
    }

    generateRecommendations() {
        const recommendations = [];
        
        if (this.vulnerabilities.some(v => v.severity === 'Critical')) {
            recommendations.push({
                category: 'Critical Secret Exposure',
                priority: 'Critical',
                actions: [
                    'Immediately rotate all exposed credentials',
                    'Remove hardcoded secrets from codebase',
                    'Implement proper secret management (HashiCorp Vault, AWS Secrets Manager)',
                    'Add secret scanning to CI/CD pipeline',
                    'Review git history for exposed secrets'
                ]
            });
        }
        
        if (this.vulnerabilities.some(v => v.type.includes('Environment'))) {
            recommendations.push({
                category: 'Environment Variable Security',
                priority: 'High',
                actions: [
                    'Use secure secret injection for production environments',
                    'Avoid committing .env files to version control',
                    'Use different secrets for different environments',
                    'Implement secret rotation policies'
                ]
            });
        }
        
        if (this.vulnerabilities.some(v => v.type.includes('Sprawl'))) {
            recommendations.push({
                category: 'Secret Management',
                priority: 'Medium',
                actions: [
                    'Centralize secret management',
                    'Eliminate duplicate secrets across the codebase',
                    'Implement secret versioning and rotation',
                    'Use secret management tools and services'
                ]
            });
        }
        
        recommendations.push({
            category: 'Prevention',
            priority: 'Medium',
            actions: [
                'Add pre-commit hooks for secret detection',
                'Train developers on secure coding practices',
                'Implement code review processes',
                'Use secret scanning tools in CI/CD',
                'Regular security audits and penetration testing'
            ]
        });
        
        return recommendations;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecretScanner;
}