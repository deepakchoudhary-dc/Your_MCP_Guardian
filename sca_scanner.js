/**
 * Software Composition Analysis (SCA) Scanner
 * Scans for vulnerabilities in third-party dependencies
 */

class SCAScanner {
    constructor(projectPath = '.') {
        this.projectPath = projectPath;
        this.vulnerabilities = [];
        this.dependencies = {};
        this.scanResults = {};
        
        // Known vulnerability database (simplified for demo)
        this.vulnerabilityDB = {
            'lodash': {
                '4.17.20': [
                    {
                        id: 'CVE-2021-23337',
                        severity: 'High',
                        description: 'Command injection in lodash',
                        affectedVersions: '< 4.17.21',
                        fixedVersion: '4.17.21'
                    }
                ],
                '4.17.15': [
                    {
                        id: 'CVE-2020-8203',
                        severity: 'High',
                        description: 'Prototype pollution in lodash',
                        affectedVersions: '< 4.17.19',
                        fixedVersion: '4.17.19'
                    }
                ]
            },
            'express': {
                '4.16.0': [
                    {
                        id: 'CVE-2022-24999',
                        severity: 'Medium',
                        description: 'Open redirect in express',
                        affectedVersions: '< 4.17.3',
                        fixedVersion: '4.17.3'
                    }
                ]
            },
            'axios': {
                '0.21.0': [
                    {
                        id: 'CVE-2021-3749',
                        severity: 'Medium',
                        description: 'Regular expression denial of service',
                        affectedVersions: '< 0.21.2',
                        fixedVersion: '0.21.2'
                    }
                ]
            },
            'moment': {
                '2.29.1': [
                    {
                        id: 'CVE-2022-24785',
                        severity: 'High',
                        description: 'Path traversal in moment.js',
                        affectedVersions: '< 2.29.2',
                        fixedVersion: '2.29.2'
                    }
                ]
            },
            'node-fetch': {
                '2.6.6': [
                    {
                        id: 'CVE-2022-0235',
                        severity: 'Medium',
                        description: 'Exposure of sensitive information',
                        affectedVersions: '< 2.6.7',
                        fixedVersion: '2.6.7'
                    }
                ]
            },
            'ws': {
                '7.4.5': [
                    {
                        id: 'CVE-2021-32640',
                        severity: 'Medium',
                        description: 'ReDoS vulnerability in ws',
                        affectedVersions: '< 7.4.6',
                        fixedVersion: '7.4.6'
                    }
                ]
            },
            'minimist': {
                '1.2.5': [
                    {
                        id: 'CVE-2021-44906',
                        severity: 'Critical',
                        description: 'Prototype pollution in minimist',
                        affectedVersions: '< 1.2.6',
                        fixedVersion: '1.2.6'
                    }
                ]
            },
            'serialize-javascript': {
                '3.1.0': [
                    {
                        id: 'CVE-2020-7660',
                        severity: 'High',
                        description: 'XSS via unsafe characters in serialized regular expressions',
                        affectedVersions: '< 4.0.0',
                        fixedVersion: '4.0.0'
                    }
                ]
            },
            'yargs-parser': {
                '18.1.3': [
                    {
                        id: 'CVE-2020-7608',
                        severity: 'Medium',
                        description: 'Prototype pollution in yargs-parser',
                        affectedVersions: '< 18.1.4',
                        fixedVersion: '18.1.4'
                    }
                ]
            },
            'handlebars': {
                '4.7.6': [
                    {
                        id: 'CVE-2021-23369',
                        severity: 'Medium',
                        description: 'Remote code execution in handlebars',
                        affectedVersions: '< 4.7.7',
                        fixedVersion: '4.7.7'
                    }
                ]
            }
        };
    }

    async performSCAScan() {
        console.log('📦 Starting Software Composition Analysis (SCA)...');
        
        try {
            // Scan different dependency files
            await Promise.all([
                this.scanPackageJson(),
                this.scanPackageLock(),
                this.scanRequirementsTxt(),
                this.scanPipfileLock(),
                this.scanComposerJson(),
                this.scanGemfile(),
                this.scanGoMod(),
                this.scanCargoToml(),
                this.scanPomXml(),
                this.scanGradleBuild()
            ]);

            // Analyze dependencies for vulnerabilities
            await this.analyzeDependencies();
            
            // Check for outdated dependencies
            await this.checkOutdatedDependencies();
            
            // Check for license compliance
            await this.checkLicenseCompliance();
            
            // Generate dependency tree analysis
            await this.analyzeDependencyTree();

            return {
                vulnerabilities: this.vulnerabilities,
                dependencies: this.dependencies,
                scanResults: this.scanResults
            };

        } catch (error) {
            console.error('SCA scan failed:', error);
            this.addVulnerability({
                type: 'SCA Scan Error',
                severity: 'Medium',
                description: 'Software composition analysis encountered errors',
                evidence: error.message,
                recommendation: 'Review project structure and dependency files'
            });
            return { vulnerabilities: this.vulnerabilities, scanResults: this.scanResults };
        }
    }

    async scanPackageJson() {
        try {
            const packageJsonContent = await this.readFile('package.json');
            if (!packageJsonContent) return;

            const packageJson = JSON.parse(packageJsonContent);
            
            // Extract dependencies
            const dependencies = {
                ...packageJson.dependencies,
                ...packageJson.devDependencies,
                ...packageJson.peerDependencies,
                ...packageJson.optionalDependencies
            };

            this.dependencies.npm = dependencies;
            this.scanResults.packageJson = {
                found: true,
                dependencyCount: Object.keys(dependencies).length,
                hasLockFile: await this.fileExists('package-lock.json') || await this.fileExists('yarn.lock')
            };

            // Check for suspicious packages
            await this.checkSuspiciousPackages(dependencies, 'npm');
            
            // Check for deprecated packages
            await this.checkDeprecatedPackages(dependencies, 'npm');

        } catch (error) {
            console.error('Error scanning package.json:', error);
        }
    }

    async scanPackageLock() {
        try {
            const lockContent = await this.readFile('package-lock.json');
            if (!lockContent) return;

            const lockJson = JSON.parse(lockContent);
            
            // Extract all dependencies including transitive ones
            const allDependencies = {};
            
            if (lockJson.dependencies) {
                this.extractDependenciesFromLock(lockJson.dependencies, allDependencies);
            }
            
            if (lockJson.packages) {
                Object.entries(lockJson.packages).forEach(([path, pkg]) => {
                    if (path && path !== '' && pkg.version) {
                        const name = path.replace('node_modules/', '');
                        allDependencies[name] = pkg.version;
                    }
                });
            }

            this.dependencies.npmLock = allDependencies;
            this.scanResults.packageLock = {
                found: true,
                totalDependencies: Object.keys(allDependencies).length,
                lockfileVersion: lockJson.lockfileVersion
            };

        } catch (error) {
            console.error('Error scanning package-lock.json:', error);
        }
    }

    async scanRequirementsTxt() {
        try {
            const requirementsContent = await this.readFile('requirements.txt');
            if (!requirementsContent) return;

            const dependencies = {};
            const lines = requirementsContent.split('\n');
            
            for (const line of lines) {
                const trimmed = line.trim();
                if (trimmed && !trimmed.startsWith('#')) {
                    const match = trimmed.match(/^([a-zA-Z0-9\-_.]+)([>=<~!]+)(.+)$/);
                    if (match) {
                        dependencies[match[1]] = match[3];
                    }
                }
            }

            this.dependencies.python = dependencies;
            this.scanResults.requirementsTxt = {
                found: true,
                dependencyCount: Object.keys(dependencies).length
            };

            // Check for known vulnerable Python packages
            await this.checkPythonVulnerabilities(dependencies);

        } catch (error) {
            console.error('Error scanning requirements.txt:', error);
        }
    }

    async scanPipfileLock() {
        try {
            const pipfileLockContent = await this.readFile('Pipfile.lock');
            if (!pipfileLockContent) return;

            const pipfileLock = JSON.parse(pipfileLockContent);
            const dependencies = {};
            
            if (pipfileLock.default) {
                Object.entries(pipfileLock.default).forEach(([name, info]) => {
                    dependencies[name] = info.version?.replace('==', '') || 'unknown';
                });
            }
            
            if (pipfileLock.develop) {
                Object.entries(pipfileLock.develop).forEach(([name, info]) => {
                    dependencies[name] = info.version?.replace('==', '') || 'unknown';
                });
            }

            this.dependencies.pipenv = dependencies;
            this.scanResults.pipfileLock = {
                found: true,
                dependencyCount: Object.keys(dependencies).length
            };

        } catch (error) {
            console.error('Error scanning Pipfile.lock:', error);
        }
    }

    async scanComposerJson() {
        try {
            const composerContent = await this.readFile('composer.json');
            if (!composerContent) return;

            const composer = JSON.parse(composerContent);
            const dependencies = {
                ...composer.require,
                ...composer['require-dev']
            };

            this.dependencies.php = dependencies;
            this.scanResults.composerJson = {
                found: true,
                dependencyCount: Object.keys(dependencies).length
            };

            // Check for known vulnerable PHP packages
            await this.checkPhpVulnerabilities(dependencies);

        } catch (error) {
            console.error('Error scanning composer.json:', error);
        }
    }

    async scanGemfile() {
        try {
            const gemfileContent = await this.readFile('Gemfile');
            if (!gemfileContent) return;

            const dependencies = {};
            const lines = gemfileContent.split('\n');
            
            for (const line of lines) {
                const match = line.match(/gem\s+['"]([^'"]+)['"](?:,\s*['"]([^'"]+)['"])?/);
                if (match) {
                    dependencies[match[1]] = match[2] || 'latest';
                }
            }

            this.dependencies.ruby = dependencies;
            this.scanResults.gemfile = {
                found: true,
                dependencyCount: Object.keys(dependencies).length
            };

        } catch (error) {
            console.error('Error scanning Gemfile:', error);
        }
    }

    async scanGoMod() {
        try {
            const goModContent = await this.readFile('go.mod');
            if (!goModContent) return;

            const dependencies = {};
            const lines = goModContent.split('\n');
            
            for (const line of lines) {
                const match = line.trim().match(/^([^\s]+)\s+v(.+)$/);
                if (match && !match[1].startsWith('//')) {
                    dependencies[match[1]] = match[2];
                }
            }

            this.dependencies.go = dependencies;
            this.scanResults.goMod = {
                found: true,
                dependencyCount: Object.keys(dependencies).length
            };

        } catch (error) {
            console.error('Error scanning go.mod:', error);
        }
    }

    async scanCargoToml() {
        try {
            const cargoContent = await this.readFile('Cargo.toml');
            if (!cargoContent) return;

            // Simple TOML parsing for dependencies section
            const dependencies = {};
            const lines = cargoContent.split('\n');
            let inDependencies = false;
            
            for (const line of lines) {
                if (line.trim() === '[dependencies]') {
                    inDependencies = true;
                    continue;
                }
                if (line.trim().startsWith('[') && line.trim() !== '[dependencies]') {
                    inDependencies = false;
                    continue;
                }
                if (inDependencies && line.includes('=')) {
                    const match = line.match(/^([^=]+)=\s*"([^"]+)"/);
                    if (match) {
                        dependencies[match[1].trim()] = match[2];
                    }
                }
            }

            this.dependencies.rust = dependencies;
            this.scanResults.cargoToml = {
                found: true,
                dependencyCount: Object.keys(dependencies).length
            };

        } catch (error) {
            console.error('Error scanning Cargo.toml:', error);
        }
    }

    async scanPomXml() {
        try {
            const pomContent = await this.readFile('pom.xml');
            if (!pomContent) return;

            // Simple XML parsing for Maven dependencies
            const dependencies = {};
            const dependencyMatches = pomContent.match(/<dependency>[\s\S]*?<\/dependency>/g) || [];
            
            for (const dep of dependencyMatches) {
                const groupMatch = dep.match(/<groupId>([^<]+)<\/groupId>/);
                const artifactMatch = dep.match(/<artifactId>([^<]+)<\/artifactId>/);
                const versionMatch = dep.match(/<version>([^<]+)<\/version>/);
                
                if (groupMatch && artifactMatch) {
                    const name = `${groupMatch[1]}:${artifactMatch[1]}`;
                    const version = versionMatch ? versionMatch[1] : 'unknown';
                    dependencies[name] = version;
                }
            }

            this.dependencies.java = dependencies;
            this.scanResults.pomXml = {
                found: true,
                dependencyCount: Object.keys(dependencies).length
            };

        } catch (error) {
            console.error('Error scanning pom.xml:', error);
        }
    }

    async scanGradleBuild() {
        try {
            const gradleContent = await this.readFile('build.gradle');
            if (!gradleContent) return;

            const dependencies = {};
            const lines = gradleContent.split('\n');
            
            for (const line of lines) {
                // Match various Gradle dependency formats
                const matches = [
                    line.match(/implementation\s+['"]([^'"]+):([^'"]+):([^'"]+)['"]/),
                    line.match(/compile\s+['"]([^'"]+):([^'"]+):([^'"]+)['"]/),
                    line.match(/api\s+['"]([^'"]+):([^'"]+):([^'"]+)['"]/),
                    line.match(/testImplementation\s+['"]([^'"]+):([^'"]+):([^'"]+)['"]/)
                ];
                
                for (const match of matches) {
                    if (match) {
                        const name = `${match[1]}:${match[2]}`;
                        dependencies[name] = match[3];
                        break;
                    }
                }
            }

            this.dependencies.gradle = dependencies;
            this.scanResults.gradleBuild = {
                found: true,
                dependencyCount: Object.keys(dependencies).length
            };

        } catch (error) {
            console.error('Error scanning build.gradle:', error);
        }
    }

    async analyzeDependencies() {
        console.log('Analyzing dependencies for known vulnerabilities...');
        
        // Analyze each dependency type
        for (const [ecosystem, deps] of Object.entries(this.dependencies)) {
            if (!deps || typeof deps !== 'object') continue;
            
            for (const [packageName, version] of Object.entries(deps)) {
                await this.checkPackageVulnerabilities(packageName, version, ecosystem);
            }
        }
    }

    async checkPackageVulnerabilities(packageName, version, ecosystem) {
        // Check against our vulnerability database
        if (this.vulnerabilityDB[packageName]) {
            const packageVulns = this.vulnerabilityDB[packageName];
            
            for (const [vulnVersion, vulnerabilities] of Object.entries(packageVulns)) {
                if (this.isVersionAffected(version, vulnVersion)) {
                    for (const vuln of vulnerabilities) {
                        this.addVulnerability({
                            type: 'Vulnerable Dependency',
                            severity: vuln.severity,
                            package: packageName,
                            version: version,
                            ecosystem: ecosystem,
                            description: `${packageName}@${version} has known vulnerability: ${vuln.description}`,
                            evidence: `CVE: ${vuln.id}, Affected versions: ${vuln.affectedVersions}`,
                            recommendation: `Update ${packageName} to version ${vuln.fixedVersion} or later`
                        });
                    }
                }
            }
        }
        
        // Check for other vulnerability patterns
        await this.checkPackagePatterns(packageName, version, ecosystem);
    }

    async checkPackagePatterns(packageName, version, ecosystem) {
        // Check for suspicious package names
        const suspiciousPatterns = [
            /^[a-z]{1,3}$/,  // Very short names
            /\d{10,}/,       // Long numbers
            /[A-Z]{5,}/,     // All caps
            /test|demo|example/i,  // Test packages
            /hack|exploit|malware/i  // Malicious keywords
        ];
        
        for (const pattern of suspiciousPatterns) {
            if (pattern.test(packageName)) {
                this.addVulnerability({
                    type: 'Suspicious Package Name',
                    severity: 'Medium',
                    package: packageName,
                    version: version,
                    ecosystem: ecosystem,
                    description: `Package name "${packageName}" matches suspicious pattern`,
                    evidence: `Pattern: ${pattern.source}`,
                    recommendation: 'Review package legitimacy and consider alternatives'
                });
            }
        }
        
        // Check for typosquatting
        const popularPackages = {
            npm: ['react', 'lodash', 'express', 'axios', 'moment', 'webpack'],
            python: ['requests', 'numpy', 'pandas', 'flask', 'django', 'tensorflow'],
            php: ['symfony', 'laravel', 'doctrine', 'monolog', 'guzzle'],
            java: ['spring', 'hibernate', 'junit', 'jackson', 'apache'],
            ruby: ['rails', 'devise', 'rspec', 'nokogiri', 'sidekiq']
        };
        
        const ecosystemPackages = popularPackages[ecosystem] || [];
        for (const popular of ecosystemPackages) {
            if (this.isTyposquatting(packageName, popular)) {
                this.addVulnerability({
                    type: 'Potential Typosquatting',
                    severity: 'High',
                    package: packageName,
                    version: version,
                    ecosystem: ecosystem,
                    description: `Package "${packageName}" may be typosquatting "${popular}"`,
                    evidence: `Similar to popular package: ${popular}`,
                    recommendation: `Verify package legitimacy. Consider using "${popular}" instead.`
                });
            }
        }
    }

    async checkOutdatedDependencies() {
        console.log('Checking for outdated dependencies...');
        
        // Simulate checking for outdated packages
        for (const [ecosystem, deps] of Object.entries(this.dependencies)) {
            if (!deps || typeof deps !== 'object') continue;
            
            for (const [packageName, version] of Object.entries(deps)) {
                // Simulate version checking (in real implementation, would call registry APIs)
                const isOutdated = Math.random() > 0.7; // 30% chance of being outdated
                
                if (isOutdated) {
                    const latestVersion = this.generateNewerVersion(version);
                    this.addVulnerability({
                        type: 'Outdated Dependency',
                        severity: 'Low',
                        package: packageName,
                        version: version,
                        ecosystem: ecosystem,
                        description: `${packageName}@${version} is outdated`,
                        evidence: `Current: ${version}, Latest: ${latestVersion}`,
                        recommendation: `Update ${packageName} to version ${latestVersion}`
                    });
                }
            }
        }
    }

    async checkLicenseCompliance() {
        console.log('Checking license compliance...');
        
        const problematicLicenses = [
            'GPL-3.0',
            'AGPL-3.0',
            'SSPL-1.0',
            'Commons Clause',
            'BUSL-1.1'
        ];
        
        // Simulate license checking
        for (const [ecosystem, deps] of Object.entries(this.dependencies)) {
            if (!deps || typeof deps !== 'object') continue;
            
            for (const [packageName, version] of Object.entries(deps)) {
                // Simulate license detection
                const hasProblematicLicense = Math.random() > 0.9; // 10% chance
                
                if (hasProblematicLicense) {
                    const license = problematicLicenses[Math.floor(Math.random() * problematicLicenses.length)];
                    this.addVulnerability({
                        type: 'License Compliance Issue',
                        severity: 'Medium',
                        package: packageName,
                        version: version,
                        ecosystem: ecosystem,
                        description: `${packageName}@${version} uses restrictive license: ${license}`,
                        evidence: `License: ${license}`,
                        recommendation: 'Review license compatibility with your project requirements'
                    });
                }
            }
        }
    }

    async analyzeDependencyTree() {
        console.log('Analyzing dependency tree for conflicts...');
        
        // Check for version conflicts
        const allPackages = {};
        
        for (const [ecosystem, deps] of Object.entries(this.dependencies)) {
            if (!deps || typeof deps !== 'object') continue;
            
            for (const [packageName, version] of Object.entries(deps)) {
                if (!allPackages[packageName]) {
                    allPackages[packageName] = [];
                }
                allPackages[packageName].push({ version, ecosystem });
            }
        }
        
        // Find packages with multiple versions
        for (const [packageName, versions] of Object.entries(allPackages)) {
            if (versions.length > 1) {
                const uniqueVersions = [...new Set(versions.map(v => v.version))];
                if (uniqueVersions.length > 1) {
                    this.addVulnerability({
                        type: 'Dependency Version Conflict',
                        severity: 'Medium',
                        package: packageName,
                        description: `Multiple versions of ${packageName} detected`,
                        evidence: `Versions: ${uniqueVersions.join(', ')}`,
                        recommendation: 'Resolve version conflicts to ensure consistent behavior'
                    });
                }
            }
        }
        
        // Check for circular dependencies (simplified)
        this.scanResults.dependencyTree = {
            totalUniquePackages: Object.keys(allPackages).length,
            conflictingPackages: Object.values(allPackages).filter(v => v.length > 1).length
        };
    }

    async checkSuspiciousPackages(dependencies, ecosystem) {
        const suspiciousKeywords = [
            'bitcoin', 'crypto', 'wallet', 'miner', 'mining',
            'hack', 'exploit', 'backdoor', 'malware', 'virus',
            'keylogger', 'stealer', 'trojan', 'rootkit'
        ];
        
        for (const [packageName, version] of Object.entries(dependencies)) {
            for (const keyword of suspiciousKeywords) {
                if (packageName.toLowerCase().includes(keyword)) {
                    this.addVulnerability({
                        type: 'Suspicious Package',
                        severity: 'High',
                        package: packageName,
                        version: version,
                        ecosystem: ecosystem,
                        description: `Package contains suspicious keyword: ${keyword}`,
                        evidence: `Package name: ${packageName}`,
                        recommendation: 'Review package functionality and legitimacy'
                    });
                }
            }
        }
    }

    async checkDeprecatedPackages(dependencies, ecosystem) {
        // List of known deprecated packages
        const deprecatedPackages = {
            npm: ['request', 'bower', 'gulp-util', 'node-uuid', 'left-pad'],
            python: ['imp', 'optparse', 'md5', 'sha'],
            php: ['mcrypt', 'mysql_*'],
            java: ['commons-httpclient'],
            ruby: ['therubyracer', 'coffee-rails']
        };
        
        const deprecated = deprecatedPackages[ecosystem] || [];
        
        for (const [packageName, version] of Object.entries(dependencies)) {
            if (deprecated.includes(packageName)) {
                this.addVulnerability({
                    type: 'Deprecated Package',
                    severity: 'Medium',
                    package: packageName,
                    version: version,
                    ecosystem: ecosystem,
                    description: `Package ${packageName} is deprecated`,
                    evidence: `Deprecated package in use`,
                    recommendation: 'Replace with actively maintained alternative'
                });
            }
        }
    }

    async checkPythonVulnerabilities(dependencies) {
        const pythonVulns = {
            'django': {
                '3.1.0': 'CVE-2021-35042',
                '2.2.0': 'CVE-2020-24583'
            },
            'flask': {
                '1.0.0': 'CVE-2019-1010083'
            },
            'requests': {
                '2.25.0': 'CVE-2021-33503'
            }
        };
        
        for (const [packageName, version] of Object.entries(dependencies)) {
            if (pythonVulns[packageName] && pythonVulns[packageName][version]) {
                this.addVulnerability({
                    type: 'Python Vulnerability',
                    severity: 'High',
                    package: packageName,
                    version: version,
                    ecosystem: 'python',
                    description: `Known vulnerability in ${packageName}@${version}`,
                    evidence: `CVE: ${pythonVulns[packageName][version]}`,
                    recommendation: `Update ${packageName} to latest secure version`
                });
            }
        }
    }

    async checkPhpVulnerabilities(dependencies) {
        const phpVulns = {
            'symfony/symfony': {
                '5.2.0': 'CVE-2021-21424'
            },
            'laravel/framework': {
                '8.0.0': 'CVE-2021-3129'
            }
        };
        
        for (const [packageName, version] of Object.entries(dependencies)) {
            if (phpVulns[packageName] && phpVulns[packageName][version]) {
                this.addVulnerability({
                    type: 'PHP Vulnerability',
                    severity: 'High',
                    package: packageName,
                    version: version,
                    ecosystem: 'php',
                    description: `Known vulnerability in ${packageName}@${version}`,
                    evidence: `CVE: ${phpVulns[packageName][version]}`,
                    recommendation: `Update ${packageName} to latest secure version`
                });
            }
        }
    }

    // Helper methods
    async readFile(filename) {
        // Simulate file reading (in real implementation, would use fs.readFile)
        const mockFiles = {
            'package.json': JSON.stringify({
                dependencies: {
                    'lodash': '4.17.20',
                    'express': '4.16.0',
                    'axios': '0.21.0',
                    'moment': '2.29.1'
                },
                devDependencies: {
                    'minimist': '1.2.5',
                    'serialize-javascript': '3.1.0'
                }
            }),
            'requirements.txt': 'django==3.1.0\nflask==1.0.0\nrequests==2.25.0',
            'composer.json': JSON.stringify({
                require: {
                    'symfony/symfony': '5.2.0',
                    'laravel/framework': '8.0.0'
                }
            })
        };
        
        return mockFiles[filename] || null;
    }

    async fileExists(filename) {
        // Simulate file existence check
        const existingFiles = ['package.json', 'requirements.txt', 'composer.json'];
        return existingFiles.includes(filename);
    }

    extractDependenciesFromLock(dependencies, result) {
        for (const [name, info] of Object.entries(dependencies)) {
            if (info.version) {
                result[name] = info.version;
            }
            if (info.dependencies) {
                this.extractDependenciesFromLock(info.dependencies, result);
            }
        }
    }

    isVersionAffected(currentVersion, vulnerableVersion) {
        // Simplified version comparison
        return currentVersion === vulnerableVersion || 
               this.compareVersions(currentVersion, vulnerableVersion) <= 0;
    }

    compareVersions(version1, version2) {
        // Simplified version comparison
        const v1Parts = version1.split('.').map(Number);
        const v2Parts = version2.split('.').map(Number);
        
        for (let i = 0; i < Math.max(v1Parts.length, v2Parts.length); i++) {
            const v1Part = v1Parts[i] || 0;
            const v2Part = v2Parts[i] || 0;
            
            if (v1Part < v2Part) return -1;
            if (v1Part > v2Part) return 1;
        }
        
        return 0;
    }

    generateNewerVersion(currentVersion) {
        // Generate a plausible newer version
        const parts = currentVersion.split('.');
        if (parts.length >= 3) {
            parts[2] = String(parseInt(parts[2]) + 1);
        } else if (parts.length >= 2) {
            parts[1] = String(parseInt(parts[1]) + 1);
        } else {
            parts[0] = String(parseInt(parts[0]) + 1);
        }
        return parts.join('.');
    }

    isTyposquatting(packageName, popularName) {
        // Simple typosquatting detection
        if (packageName === popularName) return false;
        
        const distance = this.levenshteinDistance(packageName, popularName);
        return distance <= 2 && packageName.length >= popularName.length - 2;
    }

    levenshteinDistance(str1, str2) {
        const matrix = [];
        
        for (let i = 0; i <= str2.length; i++) {
            matrix[i] = [i];
        }
        
        for (let j = 0; j <= str1.length; j++) {
            matrix[0][j] = j;
        }
        
        for (let i = 1; i <= str2.length; i++) {
            for (let j = 1; j <= str1.length; j++) {
                if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
                    matrix[i][j] = matrix[i - 1][j - 1];
                } else {
                    matrix[i][j] = Math.min(
                        matrix[i - 1][j - 1] + 1,
                        matrix[i][j - 1] + 1,
                        matrix[i - 1][j] + 1
                    );
                }
            }
        }
        
        return matrix[str2.length][str1.length];
    }

    addVulnerability(vuln) {
        this.vulnerabilities.push({
            ...vuln,
            timestamp: new Date().toISOString(),
            id: `SCA-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            scanType: 'SCA'
        });
    }

    generateReport() {
        const severityCounts = this.vulnerabilities.reduce((acc, vuln) => {
            acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
            return acc;
        }, {});

        const ecosystemCounts = {};
        for (const [ecosystem, deps] of Object.entries(this.dependencies)) {
            if (deps && typeof deps === 'object') {
                ecosystemCounts[ecosystem] = Object.keys(deps).length;
            }
        }

        return {
            summary: {
                totalVulnerabilities: this.vulnerabilities.length,
                severityBreakdown: severityCounts,
                ecosystemBreakdown: ecosystemCounts,
                scanTimestamp: new Date().toISOString()
            },
            vulnerabilities: this.vulnerabilities,
            dependencies: this.dependencies,
            scanResults: this.scanResults,
            recommendations: this.generateRecommendations()
        };
    }

    generateRecommendations() {
        const recommendations = [];
        
        if (this.vulnerabilities.some(v => v.type.includes('Vulnerable'))) {
            recommendations.push({
                category: 'Vulnerable Dependencies',
                priority: 'Critical',
                actions: [
                    'Update all vulnerable dependencies to secure versions',
                    'Implement automated dependency scanning in CI/CD',
                    'Set up security alerts for new vulnerabilities',
                    'Regular dependency audits and updates'
                ]
            });
        }
        
        if (this.vulnerabilities.some(v => v.type.includes('Outdated'))) {
            recommendations.push({
                category: 'Dependency Management',
                priority: 'Medium',
                actions: [
                    'Establish regular dependency update schedule',
                    'Use dependency management tools (Dependabot, Renovate)',
                    'Implement semantic versioning strategy',
                    'Test updates in staging environment'
                ]
            });
        }
        
        if (this.vulnerabilities.some(v => v.type.includes('License'))) {
            recommendations.push({
                category: 'License Compliance',
                priority: 'Medium',
                actions: [
                    'Review and document acceptable licenses',
                    'Implement license scanning in build process',
                    'Maintain license inventory and compliance records',
                    'Consult legal team for license compatibility'
                ]
            });
        }
        
        return recommendations;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SCAScanner;
}