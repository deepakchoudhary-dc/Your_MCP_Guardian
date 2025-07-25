/**
 * Infrastructure as Code (IaC) Security Scanner
 * Scans Terraform, CloudFormation, Kubernetes, Docker, and other IaC files for security misconfigurations
 */

class IaCScanner {
    constructor(projectPath = '.') {
        this.projectPath = projectPath;
        this.vulnerabilities = [];
        this.scanResults = {};
        this.scannedFiles = [];
        
        // IaC security rules
        this.securityRules = {
            terraform: [
                {
                    id: 'TF001',
                    severity: 'Critical',
                    title: 'S3 Bucket Public Read Access',
                    pattern: /resource\s+"aws_s3_bucket_public_access_block"[\s\S]*?block_public_acls\s*=\s*false/g,
                    description: 'S3 bucket allows public read access',
                    recommendation: 'Set block_public_acls = true to prevent public access'
                },
                {
                    id: 'TF002',
                    severity: 'High',
                    title: 'Security Group Allows All Traffic',
                    pattern: /resource\s+"aws_security_group"[\s\S]*?cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"\s*\]/g,
                    description: 'Security group allows traffic from all IP addresses (0.0.0.0/0)',
                    recommendation: 'Restrict CIDR blocks to specific IP ranges'
                },
                {
                    id: 'TF003',
                    severity: 'Critical',
                    title: 'RDS Instance Without Encryption',
                    pattern: /resource\s+"aws_db_instance"[\s\S]*?(?!.*storage_encrypted\s*=\s*true)/g,
                    description: 'RDS instance does not have encryption enabled',
                    recommendation: 'Enable storage_encrypted = true for RDS instances'
                },
                {
                    id: 'TF004',
                    severity: 'High',
                    title: 'EC2 Instance Without IMDSv2',
                    pattern: /resource\s+"aws_instance"[\s\S]*?(?!.*metadata_options[\s\S]*?http_tokens\s*=\s*"required")/g,
                    description: 'EC2 instance does not enforce IMDSv2',
                    recommendation: 'Set http_tokens = "required" in metadata_options'
                },
                {
                    id: 'TF005',
                    severity: 'Medium',
                    title: 'CloudTrail Without Log File Validation',
                    pattern: /resource\s+"aws_cloudtrail"[\s\S]*?(?!.*enable_log_file_validation\s*=\s*true)/g,
                    description: 'CloudTrail does not have log file validation enabled',
                    recommendation: 'Enable log file validation for CloudTrail'
                },
                {
                    id: 'TF006',
                    severity: 'Critical',
                    title: 'Hardcoded Secrets in Terraform',
                    pattern: /(password|secret|key)\s*=\s*"[^"]{8,}"/gi,
                    description: 'Hardcoded secrets found in Terraform configuration',
                    recommendation: 'Use variables or secret management services'
                },
                {
                    id: 'TF007',
                    severity: 'High',
                    title: 'Lambda Function Without Dead Letter Queue',
                    pattern: /resource\s+"aws_lambda_function"[\s\S]*?(?!.*dead_letter_config)/g,
                    description: 'Lambda function does not have dead letter queue configured',
                    recommendation: 'Configure dead_letter_config for error handling'
                },
                {
                    id: 'TF008',
                    severity: 'Medium',
                    title: 'ELB Without Access Logs',
                    pattern: /resource\s+"aws_lb"[\s\S]*?(?!.*access_logs[\s\S]*?enabled\s*=\s*true)/g,
                    description: 'Load balancer does not have access logs enabled',
                    recommendation: 'Enable access logs for monitoring and compliance'
                }
            ],
            
            cloudformation: [
                {
                    id: 'CF001',
                    severity: 'Critical',
                    title: 'S3 Bucket Public Read Access',
                    pattern: /"PublicRead"|"PublicReadWrite"/g,
                    description: 'S3 bucket configured with public read access',
                    recommendation: 'Remove public access and use IAM policies'
                },
                {
                    id: 'CF002',
                    severity: 'High',
                    title: 'Security Group Open to World',
                    pattern: /"CidrIp"\s*:\s*"0\.0\.0\.0\/0"/g,
                    description: 'Security group allows access from anywhere',
                    recommendation: 'Restrict access to specific IP ranges'
                },
                {
                    id: 'CF003',
                    severity: 'Critical',
                    title: 'RDS Without Encryption',
                    pattern: /"AWS::RDS::DBInstance"[\s\S]*?(?!.*"StorageEncrypted"\s*:\s*true)/g,
                    description: 'RDS instance without encryption',
                    recommendation: 'Enable StorageEncrypted property'
                },
                {
                    id: 'CF004',
                    severity: 'Medium',
                    title: 'CloudFormation Stack Without Termination Protection',
                    pattern: /(?!.*"EnableTerminationProtection"\s*:\s*true)/g,
                    description: 'Stack does not have termination protection',
                    recommendation: 'Enable termination protection for production stacks'
                }
            ],
            
            kubernetes: [
                {
                    id: 'K8S001',
                    severity: 'Critical',
                    title: 'Container Running as Root',
                    pattern: /runAsUser:\s*0/g,
                    description: 'Container configured to run as root user',
                    recommendation: 'Use non-root user ID (runAsUser > 0)'
                },
                {
                    id: 'K8S002',
                    severity: 'High',
                    title: 'Privileged Container',
                    pattern: /privileged:\s*true/g,
                    description: 'Container running in privileged mode',
                    recommendation: 'Remove privileged: true unless absolutely necessary'
                },
                {
                    id: 'K8S003',
                    severity: 'High',
                    title: 'Host Network Access',
                    pattern: /hostNetwork:\s*true/g,
                    description: 'Pod has access to host network',
                    recommendation: 'Remove hostNetwork: true unless required'
                },
                {
                    id: 'K8S004',
                    severity: 'Medium',
                    title: 'Missing Resource Limits',
                    pattern: /resources:\s*\{\s*\}/g,
                    description: 'Container without resource limits',
                    recommendation: 'Set CPU and memory limits for containers'
                },
                {
                    id: 'K8S005',
                    severity: 'High',
                    title: 'Capabilities Added',
                    pattern: /add:\s*\[[\s\S]*?\]/g,
                    description: 'Container has additional capabilities',
                    recommendation: 'Remove unnecessary capabilities'
                },
                {
                    id: 'K8S006',
                    severity: 'Medium',
                    title: 'Missing Security Context',
                    pattern: /(?!.*securityContext)/g,
                    description: 'Pod/Container missing security context',
                    recommendation: 'Define security context with appropriate settings'
                },
                {
                    id: 'K8S007',
                    severity: 'High',
                    title: 'Host Path Volume Mount',
                    pattern: /hostPath:/g,
                    description: 'Pod mounts host filesystem',
                    recommendation: 'Use persistent volumes instead of hostPath'
                },
                {
                    id: 'K8S008',
                    severity: 'Medium',
                    title: 'Default Service Account',
                    pattern: /serviceAccountName:\s*default/g,
                    description: 'Pod uses default service account',
                    recommendation: 'Create dedicated service account with minimal permissions'
                }
            ],
            
            docker: [
                {
                    id: 'DOC001',
                    severity: 'High',
                    title: 'Running as Root User',
                    pattern: /USER\s+root|USER\s+0/gi,
                    description: 'Dockerfile sets user to root',
                    recommendation: 'Use non-root user (USER 1000 or create dedicated user)'
                },
                {
                    id: 'DOC002',
                    severity: 'Medium',
                    title: 'Using Latest Tag',
                    pattern: /FROM\s+[^:\s]+:latest/gi,
                    description: 'Using latest tag for base image',
                    recommendation: 'Use specific version tags for reproducible builds'
                },
                {
                    id: 'DOC003',
                    severity: 'Critical',
                    title: 'Hardcoded Secrets',
                    pattern: /(ENV|ARG)\s+[A-Z_]*(?:PASSWORD|SECRET|KEY|TOKEN)[A-Z_]*\s*[=\s]\s*[^\s]+/gi,
                    description: 'Hardcoded secrets in Dockerfile',
                    recommendation: 'Use build-time secrets or runtime secret injection'
                },
                {
                    id: 'DOC004',
                    severity: 'Medium',
                    title: 'Unnecessary Packages',
                    pattern: /apt-get\s+install[\s\S]*?(curl|wget|ssh|telnet)/gi,
                    description: 'Installing potentially unnecessary packages',
                    recommendation: 'Remove unnecessary packages to reduce attack surface'
                },
                {
                    id: 'DOC005',
                    severity: 'Low',
                    title: 'Missing Health Check',
                    pattern: /(?!.*HEALTHCHECK)/g,
                    description: 'Dockerfile missing health check',
                    recommendation: 'Add HEALTHCHECK instruction for container monitoring'
                },
                {
                    id: 'DOC006',
                    severity: 'Medium',
                    title: 'Exposed Sensitive Ports',
                    pattern: /EXPOSE\s+(22|23|135|139|445|1433|3389|5432|6379)/gi,
                    description: 'Exposing sensitive ports',
                    recommendation: 'Avoid exposing administrative or database ports'
                },
                {
                    id: 'DOC007',
                    severity: 'High',
                    title: 'ADD Instead of COPY',
                    pattern: /ADD\s+(?!.*\.tar)/gi,
                    description: 'Using ADD instead of COPY for local files',
                    recommendation: 'Use COPY for local files, ADD only for archives'
                }
            ],
            
            ansible: [
                {
                    id: 'ANS001',
                    severity: 'Critical',
                    title: 'Hardcoded Passwords',
                    pattern: /(password|passwd):\s*[^{][^\s]+/gi,
                    description: 'Hardcoded password in Ansible playbook',
                    recommendation: 'Use Ansible Vault for sensitive data'
                },
                {
                    id: 'ANS002',
                    severity: 'High',
                    title: 'Shell Command Injection Risk',
                    pattern: /shell:\s*.*\{\{.*\}\}/g,
                    description: 'Shell module with variable interpolation',
                    recommendation: 'Use command module or properly escape variables'
                },
                {
                    id: 'ANS003',
                    severity: 'Medium',
                    title: 'Sudo Without Password',
                    pattern: /become:\s*yes[\s\S]*?(?!.*become_pass)/g,
                    description: 'Using sudo without password',
                    recommendation: 'Configure proper sudo authentication'
                },
                {
                    id: 'ANS004',
                    severity: 'Low',
                    title: 'HTTP Instead of HTTPS',
                    pattern: /url:\s*http:\/\//gi,
                    description: 'Using HTTP instead of HTTPS',
                    recommendation: 'Use HTTPS for secure communication'
                }
            ]
        };
        
        // File patterns to scan
        this.filePatterns = {
            terraform: ['.tf', '.tfvars'],
            cloudformation: ['.yaml', '.yml', '.json'],
            kubernetes: ['.yaml', '.yml'],
            docker: ['Dockerfile', 'dockerfile', '.dockerfile'],
            ansible: ['.yml', '.yaml']
        };
    }

    async performIaCScan() {
        console.log('🏗️ Starting Infrastructure as Code (IaC) Security Scan...');
        
        try {
            // Discover IaC files
            const iacFiles = await this.discoverIaCFiles();
            
            // Scan each file type
            for (const [iacType, files] of Object.entries(iacFiles)) {
                if (files.length > 0) {
                    await this.scanIaCType(iacType, files);
                }
            }
            
            // Additional security checks
            await this.checkIaCBestPractices();
            await this.analyzeIaCFindings();

            return {
                vulnerabilities: this.vulnerabilities,
                scanResults: this.scanResults,
                scannedFiles: this.scannedFiles
            };

        } catch (error) {
            console.error('IaC scan failed:', error);
            this.addVulnerability({
                type: 'IaC Scan Error',
                severity: 'Medium',
                description: 'Infrastructure as Code scanning encountered errors',
                evidence: error.message,
                recommendation: 'Review project structure and IaC file formats'
            });
            return { vulnerabilities: this.vulnerabilities, scanResults: this.scanResults };
        }
    }

    async discoverIaCFiles() {
        // Simulate file discovery
        const mockFiles = {
            terraform: [
                'main.tf',
                'variables.tf',
                'outputs.tf',
                'terraform.tfvars',
                'modules/vpc/main.tf',
                'modules/security/security_groups.tf'
            ],
            cloudformation: [
                'template.yaml',
                'infrastructure.yml',
                'cloudformation.json'
            ],
            kubernetes: [
                'deployment.yaml',
                'service.yaml',
                'ingress.yml',
                'configmap.yaml',
                'secret.yaml',
                'k8s/namespace.yaml'
            ],
            docker: [
                'Dockerfile',
                'Dockerfile.prod',
                'docker/Dockerfile.api'
            ],
            ansible: [
                'playbook.yml',
                'site.yaml',
                'roles/common/tasks/main.yml'
            ]
        };
        
        return mockFiles;
    }

    async scanIaCType(iacType, files) {
        console.log(`Scanning ${iacType} files...`);
        
        const rules = this.securityRules[iacType] || [];
        
        for (const filePath of files) {
            const content = await this.readIaCFile(filePath, iacType);
            if (!content) continue;
            
            this.scannedFiles.push(filePath);
            
            // Apply security rules
            for (const rule of rules) {
                await this.applySecurityRule(rule, content, filePath, iacType);
            }
            
            // Additional file-specific checks
            await this.performAdditionalChecks(filePath, content, iacType);
        }
        
        this.scanResults[iacType] = {
            filesScanned: files.length,
            rulesApplied: rules.length
        };
    }

    async applySecurityRule(rule, content, filePath, iacType) {
        const matches = content.match(rule.pattern);
        
        if (matches) {
            for (const match of matches) {
                // Skip false positives
                if (this.isFalsePositive(match, content, rule)) continue;
                
                const lineNumber = this.getLineNumber(content, match);
                
                this.addVulnerability({
                    type: 'IaC Security Misconfiguration',
                    iacType: iacType,
                    ruleId: rule.id,
                    severity: rule.severity,
                    title: rule.title,
                    file: filePath,
                    line: lineNumber,
                    description: `${rule.description} in ${filePath}`,
                    evidence: this.truncateEvidence(match),
                    recommendation: rule.recommendation
                });
            }
        }
    }

    async performAdditionalChecks(filePath, content, iacType) {
        // Terraform-specific checks
        if (iacType === 'terraform') {
            await this.checkTerraformSpecific(filePath, content);
        }
        
        // Kubernetes-specific checks
        if (iacType === 'kubernetes') {
            await this.checkKubernetesSpecific(filePath, content);
        }
        
        // Docker-specific checks
        if (iacType === 'docker') {
            await this.checkDockerSpecific(filePath, content);
        }
        
        // CloudFormation-specific checks
        if (iacType === 'cloudformation') {
            await this.checkCloudFormationSpecific(filePath, content);
        }
    }

    async checkTerraformSpecific(filePath, content) {
        // Check for missing provider version constraints
        if (content.includes('provider ') && !content.includes('required_version')) {
            this.addVulnerability({
                type: 'Terraform Best Practice',
                severity: 'Low',
                file: filePath,
                description: 'Missing Terraform version constraints',
                recommendation: 'Add required_version in terraform block'
            });
        }
        
        // Check for missing backend configuration
        if (content.includes('terraform {') && !content.includes('backend ')) {
            this.addVulnerability({
                type: 'Terraform Best Practice',
                severity: 'Medium',
                file: filePath,
                description: 'Missing remote backend configuration',
                recommendation: 'Configure remote backend for state management'
            });
        }
        
        // Check for hardcoded regions
        const regionMatches = content.match(/region\s*=\s*"[^"]+"/g);
        if (regionMatches && regionMatches.length > 1) {
            this.addVulnerability({
                type: 'Terraform Configuration',
                severity: 'Low',
                file: filePath,
                description: 'Hardcoded AWS regions detected',
                recommendation: 'Use variables for region configuration'
            });
        }
    }

    async checkKubernetesSpecific(filePath, content) {
        // Check for missing namespace
        if (content.includes('kind: ') && !content.includes('namespace:')) {
            this.addVulnerability({
                type: 'Kubernetes Best Practice',
                severity: 'Low',
                file: filePath,
                description: 'Resource without explicit namespace',
                recommendation: 'Specify namespace for all resources'
            });
        }
        
        // Check for missing labels
        if (content.includes('metadata:') && !content.includes('labels:')) {
            this.addVulnerability({
                type: 'Kubernetes Best Practice',
                severity: 'Low',
                file: filePath,
                description: 'Resource without labels',
                recommendation: 'Add appropriate labels for resource management'
            });
        }
        
        // Check for image pull policy
        if (content.includes('image:') && !content.includes('imagePullPolicy:')) {
            this.addVulnerability({
                type: 'Kubernetes Configuration',
                severity: 'Low',
                file: filePath,
                description: 'Missing image pull policy',
                recommendation: 'Set imagePullPolicy to Always for latest tags'
            });
        }
    }

    async checkDockerSpecific(filePath, content) {
        // Check for package cache cleanup
        if (content.includes('apt-get install') && !content.includes('rm -rf /var/lib/apt/lists/*')) {
            this.addVulnerability({
                type: 'Docker Best Practice',
                severity: 'Low',
                file: filePath,
                description: 'Package cache not cleaned up',
                recommendation: 'Clean package cache to reduce image size'
            });
        }
        
        // Check for multiple RUN commands
        const runCommands = (content.match(/^RUN /gm) || []).length;
        if (runCommands > 5) {
            this.addVulnerability({
                type: 'Docker Optimization',
                severity: 'Low',
                file: filePath,
                description: 'Multiple RUN commands increase image layers',
                recommendation: 'Combine RUN commands to reduce layers'
            });
        }
        
        // Check for WORKDIR usage
        if (content.includes('COPY') && !content.includes('WORKDIR')) {
            this.addVulnerability({
                type: 'Docker Best Practice',
                severity: 'Low',
                file: filePath,
                description: 'Missing WORKDIR instruction',
                recommendation: 'Use WORKDIR to set working directory'
            });
        }
    }

    async checkCloudFormationSpecific(filePath, content) {
        // Check for missing description
        if (!content.includes('"Description"') && !content.includes('Description:')) {
            this.addVulnerability({
                type: 'CloudFormation Best Practice',
                severity: 'Low',
                file: filePath,
                description: 'Missing template description',
                recommendation: 'Add description to CloudFormation template'
            });
        }
        
        // Check for hardcoded values
        const hardcodedPatterns = [
            /"ami-[a-z0-9]+"/g,
            /"subnet-[a-z0-9]+"/g,
            /"vpc-[a-z0-9]+"/g
        ];
        
        for (const pattern of hardcodedPatterns) {
            if (pattern.test(content)) {
                this.addVulnerability({
                    type: 'CloudFormation Configuration',
                    severity: 'Medium',
                    file: filePath,
                    description: 'Hardcoded AWS resource IDs detected',
                    recommendation: 'Use parameters or mappings for resource IDs'
                });
            }
        }
    }

    async checkIaCBestPractices() {
        console.log('Checking IaC best practices...');
        
        // Check for security scanning in CI/CD
        const ciFiles = ['Jenkinsfile', '.github/workflows/ci.yml', '.gitlab-ci.yml', 'azure-pipelines.yml'];
        let hasSecurityScanning = false;
        
        for (const ciFile of ciFiles) {
            const content = await this.readIaCFile(ciFile, 'ci');
            if (content && (content.includes('checkov') || content.includes('tfsec') || content.includes('terrascan'))) {
                hasSecurityScanning = true;
                break;
            }
        }
        
        if (!hasSecurityScanning) {
            this.addVulnerability({
                type: 'IaC Best Practice',
                severity: 'Medium',
                description: 'No IaC security scanning detected in CI/CD pipeline',
                recommendation: 'Add IaC security scanning tools (Checkov, tfsec, Terrascan) to CI/CD'
            });
        }
        
        // Check for state file security
        const gitignoreContent = await this.readIaCFile('.gitignore', 'config');
        if (gitignoreContent && !gitignoreContent.includes('*.tfstate')) {
            this.addVulnerability({
                type: 'Terraform Security',
                severity: 'High',
                description: 'Terraform state files not excluded from version control',
                recommendation: 'Add *.tfstate* to .gitignore and use remote backend'
            });
        }
    }

    async analyzeIaCFindings() {
        // Group findings by severity and type
        const findingsByType = {};
        const findingsBySeverity = {};
        
        for (const vuln of this.vulnerabilities) {
            const type = vuln.iacType || 'general';
            const severity = vuln.severity;
            
            if (!findingsByType[type]) findingsByType[type] = 0;
            if (!findingsBySeverity[severity]) findingsBySeverity[severity] = 0;
            
            findingsByType[type]++;
            findingsBySeverity[severity]++;
        }
        
        // Check for critical infrastructure security issues
        const criticalIssues = this.vulnerabilities.filter(v => v.severity === 'Critical').length;
        if (criticalIssues > 0) {
            this.addVulnerability({
                type: 'Infrastructure Security Risk',
                severity: 'Critical',
                description: `${criticalIssues} critical infrastructure security issues detected`,
                recommendation: 'Address critical issues before deployment to production'
            });
        }
        
        this.scanResults.analysis = {
            totalFindings: this.vulnerabilities.length,
            findingsByType,
            findingsBySeverity,
            criticalIssues
        };
    }

    // Helper methods
    async readIaCFile(filename, iacType) {
        // Mock file contents for different IaC types
        const mockContents = {
            'main.tf': `
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name_prefix = "web-"
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "example" {
  identifier = "mydb"
  engine     = "mysql"
  username   = "admin"
  password   = "EXAMPLE_PASSWORD_123"
  # storage_encrypted = false  # Missing encryption
}

resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
  
  # Missing metadata_options for IMDSv2
}`,
            
            'template.yaml': `
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
      
  MySecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: "0.0.0.0/0"
          
  MyDatabase:
    Type: AWS::RDS::DBInstance
    Properties:
      Engine: mysql
      MasterUsername: admin
      MasterUserPassword: hardcoded_password
      # StorageEncrypted: false`,
      
            'deployment.yaml': `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: web-app
  template:
    metadata:
      labels:
        app: web-app
    spec:
      containers:
      - name: web
        image: nginx:latest
        ports:
        - containerPort: 80
        securityContext:
          runAsUser: 0
          privileged: true
        resources: {}
      hostNetwork: true
      serviceAccountName: default`,
      
            'Dockerfile': `
FROM ubuntu:latest

USER root

ENV DATABASE_PASSWORD=EXAMPLE_SECRET_123
ENV API_KEY=EXAMPLE_API_KEY_HERE

RUN apt-get update
RUN apt-get install -y curl wget ssh
RUN apt-get install -y python3
RUN apt-get install -y nodejs
RUN apt-get install -y git

ADD app.tar.gz /app/

EXPOSE 22
EXPOSE 3389
EXPOSE 5432

# Missing HEALTHCHECK
# No USER instruction to switch from root`,

            'playbook.yml': `
---
- hosts: all
  become: yes
  vars:
    db_password: EXAMPLE_PASSWORD_123
    api_key: EXAMPLE_API_KEY_HERE
  tasks:
    - name: Download file
      get_url:
        url: http://example.com/file.tar.gz
        dest: /tmp/file.tar.gz
        
    - name: Run shell command
      shell: echo "{{ user_input }}" > /tmp/output.txt
      
    - name: Install package
      apt:
        name: mysql-server
        state: present
      become_pass: "{{ db_password }}"`,
      
            '.gitignore': `
node_modules/
*.log
.env
# Missing *.tfstate*`,

            'Jenkinsfile': `
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'npm install'
            }
        }
        stage('Test') {
            steps {
                sh 'npm test'
            }
        }
        stage('Deploy') {
            steps {
                sh 'terraform apply -auto-approve'
            }
        }
    }
}
# Missing security scanning stages`
        };
        
        return mockContents[filename] || null;
    }

    isFalsePositive(match, content, rule) {
        // Common false positive patterns
        const falsePositives = [
            /example/i,
            /test/i,
            /demo/i,
            /placeholder/i,
            /template/i,
            /sample/i
        ];
        
        // Check if the match is in a comment
        const lines = content.split('\n');
        for (const line of lines) {
            if (line.includes(match) && (line.trim().startsWith('#') || line.trim().startsWith('//'))) {
                return true;
            }
        }
        
        // Check for false positive patterns
        for (const fp of falsePositives) {
            if (fp.test(match)) return true;
        }
        
        return false;
    }

    getLineNumber(content, match) {
        const beforeMatch = content.substring(0, content.indexOf(match));
        return beforeMatch.split('\n').length;
    }

    truncateEvidence(evidence) {
        if (evidence.length > 200) {
            return evidence.substring(0, 200) + '...';
        }
        return evidence;
    }

    addVulnerability(vuln) {
        this.vulnerabilities.push({
            ...vuln,
            timestamp: new Date().toISOString(),
            id: `IAC-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            scanType: 'IaC'
        });
    }

    generateReport() {
        const severityCounts = this.vulnerabilities.reduce((acc, vuln) => {
            acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
            return acc;
        }, {});

        const iacTypeCounts = {};
        for (const vuln of this.vulnerabilities) {
            const type = vuln.iacType || 'general';
            iacTypeCounts[type] = (iacTypeCounts[type] || 0) + 1;
        }

        return {
            summary: {
                totalFindings: this.vulnerabilities.length,
                severityBreakdown: severityCounts,
                iacTypeBreakdown: iacTypeCounts,
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
                category: 'Critical Infrastructure Issues',
                priority: 'Critical',
                actions: [
                    'Fix all critical security misconfigurations before deployment',
                    'Enable encryption for all data stores',
                    'Remove hardcoded secrets from IaC files',
                    'Implement least privilege access controls'
                ]
            });
        }
        
        if (this.vulnerabilities.some(v => v.iacType === 'terraform')) {
            recommendations.push({
                category: 'Terraform Security',
                priority: 'High',
                actions: [
                    'Use remote backend for state management',
                    'Add provider version constraints',
                    'Implement Terraform security scanning (tfsec)',
                    'Use variables for sensitive values'
                ]
            });
        }
        
        if (this.vulnerabilities.some(v => v.iacType === 'kubernetes')) {
            recommendations.push({
                category: 'Kubernetes Security',
                priority: 'High',
                actions: [
                    'Implement Pod Security Standards',
                    'Use non-root containers',
                    'Set resource limits and requests',
                    'Enable network policies'
                ]
            });
        }
        
        if (this.vulnerabilities.some(v => v.iacType === 'docker')) {
            recommendations.push({
                category: 'Container Security',
                priority: 'Medium',
                actions: [
                    'Use specific image tags instead of latest',
                    'Run containers as non-root user',
                    'Minimize image layers and size',
                    'Add health checks to containers'
                ]
            });
        }
        
        recommendations.push({
            category: 'IaC Best Practices',
            priority: 'Medium',
            actions: [
                'Implement IaC security scanning in CI/CD pipeline',
                'Use policy as code (OPA, Sentinel)',
                'Regular security reviews of infrastructure code',
                'Implement infrastructure testing and validation'
            ]
        });
        
        return recommendations;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = IaCScanner;
}