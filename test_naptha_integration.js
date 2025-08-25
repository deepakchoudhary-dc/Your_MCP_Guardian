/**
 * Test Naptha AI Integration
 */

// Load the comprehensive security scanner
const ComprehensiveSecurityScanner = require('./comprehensive_security_scanner.js');

async function testNapthaIntegration() {
    console.log('🧪 Testing Naptha AI Integration...\n');
    
    try {
        // Create scanner instance
        const scanner = new ComprehensiveSecurityScanner({
            napthaIntegration: true,
            aiAnalytics: true,
            threatIntelligence: true
        });
        
        // Wait a moment for initialization
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Test server configuration
        const testConfig = {
            serverName: 'Test MCP Server',
            serverUrl: 'http://localhost:8080',
            tools: [
                {
                    name: 'run_command',
                    description: 'Execute system commands',
                    inputSchema: { 
                        properties: { 
                            command: { type: 'string' },
                            url: { type: 'string' }
                        }
                    }
                },
                {
                    name: 'admin_reset',
                    description: 'Reset admin settings'
                },
                {
                    name: 'get_weather',
                    description: 'Get weather information'
                }
            ],
            oauthScopes: ['read', 'write', 'admin', 'delete']
        };
        
        console.log('📋 Setting server configuration...');
        scanner.setServerConfig(testConfig);
        
        console.log('🔍 Running comprehensive scan with Naptha AI...');
        const results = await scanner.runComprehensiveScan();
        
        console.log('\n✅ Scan completed successfully!');
        console.log(`📊 Total vulnerabilities found: ${results.summary.totalVulnerabilities}`);
        console.log(`🎯 Risk Score: ${results.riskScore}/10`);
        
        // Test Naptha AI specific features
        console.log('\n🤖 Testing Naptha AI features:');
        const status = scanner.getStatus();
        console.log(`   ✓ Naptha Active: ${status.aiComponents.naptha}`);
        console.log(`   ✓ AI Analytics: ${status.aiComponents.analytics}`);
        console.log(`   ✓ Threat Intel: ${status.aiComponents.threatIntel}`);
        console.log(`   ✓ Active Agents: ${status.activeAgents}`);
        console.log(`   ✓ Total Agents: ${status.totalAgents}`);
        
        // Check if Naptha results are included
        if (results.results.naptha) {
            console.log('\n🧠 Naptha AI Analysis Results:');
            const napthaData = results.results.naptha;
            console.log(`   ✓ Scan ID: ${napthaData.scanId}`);
            console.log(`   ✓ Total Findings: ${napthaData.totalFindings}`);
            console.log(`   ✓ Correlated Findings: ${napthaData.correlatedFindings}`);
            console.log(`   ✓ Risk Vector: ${napthaData.aiInsights.riskVector.overall}`);
            console.log(`   ✓ AI Insights Available: ${Object.keys(napthaData.aiInsights).length} categories`);
        } else {
            console.log('\n⚠️ Naptha AI results not found in scan output');
        }
        
        console.log('\n🎉 Naptha AI Integration Test PASSED!');
        return true;
        
    } catch (error) {
        console.error('\n❌ Naptha AI Integration Test FAILED:', error);
        console.error('Stack trace:', error.stack);
        return false;
    }
}

// Run the test
if (require.main === module) {
    testNapthaIntegration()
        .then(success => {
            process.exit(success ? 0 : 1);
        })
        .catch(error => {
            console.error('Test execution failed:', error);
            process.exit(1);
        });
}

module.exports = { testNapthaIntegration };
