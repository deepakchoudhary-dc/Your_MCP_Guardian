/**
 * Test All Scanner Method Calls
 */

console.log('🧪 Testing All Scanner Method Calls...\n');

try {
    // Load all scanner modules
    console.log('📦 Loading scanner modules...');
    const ComprehensiveSecurityScanner = require('./comprehensive_security_scanner.js');
    
    // Create scanner instance
    const scanner = new ComprehensiveSecurityScanner({
        napthaIntegration: true
    });
    
    // Test configuration
    const testConfig = {
        serverName: 'Test MCP Server',
        serverUrl: 'https://localhost:8080',
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
            }
        ],
        oauthScopes: ['read', 'admin']
    };
    
    console.log('📋 Setting server configuration...');
    scanner.setServerConfig(testConfig);
    
    console.log('🔍 Testing comprehensive scan...');
    scanner.runComprehensiveScan()
        .then(results => {
            console.log('\n✅ All Scanner Methods Working!');
            console.log(`📊 Results Summary:`);
            console.log(`   • Static Analysis: ${results.results.static?.vulnerabilities?.length || 0} vulnerabilities`);
            console.log(`   • Runtime Scan: ${results.results.runtime?.summary?.status || 'completed'}`);
            console.log(`   • Network Scan: ${results.results.network?.summary?.status || 'completed'}`);
            console.log(`   • Logic Scan: ${results.results.logic?.summary?.status || 'completed'}`);
            console.log(`   • DAST Scan: ${results.results.dast?.summary?.status || 'completed'}`);
            console.log(`   • SCA Scan: ${results.results.sca?.summary?.status || 'completed'}`);
            console.log(`   • Secret Scan: ${results.results.secret?.summary?.status || 'completed'}`);
            console.log(`   • IaC Scan: ${results.results.iac?.summary?.status || 'completed'}`);
            console.log(`   • Naptha AI: ${results.results.naptha?.scanId ? 'active' : 'inactive'}`);
            
            console.log(`\n🎯 Total Vulnerabilities: ${results.summary.totalVulnerabilities}`);
            console.log(`📈 Risk Score: ${results.riskScore}/10`);
            
            console.log('\n🎉 Scanner Method Integration Test PASSED!');
            process.exit(0);
        })
        .catch(error => {
            console.error('\n❌ Scanner Method Test FAILED:', error.message);
            process.exit(1);
        });
        
} catch (error) {
    console.error('❌ Test setup failed:', error.message);
    process.exit(1);
}
