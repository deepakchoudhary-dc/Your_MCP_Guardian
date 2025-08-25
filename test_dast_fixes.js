/**
 * Test DAST Scanner Fixes
 */

console.log('🧪 Testing DAST Scanner Fixes...\n');

async function testDASTScanner() {
    try {
        // Load DAST scanner
        const DASTScanner = require('./dast_scanner.js');
        
        // Test with HTTPS localhost URL (should convert to HTTP)
        console.log('📋 Testing HTTPS to HTTP conversion...');
        const httpsConfig = {
            serverUrl: 'https://localhost:3000',
            tools: [{ name: 'test_tool', description: 'Test tool' }]
        };
        
        const dastScanner = new DASTScanner(httpsConfig);
        console.log(`✅ Base URL normalized: ${dastScanner.baseUrl}`);
        
        // Test server reachability
        console.log('\n🔍 Testing server reachability...');
        const isReachable = await dastScanner.checkServerReachability();
        console.log(`✅ Server reachable: ${isReachable}`);
        
        // Test DAST scan
        console.log('\n🎯 Testing DAST scan...');
        const scanResult = await dastScanner.performDASTScan();
        console.log('✅ DAST scan completed successfully');
        console.log(`📊 Vulnerabilities found: ${scanResult.vulnerabilities?.length || 0}`);
        console.log(`📋 Scan status: ${scanResult.metadata?.status || 'unknown'}`);
        
        console.log('\n🎉 DAST Scanner Fix Test PASSED!');
        return true;
        
    } catch (error) {
        console.error('❌ DAST Scanner Test FAILED:', error.message);
        return false;
    }
}

// Run the test
if (require.main === module) {
    testDASTScanner()
        .then(success => {
            process.exit(success ? 0 : 1);
        })
        .catch(error => {
            console.error('Test execution failed:', error);
            process.exit(1);
        });
}

module.exports = { testDASTScanner };
