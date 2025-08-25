/**
 * Quick Naptha AI Integration Test
 */

console.log('🧪 Quick Naptha AI Integration Test...\n');

try {
    // Test loading modules
    console.log('📦 Loading modules...');
    const ComprehensiveSecurityScanner = require('./comprehensive_security_scanner.js');
    console.log('✅ ComprehensiveSecurityScanner loaded');
    
    const NapthaAgentCoordinator = require('./naptha_agent_coordinator.js');
    console.log('✅ NapthaAgentCoordinator loaded');
    
    // Test instantiation
    console.log('\n🏗️ Testing instantiation...');
    const naptha = new NapthaAgentCoordinator();
    console.log('✅ NapthaAgentCoordinator created');
    
    const scanner = new ComprehensiveSecurityScanner({
        napthaIntegration: true,
        aiAnalytics: true
    });
    console.log('✅ ComprehensiveSecurityScanner created');
    
    // Test basic methods
    console.log('\n🔍 Testing basic methods...');
    
    // Test getStatus
    const status = scanner.getStatus();
    console.log('✅ getStatus() works:', {
        naptha: status.aiComponents.naptha,
        analytics: status.aiComponents.analytics,
        totalAgents: status.totalAgents
    });
    
    // Test initialize
    naptha.initialize().then(() => {
        console.log('✅ naptha.initialize() works');
        
        // Test getAIAnalysis
        const analysis = naptha.getAIAnalysis();
        console.log('✅ getAIAnalysis() works:', {
            scanId: analysis.scanId,
            totalFindings: analysis.totalFindings
        });
        
        console.log('\n🎉 Basic Naptha AI Integration WORKING!');
        console.log('\n📋 Summary:');
        console.log('   ✓ All modules load successfully');
        console.log('   ✓ Objects instantiate without errors');
        console.log('   ✓ Required methods exist and callable');
        console.log('   ✓ Integration layer is functional');
        
        console.log('\n✅ Naptha AI Integration Test PASSED!');
        process.exit(0);
        
    }).catch(error => {
        console.error('❌ naptha.initialize() failed:', error);
        process.exit(1);
    });
    
} catch (error) {
    console.error('❌ Test failed:', error.message);
    process.exit(1);
}
