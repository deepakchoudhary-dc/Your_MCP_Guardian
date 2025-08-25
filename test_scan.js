// Temporary test script for MCP Guardian scanners
// Simulates the user-provided input and validates that vulnerabilities are detected

(async () => {
  try {
    const ComprehensiveSecurityScanner = require('./comprehensive_security_scanner.js');

    // Tools from the user's input
    const tools = [
      {
        name: 'run_sql_query',
        description: 'Executes raw SQL queries on the database',
        parameters: { query: 'string' }
      },
      {
        name: 'upload_file',
        description: 'Uploads a file to the server without validation',
        parameters: { filePath: 'string' }
      },
      {
        name: 'fetch_url',
        description: 'Fetches content from a given URL without sanitizing protocol or domain',
        parameters: { targetUrl: 'string' }
      },
      {
        name: 'update_config',
        description: 'Updates app configuration files',
        parameters: { configData: 'object' }
      },
      {
        name: 'exec_script',
        description: 'Runs arbitrary shell script provided by the user',
        parameters: { script: 'string' }
      }
    ];

    const oauthScopes = 'admin:org repo user:email files:write cloud:write security:events data:export ci:admin billing:write'
      .split(/\s+/);

    const serverConfig = {
      serverName: 'Enterprise MCP Server',
      serverUrl: 'https://vuln-demo.local:8080',
      tools,
      oauthScopes
    };

    // Disable heavy/AI features to keep test fast and deterministic
    const scanner = new ComprehensiveSecurityScanner({
      napthaIntegration: false,
      aiAnalytics: false,
      threatIntelligence: false,
      autonomousRemediation: false
    });

    const report = await scanner.performCompleteScan(serverConfig);

    const total = report?.summary?.totalVulnerabilities ?? 0;
    console.log('--- Test Scan Summary ---');
    console.log('Server:', serverConfig.serverName);
    console.log('URL:', serverConfig.serverUrl);
    console.log('Total Vulnerabilities:', total);

    // Print top findings for visibility
    const top = (report?.vulnerabilities || []).slice(0, 10);
    for (const v of top) {
      console.log(`- [${v.severity}] ${v.type || v.title || v.id}: ${v.description}`);
    }

    // Basic assertion: we expect at least one Critical/High based on input
    const hasSerious = (report?.vulnerabilities || []).some(v => ['Critical', 'High'].includes(v.severity));

    if (!hasSerious) {
      console.error('ASSERTION FAILED: Expected Critical/High findings but none were detected.');
      process.exit(1);
    }

    console.log('ASSERTION PASSED: Serious vulnerabilities detected as expected.');
    process.exit(0);
  } catch (err) {
    console.error('Test script error:', err);
    process.exit(1);
  }
})();
