// Entry point for MCP Guardian Enterprise Platform
// Starts the Security Dashboard and all core modules

const { SecurityDashboard } = require('./security_dashboard.js');

console.log('🚀 Starting MCP Guardian Enterprise Platform...');

const dashboard = new SecurityDashboard();

// Optionally, you can expose dashboard for REPL or further scripting
module.exports = dashboard;
