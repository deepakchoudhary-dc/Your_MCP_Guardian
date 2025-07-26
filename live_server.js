/**
 * Simple HTTP Server for MCP Guardian Enterprise Dashboard
 * No dependencies required - uses built-in Node.js modules
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

const PORT = process.env.PORT || 3000;

// MIME types for different file extensions
const mimeTypes = {
    '.html': 'text/html',
    '.js': 'text/javascript',
    '.css': 'text/css',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon'
};

function getMimeType(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    return mimeTypes[ext] || 'application/octet-stream';
}

const server = http.createServer((req, res) => {
    try {
        let filePath = url.parse(req.url).pathname;
        
        // Default to enterprise_security_hub.html for root path
        if (filePath === '/') {
            filePath = '/enterprise_security_hub.html';
        }
        
        // Remove leading slash and resolve full path
        const fullPath = path.join(__dirname, filePath.substring(1));
        
        // Security check - prevent directory traversal
        if (!fullPath.startsWith(__dirname)) {
            res.writeHead(403, { 'Content-Type': 'text/plain' });
            res.end('403 Forbidden');
            return;
        }
        
        // Check if file exists
        fs.access(fullPath, fs.constants.F_OK, (err) => {
            if (err) {
                console.log(`404 - File not found: ${filePath}`);
                res.writeHead(404, { 'Content-Type': 'text/html' });
                res.end(`
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>404 - File Not Found</title>
                        <style>
                            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                            h1 { color: #ff6b6b; }
                        </style>
                    </head>
                    <body>
                        <h1>404 - File Not Found</h1>
                        <p>The requested file <strong>${filePath}</strong> was not found.</p>
                        <p><a href="/">Return to MCP Guardian Dashboard</a></p>
                    </body>
                    </html>
                `);
                return;
            }
            
            // Read and serve the file
            fs.readFile(fullPath, (err, data) => {
                if (err) {
                    console.error(`Error reading file ${filePath}:`, err);
                    res.writeHead(500, { 'Content-Type': 'text/plain' });
                    res.end('500 Internal Server Error');
                    return;
                }
                
                const mimeType = getMimeType(fullPath);
                res.writeHead(200, { 
                    'Content-Type': mimeType,
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                    'Pragma': 'no-cache',
                    'Expires': '0'
                });
                res.end(data);
                
                console.log(`✅ Served: ${filePath} (${mimeType})`);
            });
        });
        
    } catch (error) {
        console.error('Server error:', error);
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('500 Internal Server Error');
    }
});

// Handle server errors
server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`❌ Port ${PORT} is already in use. Please try a different port.`);
        console.log(`   Try: PORT=3001 node live_server.js`);
    } else {
        console.error('❌ Server error:', err);
    }
    process.exit(1);
});

// Start the server
server.listen(PORT, () => {
    console.log('\n🚀 MCP Guardian Enterprise Platform - Live Server Started!');
    console.log('═'.repeat(60));
    console.log(`🌐 Dashboard URL: http://localhost:${PORT}`);
    console.log(`📁 Serving files from: ${__dirname}`);
    console.log(`⚡ Server running on port: ${PORT}`);
    console.log('═'.repeat(60));
    console.log('📊 Available endpoints:');
    console.log(`   • Main Dashboard: http://localhost:${PORT}/`);
    console.log(`   • Enterprise Hub: http://localhost:${PORT}/enterprise_security_hub.html`);
    console.log(`   • Legacy Hub: http://localhost:${PORT}/mcp_security_hub.html`);
    console.log('═'.repeat(60));
    console.log('🔧 Server ready - Access your MCP Guardian Enterprise Dashboard!');
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🔄 Shutting down MCP Guardian server...');
    server.close(() => {
        console.log('✅ Server shutdown complete');
        process.exit(0);
    });
});

process.on('SIGTERM', () => {
    console.log('\n🔄 Received SIGTERM, shutting down gracefully...');
    server.close(() => {
        console.log('✅ Server shutdown complete');
        process.exit(0);
    });
});
