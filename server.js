// Express server for MCP Guardian Enterprise Dashboard
const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Serve static files (JS, CSS, images, etc.)
app.use(express.static(__dirname));

// Serve the main dashboard HTML
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'enterprise_security_hub.html'));
});

app.listen(PORT, () => {
    console.log(`🌐 MCP Guardian Enterprise Dashboard running at http://localhost:${PORT}`);
});
