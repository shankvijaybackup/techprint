const express = require('express');
const cors = require('cors');
const path = require('path');
const { performScan } = require('./scanner');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());

app.get('/', (_req, res) => {
    res.sendFile(path.join(__dirname, 'techprint.html'));
});

app.get('/api/scan', async (req, res) => {
    const targetUrl = req.query.url;

    if (!targetUrl) {
        return res.status(400).json({ error: 'URL parameter is required.' });
    }

    try {
        const result = await performScan(targetUrl);
        res.json(result);
    } catch (error) {
        console.error(`Error scanning ${targetUrl}:`, error.message);
        res.status(500).json({
            error: `Failed to fetch or analyze the URL. Please check if the URL is correct and accessible. (${error.message})`,
        });
    }
});

app.listen(PORT, () => {
    console.log(`TechPrint backend server running on http://localhost:${PORT}`);
    console.log(`Open http://localhost:${PORT}/ in your browser to use the TechPrint UI.`);
});
