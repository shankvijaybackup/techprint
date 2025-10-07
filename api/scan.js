const { performScan } = require('../scanner');

module.exports = async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.status(204).end();
        return;
    }

    if (req.method !== 'GET') {
        res.status(405).json({ error: 'Method not allowed. Use GET.' });
        return;
    }

    const targetUrl = req.query.url;
    if (!targetUrl) {
        res.status(400).json({ error: 'URL parameter is required.' });
        return;
    }

    try {
        const result = await performScan(targetUrl);
        res.status(200).json(result);
    } catch (error) {
        console.error(`Error scanning ${targetUrl}:`, error.message);
        res.status(500).json({
            error: `Failed to fetch or analyze the URL. Please check if the URL is correct and accessible. (${error.message})`,
        });
    }
};
