const axios = require('axios');

const SCRIPT_FETCH_LIMIT = 10;
const SCRIPT_FETCH_TIMEOUT = 8000;
const SCRIPT_MAX_BYTES = 500_000;

const DEFAULT_REQUEST_HEADERS = {
    'User-Agent': 'TechPrint/1.0 (Security Scanner; +https://example.com/techprint)',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
};
const SCRIPT_REQUEST_HEADERS = {
    'User-Agent': DEFAULT_REQUEST_HEADERS['User-Agent'],
    'Accept': 'application/javascript,text/javascript;q=0.9,*/*;q=0.8',
};

const SCRIPT_SRC_REGEX = /<script[^>]+src=["']([^"']+)["']/gi;

// Central detection signatures database. Keeping this backend-only helps avoid
// shipping detection heuristics publicly.
const SIGNATURE_DB = {
    // Frameworks, CMS, and Website Builders
    'React': { category: 'JavaScript Framework', confidence: 95, patterns: { html: ['data-reactroot'] } },
    'Angular': { category: 'JavaScript Framework', confidence: 95, patterns: { html: [/ng-version="([^"]+)"/i] } },
    'Vue.js': { category: 'JavaScript Framework', confidence: 95, patterns: { html: ['data-v-app', '__vue__'] } },
    'Next.js': { category: 'Web Framework', confidence: 90, patterns: { headers: { 'x-powered-by': /Next\.js/i } } },
    'Nuxt.js': { category: 'Web Framework', confidence: 95, patterns: { html: ['data-n-head-ssr', 'window.__NUXT__'] } },
    'Gatsby': { category: 'Web Framework', confidence: 100, patterns: { html: ['__gatsby'] } },
    'SvelteKit': { category: 'Web Framework', confidence: 95, patterns: { html: ['data-sveltekit-'] } },
    'WordPress': {
        category: 'CMS',
        confidence: 100,
        patterns: {
            html: ['wp-content/', 'wp-json/', /<meta name="generator" content="WordPress ([^"]+)"\s?\/?>/i],
        },
        risk: 'Ensure core, themes, and plugins are updated to the latest version to mitigate known vulnerabilities.',
    },
    'Shopify': { category: 'E-commerce', confidence: 100, patterns: { html: ['cdn.shopify.com', 'Shopify.theme'] } },
    'Drupal': { category: 'CMS', confidence: 100, patterns: { html: ['Drupal.settings', 'sites/default/files'] } },
    'Joomla': { category: 'CMS', confidence: 100, patterns: { html: ['<meta name="generator" content="Joomla!'] } },
    'Wix': { category: 'Website Builder', confidence: 100, patterns: { html: ['wix-'], headers: { 'x-wix-request-id': /.*/i } } },
    'Squarespace': { category: 'Website Builder', confidence: 100, patterns: { html: ['squarespace-'] } },
    'Webflow': {
        category: 'Website Builder',
        confidence: 95,
        patterns: { html: ['Webflow', 'wf-page', 'website-files.com'] },
    },
    'Magento': {
        category: 'E-commerce',
        confidence: 100,
        patterns: { html: ['/media/wysiwyg/'], headers: { 'set-cookie': /frontend=/i } },
    },
    'Ghost': {
        category: 'CMS',
        confidence: 100,
        patterns: { html: [/<meta name="generator" content="Ghost ([^"]+)"\s?\/?>/i] },
    },
    'Ruby on Rails': { category: 'Web Framework', confidence: 90, patterns: { headers: { 'x-powered-by': /Phusion Passenger/i } } },
    'ASP.NET': {
        category: 'Web Framework',
        confidence: 90,
        patterns: { headers: { 'x-aspnet-version': /.*/i, 'x-powered-by': /ASP\.NET/i } },
    },
    'Laravel': { category: 'Web Framework', confidence: 95, patterns: { headers: { 'set-cookie': /laravel_session/i } } },
    'Django': { category: 'Web Framework', confidence: 90, patterns: { headers: { 'set-cookie': /csrftoken/i } } },

    // Infrastructure, Servers, and CDNs
    'Vercel': { category: 'Hosting', confidence: 100, patterns: { headers: { server: /Vercel/i, 'x-vercel-id': /.*/ } } },
    'Cloudflare': {
        category: 'CDN & Security',
        confidence: 100,
        patterns: { headers: { server: /cloudflare/i, 'cf-ray': /.*/, 'cf-cache-status': /.*/ } },
    },
    'Google Frontend': { category: 'Hosting', confidence: 90, patterns: { headers: { server: /Google Frontend/i } } },
    'Netlify': { category: 'Hosting', confidence: 100, patterns: { headers: { server: /Netlify/i } } },
    'AWS S3': { category: 'Hosting', confidence: 80, patterns: { headers: { server: /S3/i } } },
    'Amazon CloudFront': {
        category: 'CDN',
        confidence: 100,
        patterns: { headers: { via: /CloudFront/i, 'x-amz-cf-id': /.*/ } },
    },
    'Fastly': {
        category: 'CDN',
        confidence: 100,
        patterns: { headers: { 'x-served-by': /cache-.*/i, 'x-fastly-request-id': /.*/ } },
    },
    'Akamai': { category: 'CDN', confidence: 100, patterns: { headers: { 'x-akamai-transformed': /.*/ } } },
    'Nginx': { category: 'Web Server', confidence: 90, patterns: { headers: { server: /nginx/i } } },
    'Apache': { category: 'Web Server', confidence: 90, patterns: { headers: { server: /apache/i } } },
    'Microsoft-IIS': { category: 'Web Server', confidence: 90, patterns: { headers: { server: /Microsoft-IIS/i } } },

    // Analytics, Marketing, and Support Widgets
    'Google Analytics': { category: 'Analytics', confidence: 100, patterns: { html: ['google-analytics.com/analytics.js', 'gtag'] } },
    'Google Tag Manager': {
        category: 'Tag Manager',
        confidence: 100,
        patterns: {
            html: ['googletagmanager.com/gtm.js', /GTM-[A-Z0-9]+/],
            headers: { 'content-security-policy': /googletagmanager\.com/i },
        },
    },
    'Hotjar': { category: 'Analytics & Feedback', confidence: 100, patterns: { html: ['static.hotjar.com'] } },
    'Intercom': {
        category: 'Customer Support',
        confidence: 100,
        patterns: { html: ['widget.intercom.io'], scripts: ['intercomsettings', 'window.intercom'] },
    },
    'Segment': { category: 'Analytics', confidence: 100, patterns: { html: ['cdn.segment.com'] } },
    'HubSpot': { category: 'Marketing Automation', confidence: 100, patterns: { html: ['js.hs-analytics.net', '_hsenc'] } },
    'Zendesk Widget': { category: 'Customer Support', confidence: 100, patterns: { html: ['static.zdassets.com'] } },
    'Facebook Pixel': { category: 'Advertising', confidence: 100, patterns: { html: ['connect.facebook.net'] } },
    'Optimizely': { category: 'A/B Testing', confidence: 100, patterns: { html: ['cdn.optimizely.com'] } },
    'Mixpanel': { category: 'Analytics', confidence: 100, patterns: { html: ['cdn.mxpnl.com'] } },
    'Drift': { category: 'Customer Support', confidence: 100, patterns: { html: ['js.driftt.com'], scripts: ['driftt.com'] } },
    'Freshchat': {
        category: 'Customer Support',
        confidence: 95,
        patterns: { html: ['wchat.freshchat.com'], scripts: ['freshchat', 'fcwidget'] },
    },
    'Stripe Chat': {
        category: 'Customer Support',
        confidence: 95,
        patterns: { html: ['UniversalChatCtaButton', 'support-conversations.stripe.com/widget'] },
    },

    // Libraries, Utilities, and Payments
    'Stripe': {
        category: 'Payments',
        confidence: 95,
        patterns: { html: ['js.stripe.com', 'b.stripecdn.com', 'stripeassets.com'] },
    },
    'PayPal': { category: 'Payments', confidence: 90, patterns: { html: ['paypal.com/sdk/js'] } },
    'jQuery': {
        category: 'JavaScript Library',
        confidence: 100,
        patterns: { html: [/jquery-?([0-9\.]+)(\.min)?\.js/i] },
        risk: 'Legacy versions of jQuery may have known XSS vulnerabilities.',
    },
    'Google Fonts': { category: 'Font Script', confidence: 100, patterns: { html: ['fonts.googleapis.com'] } },
    'Font Awesome': { category: 'Icon Library', confidence: 100, patterns: { html: ['fontawesome.com', 'fa-'] } },
    'Bootstrap': { category: 'CSS Framework', confidence: 100, patterns: { html: ['bootstrap.min.css', 'data-bs-theme'] } },
    'Modernizr': { category: 'JavaScript Library', confidence: 100, patterns: { html: ['modernizr.js', '<html class="no-js'] } },
    'Lodash': { category: 'JavaScript Library', confidence: 100, patterns: { html: ['lodash.min.js'] } },
    'GSAP': { category: 'Animation Library', confidence: 100, patterns: { html: ['gsap.min.js', 'TweenMax'] } },
    'reCAPTCHA': { category: 'Security', confidence: 100, patterns: { html: ['google.com/recaptcha/api.js'] } },
    'Sentry': {
        category: 'Error Monitoring',
        confidence: 95,
        patterns: { html: ['sentry.io', /Sentry-[A-Z0-9]+\.js/i], headers: { 'content-security-policy': /sentry\.io/i } },
    },
    'Algolia': {
        category: 'Search',
        confidence: 90,
        patterns: { html: ['algolia.net', 'algolianet.com'], headers: { 'content-security-policy': /algolianet\.com/i } },
    },
    'Contentful': {
        category: 'Headless CMS',
        confidence: 85,
        patterns: { headers: { 'content-security-policy': /contentful\.com/i, 'frame-ancestors': /contentful\.com/i } },
    },
};

function extractScriptUrls(html) {
    const urls = [];
    let match;
    while ((match = SCRIPT_SRC_REGEX.exec(html)) !== null) {
        urls.push(match[1]);
    }
    return urls;
}

function resolveResourceUrl(baseUrl, resourcePath) {
    try {
        return new URL(resourcePath, baseUrl).toString();
    } catch (error) {
        return null;
    }
}

async function buildScriptCorpus(scriptUrls) {
    const pieces = [];
    const fetched = [];

    for (const scriptUrl of scriptUrls) {
        try {
            const response = await axios.get(scriptUrl, {
                headers: SCRIPT_REQUEST_HEADERS,
                timeout: SCRIPT_FETCH_TIMEOUT,
                maxRedirects: 3,
                validateStatus: () => true,
            });

            if (!response || response.status >= 400) {
                continue;
            }

            const data = response.data;
            const text =
                typeof data === 'string'
                    ? data
                    : data && typeof data.toString === 'function'
                        ? data.toString()
                        : '';

            if (text) {
                fetched.push(scriptUrl);
                pieces.push(text.slice(0, SCRIPT_MAX_BYTES));
            }
        } catch (error) {
            // Ignore script fetch failures; deep scan is best-effort.
        }
    }

    return { corpus: pieces.join('\n'), fetched };
}

async function performScan(targetUrl) {
    if (!targetUrl) {
        throw new Error('URL parameter is required.');
    }

    const response = await axios.get(targetUrl, {
        headers: DEFAULT_REQUEST_HEADERS,
        timeout: 10000,
        maxRedirects: 5,
        validateStatus: () => true,
    });

    const finalUrl =
        (response.request && response.request.res && response.request.res.responseUrl) || targetUrl;

    const html =
        typeof response.data === 'string'
            ? response.data
            : (response.data && typeof response.data.toString === 'function'
                ? response.data.toString()
                : '');
    const headers = response.headers || {};

    const scriptUrls = Array.from(new Set(extractScriptUrls(html)))
        .map((src) => resolveResourceUrl(finalUrl, src))
        .filter(Boolean)
        .slice(0, SCRIPT_FETCH_LIMIT);

    const { corpus: scriptCorpus, fetched: fetchedScripts } = await buildScriptCorpus(scriptUrls);

    const detections = [];

    Object.entries(SIGNATURE_DB).forEach(([tech, details]) => {
        let matched = false;
        let version = 'Unknown';

        const checkPatterns = (dataSource, patterns) => {
            if (typeof dataSource !== 'string' || !dataSource.length) {
                return;
            }

            const dataSourceLower = dataSource.toLowerCase();

            for (const pattern of patterns) {
                if (typeof pattern === 'string') {
                    if (dataSourceLower.includes(pattern.toLowerCase())) {
                        matched = true;
                        break;
                    }
                } else if (pattern instanceof RegExp) {
                    const match = dataSource.match(pattern);
                    if (match) {
                        matched = true;
                        if (match[1]) version = match[1].trim();
                        break;
                    }
                }
            }
        };

        if (details.patterns.html) {
            checkPatterns(html, details.patterns.html);
        }
        if (details.patterns.headers) {
            Object.entries(details.patterns.headers).forEach(([header, pattern]) => {
                const headerValue = headers[header.toLowerCase()];
                if (headerValue && String(headerValue).match(pattern)) {
                    matched = true;
                }
            });
        }
        if (details.patterns.scripts) {
            checkPatterns(scriptCorpus, details.patterns.scripts);
        }

        if (matched) {
            detections.push({
                name: tech,
                category: details.category,
                confidence: details.confidence,
                version,
                risk: details.risk || null,
            });
        }
    });

    return {
        scan_metadata: {
            target_url: targetUrl,
            resolved_url: finalUrl,
            scan_timestamp_utc: new Date().toISOString(),
            status_code: response.status,
            script_sources_attempted: scriptUrls,
            script_sources_fetched: fetchedScripts,
        },
        detected_technologies: detections,
    };
}

module.exports = {
    performScan,
    SIGNATURE_DB,
};
