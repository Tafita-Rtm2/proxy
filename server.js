import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import cors from 'cors';
import helmet from 'helmet';
import Utilities from './utilities.js';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Middleware to generate a request ID
app.use((req, res, next) => {
    req.requestId = Utilities.generateRequestId();
    next();
});

app.get('/', (req, res) => {
    const targetUrl = req.query.url || req.body.url;

    if (!targetUrl) {
        return res.status(400).json({ error: 'Target URL is required' });
    }

    if (!Utilities.validateUrl(targetUrl)) {
        return res.status(400).json({ error: 'Invalid URL format' });
    }

    const sanitizedUrl = Utilities.sanitizeInput(targetUrl);
    res.json({ 
        proxyUrl: `${req.protocol}://${req.get('host')}/proxy?url=${encodeURIComponent(sanitizedUrl)}`,
        originalUrl: sanitizedUrl,
        requestId: req.requestId
    });
});

app.use('/proxy', (req, res, next) => {
    const targetUrl = req.query.url;

    if (!targetUrl) {
        return res.status(400).json({ error: 'Target URL is required' });
    }

    if (!Utilities.validateUrl(targetUrl)) {
        return res.status(400).json({ error: 'Invalid URL format' });
    }

    const sanitizedUrl = Utilities.sanitizeInput(targetUrl);

    const dynamicProxy = createProxyMiddleware({
        target: sanitizedUrl,
        changeOrigin: true,
        pathRewrite: {
            '^/proxy': '',
        },
        followRedirects: false, // Let client handle redirects
        timeout: 10000,
        proxyTimeout: 10000,
        secure: true,
        ssl: {
            rejectUnauthorized: false
        },
        onProxyReq: (proxyReq, req, res) => {
            // Set a common user agent to avoid fingerprinting
            proxyReq.setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36');

            // Remove headers that could reveal the proxy's nature or the user's original IP
            proxyReq.removeHeader('x-forwarded-for');
            proxyReq.removeHeader('x-forwarded-proto');
            proxyReq.removeHeader('x-forwarded-host');
        },
        onProxyRes: (proxyRes, req, res) => {
            // Rewrite the Location header for redirects to keep the user within the proxy
            if (proxyRes.headers['location']) {
                try {
                    const targetUrl = new URL(proxyRes.headers['location'], sanitizedUrl);
                    const proxyHost = req.get('host');
                    const proxyProtocol = req.protocol;
                    // Important: hpm modifies the original response, so we need to set headers on `res`
                    res.setHeader('location', `${proxyProtocol}://${proxyHost}/proxy?url=${encodeURIComponent(targetUrl.href)}`);
                } catch (error) {
                    // Ignore invalid location headers
                }
            }
        },
        onError: (err, req, res) => {
            res.status(500).json({ error: 'Proxy error occurred', details: err.message });
        }
    });

    dynamicProxy(req, res, next);
});

app.get('/health', async (req, res) => {
    const health = {
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage()
    };
    res.json(health);
});

app.use((err, req, res, next) => {
    res.status(500).json({ error: 'Internal server error', requestId: req.requestId });
});

app.listen(PORT, () => {
    console.log(`Secure Proxy Server running on port ${PORT}`);
});
