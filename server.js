import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import cors from 'cors';
import helmet from 'helmet';
import Utilities from './utilities.js';
import DDoSProtection from './ddos-protection.js';

const app = express();
const PORT = process.env.PORT || 3000;
const ddosProtection = new DDoSProtection();

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

const generalLimiter = DDoSProtection.createRateLimiter(60000, 100);
app.use(generalLimiter);

app.use((req, res, next) => {
    const clientIP = Utilities.getClientIP(req);
    req.requestId = Utilities.generateRequestId();

    if (ddosProtection.isIPBlocked(clientIP)) {
        return res.status(429).json({ error: 'IP temporarily blocked due to excessive requests' });
    }

    if (!ddosProtection.monitorRequest(clientIP)) {
        return res.status(429).json({ error: 'Request rate limit exceeded' });
    }

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
        followRedirects: true,
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
        onError: (err, req, res) => {
            res.status(500).json({ error: 'Proxy error occurred', details: err.message });
        }
    });

    dynamicProxy(req, res, next);
});

app.get('/stats/:ip?', (req, res) => {
    const ip = req.params.ip || Utilities.getClientIP(req);
    const stats = ddosProtection.getIPStats(ip);
    res.json(stats);
});

app.get('/health', async (req, res) => {
    const health = {
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        blockedIPs: Array.from(ddosProtection.blockedIPs).length
    };
    res.json(health);
});

setInterval(() => ddosProtection.cleanupOldRequests(), 3600000);

app.use((err, req, res, next) => {
    res.status(500).json({ error: 'Internal server error', requestId: req.requestId });
});

app.listen(PORT, () => {
    console.log(`Secure Proxy Server running on port ${PORT}`);
});
