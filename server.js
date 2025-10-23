import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import cors from 'cors';
import helmet from 'helmet';
import zlib from 'zlib';
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
    const targetOrigin = new URL(sanitizedUrl).origin;

    const dynamicProxy = createProxyMiddleware({
        target: sanitizedUrl,
        changeOrigin: true,
        selfHandleResponse: true, // This is key to rewriting content
        cookieDomainRewrite: "", // Rewrite cookie domains to the proxy's domain
        cookiePathRewrite: { // Rewrite cookie paths to be generic
            "*": "/"
        },
        timeout: 30000,
        proxyTimeout: 30000,
        
        onProxyReq: (proxyReq, req, res) => {
            proxyReq.setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36');
            proxyReq.removeHeader('x-forwarded-for');
            proxyReq.removeHeader('x-forwarded-proto');
            proxyReq.removeHeader('x-forwarded-host');
        },

        onProxyRes: (proxyRes, req, res) => {
            // Handle cookies to make them work better over the proxy
            if (proxyRes.headers['set-cookie']) {
                const cookies = proxyRes.headers['set-cookie'].map(cookie => {
                    return cookie.replace(/; secure/ig, ''); // Allow secure cookies even if proxy is not https
                });
                proxyRes.headers['set-cookie'] = cookies;
            }

            const proxyHost = req.get('host');
            const proxyProtocol = req.protocol;

            const proxifyUrl = (originalUrl) => {
                try {
                    const absoluteUrl = new URL(originalUrl, targetOrigin).href;
                    return `${proxyProtocol}://${proxyHost}/proxy?url=${encodeURIComponent(absoluteUrl)}`;
                } catch (e) {
                    return originalUrl;
                }
            };

            // Handle redirects
            if (proxyRes.headers['location']) {
                res.setHeader('location', proxifyUrl(proxyRes.headers['location']));
                res.writeHead(proxyRes.statusCode);
                res.end();
                return;
            }

            // Don't rewrite non-text content (images, etc.)
            const contentType = proxyRes.headers['content-type'] || '';
            if (!/^(text\/html|text\/css|application\/javascript|application\/json)/.test(contentType)) {
                proxyRes.pipe(res);
                return;
            }

            const chunks = [];
            proxyRes.on('data', chunk => chunks.push(chunk));
            proxyRes.on('end', () => {
                const buffer = Buffer.concat(chunks);
                const contentEncoding = proxyRes.headers['content-encoding'];
                let body;

                try {
                    if (contentEncoding === 'gzip') {
                        body = zlib.gunzipSync(buffer).toString();
                    } else if (contentEncoding === 'deflate') {
                        body = zlib.inflateSync(buffer).toString();
                    } else {
                        body = buffer.toString();
                    }
                } catch (e) {
                    res.writeHead(proxyRes.statusCode, proxyRes.headers);
                    res.end(buffer);
                    return;
                }

                // Rewrite URLs in the body
                const rewrittenBody = body
                    .replace(/(href|src|action|poster|data-src)=["'](\/[^/][^"']*)["']/g, (match, attr, url) => `${attr}="${proxifyUrl(url)}"`)
                    .replace(/(href|src|action)=["'](\/\/[^"']+)["']/g, (match, attr, url) => `${attr}="${proxifyUrl(`https:${url}`)}"`)
                    .replace(/url\(\s*['"]?(\/.*?)['"]?\s*\)/g, (match, url) => `url(${proxifyUrl(url)})`)
                    .replace(new RegExp(targetOrigin.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), `${proxyProtocol}://${proxyHost}/proxy?url=${encodeURIComponent(targetOrigin)}`);

                delete proxyRes.headers['content-length'];
                delete proxyRes.headers['content-encoding'];
                res.writeHead(proxyRes.statusCode, proxyRes.headers);

                if (contentEncoding === 'gzip') {
                    res.end(zlib.gzipSync(rewrittenBody));
                } else if (contentEncoding === 'deflate') {
                    res.end(zlib.deflateSync(rewrittenBody));
                } else {
                    res.end(rewrittenBody);
                }
            });
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
