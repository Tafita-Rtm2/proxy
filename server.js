import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import cors from 'cors';
import helmet from 'helmet';
import Utilities from './utilities.js';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.use('/proxy', (req, res, next) => {
    const targetUrl = req.query.url;
    const country = req.query.country;

    if (!targetUrl) return res.status(400).json({ error: 'Target URL is required' });
    if (!Utilities.validateUrl(targetUrl)) return res.status(400).json({ error: 'Invalid URL format' });

    const sanitizedUrl = Utilities.sanitizeInput(targetUrl);
    const targetOrigin = new URL(sanitizedUrl).origin;

    const dynamicProxy = createProxyMiddleware({
        target: sanitizedUrl,
        changeOrigin: true,
        selfHandleResponse: true,
        cookieDomainRewrite: "",
        cookiePathRewrite: { "*": "/" },
        timeout: 30000,
        proxyTimeout: 30000,
        pathRewrite: { '^/proxy': '' },

        onProxyReq: (proxyReq, req, res) => {
            proxyReq.setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36');
            proxyReq.setHeader('Accept-Encoding', 'identity');
            proxyReq.removeHeader('x-forwarded-for');
            proxyReq.removeHeader('x-forwarded-proto');
            proxyReq.removeHeader('x-forwarded-host');

            if (country === 'france') {
                proxyReq.setHeader('X-Forwarded-For', '195.154.29.111'); // IP française
            }
        },

        onProxyRes: (proxyRes, req, res) => {
            const proxyHost = req.get('host');
            const proxyProtocol = req.protocol;

            const proxifyUrl = (originalUrl) => {
                try {
                    const absoluteUrl = new URL(originalUrl, targetOrigin).href;
                    let proxyUrl = `${proxyProtocol}://${proxyHost}/proxy?url=${encodeURIComponent(absoluteUrl)}`;
                    if (country) {
                        proxyUrl += `&country=${country}`;
                    }
                    return proxyUrl;
                } catch (e) { return originalUrl; }
            };

            if (proxyRes.headers['set-cookie']) {
                proxyRes.headers['set-cookie'] = proxyRes.headers['set-cookie'].map(cookie => cookie.replace(/; secure/ig, ''));
            }

            if (proxyRes.headers['location']) {
                res.setHeader('location', proxifyUrl(proxyRes.headers['location']));
                res.writeHead(proxyRes.statusCode);
                res.end();
                return;
            }

            const contentType = proxyRes.headers['content-type'] || '';
            if (!/^(text\/html|text\/css|application\/javascript|application\/json)/.test(contentType)) {
                proxyRes.pipe(res);
                return;
            }

            const chunks = [];
            proxyRes.on('data', chunk => chunks.push(chunk));
            proxyRes.on('end', () => {
                let body = Buffer.concat(chunks).toString();

                const rewrittenBody = body
                    .replace(/(href|src|action|poster|data-src)=["'](\/[^/][^"']*)["']/g, (match, attr, url) => `${attr}="${proxifyUrl(url)}"`)
                    .replace(/(href|src|action)=["'](\/\/[^"']+)["']/g, (match, attr, url) => `${attr}="${proxifyUrl(`https:${url}`)}"`)
                    .replace(/url\(\s*['"]?(\/.*?)['"]?\s*\)/g, (match, url) => `url(${proxifyUrl(url)})`);

                res.writeHead(proxyRes.statusCode, proxyRes.headers);
                res.end(rewrittenBody);
            });
        },

        onError: (err, req, res) => {
            res.status(500).json({ error: 'Proxy error occurred', details: err.message });
        }
    });

    dynamicProxy(req, res, next);
});

app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage()
    });
});

app.use((err, req, res, next) => {
    res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
    console.log(`Secure Proxy Server running on port ${PORT}`);
});
