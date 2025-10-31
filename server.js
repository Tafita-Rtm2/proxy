import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import cors from 'cors';
import helmet from 'helmet';
import Utilities from './utilities.js';
import path from 'path';
import { fileURLToPath } from 'url';
import { ProxyAgent } from 'proxy-agent';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3000;

const frenchProxies = [
    'socks4://37.44.238.2:52611', 'http://51.38.191.151:443',   'http://51.254.213.34:443',
    'http://62.138.18.91:443',     'http://130.180.208.145:443', 'http://51.158.253.115:443',
    'http://51.158.253.130:443',  'http://51.158.253.120:443',  'http://51.158.253.113:443',
    'http://51.158.253.153:443',  'http://51.158.253.152:443',  'http://51.158.252.252:443',
    'http://51.158.253.114:443',  'http://51.158.252.160:443',  'http://51.158.253.128:443',
    'http://51.158.253.154:443',  'http://51.158.253.45:443',   'http://51.158.253.77:443',
    'http://51.158.253.78:443',   'http://141.94.246.168:443',  'http://51.210.148.119:443',
    'http://145.239.196.123:443', 'http://162.19.49.131:443',   'http://94.23.9.170:443',
    'http://51.159.225.129:8118', 'http://212.83.168.126:8081', 'http://51.159.226.157:443',
    'http://51.159.226.159:443',  'http://51.159.226.153:443',  'http://51.159.226.154:443',
    'http://51.159.226.151:443',  'http://51.159.226.150:443',  'http://51.159.226.155:443',
    'http://51.159.226.149:443',  'http://51.159.226.156:443',  'http://51.159.226.162:443',
    'http://51.159.226.128:443',  'http://51.159.226.160:443',  'http://51.159.226.158:443',
    'http://51.159.226.161:443',  'http://51.159.226.152:443',  'http://51.159.226.129:443',
    'http://51.158.253.130:14991','http://51.159.225.194:23767','http://51.158.204.131:23767',
    'http://51.158.253.45:7901',  'http://51.158.253.115:17401','http://51.159.226.154:17401',
    'http://51.158.202.102:8118', 'http://51.159.225.202:8118','http://51.159.226.149:7081',
    'http://51.158.252.3:443',    'http://51.159.226.159:10243','http://51.158.252.160:10074',
    'http://51.158.253.152:10243','http://51.159.226.151:10074','http://51.159.226.159:5094',
    'http://51.159.226.128:15846','http://51.158.252.50:15846', 'http://51.159.225.196:23856',
    'http://51.159.225.197:19362','http://51.158.204.131:3004', 'http://51.159.226.153:7901',
    'http://146.59.198.90:443',   'http://51.158.252.149:16684','http://51.159.226.126:16684',
    'http://51.158.253.45:5299',  'http://51.158.204.46:21384','http://51.159.226.161:19030',
    'http://51.159.226.156:10472','http://51.158.253.152:5698', 'http://51.159.226.159:5698',
    'http://51.159.226.126:443',  'http://51.158.36.17:443',    'http://51.158.205.139:443',
    'http://51.159.28.39:443',    'http://51.158.205.179:443',  'http://163.172.167.48:443',
    'http://176.162.240.186:443','http://51.159.226.148:443',  'http://51.159.226.125:443',
    'http://51.158.204.215:443','http://51.159.15.12:443',    'http://51.15.228.52:8080',
    'http://37.187.109.70:10111', 'http://185.41.152.110:3128', 'http://205.237.104.203:3128',
    'http://51.91.96.190:8080',   'http://67.43.236.20:15743',  'http://144.24.200.164:80',
    'http://173.245.49.247:80',   'http://173.245.49.192:80',   'http://173.245.49.52:80',
    'http://173.245.49.237:80',   'http://173.245.49.118:80',   'http://173.245.49.45:80'
];

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.use('/proxy', (req, res, next) => {
    const targetUrl = req.query.url;
    console.log(`[${new Date().toISOString()}] New proxy request for: ${targetUrl}`);

    if (!targetUrl) return res.status(400).json({ error: 'Target URL is required' });
    if (!Utilities.validateUrl(targetUrl)) return res.status(400).json({ error: 'Invalid URL format' });

    const sanitizedUrl = Utilities.sanitizeInput(targetUrl);
    const targetOrigin = new URL(sanitizedUrl).origin;
    const country = req.query.country;
    let retries = 3;
    let usedProxies = new Set();

    const tryProxy = () => {
        if (retries <= 0) {
            console.log(`[${new Date().toISOString()}] Failing request. All ${usedProxies.size} proxy attempts failed.`);
            return res.status(502).json({ error: 'Failed to connect through French proxies after several attempts.' });
        }
        retries--;

        let agent;
        let randomProxy;
        if (country === 'france') {
            const availableProxies = frenchProxies.filter(p => !usedProxies.has(p));
            if (availableProxies.length === 0) {
                console.log(`[${new Date().toISOString()}] Failing request. No more available proxies to try.`);
                return res.status(503).json({ error: 'No more available French proxies to try.' });
            }
            randomProxy = availableProxies[Math.floor(Math.random() * availableProxies.length)];
            usedProxies.add(randomProxy);
            console.log(`[${new Date().toISOString()}] Attempting to proxy via: ${randomProxy} (${retries + 1} attempts left)`);
            agent = new ProxyAgent(randomProxy);
        }

        const proxy = createProxyMiddleware({
            target: sanitizedUrl,
            changeOrigin: true,
            selfHandleResponse: true,
            agent: agent,
            cookieDomainRewrite: "",
            cookiePathRewrite: { "*": "/" },
            timeout: 15000,
            proxyTimeout: 15000,
            pathRewrite: { '^/proxy': '' },
            onProxyReq: (proxyReq) => {
                proxyReq.setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36');
                proxyReq.setHeader('Accept-Encoding', 'identity');
            },
            onProxyRes: (proxyRes, req, res) => {
                // Si le proxy externe renvoie une erreur 5xx, on le considère comme un échec et on réessaie.
                if (proxyRes.statusCode >= 500 && proxyRes.statusCode <= 599) {
                    console.error(`[${new Date().toISOString()}] Proxy ${randomProxy} returned status ${proxyRes.statusCode}. Retrying...`);
                    return tryProxy();
                }

                console.log(`[${new Date().toISOString()}] Successfully connected via ${randomProxy}`);
                const proxyHost = req.get('host');
                const proxyProtocol = req.protocol;
                const proxifyUrl = (originalUrl) => {
                    try {
                        const absoluteUrl = new URL(originalUrl, targetOrigin).href;
                        let proxyUrl = `${proxyProtocol}://${proxyHost}/proxy?url=${encodeURIComponent(absoluteUrl)}`;
                        if (country) proxyUrl += `&country=${country}`;
                        return proxyUrl;
                    } catch (e) { return originalUrl; }
                };

                if (proxyRes.headers['set-cookie']) {
                    proxyRes.headers['set-cookie'] = proxyRes.headers['set-cookie'].map(c => c.replace(/; secure/ig, ''));
                }
                if (proxyRes.headers['location']) {
                    res.setHeader('location', proxifyUrl(proxyRes.headers['location']));
                    res.writeHead(proxyRes.statusCode);
                    return res.end();
                }

                const contentType = proxyRes.headers['content-type'] || '';
                if (!/^(text\/html|text\/css|application\/javascript|application\/json)/.test(contentType)) {
                    return proxyRes.pipe(res);
                }

                const chunks = [];
                proxyRes.on('data', chunk => chunks.push(chunk));
                proxyRes.on('end', () => {
                    let body = Buffer.concat(chunks).toString();
                    const rewrittenBody = body
                        .replace(/(href|src|action|poster|data-src)=["'](\/[^/][^"']*)["']/g, (m, attr, url) => `${attr}="${proxifyUrl(url)}"`)
                        .replace(/(href|src|action)=["'](\/\/[^"']+)["']/g, (m, attr, url) => `${attr}="${proxifyUrl(`https:${url}`)}"`)
                        .replace(/url\(\s*['"]?(\/.*?)['"]?\s*\)/g, (m, url) => `url(${proxifyUrl(url)})`);
                    res.writeHead(proxyRes.statusCode, proxyRes.headers);
                    res.end(rewrittenBody);
                });
            },
            onError: (err, req, res) => {
                console.error(`[${new Date().toISOString()}] Proxy error with ${randomProxy}: ${err.message}`);
                tryProxy();
            }
        });
        proxy(req, res, next);
    };

    tryProxy();
});

app.get('/health', (req, res) => res.json({ status: 'OK', timestamp: new Date().toISOString() }));
app.use((err, req, res, next) => {
    console.error(`[${new Date().toISOString()}] Unhandled internal server error:`, err);
    res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => console.log(`[${new Date().toISOString()}] Secure Proxy Server running on port ${PORT}`));
