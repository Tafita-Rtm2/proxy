import rateLimit from 'express-rate-limit';

class DDoSProtection {
    constructor() {
        this.ipRequestCounts = new Map();
        this.blockedIPs = new Set();
        this.requestTimestamps = new Map();
    }

    static createRateLimiter(windowMs, maxRequests) {
        return rateLimit({
            windowMs: windowMs,
            max: maxRequests,
            message: 'Too many requests, please try again later.',
            headers: true
        });
    }

    monitorRequest(ip) {
        const now = Date.now();
        const windowStart = now - 60000;

        if (!this.requestTimestamps.has(ip)) {
            this.requestTimestamps.set(ip, []);
        }

        const timestamps = this.requestTimestamps.get(ip);
        const recentRequests = timestamps.filter(time => time > windowStart);

        recentRequests.push(now);
        this.requestTimestamps.set(ip, recentRequests);

        if (recentRequests.length > 100) {
            this.blockedIPs.add(ip);
            setTimeout(() => this.blockedIPs.delete(ip), 300000);
            return false;
        }

        return true;
    }

    isIPBlocked(ip) {
        return this.blockedIPs.has(ip);
    }

    getIPStats(ip) {
        const timestamps = this.requestTimestamps.get(ip) || [];
        const now = Date.now();
        const minuteRequests = timestamps.filter(time => time > now - 60000).length;
        const hourRequests = timestamps.filter(time => time > now - 3600000).length;

        return {
            totalRequests: timestamps.length,
            minuteRequests: minuteRequests,
            hourRequests: hourRequests,
            isBlocked: this.isIPBlocked(ip)
        };
    }

    cleanupOldRequests() {
        const now = Date.now();
        const oneHourAgo = now - 3600000;

        for (const [ip, timestamps] of this.requestTimestamps.entries()) {
            const filtered = timestamps.filter(time => time > oneHourAgo);
            if (filtered.length === 0) {
                this.requestTimestamps.delete(ip);
            } else {
                this.requestTimestamps.set(ip, filtered);
            }
        }
    }
}

export default DDoSProtection;