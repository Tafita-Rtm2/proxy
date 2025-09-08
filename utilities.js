import axios from 'axios';

class Utilities {
    static validateUrl(url) {
        try {
            new URL(url);
            return true;
        } catch {
            return false;
        }
    }

    static sanitizeInput(input) {
        if (typeof input !== 'string') return '';
        return input.replace(/[<>"'`]/g, '');
    }

    static async checkServiceHealth(url) {
        try {
            const response = await axios.get(url, { timeout: 5000 });
            return response.status === 200;
        } catch {
            return false;
        }
    }

    static generateRequestId() {
        return Date.now().toString(36) + Math.random().toString(36).substr(2);
    }

    static getClientIP(req) {
        return req.ip || req.connection.remoteAddress || req.socket.remoteAddress || (req.connection.socket ? req.connection.socket.remoteAddress : null);
    }
}

export default Utilities;