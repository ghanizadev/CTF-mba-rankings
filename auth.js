const crypto = require('crypto');
const Database = require('./database');

module.exports = {
    hash: function(password) {
        const salt = crypto.randomBytes(16).toString('base64url');
        const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha256').toString('base64url');
        return `${salt}.${hash}`
    },
    compare: function(input, password) {
        const [salt, hash] = password.split('.');
        const hashedInput = crypto.pbkdf2Sync(input, salt, 100000, 64, 'sha256').toString('base64url');
        return hash === hashedInput;
    },
    session(user) {
        const [salt] = user.password.split('.');
        const payload = Buffer.from(`${user.id}#${Date.now()}`, 'utf-8').toString('base64url');
        const signature =  crypto.pbkdf2Sync(payload, salt, 100000, 64, 'sha256').toString('base64url');

        return `${payload}.${signature}`;
    },
    validateSession(sessionToken) {
        const [payload, signature] = sessionToken.split('.');
        const decoded = Buffer.from(payload, 'base64url').toString('utf-8');
        const [id] = decoded.split('#');
        const user = Database.getInstance().getById(id);

        if(!user) return false;

        const [salt] = user.password.split('.');
        const hash = crypto.pbkdf2Sync(payload, salt, 100000, 64, 'sha256').toString('base64url');
        if (hash === signature) return id;
        return false;
    }
}