const crypto = require('crypto');

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
    }
}