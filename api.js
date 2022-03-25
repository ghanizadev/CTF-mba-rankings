const querystring = require('querystring');
const crypto = require('crypto');
const Database = require('./database');
const auth = require('./auth');
const RateLimiter = require('./rate-limiter');
const { parseHeaderArray, parseCookies, validatePasswordFormat } = require('./helper');

function helloWorld(request, response) {
    response.writeHead(200, 'OK', ['Content-Type', 'application/json']);
    response.end(JSON.stringify({message: 'Hello world!'}))
}

function authorize(request, response) {
    request.on('data', (data) => {
        if(!data) {
            response.writeHead(400, 'Bad Request', ['Content-Type', 'application/json']);
            response.end(JSON.stringify({ message: 'BAD REQUEST' }));
            return;
        }

        const body = data.toString('utf-8');
        const { username, password } = querystring.parse(body);

        const user = Database.getInstance().getByUsername(username);

        if(user && auth.compare(password, user.password)) {
            const cookie = `__HOST_SID=${encodeURIComponent(auth.session(user))}; Max-Age=86400; Secure; HttpOnly; Path=/; SameSite=Strict`;
            response.writeHead(307, 'Temporary Redirect', ['Location', '/dashboard', 'Set-Cookie', cookie]);
            response.end();
            return;
        }

        response.writeHead(401, 'Unauthorized', ['Content-Type', 'application/json']);
        response.end(JSON.stringify({ message: 'UNAUTHORIZED' }));
    })
}

function logout(request, response) {
    const cookie = `__HOST_SID=${encodeURIComponent('popcorn')}; Max-Age=0; Path=/; SameSite=Strict`;
    response.writeHead(307, 'Temporary Redirect', ['Location', '/', 'Set-Cookie', cookie]);
    response.end();
}

function register(request, response) {
    request.on('data', (data) => {
        if(!data) {
            response.writeHead(400, 'Bad Request', ['Content-Type', 'application/json']);
            response.end(JSON.stringify({ message: 'BAD REQUEST' }));
            return;
        }

        const body = data.toString('utf-8');
        const id = crypto.randomBytes(12).toString('hex')
        const { username, password } = querystring.parse(body);

        if(username.length < 4 && username.length > 12) {
            response.writeHead(400, 'Bad Request', ['Content-Type', 'application/json']);
            response.end(JSON.stringify({ message: 'INVALID USERNAME' }));
            return;
        }

        if(!validatePasswordFormat(password)) {
            response.writeHead(400, 'Bad Request', ['Content-Type', 'application/json']);
            response.end(JSON.stringify({ message: 'INVALID PASSWORD FORMAT' }));
            return;
        }

        const exists = Database.getInstance().getByUsername(username);

        if(exists) {
            response.writeHead(400, 'Bad Request', ['Content-Type', 'application/json']);
            response.end(JSON.stringify({ message: 'USERNAME IN USE' }));
            return;
        }

        const flag = crypto.randomBytes(16).toString('base64url');

        const user = {
            id,
            username,
            password: auth.hash(password),
            flag
        }

        Database.getInstance().insert(user);

        const cookie = `__HOST_SID=${encodeURIComponent(auth.session(user))}; Max-Age=86400; Secure; HttpOnly; Path=/; SameSite=Strict`;
        response.writeHead(307, 'Temporary Redirect', ['Location', '/dashboard', 'Set-Cookie', cookie]);
        response.end();
        return;
    })
}

function getRequestInfo(request, response) {
    const {cookie} = parseHeaderArray(request.rawHeaders);
    if(!cookie) {
        response.writeHead(401, 'Unauthorized');
        response.end('C01');
        return;
    }

    const {__HOST_SID} = parseCookies(cookie);
    if(!__HOST_SID) {
        response.writeHead(401, 'Unauthorized');
        response.end('C02');
        return;
    }

    const userId = auth.validateSession(__HOST_SID);
    if(!userId) {
        const cookie = `__HOST_SID=${encodeURIComponent('popcorn')}; Max-Age=0; Secure; HttpOnly; Path=/; SameSite=Strict`;
        response.writeHead(401, 'Unauthorized', ['Set-Cookie', cookie]);
        response.end('C03');
        return;
    }

    const user = Database.getInstance().getById(userId);

    if(!user) {
        const cookie = `__HOST_SID=${encodeURIComponent('popcorn')}; Max-Age=0; Secure; HttpOnly; Path=/; SameSite=Strict`;
        response.writeHead(401, 'Unauthorized', ['Set-Cookie', cookie]);
        response.end('C04');
        return;
    }

    return {...user};
}

function updatePassword(request, response) {
    request.on('data', (data) => {
        if(!data) {
            response.writeHead(400, 'Bad Request', ['Content-Type', 'application/json']);
            response.end(JSON.stringify({ message: 'BAD REQUEST' }));
            return;
        }

        const user = getRequestInfo(request, response);
        if(!user) return;

        const body = data.toString('utf-8');
        const { oldPassword, newPassword, confirmPassword } = querystring.parse(body);

        if(!validatePasswordFormat(newPassword)) {
            response.writeHead(400, 'Bad Request', ['Content-Type', 'application/json']);
            response.end(JSON.stringify({ message: 'INVALID PASSWORD FORMAT' }));
            return;
        }

        if(confirmPassword !== newPassword) {
            response.writeHead(400, 'Bad Request', ['Content-Type', 'application/json']);
            response.end(JSON.stringify({ message: 'NEW PASSWORD DOES NOT MATCH' }));
            return;
        }

        if(!auth.compare(oldPassword, user.password)) {
            response.writeHead(400, 'Bad Request', ['Content-Type', 'application/json']);
            response.end(JSON.stringify({ message: 'PASSWORD DOES NOT MATCH' }));
            return;
        }

        if(!newPassword) {
            response.writeHead(400, 'Bad Request', ['Content-Type', 'application/json']);
            response.end(JSON.stringify({ message: 'INVALID PASSWORD' }));
            return;
        }

        Database.getInstance().update(user.id, {
            password: auth.hash(newPassword)
        });

        logout(request, response);
    })
}

function profile(request, response) {
    const user = getRequestInfo(request, response);
    if(!user) {
        logout(request, response);
        return;
    }

    delete user.password;

    response.writeHead(200, 'OK', ['Content-Type', 'application/json']);
    response.end(JSON.stringify(user));    
}

module.exports = function (request, response) {
    try {
        const { url, method } = request;
        const headers = parseHeaderArray(request.rawHeaders);

        if(!RateLimiter.getInstance().check(headers['x-forwarded-for'] || request.socket.remoteAddress)) {
            response.writeHead(429, 'Too Many Requests');
            response.end();
            return;
        }

        switch(true){
            case url === '/api/login' && method === 'POST':
                authorize(...arguments);
                break;
    
            case url === '/api/register' && method === 'POST':
                register(...arguments);
                break;
    
            case url === '/api/logout' && method === 'GET':
                logout(...arguments);
                break;
    
            case url === '/api/update-password' && method === 'POST':
                updatePassword(...arguments);
                break;

            case url === '/api/profile' && method === 'GET':
                profile(...arguments);
                break;

            case url === '/api/test' && method === 'GET':
                response.writeHead(200, 'OK');
                response.end();
                break;
    
            default:
                helloWorld(...arguments);
                break;
        }
    } catch(e) {
        console.log(e);
        response.writeHead(500, 'Internal Error');
        response.end();
        return;
    }
}