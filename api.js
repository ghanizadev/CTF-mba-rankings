const querystring = require('querystring');
const crypto = require('crypto');
const Database = require('./database');
const auth = require('./auth')

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
            response.writeHead(307, 'Temporary Redirect', ['Location', '/dashboard']);
            response.end();
            return;
        }

        response.writeHead(401, 'Unauthorized', ['Content-Type', 'application/json']);
        response.end(JSON.stringify({ message: 'UNAUTHORIZED' }));
    })
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
            flag
        }

        Database.getInstance().insert({ ...user, password: auth.hash(password) });

        response.writeHead(201, 'Created', ['Content-Type', 'application/json']);
        response.end(JSON.stringify(user));
        return;
    })
}

function getFlag(request, response) {
    response.writeHead(200, 'OK', ['Content-Type', 'application/json']);
    response.end(JSON.stringify({ flag: 'v=dQw4w9WgXcQ' }));
}

module.exports = function (request) {
    const { url, method } = request;

    switch(true){
        case url === '/api/login' && method === 'POST':
            authorize(...arguments);
            break;

        case url === '/api/flag' && method === 'GET':
            getFlag(...arguments);
            break;

        case url === '/api/register' && method === 'POST':
            register(...arguments);
            break;

        default:
            helloWorld(...arguments);
            break;
    }
}