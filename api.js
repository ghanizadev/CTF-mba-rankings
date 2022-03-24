const querystring = require('querystring');

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

        if(username === 'admin' && password === 'admin') {
            response.writeHead(307, 'Temporary Redirect', ['Location', '/dashboard']);
            response.end();
            return;
        }

        response.writeHead(401, 'Unauthorized', ['Content-Type', 'application/json']);
        response.end(JSON.stringify({ message: 'UNAUTHORIZED' }));
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

        default:
            helloWorld(...arguments);
            break;
    }
}