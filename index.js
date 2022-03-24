const http = require('http');
const path = require('path');
const url = require('url');
const fs = require('fs');
const apiHandler = require('./api');

const PUBLIC_PATH = './public';
const EXT_MAP = {
    '.ico': 'image/x-icon',
    '.html': 'text/html',
    '.js': 'text/javascript',
    '.json': 'application/json',
    '.css': 'text/css',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.wav': 'audio/wav',
    '.mp3': 'audio/mpeg',
    '.svg': 'image/svg+xml',
    '.pdf': 'application/pdf',
    '.doc': 'application/msword'
};

function serverStatic(request, response) {
    const parsedUrl = url.parse(request.url);
    let pathname = `${PUBLIC_PATH}/${parsedUrl.pathname}`;
    const ext = path.parse(pathname).ext;

    if(request.url.endsWith('/')) pathname = pathname.slice(0, -1);
    if(pathname !== `${PUBLIC_PATH}/` && !ext) pathname += '.html';

    fs.exists(pathname, function (exist) {
        if(!exist) {
          response.writeHead(404);
          response.end('Not Found');
          console.log(`File ${pathname} not found`);
          return;
        }
    
        if (fs.statSync(pathname).isDirectory()) pathname += 'index.html';
    
        fs.readFile(pathname, function(err, data){
          if(err){
            response.writeHead(500);
            response.end(`Error getting the file: ${err}.`);
          } else {
            response.setHeader('Content-type', EXT_MAP[ext] || 'text/html' );
            response.end(data);
          }
        });
    });
}

function handler(request, response) {
    const { url, method } = request;

    switch(true) {
        case method === 'OPTIONS':
            response.setHeader('Access-Control-Allow-Origin', '*');
            response.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
            response.setHeader('Access-Control-Allow-Headers', '*');
            response.setHeader('Access-Control-Allow-Credentials', true);
            response.end('GET, POST, OPTIONS, PUT, PATCH, DELETE');
            break;

        case url.startsWith('/api'):
            apiHandler(request, response);
            break;

        default:
            serverStatic(request, response);
            break;
    }
}

const server = http.createServer(handler);
server.listen(process.env.PORT || process.argv[2] || 8080);