class RateLimiter {
    static instance;
    clients = [];
    timeout = 1000;
    limit = 3;

    static getInstance() {
        if(!this.instance) this.instance = new RateLimiter();
        return this.instance;
    }
    
    check(ip) {
        const index = this.clients.findIndex(c => c[0] === ip);

        if(index < 0) {
            this.clients.push([ip, 1, Date.now(), -1]);
            return true;
        }

        const [_, times, timestamp, timeout] = this.clients[index];

        console.log({times})

        if(timeout) clearTimeout(timeout);

        const t = setTimeout(() => {
            this.clients.splice(index, 1);
            clearTimeout(timeout);
        }, this.timeout);

        this.clients[index][3] = t;

        if(times >= this.limit) return false;

        if(Date.now() - timestamp <= this.timeout) {
            this.clients.splice(index, 1, [ip, times + 1, timestamp, t]);
            return true;
        }

        return true;
    }
}

module.exports = RateLimiter;