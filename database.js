const fs = require('fs');

class Database {
    static instance;
    static data = [];
    static t;

    constructor() {
        const file = fs.readFileSync('db');
        this.data = JSON.parse(file.toString('utf-8'));
    }

    static getInstance() {
        if(!this.instance) this.instance = new Database();
        return this.instance;
    }

    static insert(user) {
        this.data.push(user);
        this.flush();
    }

    static get(userId) {
        return this.data.find(({id}) => id === userId)
    }

    static update(userId, userData) {
        const index = this.data.find(({id}) => id === userId);

        if(index < 0) return;

        const user = {...this.data[index], ...userData}
        this.data.splice(index, 1, user)

        return user;
    }

    static flush() {
        if(this.t) clearTimeout(t);

        this.t = setTimeout(() => {
            fs.writeFileSync('db', JSON.stringify(this.data, null, 2));
            clearTimeout(this.t);
        }, 100);
    }
}

module.exports = Database;