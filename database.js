const fs = require('fs');

class Database {
    static instance;
    data = [];
    t;

    constructor() {
        const file = fs.readFileSync('db');
        this.data = JSON.parse(file.toString('utf-8'));
    }

    static getInstance() {
        if(!this.instance) this.instance = new Database();
        return this.instance;
    }

    insert(user) {
        this.data.push(user);
        this.flush();
    }

    getByUsername(username) {
        return this.data.find((user) => user.username === username)
    }

    getById(userId) {
        return this.data.find((user) => user.id === userId)
    }

    update(userId, userData) {
        const index = this.data.find(({id}) => id === userId);

        if(index < 0) return;

        const user = {...this.data[index], ...userData}
        this.data.splice(index, 1, user);
        this.flush();

        return user;
    }

    flush() {
        if(this.t) clearTimeout(t);

        this.t = setTimeout(() => {
            fs.writeFileSync('db', JSON.stringify(this.data, null, 2));
            clearTimeout(this.t);
        }, 100);
    }
}

module.exports = Database;