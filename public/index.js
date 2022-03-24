function getFlag() {
    fetch('/api/flag', {
        method: 'GET',
    })
    .then(res => res.json())
    .then(data => {
        document.querySelector('h1#flag').innerText += data.flag;
    })
}

function getUserProfile() {
    fetch('/api/profile', {
        method: 'GET',
    })
    .then(res => res.json())
    .then(data => {
        document.querySelector('h1#username').innerText += data.username;
    })
}

function init() {
    getUserProfile();
    getFlag();
}