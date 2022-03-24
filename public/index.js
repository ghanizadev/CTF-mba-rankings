function getUserProfile() {
    return fetch('/api/profile', {
        method: 'GET',
    })
    .then(res => res.json())
}

async function init() {
    const { username, flag } = await getUserProfile();
    document.querySelector('h1#message').innerText = `Hello ${username}, your flag is ${flag}`;
    document.querySelector('#logoutContainer').style.display = "block";
}