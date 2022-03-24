function getFlag() {
    fetch('/api/flag', {
        method: 'GET',
    })
    .then(res => res.json())
    .then(data => {
        document.querySelector('h1').innerHTML += data.flag;
    })
}