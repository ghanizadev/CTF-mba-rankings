module.exports = {
    parseHeaderArray: function(headers) {
    return headers.reduce((p, c, i, a) => {
        if (i % 2 === 0) return { ...p, [c.toLowerCase()]: a[i + 1] };
        return p;
        }, {});
    },
    parseCookies: function (cookies) {
        return cookies
            .split(';')
            .map(v => v.split('='))
            .reduce((acc, v) => {
            acc[decodeURIComponent(v[0].trim())] = decodeURIComponent(v[1].trim());
            return acc;
            }, {});
    },
    validatePasswordFormat: function(password) {
        return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(password);
    },
    basicInputFieldSanitizer: function (fieldValue){
        return fieldValue
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');
}
}