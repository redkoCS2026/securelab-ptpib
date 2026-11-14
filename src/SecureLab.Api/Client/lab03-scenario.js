const out = document.getElementById('out');

function value(id) {
    return document.getElementById(id).value;
}

function clearPasswords() {
    document.getElementById('reg-pass').value = '';
    document.getElementById('log-pass').value = '';
}

async function send(step, method, url, payload) {
    const options = { method: method, headers: {}, credentials: 'same-origin' };
    if (payload !== undefined) {
        options.headers['Content-Type'] = 'application/json';
        options.body = JSON.stringify(payload);
    }
    const response = await fetch(url, options);
    const text = await response.text();
    out.textContent = step + '\n' + method + ' ' + url + '\nHTTP ' + response.status + '\n' + text;
    return response.status;
}

document.getElementById('btn-register').addEventListener('click', async () => {
    await send('Реєстрація', 'POST', '/api/auth/register', {
        userName: value('reg-login'),
        email: value('reg-mail'),
        displayName: value('reg-name'),
        password: value('reg-pass')
    });
    clearPasswords();
});

document.getElementById('btn-login').addEventListener('click', async () => {
    await send('Вхід', 'POST', '/api/auth/login', {
        userName: value('log-login'),
        password: value('log-pass')
    });
    clearPasswords();
});

document.getElementById('btn-me').addEventListener('click', () =>
    send('Профіль', 'GET', '/api/me'));

document.getElementById('btn-create').addEventListener('click', () => {
    const when = value('inc-time');
    send('Створення інциденту', 'POST', '/api/incidents', {
        title: value('inc-title'),
        description: value('inc-desc'),
        severity: value('inc-sev'),
        occurredAtUtc: when ? new Date(when).toISOString() : new Date().toISOString()
    });
});

document.getElementById('btn-logout').addEventListener('click', () =>
    send('Вихід', 'POST', '/api/auth/logout'));