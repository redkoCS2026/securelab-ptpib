(function () {
  const nativeFetch = window.fetch.bind(window);
  const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
  const noToken = ['/api/auth/csrf-token', '/api/auth/login', '/api/auth/register'];

  async function getToken() {
    const response = await nativeFetch('/api/auth/csrf-token', { credentials: 'same-origin' });
    if (!response.ok) return null;
    const body = await response.json();
    return body.token;
  }

  window.fetch = async function (input, init) {
    const options = init || {};
    const isRequest = input instanceof Request;
    const method = (options.method || (isRequest ? input.method : 'GET')).toUpperCase();
    const url = new URL(isRequest ? input.url : input, location.href);

    if (safeMethods.includes(method) || url.origin !== location.origin || noToken.includes(url.pathname)) {
      return nativeFetch(input, init);
    }

    const token = await getToken();
    const headers = new Headers(options.headers || (isRequest ? input.headers : undefined));
    if (token) headers.set('X-Lab-CSRF', token);
    return nativeFetch(input, { ...options, headers });
  };
})();