exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ok: false, error: 'method_not_allowed' }),
    };
  }

  let payload;
  try {
    payload = JSON.parse(event.body || '{}');
  } catch {
    return {
      statusCode: 400,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ok: false, error: 'invalid_json' }),
    };
  }

  const expectedUsername = process.env.VERIFIER_USERNAME;
  const expectedPassword = process.env.VERIFIER_PASSWORD;

  if (!expectedUsername || !expectedPassword) {
    return {
      statusCode: 503,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ok: false, error: 'verifier_not_configured' }),
    };
  }

  const ok = payload.username === expectedUsername
    && payload.password === expectedPassword;

  return {
    statusCode: ok ? 200 : 401,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ok }),
  };
};
