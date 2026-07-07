const crypto = require('crypto');
const { ADMIN_PASSWORD, COOKIE_NAME, SESSION_MAX_AGE_MS, makeToken } = require('./_lib/auth');

module.exports = (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).json({ ok: false });
    return;
  }

  let password = '';
  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});
    password = body.password || '';
  } catch (e) {}

  const a = Buffer.from(password);
  const b = Buffer.from(ADMIN_PASSWORD);
  const match = ADMIN_PASSWORD.length > 0 && a.length === b.length && crypto.timingSafeEqual(a, b);

  if (match) {
    const token = makeToken();
    res.setHeader(
      'Set-Cookie',
      `${COOKIE_NAME}=${encodeURIComponent(token)}; HttpOnly; Path=/; Max-Age=${SESSION_MAX_AGE_MS / 1000}; SameSite=Strict; Secure`
    );
    res.status(200).json({ ok: true });
  } else {
    res.status(401).json({ ok: false });
  }
};
