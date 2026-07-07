const { isAuthed } = require('./_lib/auth');

module.exports = (req, res) => {
  if (req.method !== 'GET') {
    res.status(405).json({ ok: false });
    return;
  }

  if (!isAuthed(req)) {
    res.status(401).json({ ok: false });
    return;
  }

  res.status(200).json({ ok: true, shareUrl: process.env.PLAUSIBLE_SHARE_URL || '' });
};
