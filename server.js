'use strict';

const express = require('express');
const compression = require('compression');
const path = require('node:path');
const { createStore } = require('./src/store');
const { createChecker } = require('./src/checker');
const { createScheduler } = require('./src/scheduler');
const { hashToken } = require('./src/auth');

const store = createStore();
const checker = createChecker(store);
const scheduler = createScheduler(store, checker);
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(compression());
app.use(express.json({ limit: '100kb' }));
app.use((_req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'strict-origin-when-cross-origin', 'Content-Security-Policy': "default-src 'self'; img-src 'self' data: blob:; style-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" });
  next();
});

const publicDir = path.join(__dirname, 'public');
app.get('/healthz', (_req, res) => res.type('text').send('ok'));

function readCookie(req, key) {
  const part = String(req.headers.cookie || '').split(';').map((x) => x.trim()).find((x) => x.startsWith(`${key}=`));
  if (!part) return '';
  try { return decodeURIComponent(part.slice(key.length + 1)); } catch { return ''; }
}
const authAttempts = new Map();
function authRateLimit(req, res, next) {
  const now = Date.now(); const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const state = authAttempts.get(ip);
  if (state && state.until > now && state.count >= 10) return res.status(429).json({ error: 'Too many attempts. Try again in a few minutes.' });
  if (!state || state.until <= now) authAttempts.set(ip, { count: 1, until: now + 15 * 60 * 1000 });
  else state.count += 1;
  if (authAttempts.size > 5000) for (const [key, value] of authAttempts) if (value.until <= now) authAttempts.delete(key);
  next();
}
function issueSession(res, user) {
  const session = store.createSession(user.id);
  res.cookie('changewatch_session', session.token, { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', path: '/', maxAge: 30 * 86400000 });
  return { id: user.id, email: user.email };
}
app.post('/api/auth/signup', authRateLimit, async (req, res) => {
  try { const user = await store.createUser(req.body?.email, req.body?.password); res.status(201).json(issueSession(res, user)); }
  catch (error) { apiError(res, error); }
});
app.post('/api/auth/signin', authRateLimit, async (req, res) => {
  try {
    const user = await store.authenticate(req.body?.email, req.body?.password);
    if (!user) return res.status(401).json({ error: 'Email or password is incorrect.' });
    res.json(issueSession(res, user));
  } catch (error) { apiError(res, error); }
});
app.post('/api/auth/signout', (req, res) => {
  store.deleteSession(readCookie(req, 'changewatch_session'));
  res.clearCookie('changewatch_session', { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', path: '/' });
  res.status(204).end();
});
app.get('/api/auth/me', (req, res) => {
  const user = store.sessionUser(readCookie(req, 'changewatch_session'));
  if (!user) return res.status(401).json({ error: 'Sign in required.' });
  res.json(user);
});
app.use('/api', (req, res, next) => {
  if (req.path.startsWith('/auth/')) return next();
  const user = store.sessionUser(readCookie(req, 'changewatch_session'));
  if (!user) return res.status(401).json({ error: 'Sign in required.' });
  req.user = user;
  next();
});
app.use(express.static(publicDir, { etag: true, maxAge: 0 }));

function apiError(res, error) {
  const status = error.status || 400;
  res.status(status).json({ error: error.message || 'Request failed' });
}
function pageId(req) {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) throw Object.assign(new Error('Invalid page id'), { status: 400 });
  return id;
}

app.get('/api/pages', (req, res) => res.json(store.listPages(req.user.id)));
app.post('/api/pages', async (req, res) => {
  try {
    const page = store.addPage(req.body || {}, req.user.id);
    scheduler.enqueue(page.id);
    res.status(201).json(page);
  } catch (error) { apiError(res, error); }
});
app.get('/api/pages/:id', (req, res) => {
  try { const page = store.getOwnedPage(pageId(req), req.user.id); if (!page) return res.status(404).json({ error: 'Page not found' }); res.json(page); }
  catch (error) { apiError(res, error); }
});
app.patch('/api/pages/:id', (req, res) => {
  try { res.json(store.updatePage(pageId(req), req.body || {}, req.user.id)); }
  catch (error) { apiError(res, error); }
});
app.delete('/api/pages/:id', async (req, res) => {
  try { const id = pageId(req); if (!store.getOwnedPage(id, req.user.id)) return res.status(404).json({ error: 'Page not found' }); await checker.closePicker(id); store.deletePage(id, req.user.id); res.status(204).end(); }
  catch (error) { apiError(res, error); }
});
app.post('/api/pages/:id/check', async (req, res) => {
  try { const id = pageId(req); if (!store.getOwnedPage(id, req.user.id)) return res.status(404).json({ error: 'Page not found' }); res.json(await scheduler.enqueue(id, true)); }
  catch (error) { apiError(res, error); }
});
app.get('/api/pages/:id/versions', (req, res) => {
  try { res.json(store.listSnapshots(pageId(req), req.user.id)); } catch (error) { apiError(res, error); }
});
app.get('/api/pages/:id/checks', (req, res) => {
  try { res.json(store.checkHistory(pageId(req), 40, req.user.id)); } catch (error) { apiError(res, error); }
});
app.get('/api/pages/:id/versions/:version/screenshot', (req, res) => {
  try {
    const image = store.snapshotImage(pageId(req), Number(req.params.version), req.user.id);
    if (!image) return res.status(404).end();
    res.type('png').set('Cache-Control', 'private, max-age=300').send(image);
  } catch (error) { apiError(res, error); }
});
app.get('/api/pages/:id/compare', async (req, res) => {
  try {
    const id=pageId(req); if (!store.getOwnedPage(id, req.user.id)) return res.status(404).json({ error: 'Page not found' });
    const result = await checker.compare(id, Number(req.query.a), Number(req.query.b));
    res.json(result);
  } catch (error) { apiError(res, error); }
});
app.post('/api/pages/:id/picker', async (req, res) => {
  try { const id=pageId(req); if (!store.getOwnedPage(id, req.user.id)) return res.status(404).json({ error: 'Page not found' }); res.json(await checker.openPicker(id)); } catch (error) { apiError(res, error); }
});
app.post('/api/pages/:id/picker/select', async (req, res) => {
  try { const id=pageId(req); if (!store.getOwnedPage(id, req.user.id)) return res.status(404).json({ error: 'Page not found' }); res.json(await checker.pickSelector(id, req.body || {})); } catch (error) { apiError(res, error); }
});
app.delete('/api/pages/:id/picker', async (req, res) => {
  try { const id=pageId(req); if (!store.getOwnedPage(id, req.user.id)) return res.status(404).json({ error: 'Page not found' }); await checker.closePicker(id); res.status(204).end(); } catch (error) { apiError(res, error); }
});
app.post('/api/pages/:id/feed-token', (req, res) => {
  try { const id=pageId(req); const token=store.issueFeedToken(id, req.user.id); res.json({ url: `/feeds/${id}.xml?token=${encodeURIComponent(token)}` }); } catch (error) { apiError(res, error); }
});
app.get('/feeds/:id.xml', (req, res) => {
  try {
    const id = pageId(req);
    if (!store.verifyFeedToken(id, req.query.token)) return res.status(404).end();
    const xml = store.rss(id);
    res.type('application/rss+xml').send(xml);
  } catch (error) { apiError(res, error); }
});
app.get('/api/stats', (req, res) => res.json(store.stats(req.user.id)));

const server = app.listen(process.env.PORT || 3000, () => console.log(`Changewatch listening on ${server.address().port}`));
const shutdown = async () => {
  scheduler.stop();
  server.close(async () => { await checker.close(); store.close(); process.exit(0); });
  setTimeout(() => process.exit(1), 10000).unref();
};
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

module.exports = { app, server, store, checker, scheduler };
