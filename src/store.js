'use strict';

const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const { DatabaseSync } = require('node:sqlite');
const { URL } = require('node:url');
const { emailAddress, passwordHash, passwordMatches, newSessionToken, hashToken } = require('./auth');

const MIN_INTERVAL = 15 * 60;
const MAX_INTERVAL = 24 * 60 * 60;
const DEFAULT_IGNORE = 'script,style,noscript,svg,iframe,nav,footer,[aria-hidden="true"],[class~="ad"],[id*="advert" i],[class*="advert" i],[class*="sponsor" i],[class*="banner" i],[class*="carousel" i],[class*="ticker" i],[class*="clock" i],time';

function isPrivateIpv4(address) {
  const [a, b] = address.split('.').map(Number);
  return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}
function mappedIpv4(address) {
  if (!address.startsWith('::ffff:')) return '';
  let mapped = address.slice(7);
  if (net.isIPv4(mapped)) return mapped;
  const groups = mapped.split(':');
  if (groups.length !== 2 || !groups.every((x) => /^[0-9a-f]{1,4}$/.test(x))) return '';
  const value = (parseInt(groups[0], 16) * 65536 + parseInt(groups[1], 16)) >>> 0;
  return [value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join('.');
}

function validPublicUrl(value) {
  let url;
  try { url = new URL(String(value || '').trim()); } catch { throw new Error('Enter a valid public URL.'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error('Only public HTTP or HTTPS URLs are supported.');
  if ([...url.searchParams.keys()].some((key) => /^(?:access_?token|api_?key|auth|authorization|key|password|secret|session(?:id)?|signature|token)$/i.test(key))) throw new Error('URLs with credential-like query parameters are not supported.');
  if (url.hostname === 'localhost' || url.hostname.endsWith('.localhost') || url.hostname.endsWith('.local') || url.hostname === 'metadata.google.internal') throw new Error('Private and local addresses are not allowed.');
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (net.isIPv4(host) && isPrivateIpv4(host)) {
    throw new Error('Private and local addresses are not allowed.');
  } else if (net.isIPv6(host)) {
    const address = host.toLowerCase();
    const mapped = mappedIpv4(address);
    if (address === '::1' || address === '::' || address.startsWith('fc') || address.startsWith('fd') || /^fe[89ab]/i.test(address) || (mapped && isPrivateIpv4(mapped))) throw new Error('Private and local addresses are not allowed.');
  }
  return url.toString();
}
function selectors(value, name) {
  if (value == null || value === '') return [];
  const list = Array.isArray(value) ? value : String(value).split(',');
  const result = list.map((x) => String(x).trim()).filter(Boolean);
  if (result.length > 20 || result.some((x) => x.length > 300 || /[<>]/.test(x))) throw new Error(`${name} must contain up to 20 valid CSS selectors.`);
  return result;
}
function makePage(row) {
  if (!row) return null;
  return { ...row, watchSelectors: JSON.parse(row.watch_selectors), ignoreSelectors: JSON.parse(row.ignore_selectors), keywords: JSON.parse(row.keywords), sensitivity: row.sensitivity };
}
function createStore() {
  const dataDir = path.resolve(process.env.DATA_DIR || path.join(__dirname, '..', 'data'));
  fs.mkdirSync(dataDir, { recursive: true });
  const db = new DatabaseSync(path.join(dataDir, 'changewatch.sqlite'));
  db.exec('PRAGMA auto_vacuum = INCREMENTAL; PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      email TEXT NOT NULL COLLATE NOCASE UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
    CREATE TABLE IF NOT EXISTS pages (
      id INTEGER PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      url TEXT NOT NULL,
      name TEXT NOT NULL,
      interval_seconds INTEGER NOT NULL DEFAULT 3600,
      sensitivity TEXT NOT NULL DEFAULT 'medium',
      watch_selectors TEXT NOT NULL DEFAULT '[]',
      ignore_selectors TEXT NOT NULL DEFAULT '[]',
      keywords TEXT NOT NULL DEFAULT '[]',
      alert_email TEXT NOT NULL DEFAULT '',
      discord_enabled INTEGER NOT NULL DEFAULT 0,
      telegram_chat_id TEXT NOT NULL DEFAULT '',
      daily_digest INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      next_check_at TEXT NOT NULL,
      last_checked_at TEXT,
      last_changed_at TEXT,
      status TEXT NOT NULL DEFAULT 'waiting',
      last_error TEXT,
      last_hash TEXT,
      muted_until TEXT,
      feed_token_hash TEXT,
      UNIQUE(user_id,url)
    );
    CREATE TABLE IF NOT EXISTS checks (
      id INTEGER PRIMARY KEY,
      page_id INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
      checked_at TEXT NOT NULL,
      status TEXT NOT NULL,
      http_status INTEGER,
      text_hash TEXT,
      text TEXT,
      screenshot BLOB,
      metrics TEXT NOT NULL DEFAULT '{}',
      error TEXT,
      duration_ms INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS checks_page_time ON checks(page_id, checked_at DESC);
    CREATE TABLE IF NOT EXISTS snapshots (
      id INTEGER PRIMARY KEY,
      page_id INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
      check_id INTEGER NOT NULL UNIQUE REFERENCES checks(id) ON DELETE CASCADE,
      version INTEGER NOT NULL,
      content_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      summary TEXT NOT NULL DEFAULT '',
      UNIQUE(page_id, version)
    );
    CREATE TABLE IF NOT EXISTS alert_outbox (
      id INTEGER PRIMARY KEY,
      page_id INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
      snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
      channel TEXT NOT NULL,
      sent_at TEXT,
      attempts INTEGER NOT NULL DEFAULT 0,
      last_error TEXT,
      UNIQUE(snapshot_id, channel)
    );
    CREATE TABLE IF NOT EXISTS digest_delivery (
      page_id INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
      digest_date TEXT NOT NULL,
      sent_at TEXT NOT NULL,
      PRIMARY KEY(page_id,digest_date)
    );
  `);
  // Upgrade the original single-user schema, removing its global URL uniqueness
  // so separate accounts can independently monitor the same public address.
  const pageSql = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='pages'").get()?.sql || '';
  if (/url\s+TEXT\s+NOT\s+NULL\s+UNIQUE/i.test(pageSql) || !db.prepare('PRAGMA table_info(pages)').all().some((c) => c.name === 'user_id')) {
    db.exec('PRAGMA foreign_keys=OFF; BEGIN IMMEDIATE;');
    try {
      const existing = db.prepare('PRAGMA table_info(pages)').all().map((c) => c.name);
      const fields = ['id','user_id','url','name','interval_seconds','sensitivity','watch_selectors','ignore_selectors','keywords','alert_email','discord_enabled','telegram_chat_id','daily_digest','created_at','next_check_at','last_checked_at','last_changed_at','status','last_error','last_hash','muted_until','feed_token_hash'];
      db.exec(`CREATE TABLE pages_new (
        id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, url TEXT NOT NULL, name TEXT NOT NULL,
        interval_seconds INTEGER NOT NULL DEFAULT 3600, sensitivity TEXT NOT NULL DEFAULT 'medium',
        watch_selectors TEXT NOT NULL DEFAULT '[]', ignore_selectors TEXT NOT NULL DEFAULT '[]', keywords TEXT NOT NULL DEFAULT '[]',
        alert_email TEXT NOT NULL DEFAULT '', discord_enabled INTEGER NOT NULL DEFAULT 0, telegram_chat_id TEXT NOT NULL DEFAULT '',
        daily_digest INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, next_check_at TEXT NOT NULL, last_checked_at TEXT,
        last_changed_at TEXT, status TEXT NOT NULL DEFAULT 'waiting', last_error TEXT, last_hash TEXT, muted_until TEXT,
        feed_token_hash TEXT, UNIQUE(user_id,url)
      );`);
      const copyFields = fields.filter((name) => existing.includes(name));
      db.exec(`INSERT INTO pages_new(${copyFields.join(',')}) SELECT ${copyFields.join(',')} FROM pages; DROP TABLE pages; ALTER TABLE pages_new RENAME TO pages; COMMIT;`);
    } catch (error) { db.exec('ROLLBACK;'); throw error; }
    finally { db.exec('PRAGMA foreign_keys=ON;'); }
  }
  const snapshotColumns = db.prepare('PRAGMA table_info(snapshots)').all().map((column) => column.name);
  if (!snapshotColumns.includes('summary')) db.exec("ALTER TABLE snapshots ADD COLUMN summary TEXT NOT NULL DEFAULT ''");
  const checkColumns = db.prepare('PRAGMA table_info(checks)').all().map((column) => column.name);
  if (!checkColumns.includes('metrics')) db.exec("ALTER TABLE checks ADD COLUMN metrics TEXT NOT NULL DEFAULT '{}'");
  const pageColumns = db.prepare('PRAGMA table_info(pages)').all().map((column) => column.name);
  if (!pageColumns.includes('discord_enabled')) db.exec('ALTER TABLE pages ADD COLUMN discord_enabled INTEGER NOT NULL DEFAULT 0');
  if (pageColumns.includes('alert_webhook')) {
    db.exec("UPDATE pages SET alert_webhook = '';");
    db.exec('ALTER TABLE pages DROP COLUMN alert_webhook');
  }

  const stmt = {
    list: db.prepare(`SELECT p.*, (SELECT COUNT(*) FROM snapshots s WHERE s.page_id=p.id) AS version_count,
      (SELECT MAX(checked_at) FROM checks c WHERE c.page_id=p.id) AS last_checked_at FROM pages p WHERE p.user_id=? ORDER BY COALESCE(p.last_changed_at,p.created_at) DESC`),
    get: db.prepare('SELECT * FROM pages WHERE id=?'),
    add: db.prepare(`INSERT INTO pages(user_id,url,name,interval_seconds,sensitivity,watch_selectors,ignore_selectors,keywords,alert_email,discord_enabled,telegram_chat_id,daily_digest,created_at,next_check_at)
      VALUES(@userId,@url,@name,@interval,@sensitivity,@watch,@ignore,@keywords,@email,@discord,@telegram,@digest,@now,@now)`),
    versions: db.prepare(`SELECT s.id,s.version,s.content_hash,s.created_at,s.summary,c.text,c.status,c.http_status,c.error,c.duration_ms
      FROM snapshots s JOIN checks c ON c.id=s.check_id WHERE s.page_id=? ORDER BY s.version DESC`),
  };

  function listPages(userId) {
    if (userId == null) return db.prepare(`SELECT p.*, (SELECT COUNT(*) FROM snapshots s WHERE s.page_id=p.id) AS version_count,
      (SELECT MAX(checked_at) FROM checks c WHERE c.page_id=p.id) AS last_checked_at FROM pages p WHERE p.user_id IS NULL ORDER BY COALESCE(p.last_changed_at,p.created_at) DESC`).all().map(makePage);
    return stmt.list.all(userId).map(makePage);
  }
  function getPage(id) { return makePage(stmt.get.get(id)); }
  function getOwnedPage(id, userId) { return makePage(db.prepare('SELECT * FROM pages WHERE id=? AND user_id=?').get(id, userId)); }
  function addPage(input, userId = null) {
    const url = validPublicUrl(input.url);
    if (!new URL(url).hostname.includes('.')) throw new Error('Use a fully qualified public hostname.');
    const existing = userId == null ? db.prepare('SELECT * FROM pages WHERE url=? AND user_id IS NULL').get(url) : db.prepare('SELECT * FROM pages WHERE url=? AND user_id=?').get(url, userId);
    if (existing) return makePage(existing);
    const name = String(input.name || new URL(url).hostname).trim().slice(0, 100);
    if (!name) throw new Error('Name is required.');
    const interval = Number(input.intervalSeconds || Number(input.intervalMinutes) * 60 || 3600);
    if (!Number.isInteger(interval) || interval < MIN_INTERVAL || interval > MAX_INTERVAL) throw new Error('Check interval must be between 15 minutes and 24 hours.');
    const sensitivity = ['low', 'medium', 'high'].includes(input.sensitivity) ? input.sensitivity : 'medium';
    const keywords = selectors(input.keywords, 'Keywords').map((x) => x.slice(0, 100));
    const watch = selectors(input.watchSelectors, 'Watch regions');
    const ignore = selectors(input.ignoreSelectors, 'Ignore regions');
    const email = String(input.alertEmail || '').trim().slice(0, 254);
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error('Enter a valid alert email.');
    const telegram = String(input.telegramChatId || '').trim().slice(0, 100);
    const now = new Date().toISOString();
    const result = stmt.add.run({ userId, url, name, interval, sensitivity, watch: JSON.stringify(watch), ignore: JSON.stringify(ignore), keywords: JSON.stringify(keywords), email, discord: input.discordEnabled ? 1 : 0, telegram, digest: input.dailyDigest ? 1 : 0, now });
    return getPage(result.lastInsertRowid);
  }
  function updatePage(id, input, userId) {
    const page = userId == null ? getPage(id) : getOwnedPage(id, userId); if (!page) throw Object.assign(new Error('Page not found'), { status: 404 });
    const next = { ...page };
    if ('name' in input) { next.name = String(input.name).trim().slice(0, 100); if (!next.name) throw new Error('Name is required.'); }
    if ('intervalMinutes' in input || 'intervalSeconds' in input) {
      const value = Number(input.intervalSeconds ?? Number(input.intervalMinutes) * 60);
      if (!Number.isInteger(value) || value < MIN_INTERVAL || value > MAX_INTERVAL) throw new Error('Check interval must be between 15 minutes and 24 hours.');
      next.interval_seconds = value;
    }
    if ('sensitivity' in input) { if (!['low', 'medium', 'high'].includes(input.sensitivity)) throw new Error('Sensitivity must be low, medium, or high.'); next.sensitivity = input.sensitivity; }
    if ('watchSelectors' in input) next.watchSelectors = selectors(input.watchSelectors, 'Watch regions');
    if ('ignoreSelectors' in input) next.ignoreSelectors = selectors(input.ignoreSelectors, 'Ignore regions');
    if ('keywords' in input) next.keywords = selectors(input.keywords, 'Keywords').map((x) => x.slice(0, 100));
    if ('alertEmail' in input) { next.alert_email = String(input.alertEmail || '').trim(); if (next.alert_email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(next.alert_email)) throw new Error('Enter a valid alert email.'); }
    if ('discordEnabled' in input) next.discord_enabled = input.discordEnabled ? 1 : 0;
    if ('telegramChatId' in input) next.telegram_chat_id = String(input.telegramChatId || '').trim().slice(0, 100);
    if ('dailyDigest' in input) next.daily_digest = input.dailyDigest ? 1 : 0;
    const nextCheckAt = ('intervalMinutes' in input || 'intervalSeconds' in input) ? new Date().toISOString() : page.next_check_at;
    db.prepare(`UPDATE pages SET name=?, interval_seconds=?, sensitivity=?, watch_selectors=?, ignore_selectors=?, keywords=?, alert_email=?, discord_enabled=?, telegram_chat_id=?, daily_digest=?, next_check_at=? WHERE id=?`)
      .run(next.name, next.interval_seconds, next.sensitivity, JSON.stringify(next.watchSelectors), JSON.stringify(next.ignoreSelectors), JSON.stringify(next.keywords), next.alert_email, next.discord_enabled, next.telegram_chat_id, next.daily_digest, nextCheckAt, id);
    return getPage(id);
  }
  function deletePage(id, userId) { return (userId == null ? db.prepare('DELETE FROM pages WHERE id=?').run(id) : db.prepare('DELETE FROM pages WHERE id=? AND user_id=?').run(id, userId)).changes > 0; }
  function saveCheck(page, result) {
    const checked = new Date().toISOString();
    db.exec('BEGIN IMMEDIATE');
    try {
      const info = db.prepare(`INSERT INTO checks(page_id,checked_at,status,http_status,text_hash,text,screenshot,metrics,error,duration_ms)
        VALUES(?,?,?,?,?,?,?,?,?,?)`).run(page.id, checked, result.status, result.httpStatus || null, result.hash || null, result.text || null, result.screenshot || null, JSON.stringify(result.metrics || {}), result.error || null, result.durationMs || 0);
      let snapshot = null;
      if (result.status === 'ok' && result.hash && result.hash !== page.last_hash) {
        const version = db.prepare('SELECT COALESCE(MAX(version),0)+1 AS v FROM snapshots WHERE page_id=?').get(page.id).v;
        const snap = db.prepare('INSERT INTO snapshots(page_id,check_id,version,content_hash,created_at) VALUES(?,?,?,?,?)').run(page.id, info.lastInsertRowid, version, result.hash, checked);
        snapshot = { id: snap.lastInsertRowid, version, createdAt: checked, changed: true };
      }
      const nextCheck = new Date(Date.now() + page.interval_seconds * 1000).toISOString();
      db.prepare(`UPDATE pages SET last_checked_at=?,next_check_at=?,status=?,last_error=?,last_hash=CASE WHEN ?='ok' THEN ? ELSE last_hash END,
        last_changed_at=CASE WHEN ? IS NOT NULL THEN ? ELSE last_changed_at END WHERE id=?`)
        .run(checked, nextCheck, result.status, result.error || null, result.status, result.hash || null, snapshot ? 1 : null, checked, page.id);
      db.exec('COMMIT');
      return { checkId: info.lastInsertRowid, snapshot };
    } catch (error) { db.exec('ROLLBACK'); throw error; }
  }
  function listSnapshots(id, userId) { return userId == null ? stmt.versions.all(id) : getOwnedPage(id, userId) ? stmt.versions.all(id) : []; }
  function getSnapshot(id, version) {
    return db.prepare(`SELECT s.*,c.text,c.screenshot,c.http_status,c.status FROM snapshots s JOIN checks c ON c.id=s.check_id WHERE s.page_id=? AND s.version=?`).get(id, version);
  }
  function updateSnapshotSummary(id, summary) { db.prepare('UPDATE snapshots SET summary=? WHERE id=?').run(String(summary || '').slice(0, 300), id); }
  function snapshotImage(id, version, userId) { if (userId != null && !getOwnedPage(id, userId)) return null; const image = getSnapshot(id, version)?.screenshot; return image ? Buffer.from(image) : null; }
  function checkHistory(id, limit = 40, userId) { if (userId != null && !getOwnedPage(id, userId)) return []; return db.prepare('SELECT id,checked_at,status,http_status,text_hash,metrics,error,duration_ms FROM checks WHERE page_id=? ORDER BY id DESC LIMIT ?').all(id, limit); }
  function purgeOldChecks() {
    const configured = Number(process.env.CHECK_RETENTION_DAYS || 7);
    const days = Math.max(1, Math.min(Number.isFinite(configured) ? configured : 7, 365));
    const before = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
    const removed = db.prepare('DELETE FROM checks WHERE checked_at<? AND id NOT IN (SELECT check_id FROM snapshots)').run(before).changes;
    db.exec('PRAGMA incremental_vacuum(1000)');
    return removed;
  }
  function queueAlert(pageId, snapshotId, channel) {
    db.prepare('INSERT OR IGNORE INTO alert_outbox(page_id,snapshot_id,channel) VALUES(?,?,?)').run(pageId, snapshotId, channel);
  }
  function alertSentSince(pageId, channel, since) {
    return Boolean(db.prepare('SELECT 1 FROM alert_outbox WHERE page_id=? AND channel=? AND sent_at>=? LIMIT 1').get(pageId, channel, since));
  }
  function pendingAlerts() { return db.prepare(`SELECT a.*,p.name,p.url,p.alert_email,p.discord_enabled,p.telegram_chat_id,s.version,s.created_at,s.summary FROM alert_outbox a JOIN pages p ON p.id=a.page_id JOIN snapshots s ON s.id=a.snapshot_id WHERE a.sent_at IS NULL AND a.attempts<5`).all(); }
  function alertResult(id, error) {
    db.prepare('UPDATE alert_outbox SET attempts=attempts+1,sent_at=?,last_error=? WHERE id=?').run(error ? null : new Date().toISOString(), error ? String(error).slice(0, 500) : null, id);
  }
  function digestCandidates() {
    return db.prepare(`SELECT p.id,p.name,p.url,p.alert_email,COUNT(s.id) AS changes,GROUP_CONCAT('v' || s.version || ' · ' || s.created_at, char(10)) AS summary
      FROM pages p JOIN snapshots s ON s.page_id=p.id WHERE p.daily_digest=1 AND p.alert_email<>'' AND s.created_at>=?
      AND NOT EXISTS (SELECT 1 FROM digest_delivery d WHERE d.page_id=p.id AND d.digest_date=?) GROUP BY p.id`)
      .all(new Date(Date.now()-24*60*60*1000).toISOString(), new Date().toISOString().slice(0,10));
  }
  function pagesWithDigest() { return db.prepare("SELECT id FROM pages WHERE daily_digest=1 AND alert_email<>''").all(); }
  function digestSummary(pageId, since) {
    return db.prepare('SELECT version,created_at FROM snapshots WHERE page_id=? AND created_at>=? ORDER BY version DESC LIMIT 20').all(pageId, since);
  }
  function markDigestSent(pageId, digestDate) {
    db.prepare('INSERT OR IGNORE INTO digest_delivery(page_id,digest_date,sent_at) VALUES(?,?,?)').run(pageId, digestDate, new Date().toISOString());
  }
  function rss(id) {
    const page = getPage(id); const entries = listSnapshots(id).slice(0, 30);
    const esc = (x) => String(x || '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&apos;');
    return `<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>${esc(page.name)} changes</title><link>${esc(page.url)}</link><description>Website change feed</description>${entries.map((x) => `<item><title>${esc(page.name)} changed (v${x.version})</title><link>${esc(page.url)}</link><guid isPermaLink="false">change-${id}-${x.version}</guid><pubDate>${new Date(x.created_at).toUTCString()}</pubDate><description>${esc(String(x.text || '').slice(0, 500))}</description></item>`).join('')}</channel></rss>`;
  }
  function stats(userId) {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    return { pages: db.prepare('SELECT COUNT(*) AS n FROM pages WHERE user_id=?').get(userId).n, checks24h: db.prepare('SELECT COUNT(*) AS n FROM checks c JOIN pages p ON p.id=c.page_id WHERE p.user_id=? AND c.checked_at>=?').get(userId, since).n,
      changes24h: db.prepare('SELECT COUNT(*) AS n FROM snapshots s JOIN pages p ON p.id=s.page_id WHERE p.user_id=? AND s.created_at>=?').get(userId, since).n,
      status: db.prepare("SELECT status,COUNT(*) AS count FROM pages WHERE user_id=? GROUP BY status").all(userId) };
  }
  async function createUser(emailInput, password) {
    const email = emailAddress(emailInput); const encoded = await passwordHash(password); const now = new Date().toISOString();
    try {
      db.exec('BEGIN IMMEDIATE');
      const user = db.prepare('INSERT INTO users(email,password_hash,created_at) VALUES(?,?,?)').run(email, encoded, now);
      if (db.prepare('SELECT COUNT(*) AS n FROM users').get().n === 1) db.prepare('UPDATE pages SET user_id=? WHERE user_id IS NULL').run(user.lastInsertRowid);
      db.exec('COMMIT');
      return { id: Number(user.lastInsertRowid), email };
    } catch (error) { try { db.exec('ROLLBACK'); } catch {} if (String(error.code).includes('CONSTRAINT') || /unique constraint failed: users\.email/i.test(error.message)) throw Object.assign(new Error('An account with this email already exists.'), { status: 409 }); throw error; }
  }
  async function authenticate(emailInput, password) {
    let email;
    try { email = emailAddress(emailInput); } catch { email = ''; }
    const user = email ? db.prepare('SELECT id,email,password_hash FROM users WHERE email=? COLLATE NOCASE').get(email) : null;
    const valid = await passwordMatches(password, user?.password_hash || '');
    return user && valid ? { id: user.id, email: user.email } : null;
  }
  function createSession(userId, days = 30) {
    const token = newSessionToken(); const now = new Date(); const expiresAt = new Date(now.getTime() + days * 86400000).toISOString();
    db.prepare('DELETE FROM sessions WHERE expires_at<=?').run(now.toISOString());
    db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)').run(hashToken(token), userId, expiresAt, now.toISOString());
    return { token, expiresAt };
  }
  function sessionUser(token) {
    if (!token) return null;
    const row = db.prepare('SELECT u.id,u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?').get(hashToken(token), new Date().toISOString());
    return row || null;
  }
  function deleteSession(token) { if (token) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(hashToken(token)); }
  function issueFeedToken(id, userId) {
    const page = getOwnedPage(id, userId); if (!page) throw Object.assign(new Error('Page not found'), { status: 404 });
    const token = newSessionToken(); db.prepare('UPDATE pages SET feed_token_hash=? WHERE id=?').run(hashToken(token), id); return token;
  }
  function verifyFeedToken(id, token) {
    const row = db.prepare('SELECT feed_token_hash FROM pages WHERE id=?').get(id);
    return Boolean(row?.feed_token_hash && token && hashToken(token) === row.feed_token_hash);
  }
  return { db, listPages, getPage, getOwnedPage, addPage, updatePage, deletePage, saveCheck, listSnapshots, getSnapshot, updateSnapshotSummary, snapshotImage, checkHistory, purgeOldChecks, queueAlert, alertSentSince, pendingAlerts, alertResult, digestCandidates, pagesWithDigest, digestSummary, markDigestSent, rss, stats,
    createUser, authenticate, createSession, sessionUser, deleteSession, issueFeedToken, verifyFeedToken,
    duePages: () => db.prepare("SELECT id FROM pages WHERE user_id IS NOT NULL AND next_check_at<=? ORDER BY next_check_at LIMIT 100").all(new Date().toISOString()), close: () => db.close(), constants: { MIN_INTERVAL, MAX_INTERVAL, DEFAULT_IGNORE } };
}

module.exports = { createStore, validPublicUrl };
