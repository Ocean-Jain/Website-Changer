'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { createStore, validPublicUrl } = require('../src/store');
const { normalizeText, parseMetrics, isPrivateIp, summarizeChange } = require('../src/checker');

async function withStore(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'changewatch-'));
  const previous = process.env.DATA_DIR;
  process.env.DATA_DIR = dir;
  const store = createStore();
  try { return await fn(store); }
  finally { store.close(); fs.rmSync(dir, { recursive: true, force: true }); if (previous === undefined) delete process.env.DATA_DIR; else process.env.DATA_DIR = previous; }
}

test('stores checks but creates page snapshots only when normalized content changes', () => withStore((store) => {
  const page = store.addPage({ url: 'https://example.com/news', name: 'News', intervalMinutes: 15 });
  const initial = store.saveCheck(page, { status: 'ok', hash: 'a', text: 'First', screenshot: Buffer.from('shot-1') });
  assert.equal(initial.snapshot.version, 1);
  const afterFirst = store.getPage(page.id);
  const unchanged = store.saveCheck(afterFirst, { status: 'ok', hash: 'a', text: 'First', screenshot: Buffer.from('shot-2') });
  assert.equal(unchanged.snapshot, null);
  const changed = store.saveCheck(store.getPage(page.id), { status: 'ok', hash: 'b', text: 'Second', screenshot: Buffer.from('shot-3') });
  assert.equal(changed.snapshot.version, 2);
  assert.equal(store.listSnapshots(page.id).length, 2);
  assert.equal(store.checkHistory(page.id).length, 3);
  assert.equal(store.db.prepare('SELECT COUNT(*) AS n FROM checks WHERE screenshot IS NOT NULL AND text IS NOT NULL').get().n, 3);
}));

test('records outages without turning them into content snapshots', () => withStore((store) => {
  const page = store.addPage({ url: 'https://example.com/status', intervalMinutes: 15 });
  const result = store.saveCheck(page, { status: 'error', httpStatus: 503, error: 'Site unavailable' });
  assert.equal(result.snapshot, null);
  assert.equal(store.getPage(page.id).status, 'error');
  assert.equal(store.listSnapshots(page.id).length, 0);
}));

test('deduplicates alert records by snapshot and channel', () => withStore((store) => {
  const page = store.addPage({ url: 'https://example.com/alerts', intervalMinutes: 15 });
  const { snapshot } = store.saveCheck(page, { status: 'ok', hash: 'changed', text: 'Changed', screenshot: Buffer.from('png') });
  store.queueAlert(page.id, snapshot.id, 'email');
  store.queueAlert(page.id, snapshot.id, 'email');
  const alert = store.pendingAlerts()[0];
  assert.equal(store.pendingAlerts().length, 1);
  store.alertResult(alert.id, null);
  assert.equal(store.alertSentSince(page.id, 'email', new Date(Date.now() - 60_000).toISOString()), true);
}));

test('rejects intervals outside 15 minutes to 24 hours and reuses a duplicate URL', () => withStore((store) => {
  assert.throws(() => store.addPage({ url: 'https://example.com', intervalMinutes: 14 }), /15 minutes/);
  const a = store.addPage({ url: 'https://example.com', intervalMinutes: 15 });
  const b = store.addPage({ url: 'https://example.com', intervalMinutes: 60, name: 'Duplicate' });
  assert.equal(a.id, b.id);
  assert.equal(store.listPages().length, 1);
}));

test('stores only alert flags and rejects credential-like monitored URLs', () => withStore((store) => {
  const page = store.addPage({ url: 'https://example.com', intervalMinutes: 15, discordEnabled: true, telegramChatId: '12345' });
  assert.equal(page.discord_enabled, 1);
  assert.equal(Object.hasOwn(page, 'alert_webhook'), false);
  assert.throws(() => store.addPage({ url: 'https://example.com/private?api_key=secret', intervalMinutes: 15 }), /credential-like/i);
}));

test('accounts enforce unique email addresses and isolate identical URLs', () => withStore(async (store) => {
  const first = await store.createUser('Watcher@example.com', 'correct horse battery');
  await assert.rejects(store.createUser('watcher@EXAMPLE.com', 'another secure password'), /already exists/i);
  const second = await store.createUser('other@example.com', 'another secure password');
  assert.equal((await store.authenticate('WATCHER@example.com', 'correct horse battery')).id, first.id);
  assert.equal(await store.authenticate('watcher@example.com', 'wrong password'), null);
  const one = store.addPage({ url: 'https://example.com/shared', intervalMinutes: 15 }, first.id);
  const sameUser = store.addPage({ url: 'https://example.com/shared', intervalMinutes: 60 }, first.id);
  const other = store.addPage({ url: 'https://example.com/shared', intervalMinutes: 15 }, second.id);
  assert.equal(one.id, sameUser.id);
  assert.notEqual(one.id, other.id);
  assert.equal(store.listPages(first.id).length, 1);
  assert.equal(store.listPages(second.id).length, 1);
  assert.equal(store.getOwnedPage(one.id, second.id), null);
  const feedToken = store.issueFeedToken(one.id, first.id);
  assert.equal(store.verifyFeedToken(one.id, feedToken), true);
  assert.equal(store.verifyFeedToken(one.id, 'wrong'), false);
  const session = store.createSession(first.id);
  assert.equal(store.sessionUser(session.token).email, first.email);
  assert.equal(store.db.prepare('SELECT token_hash FROM sessions').get().token_hash.includes(session.token), false);
  store.deleteSession(session.token);
  assert.equal(store.sessionUser(session.token), null);
}));

test('account credentials and sign-in sessions survive reopening the SQLite store', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'changewatch-persistence-'));
  const previous = process.env.DATA_DIR; process.env.DATA_DIR = dir;
  let store = createStore();
  try {
    const user = await store.createUser('returning@example.com', 'a persistent account password');
    const session = store.createSession(user.id);
    store.close();
    store = createStore();
    assert.equal((await store.authenticate('RETURNING@example.com', 'a persistent account password')).id, user.id);
    assert.equal(store.sessionUser(session.token).id, user.id);
  } finally {
    store.close(); fs.rmSync(dir, { recursive: true, force: true });
    if (previous === undefined) delete process.env.DATA_DIR; else process.env.DATA_DIR = previous;
  }
});

test('the first account claims pre-account watchlist data during upgrade', () => withStore(async (store) => {
  const legacy = store.addPage({ url: 'https://example.com/legacy', intervalMinutes: 15 });
  const user = await store.createUser('owner@example.com', 'a sufficiently long password');
  assert.equal(store.getOwnedPage(legacy.id, user.id).url, legacy.url);
  assert.equal(store.duePages().some((row) => row.id === legacy.id), true);
}));

test('migrates the original globally unique page table without losing the watchlist', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'changewatch-migration-'));
  const previous = process.env.DATA_DIR; process.env.DATA_DIR = dir;
  const db = new DatabaseSync(path.join(dir, 'changewatch.sqlite'));
  db.exec("CREATE TABLE pages(id INTEGER PRIMARY KEY,url TEXT NOT NULL UNIQUE,name TEXT NOT NULL,interval_seconds INTEGER NOT NULL DEFAULT 3600,sensitivity TEXT NOT NULL DEFAULT 'medium',watch_selectors TEXT NOT NULL DEFAULT '[]',ignore_selectors TEXT NOT NULL DEFAULT '[]',keywords TEXT NOT NULL DEFAULT '[]',alert_email TEXT NOT NULL DEFAULT '',discord_enabled INTEGER NOT NULL DEFAULT 0,telegram_chat_id TEXT NOT NULL DEFAULT '',daily_digest INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,next_check_at TEXT NOT NULL,last_checked_at TEXT,last_changed_at TEXT,status TEXT NOT NULL DEFAULT 'waiting',last_error TEXT,last_hash TEXT,muted_until TEXT)");
  db.prepare('INSERT INTO pages(id,url,name,created_at,next_check_at) VALUES(1,?,?,?,?)').run('https://example.com/old', 'Old page', new Date().toISOString(), new Date().toISOString()); db.close();
  const store = createStore();
  try {
    const user = await store.createUser('migrated@example.com', 'a sufficiently long password');
    assert.equal(store.getOwnedPage(1, user.id).name, 'Old page');
    const second = await store.createUser('second@example.com', 'another sufficiently long password');
    assert.notEqual(store.addPage({ url: 'https://example.com/old', intervalMinutes: 15 }, second.id).id, 1);
  } finally { store.close(); fs.rmSync(dir, { recursive: true, force: true }); if (previous === undefined) delete process.env.DATA_DIR; else process.env.DATA_DIR = previous; }
});

test('blocks private targets and only accepts HTTP(S)', () => {
  assert.throws(() => validPublicUrl('http://127.0.0.1/admin'), /public|private/i);
  assert.throws(() => validPublicUrl('http://[::ffff:7f00:1]/admin'), /public|private/i);
  assert.throws(() => validPublicUrl('file:///etc/passwd'), /HTTP or HTTPS/i);
  assert.equal(isPrivateIp('10.4.2.1'), true);
  assert.equal(isPrivateIp('::ffff:127.0.0.1'), true);
  assert.equal(isPrivateIp('::ffff:7f00:1'), true);
  assert.equal(isPrivateIp('8.8.8.8'), false);
});

test('normalization removes common time and counter noise with sensitivity levels', () => {
  const one = normalizeText('Release updated 2026-10-15 12:45. 1,234 views', 'medium');
  const two = normalizeText('Release updated 2026-10-15 13:02. 9,876 views', 'medium');
  assert.equal(one, two);
  assert.notEqual(normalizeText('Price 50', 'high'), normalizeText('Price 51', 'high'));
  assert.equal(normalizeText('Price 50', 'low'), normalizeText('Price 51', 'low'));
});

test('extracts labeled numeric values for history charts', () => {
  assert.deepEqual(parseMetrics('Price: $1,234.50\nAvailability = 92%\nUpdated: 2026-10-15'), { Price: 1234.5, Availability: 92 });
});

test('uses the Responses API without storing generated responses when AI summaries are enabled', async () => {
  const oldKey = process.env.OPENAI_API_KEY;
  const oldModel = process.env.OPENAI_MODEL;
  const oldFetch = global.fetch;
  process.env.OPENAI_API_KEY = 'test-key';
  process.env.OPENAI_MODEL = 'test-model';
  global.fetch = async (url, options) => {
    assert.equal(url, 'https://api.openai.com/v1/responses');
    assert.equal(options.headers.authorization, 'Bearer test-key');
    const body = JSON.parse(options.body);
    assert.equal(body.model, 'test-model');
    assert.equal(body.store, false);
    return { ok: true, json: async () => ({ output: [{ content: [{ type: 'output_text', text: 'The listed price increased.' }] }] }) };
  };
  try { assert.equal(await summarizeChange('Price: 5', 'Price: 6'), 'The listed price increased.'); }
  finally {
    global.fetch = oldFetch;
    if (oldKey === undefined) delete process.env.OPENAI_API_KEY; else process.env.OPENAI_API_KEY = oldKey;
    if (oldModel === undefined) delete process.env.OPENAI_MODEL; else process.env.OPENAI_MODEL = oldModel;
  }
});
