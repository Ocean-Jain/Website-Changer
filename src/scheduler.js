'use strict';

function createScheduler(store, checker) {
  const queue = [];
  const queuedIds = new Set();
  const active = new Set();
  const hostLastRun = new Map();
  const inFlight = new Map();
  const MAX_CONCURRENT = 2;
  const MAX_QUEUE = 500;
  const HOST_GAP_MS = 15000;
  function enqueue(id, waitForResult = false) {
    if (inFlight.has(id)) return waitForResult ? inFlight.get(id) : inFlight.get(id).catch(() => {});
    const page = store.getPage(id);
    if (!page) return Promise.reject(Object.assign(new Error('Page not found'), { status: 404 }));
    if (queuedIds.has(id)) return waitForResult ? Promise.reject(new Error('Check is already queued.')) : undefined;
    if (queue.length >= MAX_QUEUE) return waitForResult ? Promise.reject(new Error('Check queue is full; try again shortly.')) : undefined;
    queuedIds.add(id);
    let resolve; let reject;
    const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
    promise.catch(() => {});
    inFlight.set(id, promise);
    queue.push({ id, host: new URL(page.url).hostname, resolve, reject });
    drain();
    return waitForResult ? promise : undefined;
  }
  function drain() {
    if (active.size >= MAX_CONCURRENT) return;
    for (let i = 0; i < queue.length && active.size < MAX_CONCURRENT;) {
      const job = queue[i];
      const previous = hostLastRun.get(job.host) || 0;
      const page = store.getPage(job.id);
      const shared = page && (checker.hasFreshCache?.(page) || checker.hasSharedFetch?.(page));
      if (!shared && Date.now() - previous < HOST_GAP_MS) { i++; continue; }
      queue.splice(i, 1); queuedIds.delete(job.id); active.add(job.id); hostLastRun.set(job.host, Date.now());
      checker.check(job.id).then(job.resolve, job.reject).finally(() => {
        active.delete(job.id); inFlight.delete(job.id); drain();
      });
    }
  }
  async function tick() {
    for (const row of store.duePages()) enqueue(row.id, false);
    drain();
  }
  const timer = setInterval(tick, 30000);
  timer.unref?.();
  const digestTimer = setInterval(() => checker.sendDailyDigests().catch((error) => console.error('Daily digest scheduler error:', error.message)), 60 * 60 * 1000);
  digestTimer.unref?.();
  const alertTimer = setInterval(() => checker.deliverPendingAlerts().catch((error) => console.error('Alert delivery error:', error.message)), 30 * 1000);
  alertTimer.unref?.();
  const cleanup = () => { try { store.purgeOldChecks(); } catch (error) { console.error('Check history cleanup failed:', error.message); } };
  const cleanupTimer = setInterval(cleanup, 24 * 60 * 60 * 1000);
  cleanupTimer.unref?.();
  const initialCleanup = setTimeout(cleanup, 60000);
  initialCleanup.unref?.();
  const initialDigest = setTimeout(() => checker.sendDailyDigests().catch((error) => console.error('Daily digest scheduler error:', error.message)), 15000);
  initialDigest.unref?.();
  tick();
  return { enqueue, stop: () => { clearInterval(timer); clearInterval(digestTimer); clearInterval(alertTimer); clearInterval(cleanupTimer); clearTimeout(initialDigest); clearTimeout(initialCleanup); }, getQueue: () => ({ queued: queue.length, active: active.size }) };
}
module.exports = { createScheduler };
