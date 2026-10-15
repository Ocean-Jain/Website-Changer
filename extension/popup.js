'use strict';

const serviceInput = document.querySelector('#service');
const pageLabel = document.querySelector('#page');
const button = document.querySelector('#add');
const message = document.querySelector('#message');
let currentUrl = '';

chrome.storage.sync.get({ serviceUrl: '' }, ({ serviceUrl }) => { serviceInput.value = serviceUrl; });
chrome.tabs.query({ active: true, lastFocusedWindow: true }, (tabs) => {
  currentUrl = tabs[0]?.url || '';
  pageLabel.textContent = currentUrl;
  button.disabled = !/^https?:\/\//i.test(currentUrl);
});
serviceInput.addEventListener('change', () => {
  try {
    const parsed = new URL(serviceInput.value.trim());
    if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Use an HTTP(S) Changewatch address.');
    chrome.storage.sync.set({ serviceUrl: parsed.origin }); message.textContent = '';
  } catch { message.textContent = 'Enter a valid Changewatch address.'; }
});
button.addEventListener('click', () => {
  try {
    const service = new URL(serviceInput.value.trim());
    const target = new URL(currentUrl);
    if (!['http:', 'https:'].includes(service.protocol) || !['http:', 'https:'].includes(target.protocol)) throw new Error('Only HTTP(S) pages are supported.');
    chrome.storage.sync.set({ serviceUrl: service.origin });
    chrome.tabs.create({ url: `${service.origin}/#add=${encodeURIComponent(target.href)}` });
    window.close();
  } catch (error) { message.textContent = error.message; }
});
