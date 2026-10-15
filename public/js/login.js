'use strict';
const form = document.querySelector('#auth-form');
const errorBox = document.querySelector('#auth-error');
let mode = 'signin';
function setMode(next) {
  mode = next;
  const signup = mode === 'signup';
  document.querySelector('#tab-signin').classList.toggle('active', !signup);
  document.querySelector('#tab-signup').classList.toggle('active', signup);
  document.querySelector('#tab-signin').setAttribute('aria-selected', String(!signup));
  document.querySelector('#tab-signup').setAttribute('aria-selected', String(signup));
  document.querySelector('#auth-title').textContent = signup ? 'Make an account' : 'Welcome back';
  document.querySelector('#auth-intro').textContent = signup ? 'Your watchlist starts with one page.' : 'Sign in to see your watchlist.';
  document.querySelector('#confirm-wrap').hidden = !signup;
  form.elements.password.autocomplete = signup ? 'new-password' : 'current-password';
  document.querySelector('#submit-auth').textContent = signup ? 'Create account' : 'Sign in';
  errorBox.textContent = '';
}
document.querySelector('#tab-signin').addEventListener('click', () => setMode('signin'));
document.querySelector('#tab-signup').addEventListener('click', () => setMode('signup'));
form.addEventListener('submit', async (event) => {
  event.preventDefault(); errorBox.textContent = '';
  const email = form.elements.email.value.trim();
  const password = form.elements.password.value;
  if (mode === 'signup' && password !== form.elements.confirmPassword.value) { errorBox.textContent = 'Those passwords do not match.'; return; }
  const submit = document.querySelector('#submit-auth'); submit.disabled = true; submit.textContent = 'Please wait…';
  try {
    const response = await fetch(`/api/auth/${mode}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email, password }) });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || 'Unable to sign in.');
    const requested = new URLSearchParams(location.search).get('next') || '/';
    const next = new URL(requested, location.origin);
    location.assign(next.origin === location.origin && requested.startsWith('/') && !requested.startsWith('//') ? next.href : '/');
  } catch (error) { errorBox.textContent = error.message; }
  finally { submit.disabled = false; submit.textContent = mode === 'signup' ? 'Create account' : 'Sign in'; }
});
fetch('/api/auth/me').then((response) => { if (response.ok) { const next = new URLSearchParams(location.search).get('next') || '/'; const target = new URL(next, location.origin); location.replace(target.origin === location.origin && next.startsWith('/') && !next.startsWith('//') ? target.href : '/'); } }).catch(() => {});
