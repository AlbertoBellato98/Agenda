/* Agenda — application logic.
 *
 * How the app is protected, in one paragraph:
 * every piece of client data lives in ONE JavaScript object (`appState`).
 * Before it ever touches the disk, it is encrypted HERE in the browser
 * (AES-256-GCM, with a key derived from the password via PBKDF2).
 * The local Python server only stores and returns that encrypted blob;
 * it never sees the password or the plaintext.
 *
 * File layout: 1. crypto  2. server API  3. state  4. helpers
 * 5. saving  6. locking  7. unlock/setup  8. home & search
 * 9. profile  10. client dialog  11. password change  12. tilt  13. boot
 */

'use strict';

/* ═══════════ 1. Cryptography ═══════════ */

const KDF_ITERATIONS = 600000; // PBKDF2 rounds: slows down password guessing

/* Base64 helpers: binary data must become text to travel inside JSON. */
const base64 = {
  encode(buffer) {
    let text = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.length; i += 0x8000) {
      text += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(text);
  },
  decode(text) {
    const binary = atob(text);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  },
};

/* Turn a password + salt into an AES key. Deliberately slow (600k rounds). */
async function deriveKey(password, saltBytes, iterations) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,             // key can never be exported out of this tab
    ['encrypt', 'decrypt']);
}

/* Encrypt the whole state object into a self-describing "envelope". */
async function encryptState(key, saltBytes, stateObject) {
  const iv = crypto.getRandomValues(new Uint8Array(12)); // fresh IV every save
  const plaintext = new TextEncoder().encode(JSON.stringify(stateObject));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  return {
    format: 'agenda-v1',
    kdf: { alg: 'PBKDF2-SHA256', iter: KDF_ITERATIONS, salt: base64.encode(saltBytes) },
    iv: base64.encode(iv),
    data: base64.encode(ciphertext),
  };
}

/* Decrypt an envelope. Throws if the key (i.e. the password) is wrong:
   AES-GCM authenticates the data, so a wrong key cannot silently succeed. */
async function decryptEnvelope(key, envelope) {
  const iv = base64.decode(envelope.iv);
  const ciphertext = base64.decode(envelope.data);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return JSON.parse(new TextDecoder().decode(plaintext));
}

/* ═══════════ 2. Server API ═══════════ */

/* Returns { envelope, etag } or null when no data exists yet (first run). */
async function fetchBlob() {
  const response = await fetch('/api/data', { cache: 'no-store' });
  if (response.status === 404) return null;
  if (!response.ok) throw new Error('server');
  return { envelope: await response.json(), etag: response.headers.get('ETag') };
}

/* Stores the envelope. The ETag works like a version number: the server
   only accepts the write if nobody else changed the file in the meantime. */
async function storeBlob(envelope, { etag, isFirstWrite, keepalive } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (isFirstWrite) headers['If-None-Match'] = '*';
  else headers['If-Match'] = etag;
  const response = await fetch('/api/data', {
    method: 'PUT',
    headers,
    body: JSON.stringify(envelope),
    keepalive: !!keepalive, // lets the request finish even if the tab closes
  });
  if (response.status === 409) throw new Error('conflict');
  if (!response.ok) throw new Error('server');
  return response.headers.get('ETag');
}

/* ═══════════ 3. Application state ═══════════ */

let appState = null;       // decrypted data: { schema, clients: [...] }
let encryptionKey = null;  // CryptoKey — lives only in this variable
let keySalt = null;        // Uint8Array — salt paired with encryptionKey
let blobEtag = null;       // version of the blob currently on disk
let lastEnvelope = null;   // last ciphertext seen (used to verify the old password)
let openClientId = null;   // client shown in the profile view, or null
let hasUnsavedChanges = false;
let editingBlocked = false; // true after a two-window conflict, until reload
let saveTimer = null;
let retryTimer = null;
let lastActivityTime = Date.now();

const AUTOLOCK_MS = 10 * 60 * 1000; // lock after 10 minutes of inactivity
const SAVE_DEBOUNCE_MS = 800;       // wait for a typing pause before saving

/* ═══════════ 4. Small helpers ═══════════ */

const $ = (id) => document.getElementById(id);

function showView(viewId) {
  for (const id of ['view-lock', 'view-home', 'view-profile']) {
    $(id).classList.toggle('hidden', id !== viewId);
  }
}

function showBanner(message) {
  const banner = $('banner');
  if (message) { banner.textContent = message; banner.classList.remove('hidden'); }
  else banner.classList.add('hidden');
}

let toastTimer = null;
function showToast(message) {
  const toast = $('toast');
  toast.textContent = message;
  toast.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.add('hidden'), 1800);
}

const dateFormatFull = new Intl.DateTimeFormat('it-IT', { dateStyle: 'full', timeStyle: 'short' });
const dateFormatShort = new Intl.DateTimeFormat('it-IT', { dateStyle: 'short', timeStyle: 'short' });

/* Lowercase + strip accents, so "giovedi" finds "giovedì".
   NFD splits "ì" into "i" + a combining accent; the regex removes the accent. */
function normalizeText(text) {
  return text.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
}

/* Normalize `text` while remembering where each normalized character came
   from. Returns { normalized, map } where map[j] is the index in the
   ORIGINAL string of normalized[j]. This lets us search on the normalized
   form yet slice the original correctly \u2014 even when the original is stored
   in decomposed (NFD) form, where the two strings have different lengths.
   Iterating with for..of keeps emoji (surrogate pairs) intact. */
function normalizeWithMap(text) {
  let normalized = '';
  const map = [];
  let offset = 0;
  for (const ch of text) {
    const piece = normalizeText(ch);
    for (let k = 0; k < piece.length; k++) map.push(offset);
    normalized += piece;
    offset += ch.length; // 1 for most chars, 2 for surrogate-pair emoji
  }
  map.push(offset); // sentinel so map[end] is always defined
  return { normalized, map };
}

/* Find the first occurrence of `query`, returning its {start, end} indices
   in the ORIGINAL string (NFD-safe), or null if there is no match. */
function findMatchRange(text, query) {
  const needle = normalizeText(query);
  if (!needle) return null;
  const { normalized, map } = normalizeWithMap(text);
  const found = normalized.indexOf(needle);
  if (found === -1) return null;
  return { start: map[found], end: map[found + needle.length] };
}

/* Wrap every occurrence of `query` in <mark>, WITHOUT using innerHTML
   (note text is user data and must never be parsed as HTML). */
function highlightMatches(text, query) {
  const fragment = document.createDocumentFragment();
  const needle = normalizeText(query);
  // A query that is empty \u2014 or normalizes to empty, e.g. a lone accent \u2014
  // highlights nothing. (It also must not enter the loop below, where an
  // empty needle would never advance and would spin forever.)
  if (!needle) { fragment.append(text); return fragment; }
  const { normalized, map } = normalizeWithMap(text);
  let searchPos = 0; // position within `normalized`
  let cursor = 0;    // position within the original `text`
  while (true) {
    const found = normalized.indexOf(needle, searchPos);
    if (found === -1) { fragment.append(text.slice(cursor)); break; }
    const start = map[found];
    const end = map[found + needle.length];
    fragment.append(text.slice(cursor, start));
    const mark = document.createElement('mark');
    mark.textContent = text.slice(start, end);
    fragment.append(mark);
    cursor = end;
    searchPos = found + needle.length;
  }
  return fragment;
}

function findClient(clientId) {
  return appState.clients.find((c) => c.id === clientId);
}

function clientsSortedByName() {
  return [...appState.clients].sort((a, b) =>
    `${a.lastName} ${a.firstName}`.localeCompare(`${b.lastName} ${b.firstName}`, 'it'));
}

/* ═══════════ 5. Saving ═══════════ */

/* Every data change calls this. It re-renders instantly but waits for a
   pause in typing before encrypting and writing to disk. */
function scheduleSave() {
  if (editingBlocked) return;
  hasUnsavedChanges = true;
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => saveNow(), SAVE_DEBOUNCE_MS);
}

/* Only ONE save cycle may run at a time. Two overlapping saves would
   race: both would send the same ETag, the slower one would get a 409
   and the app would freeze on a false "other window" conflict. */
let activeSave = null;
let cycleKeepalive = false; // sticky for the whole active cycle (see below)

/* Returns a promise that resolves to true if, when it settles, everything
   is saved (nothing dirty), or false if a save failed / is blocked. */
function saveNow({ keepalive = false } = {}) {
  // Keepalive must apply to the WHOLE cycle, not just the first caller: if a
  // tab-close flush joins a normal save already running, every remaining PUT
  // in that cycle still needs keepalive so it can outlive the page.
  if (keepalive) cycleKeepalive = true;
  if (!activeSave) {
    activeSave = runSaveCycle().finally(() => { activeSave = null; cycleKeepalive = false; });
  }
  return activeSave;
}

async function runSaveCycle() {
  clearTimeout(saveTimer);
  // "Claim then loop": mark the changes as taken BEFORE encrypting.
  // If the user edits again while a write is in flight, the flag flips
  // back to true and the loop runs one more round — nothing gets lost.
  while (hasUnsavedChanges && encryptionKey && !editingBlocked) {
    hasUnsavedChanges = false;
    try {
      const envelope = await encryptState(encryptionKey, keySalt, appState);
      blobEtag = await storeBlob(envelope, { etag: blobEtag, keepalive: cycleKeepalive });
      lastEnvelope = envelope;
      clearInterval(retryTimer);
      retryTimer = null;
      showBanner(null);
      showToast('Salvato ✓');
    } catch (error) {
      hasUnsavedChanges = true; // the claim failed: put it back
      if (!encryptionKey) return false; // the app locked mid-save: stop quietly
      if (error.message === 'conflict') {
        // Another window changed the data. Never overwrite it silently:
        // block editing here and ask the user to reload.
        editingBlocked = true;
        clearInterval(retryTimer); // no point retrying a conflict
        retryTimer = null;
        showBanner('Questi dati sono stati modificati in un’altra finestra. Ricarica la pagina per continuare.');
      } else {
        showBanner('Impossibile salvare — controlla che l’app sia avviata. Riprovo automaticamente…');
        if (!retryTimer) retryTimer = setInterval(() => saveNow(), 5000);
      }
      return false;
    }
  }
  return !hasUnsavedChanges; // true only if the data is fully persisted
}

/* Warn before closing with unsaved work, and flush a save when the tab
   is hidden or closed (keepalive lets the request outlive the page). */
window.addEventListener('beforeunload', (event) => {
  if (hasUnsavedChanges && !editingBlocked) { event.preventDefault(); event.returnValue = ''; }
});
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden' && hasUnsavedChanges) saveNow({ keepalive: true });
});
window.addEventListener('pagehide', () => {
  if (hasUnsavedChanges) saveNow({ keepalive: true });
});

/* Called by the native macOS app when its window is closing. Unlike a
   browser tab-close, the native app WAITS for this promise, so we do a
   normal (awaited) save with no size limit — nothing is lost even for a
   large agenda. Returns a short status string for the host to log. */
window.flushAndReport = async function flushAndReport() {
  if (!hasUnsavedChanges || !encryptionKey) return 'clean';
  const saved = await saveNow(); // normal save, no keepalive cap
  return saved ? 'saved' : 'failed';
};

/* ═══════════ 6. Locking ═══════════ */

async function lockApp() {
  // Flush pending work first. If the save FAILS, do not lock: locking wipes
  // the plaintext, so we would lose the edit the retry banner just promised
  // to keep. Stay open and let the automatic retry (or the user) handle it.
  if (hasUnsavedChanges) {
    const saved = await saveNow();
    if (!saved) return; // save failed / blocked — abort the lock, keep data
  }
  // Close any open dialog: it would otherwise stay on top of the lock
  // screen (dialogs live in the browser's "top layer") with stale state.
  $('client-dialog').close();
  $('password-dialog').close();
  // Stop any pending retry and clear its banner: while locked there is
  // nothing to save (locking wipes the plaintext by design).
  clearInterval(retryTimer);
  retryTimer = null;
  showBanner(null);
  // Wipe every reference to the key and the plaintext data.
  encryptionKey = null;
  appState = null;
  openClientId = null;
  hasUnsavedChanges = false;
  // Also clear plaintext that was rendered into the DOM: a locked app
  // must not leave client names, notes, or a half-typed draft readable
  // behind the lock screen (they are only display:none otherwise).
  clearDecryptedDom();
  $('search-input').value = '';
  $('unlock-password').value = '';
  $('unlock-error').classList.add('hidden');
  showView('view-lock');
  $('unlock-form').classList.remove('hidden');
  $('setup-form').classList.add('hidden');
  setTimeout(() => $('unlock-password').focus(), 50);
}

/* Blank out every element that holds decrypted content — including the
   dialog input fields, which keep their values even after .close(). */
function clearDecryptedDom() {
  for (const id of [
    'note-input', 'search-input',
    'client-code-input', 'client-first-name-input', 'client-last-name-input',
    'current-password-input', 'new-password-input', 'confirm-password-input',
  ]) $(id).value = '';
  for (const id of [
    'note-list', 'client-directory', 'search-dropdown',
    'profile-name', 'profile-code', 'profile-stats', 'client-count',
  ]) $(id).textContent = '';
}

/* Any interaction counts as activity and postpones the auto-lock. */
for (const eventName of ['mousemove', 'keydown', 'click', 'scroll']) {
  window.addEventListener(eventName, () => { lastActivityTime = Date.now(); }, { passive: true });
}
setInterval(() => {
  if (encryptionKey && Date.now() - lastActivityTime > AUTOLOCK_MS) lockApp();
}, 30000);

/* A periodic ping keeps the local server alive while the app is open.
   (The server shuts itself down after 10 minutes of silence.) */
setInterval(() => {
  if (encryptionKey && document.visibilityState === 'visible') {
    fetch('/api/ping').catch(() => {});
  }
}, 60000);

$('lock-button').addEventListener('click', lockApp);
$('lock-button-2').addEventListener('click', lockApp);

/* ═══════════ 7. First run and unlock ═══════════ */

async function boot() {
  if (!crypto.subtle) {
    $('crypto-error').classList.remove('hidden');
    showView('view-lock');
    return;
  }
  showView('view-lock');
  try {
    const stored = await fetchBlob();
    if (stored === null) {
      // First run: no data file yet — ask the user to create a password.
      $('setup-form').classList.remove('hidden');
      setTimeout(() => $('setup-password').focus(), 50);
    } else {
      lastEnvelope = stored.envelope;
      blobEtag = stored.etag;
      $('unlock-form').classList.remove('hidden');
      setTimeout(() => $('unlock-password').focus(), 50);
    }
  } catch {
    showBanner('Impossibile contattare il server. Chiudi e riapri l’app Agenda.');
  }
}

$('understood-checkbox').addEventListener('change', (event) => {
  $('setup-button').disabled = !event.target.checked;
});

$('setup-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const password = $('setup-password').value;
  const confirmation = $('setup-confirm').value;
  const errorEl = $('setup-error');
  errorEl.classList.add('hidden');
  if (password.length < 8) {
    errorEl.textContent = 'La password deve avere almeno 8 caratteri.';
    errorEl.classList.remove('hidden');
    return;
  }
  if (password !== confirmation) {
    errorEl.textContent = 'Le due password non coincidono.';
    errorEl.classList.remove('hidden');
    return;
  }

  $('setup-form').classList.add('hidden');
  $('lock-spinner').classList.remove('hidden');
  try {
    keySalt = crypto.getRandomValues(new Uint8Array(16));
    encryptionKey = await deriveKey(password, keySalt, KDF_ITERATIONS);
    appState = { schema: 1, clients: [] };
    const envelope = await encryptState(encryptionKey, keySalt, appState);
    blobEtag = await storeBlob(envelope, { isFirstWrite: true });
    lastEnvelope = envelope;
    openHome();
  } catch {
    showBanner('Errore durante la creazione. Riprova.');
    $('setup-form').classList.remove('hidden');
  } finally {
    $('lock-spinner').classList.add('hidden');
  }
});

$('unlock-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const password = $('unlock-password').value;
  $('unlock-error').classList.add('hidden');
  $('unlock-form').classList.add('hidden');
  $('lock-spinner').classList.remove('hidden');

  // Step 1: reach the server. Do this separately so we can tell a wrong
  // password (decryption fails) apart from the server being unreachable
  // (which happens by design after the app idle-shuts-down while locked).
  let reachedServer = true;
  let dataMissing = false;
  try {
    const stored = await fetchBlob();
    if (stored) { lastEnvelope = stored.envelope; blobEtag = stored.etag; }
    else dataMissing = true; // server answered 404: the data file is gone
  } catch {
    reachedServer = false;
  }

  if (!reachedServer || dataMissing) {
    $('unlock-error').textContent = reachedServer
      ? 'Dati non trovati. Riavvia l’app; se serve, ripristina un backup dalla cartella "dati/backups".'
      : 'Impossibile contattare il server. Riavvia l’app e riprova.';
    $('unlock-error').classList.remove('hidden');
    $('unlock-form').classList.remove('hidden');
    $('lock-spinner').classList.add('hidden');
    return;
  }

  // Step 2: derive the key and decrypt. Failure here means wrong password.
  try {
    keySalt = base64.decode(lastEnvelope.kdf.salt);
    const key = await deriveKey(password, keySalt, lastEnvelope.kdf.iter || KDF_ITERATIONS);
    appState = await decryptEnvelope(key, lastEnvelope); // throws if wrong password
    encryptionKey = key;
    editingBlocked = false;
    showBanner(null);
    openHome();
  } catch {
    $('unlock-error').textContent = 'Password errata, riprova.';
    $('unlock-error').classList.remove('hidden');
    $('unlock-form').classList.remove('hidden');
    $('unlock-password').value = '';
    $('unlock-password').focus();
  } finally {
    $('lock-spinner').classList.add('hidden');
  }
});

/* ═══════════ 8. Home view: search with live dropdown ═══════════ */

let dropdownResults = [];   // what the dropdown currently shows
let selectedIndex = -1;     // which dropdown row is highlighted (-1 = none)
let directoryOpen = false;  // is the "all clients" list expanded?

const MAX_CLIENT_RESULTS = 6;
const MAX_NOTE_RESULTS = 4;

function openHome() {
  openClientId = null;
  $('note-input').value = ''; // drop any unsaved composer draft
  showView('view-home');
  $('search-input').value = '';
  closeDropdown();
  renderHomeMeta();
  renderDirectory();
  setTimeout(() => $('search-input').focus(), 50);
}

function renderHomeMeta() {
  const count = appState.clients.length;
  $('client-count').textContent =
    count === 0 ? 'Nessun cliente' : count === 1 ? '1 cliente' : `${count} clienti`;
  $('home-empty').classList.toggle('hidden', count > 0);
}

/* Search rule: the query must appear in the client code, the first name,
   the last name (in either order), or inside the text of a note. */
function searchEverything(query) {
  const needle = normalizeText(query);
  const clientResults = [];
  const noteResults = [];
  for (const client of clientsSortedByName()) {
    const identity = normalizeText(
      `${client.code} ${client.firstName} ${client.lastName} ${client.firstName}`);
    if (identity.includes(needle)) {
      clientResults.push({ type: 'client', client });
      continue; // already matched by identity: no need to scan the notes
    }
    for (const note of client.notes) {
      if (normalizeText(note.text).includes(needle)) {
        noteResults.push({ type: 'note', client, note });
      }
    }
  }
  return [
    ...clientResults.slice(0, MAX_CLIENT_RESULTS),
    ...noteResults.slice(0, MAX_NOTE_RESULTS),
  ];
}

function closeDropdown() {
  dropdownResults = [];
  selectedIndex = -1;
  $('search-dropdown').classList.add('hidden');
  $('search-input').setAttribute('aria-expanded', 'false');
}

function renderDropdown() {
  const query = $('search-input').value.trim();
  const dropdown = $('search-dropdown');
  dropdown.textContent = '';

  // Close on an empty query, or one that normalizes to nothing (e.g. a
  // stray combining accent) — otherwise "contains empty string" would
  // match every client.
  if (!query || !normalizeText(query)) { closeDropdown(); return; }

  dropdownResults = searchEverything(query);
  selectedIndex = dropdownResults.length > 0 ? 0 : -1;

  if (dropdownResults.length === 0) {
    const row = document.createElement('li');
    row.className = 'no-results';
    row.setAttribute('role', 'option');       // valid child of role="listbox"
    row.setAttribute('aria-disabled', 'true');
    row.textContent = 'Nessun risultato';
    dropdown.append(row);
  }

  dropdownResults.forEach((result, index) => {
    const row = document.createElement('li');
    row.setAttribute('role', 'option');
    row.id = `search-option-${index}`;

    const nameLine = document.createElement('span');
    nameLine.className = 'result-name';
    nameLine.append(highlightMatches(
      `${result.client.lastName} ${result.client.firstName}`, query));
    nameLine.append(' ');
    const chip = document.createElement('span');
    chip.className = 'code-chip';
    chip.append(highlightMatches(result.client.code, query));
    nameLine.append(chip);
    row.append(nameLine);

    if (result.type === 'note') {
      // Show a short excerpt of the matching note under the client name.
      // findMatchRange gives positions in the ORIGINAL text (NFD-safe), so
      // the window is centered on the real match even for accented text.
      const text = result.note.text;
      const range = findMatchRange(text, query);
      const matchAt = range ? range.start : 0;
      const start = Math.max(0, matchAt - 25);
      let excerpt = text.slice(start, start + 90).replace(/\s+/g, ' ');
      if (start > 0) excerpt = '…' + excerpt;
      if (start + 90 < text.length) excerpt += '…';
      const noteLine = document.createElement('span');
      noteLine.className = 'result-note-line';
      noteLine.append(`${dateFormatShort.format(result.note.createdAt)} — `);
      noteLine.append(highlightMatches(excerpt, query));
      row.append(noteLine);
    }

    row.addEventListener('click', () => openResult(result));
    dropdown.append(row);
  });

  updateDropdownSelection();
  dropdown.classList.remove('hidden');
  $('search-input').setAttribute('aria-expanded', 'true');
}

function updateDropdownSelection() {
  const rows = $('search-dropdown').querySelectorAll('[role="option"]');
  rows.forEach((row, index) => {
    row.classList.toggle('selected', index === selectedIndex);
    row.setAttribute('aria-selected', index === selectedIndex ? 'true' : 'false');
  });
  const input = $('search-input');
  if (selectedIndex >= 0) input.setAttribute('aria-activedescendant', `search-option-${selectedIndex}`);
  else input.removeAttribute('aria-activedescendant');
}

function openResult(result) {
  closeDropdown();
  $('search-input').value = '';
  if (result.type === 'note') openProfile(result.client.id, result.note.id);
  else openProfile(result.client.id);
}

$('search-input').addEventListener('input', renderDropdown);

/* Keyboard navigation: ↓ ↑ move the highlight, Enter opens, Esc closes. */
$('search-input').addEventListener('keydown', (event) => {
  if (event.key === 'Escape') { closeDropdown(); return; } // works even on "Nessun risultato"
  if (dropdownResults.length === 0) return;
  if (event.key === 'ArrowDown') {
    event.preventDefault();
    selectedIndex = (selectedIndex + 1) % dropdownResults.length;
    updateDropdownSelection();
  } else if (event.key === 'ArrowUp') {
    event.preventDefault();
    selectedIndex = (selectedIndex - 1 + dropdownResults.length) % dropdownResults.length;
    updateDropdownSelection();
  }
});

/* Enter and the "Cerca" button both open the highlighted result. */
$('search-form').addEventListener('submit', (event) => {
  event.preventDefault();
  if (selectedIndex >= 0 && dropdownResults[selectedIndex]) {
    openResult(dropdownResults[selectedIndex]);
  } else {
    renderDropdown(); // no results yet (e.g. button clicked first): show them
  }
});

/* Clicking anywhere outside the search panel closes the dropdown. */
document.addEventListener('click', (event) => {
  if (!$('search-panel').contains(event.target)) closeDropdown();
});

/* ── "All clients" directory ── */

$('browse-button').addEventListener('click', () => {
  directoryOpen = !directoryOpen;
  $('browse-button').setAttribute('aria-expanded', String(directoryOpen));
  renderDirectory();
});

function renderDirectory() {
  const directory = $('client-directory');
  directory.classList.toggle('hidden', !directoryOpen);
  directory.textContent = '';
  if (!directoryOpen) return;

  for (const client of clientsSortedByName()) {
    const row = document.createElement('div');
    row.className = 'directory-row';
    row.setAttribute('role', 'button');
    row.tabIndex = 0;

    const name = document.createElement('span');
    name.className = 'row-name';
    name.textContent = `${client.lastName} ${client.firstName} `;
    const chip = document.createElement('span');
    chip.className = 'code-chip';
    chip.textContent = client.code;
    name.append(chip);

    const detail = document.createElement('span');
    detail.className = 'row-detail';
    const count = client.notes.length;
    let text = count === 0 ? 'Nessuna nota' : count === 1 ? '1 nota' : `${count} note`;
    if (count > 0) {
      const newest = Math.max(...client.notes.map((n) => n.createdAt));
      text += ` · ${dateFormatShort.format(newest)}`;
    }
    detail.textContent = text;

    row.append(name, detail);
    const open = () => openProfile(client.id);
    row.addEventListener('click', open);
    row.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } });
    directory.append(row);
  }
}

/* ═══════════ 9. Profile view ═══════════ */

function openProfile(clientId, noteIdToFlash = null) {
  openClientId = clientId;
  // Start with an empty composer: a draft belongs to the client it was
  // typed under, so it must never carry over to a different profile.
  $('note-input').value = '';
  autoGrowComposer();
  showView('view-profile');
  renderProfile();
  if (noteIdToFlash) {
    const noteEl = document.querySelector(`[data-note-id="${noteIdToFlash}"]`);
    if (noteEl) {
      const smooth = !matchMedia('(prefers-reduced-motion: reduce)').matches;
      noteEl.scrollIntoView({ behavior: smooth ? 'smooth' : 'auto', block: 'center' });
      noteEl.classList.add('flash');
      setTimeout(() => noteEl.classList.remove('flash'), 1700);
      noteEl.setAttribute('tabindex', '-1');
      noteEl.focus({ preventScroll: true }); // keep keyboard focus on the result
    }
  } else {
    window.scrollTo(0, 0);
    setTimeout(() => $('note-input').focus(), 50);
  }
}

function renderProfile() {
  const client = findClient(openClientId);
  if (!client) { openHome(); return; }

  $('profile-name').textContent = `${client.firstName} ${client.lastName}`;
  $('profile-code').textContent = client.code;

  const notes = [...client.notes].sort((a, b) => b.createdAt - a.createdAt);
  const count = notes.length;
  $('profile-stats').textContent =
    count === 0 ? 'Nessuna nota' : count === 1 ? '1 nota' : `${count} note`;
  $('diary-heading').textContent = 'Diario';
  $('notes-empty').classList.toggle('hidden', count > 0);

  const list = $('note-list');
  list.textContent = '';
  for (const note of notes) list.append(buildNoteElement(note));
}

function buildNoteElement(note) {
  const noteEl = document.createElement('div');
  noteEl.className = 'note';
  noteEl.dataset.noteId = note.id;

  const meta = document.createElement('div');
  meta.className = 'note-meta';
  const when = document.createElement('span');
  let label = dateFormatFull.format(note.createdAt);
  if (note.updatedAt > note.createdAt) {
    label += ` · modificata il ${dateFormatShort.format(note.updatedAt)}`;
  }
  when.textContent = label;

  const actions = document.createElement('span');
  actions.className = 'note-actions';
  const editButton = document.createElement('button');
  editButton.textContent = 'Modifica';
  editButton.addEventListener('click', () => editNoteInline(noteEl, note));
  const deleteButton = document.createElement('button');
  deleteButton.textContent = 'Elimina';
  deleteButton.addEventListener('click', () => {
    if (editingBlocked) return;
    if (confirm('Eliminare questa nota?')) {
      const client = findClient(openClientId);
      client.notes = client.notes.filter((n) => n.id !== note.id);
      client.updatedAt = Date.now();
      scheduleSave();
      renderProfile();
    }
  });
  actions.append(editButton, deleteButton);
  meta.append(when, actions);

  const text = document.createElement('p');
  text.className = 'note-text';
  text.textContent = note.text;

  noteEl.append(meta, text);
  return noteEl;
}

function editNoteInline(noteEl, note) {
  if (editingBlocked) return;
  const textEl = noteEl.querySelector('.note-text');
  if (!textEl) return;

  const textarea = document.createElement('textarea');
  textarea.value = note.text;
  textarea.rows = Math.max(3, note.text.split('\n').length);

  const editActions = document.createElement('div');
  editActions.className = 'note-edit-actions';
  const cancelButton = document.createElement('button');
  cancelButton.className = 'quiet-button';
  cancelButton.textContent = 'Annulla';
  cancelButton.addEventListener('click', () => renderProfile());
  const saveButton = document.createElement('button');
  saveButton.className = 'primary-button';
  saveButton.textContent = 'Salva';
  saveButton.addEventListener('click', () => {
    if (editingBlocked) return; // a conflict landed while editing: don't commit
    const newText = textarea.value.trim();
    if (newText && newText !== note.text) {
      note.text = newText;
      note.updatedAt = Date.now();
      findClient(openClientId).updatedAt = Date.now();
      scheduleSave();
    }
    renderProfile();
  });
  editActions.append(cancelButton, saveButton);

  textEl.replaceWith(textarea, editActions);
  textarea.focus();
}

function addNote() {
  if (editingBlocked) return;
  const input = $('note-input');
  const text = input.value.trim();
  if (!text) { input.focus(); return; }
  const now = Date.now();
  const client = findClient(openClientId);
  client.notes.push({ id: 'n-' + crypto.randomUUID(), text, createdAt: now, updatedAt: now });
  client.updatedAt = now;
  input.value = '';
  autoGrowComposer();
  scheduleSave();
  renderProfile();
  input.focus();
}

/* The composer grows with its content, like a Notion block. */
function autoGrowComposer() {
  const input = $('note-input');
  input.style.height = 'auto';
  input.style.height = `${Math.max(52, input.scrollHeight)}px`;
}

$('note-input').addEventListener('input', autoGrowComposer);
$('add-note-button').addEventListener('click', addNote);
$('note-input').addEventListener('keydown', (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') addNote();
});

$('back-button').addEventListener('click', openHome);

$('delete-client-button').addEventListener('click', () => {
  if (editingBlocked) return;
  const client = findClient(openClientId);
  const count = client.notes.length;
  const detail = count === 0 ? '' : count === 1 ? ' e la sua nota' : ` e tutte le sue ${count} note`;
  if (confirm(`Eliminare ${client.firstName} ${client.lastName}${detail}? L'operazione non si può annullare.`)) {
    appState.clients = appState.clients.filter((c) => c.id !== client.id);
    scheduleSave();
    openHome();
  }
});

/* ═══════════ 10. Client dialog (create / edit) ═══════════ */

let clientBeingEdited = null; // null = the dialog will create a new client

function openClientDialog(client = null) {
  if (editingBlocked) return;
  clientBeingEdited = client;
  $('client-dialog-title').textContent = client ? 'Modifica cliente' : 'Nuovo cliente';
  $('client-code-input').value = client ? client.code : '';
  $('client-first-name-input').value = client ? client.firstName : '';
  $('client-last-name-input').value = client ? client.lastName : '';
  $('client-form-error').classList.add('hidden');
  $('client-dialog').showModal();
  setTimeout(() => $('client-code-input').focus(), 50);
}

$('new-client-button').addEventListener('click', () => openClientDialog());
$('edit-client-button').addEventListener('click', () => openClientDialog(findClient(openClientId)));
$('client-cancel-button').addEventListener('click', () => $('client-dialog').close());

$('client-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const code = $('client-code-input').value.trim();
  const firstName = $('client-first-name-input').value.trim();
  const lastName = $('client-last-name-input').value.trim();
  const errorEl = $('client-form-error');

  if (editingBlocked) {
    errorEl.textContent = 'Ricarica la pagina prima di modificare i dati.';
    errorEl.classList.remove('hidden');
    return;
  }

  // A single space passes the HTML "required" check but is empty once
  // trimmed — show a clear message instead of failing silently.
  if (!code || !firstName || !lastName) {
    errorEl.textContent = 'Compila codice, nome e cognome.';
    errorEl.classList.remove('hidden');
    return;
  }

  // Client codes must be unique (comparison ignores case and accents).
  const duplicate = appState.clients.some((c) =>
    normalizeText(c.code) === normalizeText(code) &&
    (!clientBeingEdited || c.id !== clientBeingEdited.id));
  if (duplicate) {
    errorEl.textContent = 'Codice già esistente: scegline un altro.';
    errorEl.classList.remove('hidden');
    return;
  }

  const now = Date.now();
  let openedId = null;
  if (clientBeingEdited) {
    Object.assign(clientBeingEdited, { code, firstName, lastName, updatedAt: now });
  } else {
    const newClient = {
      id: 'c-' + crypto.randomUUID(),
      code, firstName, lastName,
      createdAt: now, updatedAt: now,
      notes: [],
    };
    appState.clients.push(newClient);
    openedId = newClient.id;
  }
  scheduleSave();
  $('client-dialog').close();

  if (openedId) openProfile(openedId);        // jump straight into the new profile
  else if (openClientId) renderProfile();     // edited from the profile view
  renderHomeMeta();
  renderDirectory();
});

/* ═══════════ 11. Settings menu and password change ═══════════ */

function closeSettingsMenu() {
  $('settings-menu').classList.add('hidden');
  $('settings-button').setAttribute('aria-expanded', 'false');
}

$('settings-button').addEventListener('click', (event) => {
  event.stopPropagation();
  const willOpen = $('settings-menu').classList.contains('hidden');
  $('settings-menu').classList.toggle('hidden', !willOpen);
  $('settings-button').setAttribute('aria-expanded', String(willOpen));
});
document.addEventListener('click', closeSettingsMenu);
// Esc closes the menu and returns focus to its trigger.
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && !$('settings-menu').classList.contains('hidden')) {
    closeSettingsMenu();
    $('settings-button').focus();
  }
});

$('change-password-button').addEventListener('click', () => {
  closeSettingsMenu();
  $('current-password-input').value = '';
  $('new-password-input').value = '';
  $('confirm-password-input').value = '';
  $('password-form-error').classList.add('hidden');
  $('password-dialog').showModal();
});

// When a dialog closes, the browser tries to restore focus to whatever was
// focused before it opened — but that trigger may now be display:none (the
// settings menu). Send focus somewhere sensible instead.
for (const dialogId of ['password-dialog', 'client-dialog']) {
  $(dialogId).addEventListener('close', () => {
    const target = openClientId ? $('back-button') : $('search-input');
    if (!$('view-lock').classList.contains('hidden')) return; // locked: leave it
    setTimeout(() => target.focus(), 0);
  });
}

$('password-cancel-button').addEventListener('click', () => $('password-dialog').close());

$('password-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const errorEl = $('password-form-error');
  errorEl.classList.add('hidden');
  const currentPassword = $('current-password-input').value;
  const newPassword = $('new-password-input').value;
  const confirmation = $('confirm-password-input').value;

  if (newPassword.length < 8) {
    errorEl.textContent = 'La nuova password deve avere almeno 8 caratteri.';
    errorEl.classList.remove('hidden');
    return;
  }
  if (newPassword !== confirmation) {
    errorEl.textContent = 'Le due nuove password non coincidono.';
    errorEl.classList.remove('hidden');
    return;
  }

  if (editingBlocked) {
    errorEl.textContent = 'Ricarica la pagina prima di cambiare password.';
    errorEl.classList.remove('hidden');
    return;
  }

  $('password-save-button').disabled = true;
  // Finish any pending save first, so we re-encrypt the very latest data.
  if (hasUnsavedChanges) await saveNow();

  try {
    // Step 1: prove the current password is right (must decrypt the blob).
    const oldSalt = base64.decode(lastEnvelope.kdf.salt);
    const oldKey = await deriveKey(currentPassword, oldSalt, lastEnvelope.kdf.iter || KDF_ITERATIONS);
    await decryptEnvelope(oldKey, lastEnvelope); // throws if current password wrong

    // Step 2: encrypt with the NEW key/salt and write it. Crucially we do
    // NOT touch the in-memory key until the write succeeds — otherwise a
    // failed save would leave the app holding a key that matches nothing
    // on disk, locking the user out. Build the new key locally first.
    const newSalt = crypto.getRandomValues(new Uint8Array(16));
    const newKey = await deriveKey(newPassword, newSalt, KDF_ITERATIONS);
    const envelope = await encryptState(newKey, newSalt, appState);
    let newEtag;
    try {
      newEtag = await storeBlob(envelope, { etag: blobEtag });
    } catch (saveError) {
      if (saveError.message === 'conflict') {
        errorEl.textContent = 'Dati modificati in un’altra finestra. Ricarica la pagina e riprova.';
      } else {
        errorEl.textContent = 'Impossibile salvare la nuova password. Controlla che l’app sia avviata e riprova.';
      }
      errorEl.classList.remove('hidden');
      return; // in-memory key untouched: the old password still works
    }

    // Step 3: the write landed — now adopt the new key everywhere.
    keySalt = newSalt;
    encryptionKey = newKey;
    blobEtag = newEtag;
    lastEnvelope = envelope;
    hasUnsavedChanges = false;
    // The data is now safely persisted, so clear any stale "retrying" state
    // left over from an earlier failed save.
    clearInterval(retryTimer);
    retryTimer = null;
    showBanner(null);
    $('password-dialog').close();
    showToast('Password cambiata ✓');
  } catch {
    errorEl.textContent = 'La password attuale non è corretta.';
    errorEl.classList.remove('hidden');
  } finally {
    $('password-save-button').disabled = false;
  }
});

/* ═══════════ 12. The 3D tilt (the app's one flourish) ═══════════ */

/* The search panel leans very gently toward the pointer, like a card
   picked up from a desk. Purely decorative: skipped entirely when the
   user prefers reduced motion, and nothing depends on it. */
function setUpTiltEffect() {
  const panel = $('search-panel');
  const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
  const MAX_TILT_DEGREES = 1.6;

  panel.addEventListener('pointermove', (event) => {
    if (reducedMotion.matches) return;
    const box = panel.getBoundingClientRect();
    const relativeX = (event.clientX - box.left) / box.width - 0.5;  // -0.5 … 0.5
    const relativeY = (event.clientY - box.top) / box.height - 0.5;
    panel.style.transform =
      `perspective(900px) rotateX(${(-relativeY * MAX_TILT_DEGREES).toFixed(2)}deg)` +
      ` rotateY(${(relativeX * MAX_TILT_DEGREES).toFixed(2)}deg)`;
  });
  panel.addEventListener('pointerleave', () => { panel.style.transform = ''; });
}

/* ═══════════ 13. Boot ═══════════ */

setUpTiltEffect();
boot();
