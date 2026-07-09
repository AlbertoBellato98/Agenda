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

/* ── Recovery phrase (24 words, BIP39) ─────────────────────────────
   Portable backups are encrypted with a key derived from a 24-word
   phrase instead of the password. 24 words from the 2048-word list
   encode 264 bits: 256 bits of random entropy + an 8-bit checksum.
   The checksum lets the app catch a mistyped or swapped word BEFORE
   attempting decryption. Wordlist: app/wordlist.js (official BIP39
   Italian list — no accented characters, easy to type). */

/* Turn 32 random bytes into 24 words. The 8 checksum bits come from
   the SHA-256 of the entropy, as the BIP39 standard prescribes. */
async function generateRecoveryPhrase() {
  const entropy = crypto.getRandomValues(new Uint8Array(32));
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', entropy));
  const bytes = [...entropy, hash[0]]; // 33 bytes = 264 bits = 24 × 11

  let bits = '';
  for (const byte of bytes) bits += byte.toString(2).padStart(8, '0');

  const words = [];
  for (let i = 0; i < 24; i++) {
    const index = parseInt(bits.slice(i * 11, (i + 1) * 11), 2);
    words.push(BIP39_WORDS[index]);
  }
  return words;
}

/* Clean up whatever the user typed: lowercase, collapse whitespace. */
function parsePhrase(text) {
  return text.normalize('NFKD').toLowerCase().trim().split(/\s+/).filter(Boolean);
}

/* Validate a typed phrase. Returns { ok: true } or { ok, error } with a
   human message pinpointing the problem (wrong count, unknown word, or
   failed checksum — which means a typo or swapped words). */
async function validateRecoveryPhrase(words) {
  if (words.length !== 24) {
    return { ok: false, error: `Servono 24 parole (ne hai scritte ${words.length}).` };
  }
  let bits = '';
  for (const [i, word] of words.entries()) {
    const index = BIP39_WORDS.indexOf(word);
    if (index === -1) {
      return { ok: false, error: `La parola n. ${i + 1} ("${word}") non è nella lista.` };
    }
    bits += index.toString(2).padStart(11, '0');
  }
  const entropy = new Uint8Array(32);
  for (let i = 0; i < 32; i++) entropy[i] = parseInt(bits.slice(i * 8, (i + 1) * 8), 2);
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', entropy));
  const expected = hash[0].toString(2).padStart(8, '0');
  if (bits.slice(256) !== expected) {
    return { ok: false, error: 'Le parole non tornano: controlla di averle scritte giuste e in ordine.' };
  }
  return { ok: true };
}

/* The phrase acts as the password for the backup file. The random salt
   stored in the backup envelope makes each backup independently keyed. */
function deriveBackupKey(words, saltBytes, iterations) {
  return deriveKey(words.join(' '), saltBytes, iterations);
}

/* Encrypt the current data into a portable backup envelope. Same shape
   as the main envelope but tagged "agenda-backup-v1" so the two can
   never be confused, plus a creation date to identify the file. */
async function buildBackupEnvelope(words) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveBackupKey(words, salt, KDF_ITERATIONS);
  const envelope = await encryptState(key, salt, appState);
  envelope.format = 'agenda-backup-v1';
  envelope.createdAt = Date.now();
  return envelope;
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
let dataExistsOnDisk = false; // does this Mac already hold an agenda? (set at boot)
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

/* ── Directory sorting ──────────────────────────────────────────────
   The home list can be ordered five ways. The choice is remembered in
   localStorage — a plain preference string, never client data. */

const DIRECTORY_SORTS = {
  cognome:  (a, b) => `${a.lastName} ${a.firstName}`.localeCompare(`${b.lastName} ${b.firstName}`, 'it'),
  nome:     (a, b) => `${a.firstName} ${a.lastName}`.localeCompare(`${b.firstName} ${b.lastName}`, 'it'),
  codice:   (a, b) => a.code.localeCompare(b.code, 'it', { numeric: true }),
  modifica: (a, b) => (b.updatedAt || 0) - (a.updatedAt || 0), // most recent first
  stato:    (a, b) =>
    (CLIENT_STATUSES[clientStatus(a)].sortOrder - CLIENT_STATUSES[clientStatus(b)].sortOrder)
    || DIRECTORY_SORTS.cognome(a, b), // same color → alphabetical
};

let directorySort = localStorage.getItem('agenda-sort');
if (!DIRECTORY_SORTS[directorySort]) directorySort = 'cognome';

function clientsSortedForDirectory() {
  return [...appState.clients].sort(DIRECTORY_SORTS[directorySort]);
}

/* Pipeline status of a client — a simple traffic light:
   prospect = being worked (yellow), client = won (green),
   noanswer = doesn't pick up (white), ko = not interested (red).
   sortOrder drives the "Stato" sorting on the home page. */
const CLIENT_STATUSES = {
  prospect: { label: 'PROSPECT',     cssClass: 'status-prospect', sortOrder: 0 },
  client:   { label: 'CLIENTE',      cssClass: 'status-client',   sortOrder: 1 },
  noanswer: { label: 'NON RISPONDE', cssClass: 'status-noanswer', sortOrder: 2 },
  ko:       { label: 'KO',           cssClass: 'status-ko',       sortOrder: 3 },
};

/* Records created before this field existed have no status:
   treat them as "prospect" instead of failing. */
function clientStatus(client) {
  return CLIENT_STATUSES[client.status] ? client.status : 'prospect';
}

/* A small colored dot for the given client, used in every list. */
function buildStatusDot(client) {
  const dot = document.createElement('span');
  dot.className = `status-dot ${CLIENT_STATUSES[clientStatus(client)].cssClass}`;
  dot.setAttribute('aria-hidden', 'true');
  return dot;
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
  $('backup-dialog').close();
  $('restore-dialog').close();
  pendingBackupWords = null; // the recovery phrase is as secret as a key
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
    'setup-password', 'setup-confirm', 'unlock-password',
    'client-code-input', 'client-first-name-input', 'client-last-name-input',
    'current-password-input', 'new-password-input', 'confirm-password-input',
    'restore-phrase-input', 'restore-password-input', 'restore-confirm-input',
    'restore-file-input',
  ]) $(id).value = '';
  for (const id of [
    'note-list', 'client-directory', 'search-dropdown',
    'profile-name', 'profile-code', 'profile-stats', 'client-count',
    'word-grid',          // the 24 recovery words must never survive a lock
    'restore-file-info',  // nor the chosen backup filename
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
      dataExistsOnDisk = false;
      $('setup-form').classList.remove('hidden');
      setTimeout(() => $('setup-password').focus(), 50);
    } else {
      dataExistsOnDisk = true;
      lastEnvelope = stored.envelope;
      blobEtag = stored.etag;
      $('unlock-form').classList.remove('hidden');
      setTimeout(() => $('unlock-password').focus(), 50);
    }
    // "Restore from backup" is available on both screens — it's the first
    // thing you use on a brand-new Mac (first run) and a recovery option
    // otherwise.
    $('restore-link').classList.remove('hidden');
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
    dataExistsOnDisk = true; // the first blob now exists on disk
    // The master password must not linger in the (hidden) setup inputs.
    $('setup-password').value = '';
    $('setup-confirm').value = '';
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
    if (stored) {
      lastEnvelope = stored.envelope;
      blobEtag = stored.etag;
      dataExistsOnDisk = true;
    } else {
      // Server answered 404: the data file is gone. Keep the state honest so
      // a "Ripristina da un backup…" from here uses first-write, not If-Match.
      dataMissing = true;
      dataExistsOnDisk = false;
      lastEnvelope = null;
      blobEtag = null;
    }
  } catch {
    reachedServer = false;
  }

  if (!reachedServer || dataMissing) {
    $('unlock-error').textContent = reachedServer
      ? 'Dati non trovati. Puoi ripristinare da un backup con il pulsante qui sotto.'
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
    $('unlock-password').value = ''; // don't leave the master password in the DOM
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
    nameLine.append(buildStatusDot(result.client), ' ');
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

/* Enter / "Cerca":
   - a result is highlighted → open it;
   - there IS a query but no match → offer to create a client from it;
   - nothing typed yet → just (re)show the dropdown. */
$('search-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const query = $('search-input').value.trim();
  if (selectedIndex >= 0 && dropdownResults[selectedIndex]) {
    openResult(dropdownResults[selectedIndex]);
  } else if (query && dropdownResults.length === 0) {
    openCreateFromSearch(); // no client matches → create one, seeded from the query
  } else {
    renderDropdown();
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

/* Changing the sort re-renders the list (and opens it if it was closed —
   picking an order clearly means "show me the list"). */
$('sort-select').addEventListener('change', () => {
  directorySort = DIRECTORY_SORTS[$('sort-select').value] ? $('sort-select').value : 'cognome';
  localStorage.setItem('agenda-sort', directorySort);
  if (!directoryOpen) {
    directoryOpen = true;
    $('browse-button').setAttribute('aria-expanded', 'true');
  }
  renderDirectory();
});

function renderDirectory() {
  const directory = $('client-directory');
  $('sort-select').value = directorySort; // keep the control in sync
  directory.classList.toggle('hidden', !directoryOpen);
  directory.textContent = '';
  if (!directoryOpen) return;

  for (const client of clientsSortedForDirectory()) {
    const row = document.createElement('div');
    row.className = 'directory-row';
    row.setAttribute('role', 'button');
    row.tabIndex = 0;

    const name = document.createElement('span');
    name.className = 'row-name';
    name.append(buildStatusDot(client), ` ${client.lastName} ${client.firstName} `);
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

  // Status chip: colored dot + label (PROSPECT / CLIENTE / KO).
  const statusChip = $('profile-status');
  statusChip.textContent = '';
  statusChip.append(buildStatusDot(client), CLIENT_STATUSES[clientStatus(client)].label);

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
  when.textContent = dateFormatFull.format(note.createdAt);

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

/* Epoch ms → "YYYY-MM-DDTHH:MM" in LOCAL time, the format the
   datetime-local input expects. (toISOString would shift to UTC.) */
function toDatetimeLocalValue(epochMs) {
  const d = new Date(epochMs);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
         `T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function editNoteInline(noteEl, note) {
  if (editingBlocked) return;
  const textEl = noteEl.querySelector('.note-text');
  if (!textEl) return;

  const textarea = document.createElement('textarea');
  textarea.value = note.text;
  textarea.rows = Math.max(3, note.text.split('\n').length);

  // Date and time are editable too — useful to file a note under the day
  // the conversation actually happened. The diary re-sorts on save.
  const whenLabel = document.createElement('label');
  whenLabel.className = 'note-when-edit';
  whenLabel.textContent = 'Data e ora ';
  const whenInput = document.createElement('input');
  whenInput.type = 'datetime-local';
  whenInput.value = toDatetimeLocalValue(note.createdAt);
  whenLabel.append(whenInput);

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
    let changed = false;

    const newText = textarea.value.trim();
    if (newText && newText !== note.text) {
      note.text = newText;
      changed = true;
    }

    // An empty or unparsable picker value keeps the original timestamp.
    const newWhen = whenInput.value ? new Date(whenInput.value).getTime() : NaN;
    if (Number.isFinite(newWhen) && newWhen !== note.createdAt) {
      note.createdAt = newWhen;
      changed = true;
    }

    if (changed) {
      note.updatedAt = Date.now();
      findClient(openClientId).updatedAt = Date.now();
      scheduleSave();
    }
    renderProfile(); // re-sorts the diary if the date moved
  });
  editActions.append(cancelButton, saveButton);

  textEl.replaceWith(textarea, whenLabel, editActions);
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

/* prefill (only when creating) can carry { code } or { lastName } to seed
   the dialog from the search box. See openCreateFromSearch below. */
function openClientDialog(client = null, prefill = null) {
  if (editingBlocked) return;
  clientBeingEdited = client;
  $('client-dialog-title').textContent = client ? 'Modifica cliente' : 'Nuovo cliente';
  $('client-code-input').value = client ? client.code : (prefill?.code || '');
  $('client-first-name-input').value = client ? client.firstName : '';
  $('client-last-name-input').value = client ? client.lastName : (prefill?.lastName || '');
  // Pre-select the client's current status; new clients start as PROSPECT.
  const status = client ? clientStatus(client) : 'prospect';
  document.querySelector(`input[name="client-status"][value="${status}"]`).checked = true;
  $('client-form-error').classList.add('hidden');
  $('client-dialog').showModal();
  // Focus where the user would naturally keep typing:
  // seeded a code → jump to Cognome; seeded a surname → jump to Nome;
  // otherwise start at the top (Codice).
  const focusId = prefill?.code ? 'client-last-name-input'
    : prefill?.lastName ? 'client-first-name-input'
    : 'client-code-input';
  setTimeout(() => $(focusId).focus(), 50);
}

/* Turn the search box text into a new-client dialog. A query made only of
   digits/codes seeds the "Codice cliente"; anything else is a name, and
   since the surname comes first it seeds "Cognome". */
function openCreateFromSearch() {
  const query = $('search-input').value.trim();
  let prefill = null;
  if (query) {
    prefill = /^[0-9\s.\-/]+$/.test(query)
      ? { code: query.toLocaleUpperCase('it-IT') }
      : { lastName: query.toLocaleUpperCase('it-IT') };
  }
  closeDropdown();
  $('search-input').value = '';
  openClientDialog(null, prefill);
}

$('new-client-button').addEventListener('click', openCreateFromSearch);
$('edit-client-button').addEventListener('click', () => openClientDialog(findClient(openClientId)));
$('client-cancel-button').addEventListener('click', () => $('client-dialog').close());

$('client-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const code = $('client-code-input').value.trim();
  // Names are stored uppercase — the archive convention of this agenda.
  const firstName = $('client-first-name-input').value.trim().toLocaleUpperCase('it-IT');
  const lastName = $('client-last-name-input').value.trim().toLocaleUpperCase('it-IT');
  const status = document.querySelector('input[name="client-status"]:checked').value;
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
    Object.assign(clientBeingEdited, { code, firstName, lastName, status, updatedAt: now });
  } else {
    const newClient = {
      id: 'c-' + crypto.randomUUID(),
      code, firstName, lastName, status,
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
    // Don't leave either password sitting in the (closed) dialog inputs.
    $('current-password-input').value = '';
    $('new-password-input').value = '';
    $('confirm-password-input').value = '';
    $('password-dialog').close();
    showToast('Password cambiata ✓');
  } catch {
    errorEl.textContent = 'La password attuale non è corretta.';
    errorEl.classList.remove('hidden');
  } finally {
    $('password-save-button').disabled = false;
  }
});

/* ═══════════ 11b. Encrypted backup: export ═══════════ */

let pendingBackupWords = null; // the phrase shown in the open export dialog

$('export-backup-button').addEventListener('click', async () => {
  closeSettingsMenu();
  pendingBackupWords = await generateRecoveryPhrase();

  // Show the 24 words as numbered chips — the explicit number keeps them
  // aligned even when a word is long, and reads in copy order (1→24).
  const grid = $('word-grid');
  grid.textContent = '';
  pendingBackupWords.forEach((word, index) => {
    const li = document.createElement('li');
    const num = document.createElement('span');
    num.className = 'word-num';
    num.textContent = `${index + 1}.`;
    const text = document.createElement('span');
    text.className = 'word-text';
    text.textContent = word;
    li.append(num, text);
    grid.append(li);
  });
  $('words-written-checkbox').checked = false;
  $('backup-save-button').disabled = true;
  $('backup-error').classList.add('hidden');
  $('backup-dialog').showModal();
});

$('words-written-checkbox').addEventListener('change', (event) => {
  $('backup-save-button').disabled = !event.target.checked;
});

$('backup-cancel-button').addEventListener('click', () => {
  pendingBackupWords = null;
  $('backup-dialog').close();
});

// However the dialog closes (button, Esc, lock): the words leave the DOM.
$('backup-dialog').addEventListener('close', () => {
  pendingBackupWords = null;
  $('word-grid').textContent = '';
});

/* Hand a file to the native app's save panel. Returns 'saved' | 'cancelled'
   | 'error', or null when not running inside the native app (plain browser
   during development — the caller then falls back to a normal download). */
async function nativeSaveFile(filename, content) {
  const handler = window.webkit?.messageHandlers?.agenda;
  if (!handler) return null;
  try {
    return await handler.postMessage({ action: 'saveBackup', filename, content });
  } catch {
    return 'error';
  }
}

$('backup-save-button').addEventListener('click', async () => {
  if (!pendingBackupWords) return;
  const words = pendingBackupWords; // capture before any await
  const errorEl = $('backup-error');
  errorEl.classList.add('hidden');
  $('backup-save-button').disabled = true;
  try {
    const envelope = await buildBackupEnvelope(words);
    // If the dialog was dismissed (Esc / lock) while we were encrypting, the
    // user cancelled: do NOT pop a save panel for a phrase they can't see.
    if (!$('backup-dialog').open) return;

    const content = JSON.stringify(envelope, null, 2);
    const stamp = new Date(envelope.createdAt).toISOString().slice(0, 10);
    const filename = `Agenda-backup-${stamp}.agendabackup`;

    const result = await nativeSaveFile(filename, content);
    if (result === null) {
      // Development fallback: trigger a browser download.
      const url = URL.createObjectURL(new Blob([content], { type: 'application/json' }));
      const link = document.createElement('a');
      link.href = url; link.download = filename;
      link.click();
      URL.revokeObjectURL(url);
    } else if (result === 'cancelled') {
      $('backup-save-button').disabled = false;
      return; // user closed the save panel; leave the dialog open
    } else if (result !== 'saved') {
      throw new Error('save-failed');
    }
    pendingBackupWords = null;
    $('backup-dialog').close();
    showToast('Backup salvato ✓');
  } catch {
    errorEl.textContent = 'Impossibile salvare il file di backup. Riprova.';
    errorEl.classList.remove('hidden');
    $('backup-save-button').disabled = false;
  }
});

/* ═══════════ 11c. Encrypted backup: restore ═══════════ */

$('restore-link').addEventListener('click', () => {
  $('restore-file-input').value = '';
  $('restore-phrase-input').value = '';
  $('restore-password-input').value = '';
  $('restore-confirm-input').value = '';
  $('restore-file-info').classList.add('hidden');
  $('restore-error').classList.add('hidden');
  $('restore-dialog').showModal();
});

let restoreInProgress = false; // true while a restore is mid-flight

$('restore-cancel-button').addEventListener('click', () => {
  if (restoreInProgress) return; // ignore clicks during an in-flight restore
  $('restore-dialog').close();
});

// Block Esc from closing the dialog while a restore is running: closing
// mid-flight would leave the flow half-done and pop the confirm sheet after
// the dialog had already vanished.
$('restore-dialog').addEventListener('cancel', (event) => {
  if (restoreInProgress) event.preventDefault();
});

// However the dialog closes, wipe the recovery phrase, passwords and chosen
// filename — they are as secret as the backup itself and must never linger
// behind the lock screen.
$('restore-dialog').addEventListener('close', () => {
  $('restore-phrase-input').value = '';
  $('restore-password-input').value = '';
  $('restore-confirm-input').value = '';
  $('restore-file-input').value = '';
  $('restore-file-info').textContent = '';
  $('restore-file-info').classList.add('hidden');
});

// Read the chosen file as text.
function readFileText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error);
    reader.readAsText(file);
  });
}

$('restore-file-input').addEventListener('change', () => {
  const file = $('restore-file-input').files[0];
  const info = $('restore-file-info');
  if (file) {
    info.textContent = `File scelto: ${file.name}`;
    info.classList.remove('hidden');
  } else {
    info.classList.add('hidden');
  }
});

$('restore-form').addEventListener('submit', async (event) => {
  event.preventDefault();

  // Claim the flow SYNCHRONOUSLY, before any await, so a double Enter/click
  // cannot start two concurrent restores (they would race on the same etag).
  if (restoreInProgress) return;
  restoreInProgress = true;
  $('restore-submit-button').disabled = true;
  $('restore-cancel-button').disabled = true;

  const errorEl = $('restore-error');
  errorEl.classList.add('hidden');

  const file = $('restore-file-input').files[0];
  const words = parsePhrase($('restore-phrase-input').value);
  const password = $('restore-password-input').value;
  const confirmation = $('restore-confirm-input').value;

  const fail = (msg) => { errorEl.textContent = msg; errorEl.classList.remove('hidden'); };

  try {
    if (!file) return fail('Scegli il file di backup.');
    if (password.length < 8) return fail('La nuova password deve avere almeno 8 caratteri.');
    if (password !== confirmation) return fail('Le due password non coincidono.');

    // The recovery phrase checksum catches a typo before we even try to
    // decrypt, so the user gets a precise message instead of a vague failure.
    const check = await validateRecoveryPhrase(words);
    if (!check.ok) return fail(check.error);

    // Parse and sanity-check the backup file.
    let envelope;
    try {
      envelope = JSON.parse(await readFileText(file));
    } catch {
      return fail('Il file scelto non è un backup di Agenda valido.');
    }
    if (!envelope || envelope.format !== 'agenda-backup-v1'
        || typeof envelope.iv !== 'string' || typeof envelope.data !== 'string'
        || !envelope.kdf?.salt) {
      return fail('Il file scelto non è un backup di Agenda valido.');
    }

    // Decrypt the backup with the 24-word key — into a LOCAL. The in-memory
    // key and app state stay untouched until the write below actually lands,
    // so a failure can never leave the app half-restored behind the lock.
    let restoredState;
    try {
      const salt = base64.decode(envelope.kdf.salt);
      const key = await deriveBackupKey(words, salt, envelope.kdf.iter || KDF_ITERATIONS);
      restoredState = await decryptEnvelope(key, envelope);
    } catch {
      return fail('Le 24 parole non aprono questo backup. Controllale e riprova.');
    }

    // Refresh our view of the disk right before writing: another client (or a
    // deletion) may have changed it while we sat on the lock screen. This
    // gives us the correct precondition (first-write vs. If-Match) and etag.
    let onDisk = false;
    let currentEtag = null;
    try {
      const stored = await fetchBlob();
      if (stored) { onDisk = true; currentEtag = stored.etag; }
    } catch {
      return fail('Impossibile contattare il server. Riavvia l’app e riprova.');
    }

    // Replacing existing data is destructive — confirm first.
    if (onDisk && !confirm('Su questo Mac ci sono già dei dati. Ripristinando il backup verranno SOSTITUITI. Continuare?')) {
      return; // the finally re-enables the buttons
    }

    // Encrypt the restored data under a fresh key for THIS Mac (locals only).
    const localSalt = crypto.getRandomValues(new Uint8Array(16));
    const localKey = await deriveKey(password, localSalt, KDF_ITERATIONS);
    const localEnvelope = await encryptState(localKey, localSalt, restoredState);
    let newEtag;
    try {
      newEtag = await storeBlob(localEnvelope,
        onDisk ? { etag: currentEtag } : { isFirstWrite: true });
    } catch (storeError) {
      return fail(storeError.message === 'conflict'
        ? 'I dati su questo Mac sono cambiati in un’altra finestra. Riprova.'
        : 'Impossibile salvare i dati ripristinati. Riprova.');
    }

    // The write landed — now adopt the restored key and data all together.
    keySalt = localSalt;
    encryptionKey = localKey;
    appState = restoredState;
    lastEnvelope = localEnvelope;
    blobEtag = newEtag;
    dataExistsOnDisk = true;
    hasUnsavedChanges = false;
    editingBlocked = false;

    $('restore-dialog').close();
    openHome();
    showToast('Dati ripristinati ✓');
  } finally {
    restoreInProgress = false;
    $('restore-submit-button').disabled = false;
    $('restore-cancel-button').disabled = false;
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
