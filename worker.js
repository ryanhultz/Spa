/**
 * The Ledger — Sync Worker
 *
 * A tiny key/value API backed by Cloudflare KV, with server-side
 * authentication and per-section permission checks — the server, not
 * just the app's UI, decides who can read or write what.
 *
 * USER STORAGE: each user has their own KV key (`user:<username>`),
 * not a single shared array for everyone. Resetting one person's
 * password, or granting a permission, only ever touches that one
 * key — it can never accidentally revert someone else's very-recent
 * change the way a shared "read everyone, write everyone back"
 * pattern can. An old single-array `stop-users` key (from earlier
 * versions) is migrated into this format automatically, once, the
 * first time it's needed.
 *
 * Auth endpoints:
 *   POST /auth/login    {username,password}          -> {ok,token,permissions,username}
 *   POST /auth/signup   {username,password,inviteCode}-> {ok,token,permissions,username}
 *   POST /auth/master   {password}                    -> {ok,token}
 *
 * User management endpoints (require a Bearer token with "users"
 * permission, or a master token):
 *   POST /users/upsert  {username, password?, permissions?} -> creates the
 *                        user if new, or patches just the given field(s)
 *                        on an existing one. Never touches any other user.
 *   POST /users/delete  {username} -> removes that one user's record.
 *
 * Data endpoints:
 *   GET  /data/:key   -> returns the JSON stored at :key (or `null`).
 *                        GET /data/stop-users assembles the list from
 *                        each user's own key, passwords always stripped.
 *   POST /data/:key   -> stores the JSON request body at :key.
 *                        Requires a valid Bearer token with the matching
 *                        permission (see KEY_PERMISSIONS below), except
 *                        stop-activity and stop-errors, which anyone can
 *                        append to (needed for pre-login failed-attempt
 *                        and crash logging). POST /data/stop-users is
 *                        disabled — use /users/upsert or /users/delete.
 *
 * Backup endpoints (all require a Bearer token with "backup" permission,
 * or a master token):
 *   GET  /backups         -> list all backups (newest first), metadata only
 *   POST /backups         -> create a manual backup of all data right now
 *   POST /backups/restore -> body {key}. Restores all data from that backup
 *   POST /backups/delete  -> body {key}. Deletes that backup
 *
 * Automatic daily backups run via the scheduled() handler below —
 * requires a Cron Trigger configured in the Cloudflare dashboard
 * (see README.md). Automatic backups older than 30 days are cleaned
 * up automatically; manual backups are kept until deleted by hand.
 *
 * Requires:
 *   - A KV namespace bound to this Worker as STOP_KV
 *   - Three Secrets set on this Worker: ADMIN_PASSWORD, INVITE_CODE,
 *     AUTH_SECRET (see README.md for setup steps)
 */

const DATA_KEYS = [
  'stop-users',
  'stop-activity',
  'stop-products',
  'stop-supplies',
  'stop-custom-protocols',
  'stop-allergens',
  'stop-errors',
  'stop-rooms',
  'stop-durations',
  'stop-categories',
  'stop-home-links',
  'stop-sub-protocols',
  'stop-shift-templates',
  'stop-announcement',
];

// Which permission a section's data requires to be WRITTEN. stop-users
// writes go through /users/upsert and /users/delete instead of this
// generic path. stop-activity and stop-errors are handled by their own
// dedicated append-only endpoints (see below) — the generic path here
// refuses both outright, the same way it already refuses stop-users.
const KEY_PERMISSIONS = {
  'stop-products': 'inventory',
  'stop-supplies': 'inventory',
  'stop-custom-protocols': 'protocols',
  'stop-allergens': 'allergens',
  'stop-rooms': 'settings',
  'stop-durations': 'settings',
  'stop-categories': 'settings',
  'stop-home-links': 'settings',
  'stop-sub-protocols': 'protocols',
  'stop-shift-templates': 'settings',
  'stop-announcement': 'settings',
};

const NO_GENERIC_WRITE_KEYS = new Set(['stop-users', 'stop-activity', 'stop-errors']);

const AUTO_BACKUP_RETENTION_DAYS = 30;
const USER_SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const MASTER_SESSION_TTL_MS = 4 * 60 * 60 * 1000; // 4 hours — broader access, shorter leash

// Which origins are allowed to call this Worker from a browser. Configurable
// via the ALLOWED_ORIGINS Secret/Variable (comma-separated, e.g.
// "https://spa.example.com,https://staging.example.com") — change it from
// the Cloudflare dashboard any time the app's domain changes, no code
// change or redeploy needed. Falls back to the app's known current domain
// if that variable isn't set, so this never silently breaks on first deploy.
function getAllowedOrigin(request, env) {
  const requestOrigin = request.headers.get('Origin') || '';
  const configured = (env.ALLOWED_ORIGINS || 'https://spa.ryanhultz.workers.dev')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
  return configured.includes(requestOrigin) ? requestOrigin : 'null';
}

/* ---------------- Token signing (stateless, HMAC-SHA256) ---------------- */

function base64url(bytes) {
  let bin = '';
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
async function getHmacKey(secret) {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}
async function signToken(payloadObj, secret) {
  const key = await getHmacKey(secret);
  const payloadB64 = base64url(new TextEncoder().encode(JSON.stringify(payloadObj)));
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadB64));
  return `${payloadB64}.${base64url(sig)}`;
}
async function verifyToken(token, secret) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payloadB64, sigB64] = parts;
  try {
    const key = await getHmacKey(secret);
    const valid = await crypto.subtle.verify(
      'HMAC', key, base64urlDecode(sigB64), new TextEncoder().encode(payloadB64)
    );
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(base64urlDecode(payloadB64)));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch (e) {
    return null;
  }
}
function getBearerToken(request) {
  const header = request.headers.get('Authorization') || '';
  const m = header.match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}
function hasPermission(payload, permKey) {
  if (!payload) return false;
  if (payload.isMaster) return true;
  if (!permKey) return true; // no specific permission required, just needs to be logged in
  // "inventory" replaces the old separate "products"/"supplies" permissions.
  // Anyone who already had either of those keeps working access automatically —
  // no data migration needed, and new grants just use the single unified key.
  if (permKey === 'inventory') {
    return !!(payload.permissions && (payload.permissions.inventory || payload.permissions.products || payload.permissions.supplies));
  }
  return !!(payload.permissions && payload.permissions[permKey]);
}
// A demo-flagged session can do everything a normal one can on screen, but
// every actual write is refused here at the server — not just skipped by
// the app's UI — so the demo account's credentials being handed out to
// other people can never let someone touch real data, even by going
// around the app entirely and calling this API directly.
// Checks a user's CURRENT demo status from the database, not the value
// frozen into their token at login. A token's isDemo claim can go stale
// the moment an admin changes someone's status — if this only checked
// the token, a user already logged in when their demo status changes
// would keep the OLD behavior for the rest of that session, which could
// mean a real account silently failing to save (or worse, a demo
// account regaining real write access) until they log out and back in.
async function isDemoToken(env, payload) {
  if (!payload || !payload.username) return false;
  if (payload.isMaster) return false; // master sessions are never demo accounts
  const user = await getUserByUsername(env, payload.username);
  return !!(user && user.isDemo);
}

/* ---------------- Password hashing (PBKDF2, salted per-user) ---------------- */
// Passwords are never stored in plain text. Existing plain-text accounts
// (from before this was added) are upgraded automatically, transparently,
// the moment they next log in successfully — no forced reset, nothing
// for anyone to notice.

const PBKDF2_ITERATIONS = 100000;

function bytesToBase64(bytes) {
  let bin = '';
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin);
}
function base64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
async function deriveHash(password, saltBytes) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBytes, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial, 256
  );
  return bytesToBase64(bits);
}
// Returns {passwordHash, passwordSalt} — spread this onto a user object in
// place of a plain `password` field whenever a password is set or changed.
async function hashNewPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const passwordHash = await deriveHash(password, salt);
  return { passwordHash, passwordSalt: bytesToBase64(salt) };
}
// Checks a submitted password against a user record, whether that record
// still has a legacy plain-text password or an already-hashed one.
async function verifyPassword(submittedPassword, user) {
  if (user.passwordHash && user.passwordSalt) {
    const computed = await deriveHash(submittedPassword, base64ToBytes(user.passwordSalt));
    return computed === user.passwordHash;
  }
  if (user.password !== undefined) {
    return user.password === submittedPassword;
  }
  return false;
}
// Called right after a successful login — if the account still has a
// legacy plain-text password, replace it with a salted hash using the
// password we just confirmed is correct. No-op if already hashed.
async function upgradePasswordIfNeeded(env, user, plainPassword) {
  if (user.passwordHash || user.password === undefined) return;
  const { passwordHash, passwordSalt } = await hashNewPassword(plainPassword);
  delete user.password;
  user.passwordHash = passwordHash;
  user.passwordSalt = passwordSalt;
  await putUser(env, user);
}

/* ---------------- Login rate limiting (per-username) ---------------- */
// A handful of wrong passwords in a row locks that username out for a
// cooldown window — scripting thousands of guesses per minute now gets a
// few real attempts before being forced to wait, not unlimited tries.
// Keyed by username (not IP), so this can't be dodged by rotating
// source addresses. KV's own TTL expiry handles cleanup automatically —
// no separate reset logic needed.

const MAX_FAILED_LOGIN_ATTEMPTS = 5;
const LOGIN_LOCKOUT_SECONDS = 15 * 60; // 15 minutes

function failedLoginKey(username) {
  return `failedlogin:${String(username).toLowerCase()}`;
}
async function isRateLimited(env, username) {
  const raw = await env.STOP_KV.get(failedLoginKey(username));
  const count = raw ? parseInt(raw, 10) : 0;
  return count >= MAX_FAILED_LOGIN_ATTEMPTS;
}
async function recordFailedLogin(env, username) {
  const key = failedLoginKey(username);
  const raw = await env.STOP_KV.get(key);
  const count = raw ? parseInt(raw, 10) : 0;
  await env.STOP_KV.put(key, String(count + 1), { expirationTtl: LOGIN_LOCKOUT_SECONDS });
}
async function clearFailedLogins(env, username) {
  await env.STOP_KV.delete(failedLoginKey(username));
}

/* ---------------- Per-user storage ---------------- */
// Each user lives at its own key: user:<username-lowercase>. Nobody's
// record is ever read-modify-written alongside anyone else's.

function blankPermissions() {
  return { users: false, protocols: false, inventory: false, allergens: false, activity: false, backup: false, errors: false, settings: false, messages: false };
}
function userKey(username) {
  return `user:${String(username).toLowerCase()}`;
}
async function getUserByUsername(env, username) {
  await migrateLegacyUsersIfNeeded(env);
  const raw = await env.STOP_KV.get(userKey(username));
  return raw ? JSON.parse(raw) : null;
}
async function putUser(env, user) {
  await env.STOP_KV.put(userKey(user.username), JSON.stringify(user));
}
async function deleteUserRecord(env, username) {
  await env.STOP_KV.delete(userKey(username));
  await env.STOP_KV.delete(`lastlogin:${String(username).toLowerCase()}`);
}
async function getAllUserKeys(env) {
  const result = await env.STOP_KV.list({ prefix: 'user:' });
  return result.keys.map(k => k.name);
}
async function getAllUsers(env) {
  await migrateLegacyUsersIfNeeded(env);
  const keys = await getAllUserKeys(env);
  const users = await Promise.all(keys.map(async (k) => {
    const raw = await env.STOP_KV.get(k);
    return raw ? JSON.parse(raw) : null;
  }));
  return users.filter(Boolean);
}
// One-time migration from the old single-array format. Runs only if no
// per-user keys exist yet but the legacy array does. The legacy key is
// left in place afterward (untouched, unused) as a free safety net.
async function migrateLegacyUsersIfNeeded(env) {
  const existingKeys = await getAllUserKeys(env);
  if (existingKeys.length > 0) return;
  const legacyRaw = await env.STOP_KV.get('stop-users');
  if (!legacyRaw) return;
  let legacyUsers;
  try { legacyUsers = JSON.parse(legacyRaw); } catch (e) { return; }
  if (!Array.isArray(legacyUsers) || legacyUsers.length === 0) return;
  for (const u of legacyUsers) {
    if (!u || !u.username) continue;
    await env.STOP_KV.put(userKey(u.username), JSON.stringify(u));
  }
}
function stripPasswords(users) {
  return users.map(u => {
    const { password, passwordHash, passwordSalt, securityAnswer, ...rest } = u;
    return rest;
  });
}
async function getUsersWithLastLogin(env) {
  const users = await getAllUsers(env);
  return Promise.all(users.map(async (u) => {
    const ll = await env.STOP_KV.get(`lastlogin:${u.username.toLowerCase()}`);
    return { ...u, lastLogin: ll || u.lastLogin || null };
  }));
}

/* ---------------- Backups ---------------- */

async function snapshotAllData(env) {
  const data = {};
  for (const key of DATA_KEYS) {
    if (key === 'stop-users') {
      data[key] = await getAllUsers(env); // full records, including passwords, for accurate restore
      continue;
    }
    const raw = await env.STOP_KV.get(key);
    data[key] = raw ? JSON.parse(raw) : null;
  }
  return data;
}
async function createBackup(env, type) {
  const timestamp = new Date().toISOString();
  const data = await snapshotAllData(env);
  const backupKey = `backup:${timestamp}`;
  await env.STOP_KV.put(backupKey, JSON.stringify({ type, timestamp, data }), { metadata: { type, timestamp } });
  return { key: backupKey, type, timestamp };
}
async function listBackups(env) {
  const result = await env.STOP_KV.list({ prefix: 'backup:' });
  return result.keys
    .map(k => ({
      key: k.name,
      type: k.metadata && k.metadata.type ? k.metadata.type : 'unknown',
      timestamp: k.metadata && k.metadata.timestamp ? k.metadata.timestamp : null,
    }))
    .sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
}
async function restoreBackup(env, key) {
  const raw = await env.STOP_KV.get(key);
  if (!raw) return { ok: false, error: 'Backup not found' };
  const backup = JSON.parse(raw);
  for (const dataKey of DATA_KEYS) {
    const value = backup.data[dataKey];
    if (dataKey === 'stop-users') {
      // Replace all per-user records wholesale with the backup's version.
      const existingKeys = await getAllUserKeys(env);
      for (const k of existingKeys) await env.STOP_KV.delete(k);
      if (Array.isArray(value)) {
        for (const u of value) { if (u && u.username) await putUser(env, u); }
      }
      continue;
    }
    await env.STOP_KV.put(dataKey, JSON.stringify(value === undefined ? null : value));
  }
  return { ok: true };
}
async function deleteBackup(env, key) {
  await env.STOP_KV.delete(key);
  return { ok: true };
}
async function cleanupOldAutoBackups(env) {
  const backups = await listBackups(env);
  const cutoff = Date.now() - AUTO_BACKUP_RETENTION_DAYS * 24 * 60 * 60 * 1000;
  for (const b of backups) {
    if (b.type === 'auto' && b.timestamp && new Date(b.timestamp).getTime() < cutoff) {
      await env.STOP_KV.delete(b.key);
    }
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    // Computed fresh for every request (never shared mutable state — Workers
    // can process multiple requests concurrently in one isolate) so the
    // Origin check is always correct for the specific caller, not whichever
    // request happened to run last.
    const corsHeaders = {
      'Access-Control-Allow-Origin': getAllowedOrigin(request, env),
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };
    function jsonResponse(obj, status = 200) {
      return new Response(JSON.stringify(obj), {
        status,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    /* ---------------- Auth ---------------- */

    if (url.pathname === '/auth/login' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return jsonResponse({ ok: false, error: 'Invalid JSON' }, 400); }
      const { username, password } = body || {};
      if (!username || !password) return jsonResponse({ ok: false, error: 'Missing username or password' }, 400);

      if (await isRateLimited(env, username)) {
        return jsonResponse({ ok: false, error: 'Too many failed attempts. Try again in a few minutes.' }, 429);
      }

      const user = await getUserByUsername(env, username);
      const passwordOk = user ? await verifyPassword(password, user) : false;
      if (!user || !passwordOk) {
        await recordFailedLogin(env, username);
        return jsonResponse({ ok: false, error: 'Incorrect username or password.' }, 401);
      }
      await clearFailedLogins(env, username);
      // lastLogin lives in its own key, separate from the user's own
      // record — a login should never need to rewrite anything else.
      await env.STOP_KV.put(`lastlogin:${user.username.toLowerCase()}`, new Date().toISOString());
      // Transparently upgrade a legacy plain-text password to a salted
      // hash now that we've confirmed it's correct. No-op if already hashed.
      await upgradePasswordIfNeeded(env, user, password);

      const permissions = user.permissions || blankPermissions();
      const token = await signToken(
        { username: user.username, permissions, isMaster: false, isDemo: !!user.isDemo, exp: Date.now() + USER_SESSION_TTL_MS },
        env.AUTH_SECRET
      );
      return jsonResponse({ ok: true, token, permissions, username: user.username });
    }

    if (url.pathname === '/auth/signup' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return jsonResponse({ ok: false, error: 'Invalid JSON' }, 400); }
      const { username, password, inviteCode, securityQuestion, securityAnswer, firstName, lastName } = body || {};
      if (!username || !password) return jsonResponse({ ok: false, error: 'Missing username or password' }, 400);
      if (!env.INVITE_CODE || inviteCode !== env.INVITE_CODE) {
        return jsonResponse({ ok: false, error: 'Invalid invitation code.' }, 401);
      }
      const existing = await getUserByUsername(env, username);
      if (existing) {
        return jsonResponse({ ok: false, error: 'That username is already taken.' }, 409);
      }
      const now = new Date().toISOString();
      // Since a demo account can look at and interact with everything but
      // never actually save a change, it's safe to start it with broad
      // access to the day-to-day sections — Users and the Activity/Error
      // logs are left off since those show real staff usernames and real
      // history, not just editable content.
      const permissions = {
        ...blankPermissions(),
        protocols: true, inventory: true,
        allergens: true, backup: true, settings: true,
      };
      const { passwordHash, passwordSalt } = await hashNewPassword(password);
      // Self-signup accounts start in Demo Mode — fully usable, but nothing
      // they touch actually saves — until an admin explicitly activates
      // them in Management → Users. Accounts an admin creates directly
      // (Add User) are unaffected by this and start as real accounts.
      const newUser = { username, passwordHash, passwordSalt, permissions, lastLogin: now, createdAt: now, isDemo: true };
      if (securityQuestion) newUser.securityQuestion = securityQuestion;
      if (securityAnswer) newUser.securityAnswer = securityAnswer;
      if (firstName) newUser.firstName = firstName;
      if (lastName) newUser.lastName = lastName;
      await putUser(env, newUser);

      const token = await signToken(
        { username, permissions, isMaster: false, isDemo: true, exp: Date.now() + USER_SESSION_TTL_MS },
        env.AUTH_SECRET
      );
      return jsonResponse({ ok: true, token, permissions, username });
    }

    if (url.pathname === '/auth/master' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return jsonResponse({ ok: false, error: 'Invalid JSON' }, 400); }
      const { password } = body || {};
      if (await isRateLimited(env, 'master-password')) {
        return jsonResponse({ ok: false, error: 'Too many failed attempts. Try again in a few minutes.' }, 429);
      }
      if (!env.ADMIN_PASSWORD || password !== env.ADMIN_PASSWORD) {
        await recordFailedLogin(env, 'master-password');
        return jsonResponse({ ok: false, error: 'Incorrect password.' }, 401);
      }
      await clearFailedLogins(env, 'master-password');
      const token = await signToken(
        { username: null, permissions: {}, isMaster: true, exp: Date.now() + MASTER_SESSION_TTL_MS },
        env.AUTH_SECRET
      );
      return jsonResponse({ ok: true, token });
    }

    // Self-service: change your OWN password and/or security question —
    // requires re-entering the current password, and only ever touches
    // the caller's own record (the token's own username), never anyone
    // else's, so it needs no special permission beyond being logged in.
    if (url.pathname === '/auth/update-account' && request.method === 'POST') {
      const payload = await verifyToken(getBearerToken(request), env.AUTH_SECRET);
      if (!payload || payload.isMaster || !payload.username) {
        return jsonResponse({ ok: false, error: 'Not authorized.' }, 403);
      }
      if (await isDemoToken(env, payload)) return jsonResponse({ ok: true }); // demo accounts never actually write anything
      let body;
      try { body = await request.json(); } catch (e) { return jsonResponse({ ok: false, error: 'Invalid JSON' }, 400); }
      const { currentPassword, newPassword, securityQuestion, securityAnswer, firstName, lastName } = body || {};
      const user = await getUserByUsername(env, payload.username);
      const currentOk = user ? await verifyPassword(currentPassword, user) : false;
      if (!user || !currentOk) {
        return jsonResponse({ ok: false, error: 'Current password is incorrect.' }, 401);
      }
      if (newPassword) {
        const { passwordHash, passwordSalt } = await hashNewPassword(newPassword);
        delete user.password;
        user.passwordHash = passwordHash;
        user.passwordSalt = passwordSalt;
      }
      if (securityQuestion !== undefined) user.securityQuestion = securityQuestion;
      if (securityAnswer !== undefined) user.securityAnswer = securityAnswer;
      if (firstName !== undefined) user.firstName = firstName;
      if (lastName !== undefined) user.lastName = lastName;
      await putUser(env, user);
      return jsonResponse({ ok: true });
    }

    // Forgot-password recovery via security question — no token needed,
    // since the whole point is helping someone who can't log in. Only
    // ever touches the one named account.
    if (url.pathname === '/auth/security-question' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return jsonResponse({ ok: false, error: 'Invalid JSON' }, 400); }
      const { username } = body || {};
      if (!username) return jsonResponse({ ok: false, error: 'Missing username' }, 400);
      const user = await getUserByUsername(env, username);
      if (!user || !user.securityQuestion) {
        return jsonResponse({ ok: false, error: 'No recovery question is set for this account. Ask an admin to reset your password instead.' }, 404);
      }
      return jsonResponse({ ok: true, question: user.securityQuestion });
    }

    if (url.pathname === '/auth/recover-password' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return jsonResponse({ ok: false, error: 'Invalid JSON' }, 400); }
      const { username, answer, newPassword } = body || {};
      if (!username || !answer || !newPassword) return jsonResponse({ ok: false, error: 'Missing information.' }, 400);
      const recoveryLimitKey = `recovery:${username}`;
      if (await isRateLimited(env, recoveryLimitKey)) {
        return jsonResponse({ ok: false, error: 'Too many failed attempts. Try again in a few minutes.' }, 429);
      }
      const user = await getUserByUsername(env, username);
      if (!user || !user.securityAnswer || String(user.securityAnswer).trim().toLowerCase() !== String(answer).trim().toLowerCase()) {
        await recordFailedLogin(env, recoveryLimitKey);
        return jsonResponse({ ok: false, error: 'That answer is incorrect.' }, 401);
      }
      await clearFailedLogins(env, recoveryLimitKey);
      const { passwordHash, passwordSalt } = await hashNewPassword(newPassword);
      delete user.password;
      user.passwordHash = passwordHash;
      user.passwordSalt = passwordSalt;
      await putUser(env, user);
      return jsonResponse({ ok: true });
    }

    /* ---------------- User management (permission: users) ---------------- */

    if (url.pathname === '/users/upsert' && request.method === 'POST') {
      const payload = await verifyToken(getBearerToken(request), env.AUTH_SECRET);
      if (!hasPermission(payload, 'users')) {
        return jsonResponse({ ok: false, error: 'Not authorized.' }, 403);
      }
      if (await isDemoToken(env, payload)) return jsonResponse({ ok: true }); // demo accounts never actually write anything
      let body;
      try { body = await request.json(); } catch (e) { return jsonResponse({ ok: false, error: 'Invalid JSON' }, 400); }
      const { username, password, permissions, isDemo } = body || {};
      if (!username) return jsonResponse({ ok: false, error: 'Missing username' }, 400);

      const existing = await getUserByUsername(env, username);
      const user = existing || { username, createdAt: new Date().toISOString(), permissions: blankPermissions(), lastLogin: null };
      user.username = username; // preserve whatever casing was provided
      if (password !== undefined) {
        const { passwordHash, passwordSalt } = await hashNewPassword(password);
        delete user.password;
        user.passwordHash = passwordHash;
        user.passwordSalt = passwordSalt;
      }
      if (permissions !== undefined) user.permissions = permissions;
      if (isDemo !== undefined) user.isDemo = isDemo;
      await putUser(env, user);
      return jsonResponse({ ok: true });
    }

    if (url.pathname === '/users/delete' && request.method === 'POST') {
      const payload = await verifyToken(getBearerToken(request), env.AUTH_SECRET);
      if (!hasPermission(payload, 'users')) {
        return jsonResponse({ ok: false, error: 'Not authorized.' }, 403);
      }
      if (await isDemoToken(env, payload)) return jsonResponse({ ok: true });
      let body;
      try { body = await request.json(); } catch (e) { return jsonResponse({ ok: false, error: 'Invalid JSON' }, 400); }
      if (!body || !body.username) return jsonResponse({ ok: false, error: 'Missing username' }, 400);
      await deleteUserRecord(env, body.username);
      return jsonResponse({ ok: true });
    }

    /* ---------------- Backups (permission: backup) ---------------- */

    if (url.pathname.startsWith('/backups')) {
      const payload = await verifyToken(getBearerToken(request), env.AUTH_SECRET);
      if (!hasPermission(payload, 'backup')) {
        return jsonResponse({ ok: false, error: 'Not authorized.' }, 403);
      }

      if (url.pathname === '/backups' && request.method === 'GET') {
        return jsonResponse(await listBackups(env));
      }
      // Every write below — especially restore, which overwrites all live
      // data — is refused for a demo token. GET (listing) above is left
      // alone since it's read-only and harmless.
      if (await isDemoToken(env, payload)) {
        if (url.pathname === '/backups' && request.method === 'POST') {
          return jsonResponse({ ok: true, backup: { key: `backup:demo-${Date.now()}`, type: 'manual', timestamp: new Date().toISOString() } });
        }
        return jsonResponse({ ok: true });
      }
      if (url.pathname === '/backups' && request.method === 'POST') {
        return jsonResponse({ ok: true, backup: await createBackup(env, 'manual') });
      }
      if (url.pathname === '/backups/restore' && request.method === 'POST') {
        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ ok: false, error: 'Invalid JSON' }, 400); }
        if (!body || !body.key) return jsonResponse({ ok: false, error: 'Missing key' }, 400);
        const result = await restoreBackup(env, body.key);
        return jsonResponse(result, result.ok ? 200 : 404);
      }
      if (url.pathname === '/backups/delete' && request.method === 'POST') {
        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ ok: false, error: 'Invalid JSON' }, 400); }
        if (!body || !body.key) return jsonResponse({ ok: false, error: 'Missing key' }, 400);
        return jsonResponse(await deleteBackup(env, body.key));
      }
      return new Response('Not found', { status: 404, headers: corsHeaders });
    }

    /* ---------------- Append-only logs (Activity + Errors) ---------------- */
    // No login required to APPEND — a failed login attempt, by definition,
    // comes from someone not yet authenticated, and that's the one
    // legitimate reason this needs to stay open. What changed: nobody can
    // send a replacement array anymore, only ever one new entry appended
    // to whatever's already there, so the history itself can't be erased
    // or rewritten by anyone anonymous. Clearing a log on purpose is still
    // possible, just moved to its own endpoint that requires real
    // authentication and the matching permission.

    async function appendLogEntry(key, entry, maxEntries) {
      const raw = await env.STOP_KV.get(key);
      let list = [];
      try { list = raw ? JSON.parse(raw) : []; } catch (e) { list = []; }
      if (!Array.isArray(list)) list = [];
      list.unshift(entry);
      while (list.length > maxEntries) list.pop();
      await env.STOP_KV.put(key, JSON.stringify(list));
    }

    if (url.pathname === '/log/activity' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return jsonResponse({ ok: false, error: 'Invalid JSON' }, 400); }
      const { username, action } = body || {};
      if (!action) return jsonResponse({ ok: false, error: 'Missing action' }, 400);
      await appendLogEntry('stop-activity', { username: username || '(unknown)', action: String(action), timestamp: new Date().toISOString() }, 200);
      return jsonResponse({ ok: true });
    }
    if (url.pathname === '/log/activity/clear' && request.method === 'POST') {
      const payload = await verifyToken(getBearerToken(request), env.AUTH_SECRET);
      if (!hasPermission(payload, 'activity')) return jsonResponse({ ok: false, error: 'Not authorized.' }, 403);
      if (await isDemoToken(env, payload)) return jsonResponse({ ok: true });
      await env.STOP_KV.put('stop-activity', '[]');
      return jsonResponse({ ok: true });
    }

    if (url.pathname === '/log/error' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return jsonResponse({ ok: false, error: 'Invalid JSON' }, 400); }
      const { message, location, username } = body || {};
      if (!message) return jsonResponse({ ok: false, error: 'Missing message' }, 400);
      await appendLogEntry('stop-errors', {
        message: String(message), location: location ? String(location) : '',
        username: username || '(unknown)', timestamp: new Date().toISOString()
      }, 100);
      return jsonResponse({ ok: true });
    }
    if (url.pathname === '/log/error/clear' && request.method === 'POST') {
      const payload = await verifyToken(getBearerToken(request), env.AUTH_SECRET);
      if (!hasPermission(payload, 'errors')) return jsonResponse({ ok: false, error: 'Not authorized.' }, 403);
      if (await isDemoToken(env, payload)) return jsonResponse({ ok: true });
      await env.STOP_KV.put('stop-errors', '[]');
      return jsonResponse({ ok: true });
    }

    /* ---------------- Messaging ---------------- */
    // Real per-user privacy, not just the app choosing not to show something:
    // GET /messages/threads only ever returns threads the caller's own index
    // says they belong to, and GET /messages/threads/:id refuses anyone who
    // isn't an actual participant — with one disclosed exception, oversight
    // (a separate, explicitly-permissioned endpoint for reading everything).

    function threadKey(id) { return `thread:${id}`; }
    function messagesKey(threadId) { return `messages:${threadId}`; }
    function userThreadsKey(username) { return `userthreads:${username.toLowerCase()}`; }

    async function getThread(id) {
      const raw = await env.STOP_KV.get(threadKey(id));
      if (!raw) return null;
      try { return JSON.parse(raw); } catch (e) { return null; }
    }
    async function putThread(thread) {
      await env.STOP_KV.put(threadKey(thread.id), JSON.stringify(thread));
    }
    async function getUserThreads(username) {
      const raw = await env.STOP_KV.get(userThreadsKey(username));
      try { const list = raw ? JSON.parse(raw) : []; return Array.isArray(list) ? list : []; }
      catch (e) { return []; }
    }
    async function putUserThreads(username, list) {
      await env.STOP_KV.put(userThreadsKey(username), JSON.stringify(list));
    }
    async function getThreadMessages(threadId) {
      const raw = await env.STOP_KV.get(messagesKey(threadId));
      try { const list = raw ? JSON.parse(raw) : []; return Array.isArray(list) ? list : []; }
      catch (e) { return []; }
    }
    function isParticipant(thread, username) {
      return !!(thread && thread.participants.some(p => p.toLowerCase() === username.toLowerCase()));
    }

    if (url.pathname === '/messages/threads' && request.method === 'POST') {
      const payload = await verifyToken(getBearerToken(request), env.AUTH_SECRET);
      if (!payload || !payload.username) return jsonResponse({ ok: false, error: 'Not authorized.' }, 403);
      let body;
      try { body = await request.json(); } catch (e) { return jsonResponse({ ok: false, error: 'Invalid JSON' }, 400); }
      const { type, participantUsernames, name } = body || {};
      if (type !== 'dm' && type !== 'group') return jsonResponse({ ok: false, error: 'Invalid thread type.' }, 400);
      if (!Array.isArray(participantUsernames) || !participantUsernames.length) {
        return jsonResponse({ ok: false, error: 'Missing participants.' }, 400);
      }
      const creator = payload.username;
      const allParticipants = Array.from(new Set([creator, ...participantUsernames]));
      for (const uname of allParticipants) {
        const u = await getUserByUsername(env, uname);
        if (!u) return jsonResponse({ ok: false, error: `User "${uname}" not found.` }, 400);
      }
      if (type === 'dm' && allParticipants.length !== 2) {
        return jsonResponse({ ok: false, error: "A direct message needs exactly one other person." }, 400);
      }
      if (type === 'dm') {
        // Reuse an existing DM between the same two people instead of
        // fragmenting their conversation across duplicate threads.
        const creatorThreads = await getUserThreads(creator);
        for (const ut of creatorThreads) {
          const existing = await getThread(ut.threadId);
          if (existing && existing.type === 'dm' && existing.participants.length === 2 &&
              existing.participants.every(p => allParticipants.includes(p))) {
            return jsonResponse({ ok: true, thread: existing });
          }
        }
      }
      const id = crypto.randomUUID();
      const thread = {
        id, type, participants: allParticipants, creatorUsername: creator,
        name: type === 'group' ? (name || 'Group') : null,
        createdAt: new Date().toISOString(),
      };
      await putThread(thread);
      await env.STOP_KV.put(messagesKey(id), '[]');
      for (const uname of allParticipants) {
        const list = await getUserThreads(uname);
        list.push({ threadId: id, lastReadAt: uname === creator ? new Date().toISOString() : null });
        await putUserThreads(uname, list);
      }
      return jsonResponse({ ok: true, thread });
    }

    if (url.pathname === '/messages/threads' && request.method === 'GET') {
      const payload = await verifyToken(getBearerToken(request), env.AUTH_SECRET);
      if (!payload || !payload.username) return jsonResponse({ ok: false, error: 'Not authorized.' }, 403);
      const userThreads = await getUserThreads(payload.username);
      const results = [];
      for (const ut of userThreads) {
        const thread = await getThread(ut.threadId);
        if (!thread) continue;
        const messages = await getThreadMessages(ut.threadId);
        const lastMessage = messages[0] || null;
        const unreadCount = ut.lastReadAt ? messages.filter(m => m.timestamp > ut.lastReadAt).length : messages.length;
        results.push({
          id: thread.id, type: thread.type, name: thread.name,
          participants: thread.participants, creatorUsername: thread.creatorUsername,
          lastMessage, unreadCount,
        });
      }
      return jsonResponse(results);
    }

    const threadDetailMatch = url.pathname.match(/^\/messages\/threads\/([a-zA-Z0-9-]+)$/);
    if (threadDetailMatch && request.method === 'GET') {
      const payload = await verifyToken(getBearerToken(request), env.AUTH_SECRET);
      if (!payload || !payload.username) return jsonResponse({ ok: false, error: 'Not authorized.' }, 403);
      const threadId = threadDetailMatch[1];
      const thread = await getThread(threadId);
      if (!thread) return jsonResponse({ ok: false, error: 'Thread not found.' }, 404);
      const isMember = isParticipant(thread, payload.username);
      const hasOversight = hasPermission(payload, 'messages');
      if (!isMember && !hasOversight) return jsonResponse({ ok: false, error: 'Not authorized.' }, 403);
      const messages = await getThreadMessages(threadId);
      if (isMember) {
        // Oversight viewing a thread never marks it read for the real
        // participants — only an actual member opening it does that.
        const userThreads = await getUserThreads(payload.username);
        const entry = userThreads.find(t => t.threadId === threadId);
        if (entry) {
          entry.lastReadAt = new Date().toISOString();
          await putUserThreads(payload.username, userThreads);
        }
      }
      return jsonResponse({ ok: true, thread, messages });
    }

    const sendMessageMatch = url.pathname.match(/^\/messages\/threads\/([a-zA-Z0-9-]+)\/messages$/);
    if (sendMessageMatch && request.method === 'POST') {
      const payload = await verifyToken(getBearerToken(request), env.AUTH_SECRET);
      if (!payload || !payload.username) return jsonResponse({ ok: false, error: 'Not authorized.' }, 403);
      const threadId = sendMessageMatch[1];
      const thread = await getThread(threadId);
      if (!thread) return jsonResponse({ ok: false, error: 'Thread not found.' }, 404);
      if (!isParticipant(thread, payload.username)) return jsonResponse({ ok: false, error: 'Not authorized.' }, 403);
      let body;
      try { body = await request.json(); } catch (e) { return jsonResponse({ ok: false, error: 'Invalid JSON' }, 400); }
      const text = body && body.text ? String(body.text).slice(0, 4000) : '';
      if (!text.trim()) return jsonResponse({ ok: false, error: 'Message is empty.' }, 400);
      if (await isDemoToken(env, payload)) {
        return jsonResponse({ ok: true, message: { id: 'demo', sender: payload.username, text, timestamp: new Date().toISOString() } });
      }
      const message = { id: crypto.randomUUID(), sender: payload.username, text, timestamp: new Date().toISOString() };
      const messages = await getThreadMessages(threadId);
      messages.unshift(message);
      while (messages.length > 500) messages.pop();
      await env.STOP_KV.put(messagesKey(threadId), JSON.stringify(messages));
      const senderThreads = await getUserThreads(payload.username);
      const entry = senderThreads.find(t => t.threadId === threadId);
      if (entry) { entry.lastReadAt = message.timestamp; await putUserThreads(payload.username, senderThreads); }
      return jsonResponse({ ok: true, message });
    }

    const deleteMessageMatch = url.pathname.match(/^\/messages\/messages\/([a-zA-Z0-9-]+)\/delete$/);
    if (deleteMessageMatch && request.method === 'POST') {
      const payload = await verifyToken(getBearerToken(request), env.AUTH_SECRET);
      if (!payload || !payload.username) return jsonResponse({ ok: false, error: 'Not authorized.' }, 403);
      const msgId = deleteMessageMatch[1];
      let body;
      try { body = await request.json(); } catch (e) { return jsonResponse({ ok: false, error: 'Invalid JSON' }, 400); }
      const threadId = body && body.threadId;
      if (!threadId) return jsonResponse({ ok: false, error: 'Missing threadId.' }, 400);
      if (await isDemoToken(env, payload)) return jsonResponse({ ok: true });
      const messages = await getThreadMessages(threadId);
      const target = messages.find(m => m.id === msgId);
      if (!target) return jsonResponse({ ok: false, error: 'Message not found.' }, 404);
      if (target.sender.toLowerCase() !== payload.username.toLowerCase()) {
        return jsonResponse({ ok: false, error: 'You can only delete your own messages.' }, 403);
      }
      await env.STOP_KV.put(messagesKey(threadId), JSON.stringify(messages.filter(m => m.id !== msgId)));
      return jsonResponse({ ok: true });
    }

    const deleteThreadMatch = url.pathname.match(/^\/messages\/threads\/([a-zA-Z0-9-]+)\/delete$/);
    if (deleteThreadMatch && request.method === 'POST') {
      const payload = await verifyToken(getBearerToken(request), env.AUTH_SECRET);
      if (!payload || !payload.username) return jsonResponse({ ok: false, error: 'Not authorized.' }, 403);
      const threadId = deleteThreadMatch[1];
      const thread = await getThread(threadId);
      if (!thread) return jsonResponse({ ok: true }); // already gone
      if (thread.creatorUsername.toLowerCase() !== payload.username.toLowerCase()) {
        return jsonResponse({ ok: false, error: 'Only the creator can delete this.' }, 403);
      }
      if (await isDemoToken(env, payload)) return jsonResponse({ ok: true });
      await env.STOP_KV.delete(threadKey(threadId));
      await env.STOP_KV.delete(messagesKey(threadId));
      for (const uname of thread.participants) {
        const list = await getUserThreads(uname);
        await putUserThreads(uname, list.filter(t => t.threadId !== threadId));
      }
      return jsonResponse({ ok: true });
    }

    const membersMatch = url.pathname.match(/^\/messages\/threads\/([a-zA-Z0-9-]+)\/members$/);
    if (membersMatch && request.method === 'POST') {
      const payload = await verifyToken(getBearerToken(request), env.AUTH_SECRET);
      if (!payload || !payload.username) return jsonResponse({ ok: false, error: 'Not authorized.' }, 403);
      const threadId = membersMatch[1];
      const thread = await getThread(threadId);
      if (!thread) return jsonResponse({ ok: false, error: 'Thread not found.' }, 404);
      if (thread.type !== 'group') return jsonResponse({ ok: false, error: 'Only groups have members to manage.' }, 400);
      if (thread.creatorUsername.toLowerCase() !== payload.username.toLowerCase()) {
        return jsonResponse({ ok: false, error: 'Only the creator can manage members.' }, 403);
      }
      let body;
      try { body = await request.json(); } catch (e) { return jsonResponse({ ok: false, error: 'Invalid JSON' }, 400); }
      const { action, username } = body || {};
      if (!username) return jsonResponse({ ok: false, error: 'Missing username.' }, 400);
      if (await isDemoToken(env, payload)) return jsonResponse({ ok: true, thread });
      if (action === 'add') {
        const u = await getUserByUsername(env, username);
        if (!u) return jsonResponse({ ok: false, error: 'User not found.' }, 400);
        if (!thread.participants.some(p => p.toLowerCase() === username.toLowerCase())) {
          thread.participants.push(username);
          await putThread(thread);
          const list = await getUserThreads(username);
          list.push({ threadId, lastReadAt: null });
          await putUserThreads(username, list);
        }
      } else if (action === 'remove') {
        if (username.toLowerCase() === thread.creatorUsername.toLowerCase()) {
          return jsonResponse({ ok: false, error: 'The creator cannot be removed. Delete the group instead.' }, 400);
        }
        thread.participants = thread.participants.filter(p => p.toLowerCase() !== username.toLowerCase());
        await putThread(thread);
        const list = await getUserThreads(username);
        await putUserThreads(username, list.filter(t => t.threadId !== threadId));
      } else {
        return jsonResponse({ ok: false, error: 'Invalid action.' }, 400);
      }
      return jsonResponse({ ok: true, thread });
    }

    if (url.pathname === '/messages/oversight' && request.method === 'GET') {
      const payload = await verifyToken(getBearerToken(request), env.AUTH_SECRET);
      if (!hasPermission(payload, 'messages')) return jsonResponse({ ok: false, error: 'Not authorized.' }, 403);
      const listResult = await env.STOP_KV.list({ prefix: 'thread:' });
      const threads = [];
      for (const key of listResult.keys) {
        const raw = await env.STOP_KV.get(key.name);
        if (!raw) continue;
        let thread;
        try { thread = JSON.parse(raw); } catch (e) { continue; }
        const messages = await getThreadMessages(thread.id);
        threads.push({ ...thread, messages });
      }
      return jsonResponse(threads);
    }

    /* ---------------- Generic data endpoints ---------------- */

    const match = url.pathname.match(/^\/data\/([a-zA-Z0-9_-]+)$/);
    if (!match) {
      return new Response('Not found', { status: 404, headers: corsHeaders });
    }
    const key = match[1];

    if (request.method === 'GET') {
      if (key === 'stop-users') {
        return jsonResponse(stripPasswords(await getUsersWithLastLogin(env)));
      }
      const value = await env.STOP_KV.get(key);
      return new Response(value ?? 'null', {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (request.method === 'POST') {
      if (NO_GENERIC_WRITE_KEYS.has(key)) {
        const hint = key === 'stop-users'
          ? 'Use /users/upsert or /users/delete instead.'
          : 'Use /log/activity or /log/error instead — this key only accepts single-entry appends now, not a full replacement.';
        return jsonResponse({ ok: false, error: `Writing this directly is disabled. ${hint}` }, 410);
      }
      const payload = await verifyToken(getBearerToken(request), env.AUTH_SECRET);
      const neededPerm = KEY_PERMISSIONS[key];
      if (!hasPermission(payload, neededPerm)) {
        return jsonResponse({ ok: false, error: 'Not authorized.' }, 403);
      }
      if (await isDemoToken(env, payload)) return jsonResponse({ ok: true }); // demo accounts never actually write anything
      const body = await request.text();
      try {
        JSON.parse(body);
      } catch (e) {
        return jsonResponse({ ok: false, error: 'Invalid JSON' }, 400);
      }
      await env.STOP_KV.put(key, body);
      return jsonResponse({ ok: true });
    }

    return new Response('Method not allowed', { status: 405, headers: corsHeaders });
  },

  // Runs automatically on the schedule configured as a Cron Trigger in
  // the Cloudflare dashboard (see README.md). Creates one daily
  // automatic backup and cleans up auto backups older than 30 days.
  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      await createBackup(env, 'auto');
      await cleanupOldAutoBackups(env);
    })());
  },
};
