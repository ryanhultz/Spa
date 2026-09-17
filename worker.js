import { DurableObject } from 'cloudflare:workers';

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
 * Messaging (v1.39.0): every /messages/* request is checked here, then
 * handed to the MessagingHub Durable Object (bottom of this file), which
 * stores conversations in its own SQLite database and pushes new
 * messages to open apps over WebSockets. Existing KV conversations are
 * copied into it automatically the first time it starts.
 *   GET  /messages/socket-ticket              -> {ok, ticket} (60-second pass)
 *   GET  /messages/socket?ticket=...          -> WebSocket (live updates)
 *   GET  /messages/threads                    -> your conversations
 *   POST /messages/threads                    {type, participantUsernames, name, firstMessage?}
 *   GET  /messages/threads/:id?before=&limit= -> messages (newest first, paged)
 *   POST /messages/threads/:id/messages       {text, clientId}
 *   POST /messages/threads/:id/read|hide|leave
 *   POST /messages/threads/:id/rename         {name}
 *   POST /messages/threads/:id/members        {action: add|remove, username}
 *   POST /messages/threads/:id/delete
 *   POST /messages/messages/:msgId/delete     {threadId}
 *   GET  /messages/oversight                  -> all conversations (Messages permission)
 * This is not a private messaging platform: deleted messages and
 * conversations are kept for anyone with the Messages permission, and
 * reading a conversation you aren't part of is written to the Activity Log.
 *
 * Requires:
 *   - A KV namespace bound to this Worker as STOP_KV
 *   - A Durable Object binding MESSAGING_HUB -> class MessagingHub
 *     (SQLite storage; see wrangler.toml and DEPLOY-MESSAGING.md)
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
      const newUser = { username, passwordHash, passwordSalt, permissions, lastLogin: now, createdAt: now, updatedAt: now, isDemo: true };
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
      // Deliberately stamped here rather than inside putUser: a login only
      // touches lastLogin, and bumping this on every login would make the
      // "someone else changed this user" check fire constantly later on.
      user.updatedAt = new Date().toISOString();
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
      // Take them out of their conversations so a future account with the
      // same username can't see old messages, and hand their groups on.
      if (env.MESSAGING_HUB) {
        try {
          const hub = env.MESSAGING_HUB.get(env.MESSAGING_HUB.idFromName('main'));
          await hub.fetch(new Request('https://hub/internal/user-deleted', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: body.username }),
          }));
        } catch (e) { console.error('Could not update messaging for deleted user', e); }
      }
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

    /* ---------------- Messaging (MessagingHub Durable Object) ---------------- */

    if (url.pathname.startsWith('/messages/')) {
      if (!env.MESSAGING_HUB) {
        return jsonResponse({ ok: false, error: 'Messaging isn\'t set up on the server yet (MESSAGING_HUB binding missing).' }, 503);
      }
      const hub = env.MESSAGING_HUB.get(env.MESSAGING_HUB.idFromName('main'));

      // Live updates. Browsers can't send the login header on a WebSocket,
      // so the app first gets a signed 60-second ticket (below) and passes
      // that instead. Nothing is stored for tickets.
      if (url.pathname === '/messages/socket') {
        if ((request.headers.get('Upgrade') || '').toLowerCase() !== 'websocket') {
          return jsonResponse({ ok: false, error: 'Expected a WebSocket.' }, 426);
        }
        const origin = request.headers.get('Origin');
        if (origin && getAllowedOrigin(request, env) !== origin) {
          return new Response('Forbidden', { status: 403 });
        }
        const ticket = await verifyToken(url.searchParams.get('ticket'), env.AUTH_SECRET);
        if (!ticket || ticket.purpose !== 'messages-socket' || !ticket.username) {
          return new Response('Not authorized', { status: 403 });
        }
        const headers = new Headers(request.headers);
        headers.set('X-Hub-User', ticket.username);
        headers.delete('X-Hub-Oversight');
        headers.delete('X-Hub-Demo');
        return hub.fetch(new Request('https://hub/messages/socket', { method: 'GET', headers }));
      }

      const payload = await verifyToken(getBearerToken(request), env.AUTH_SECRET);
      if (!payload) return jsonResponse({ ok: false, error: 'Not authorized.' }, 403);

      if (url.pathname === '/messages/socket-ticket' && request.method === 'GET') {
        if (!payload.username) return jsonResponse({ ok: false, error: 'Not authorized.' }, 403);
        const ticket = await signToken(
          { username: payload.username, purpose: 'messages-socket', exp: Date.now() + 60 * 1000 },
          env.AUTH_SECRET
        );
        return jsonResponse({ ok: true, ticket });
      }

      const oversight = hasPermission(payload, 'messages');
      const isDemo = await isDemoToken(env, payload);
      let bodyText;
      if (request.method === 'POST') {
        bodyText = await request.text();
        if (!bodyText.trim()) bodyText = '{}';
      }
      const hubRes = await hub.fetch(new Request(`https://hub${url.pathname}${url.search}`, {
        method: request.method,
        headers: {
          'Content-Type': 'application/json',
          'X-Hub-User': payload.username || '',
          'X-Hub-Oversight': oversight ? '1' : '0',
          'X-Hub-Demo': isDemo ? '1' : '0',
        },
        body: bodyText,
      }));
      const text = await hubRes.text();

      // Reading a conversation you aren't part of is always logged here,
      // on the server, so no app version can skip it.
      const logLine = hubRes.headers.get('X-Hub-Log');
      if (logLine && hubRes.ok && !isDemo) {
        try {
          const actor = payload.isMaster ? 'Master' : payload.username;
          await appendLogEntry('stop-activity', {
            username: actor, action: decodeURIComponent(logLine), timestamp: new Date().toISOString(),
          }, 200);
        } catch (e) { console.error('Could not log oversight view', e); }
      }
      return new Response(text, { status: hubRes.status, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
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

/* ======================================================================
 * MessagingHub — one Durable Object (SQLite storage) for all messaging.
 *
 * Requests reach it only through the Worker above, which has already
 * checked the login token and passes who is asking in X-Hub-* headers.
 * The hub handles one request at a time with its own database, so two
 * people sending at once can never overwrite each other, and new
 * messages are pushed to open apps over hibernating WebSockets.
 *
 * "This is not a private messaging platform": deleted messages and
 * deleted conversations are kept (hidden from staff, visible to anyone
 * with the Messages permission), and whenever someone reads a
 * conversation they aren't part of, the Worker writes it to the
 * Activity Log.
 * ====================================================================== */

const HUB_SCHEMA = [
  `CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)`,
  `CREATE TABLE IF NOT EXISTS threads (
     id TEXT PRIMARY KEY,
     type TEXT NOT NULL,
     name TEXT,
     creator TEXT NOT NULL,
     created_at TEXT NOT NULL,
     last_seq INTEGER NOT NULL DEFAULT 0,
     last_message_at TEXT,
     deleted INTEGER NOT NULL DEFAULT 0,
     deleted_at TEXT,
     deleted_by TEXT
   )`,
  `CREATE TABLE IF NOT EXISTS members (
     thread_id TEXT NOT NULL,
     username TEXT NOT NULL,
     username_lc TEXT NOT NULL,
     joined_at TEXT NOT NULL,
     last_read_seq INTEGER NOT NULL DEFAULT 0,
     hidden_seq INTEGER,
     PRIMARY KEY (thread_id, username_lc)
   )`,
  `CREATE INDEX IF NOT EXISTS members_by_user ON members (username_lc)`,
  `CREATE TABLE IF NOT EXISTS messages (
     seq INTEGER PRIMARY KEY AUTOINCREMENT,
     id TEXT NOT NULL UNIQUE,
     thread_id TEXT NOT NULL,
     sender TEXT NOT NULL,
     sender_lc TEXT NOT NULL,
     text TEXT NOT NULL,
     timestamp TEXT NOT NULL,
     client_id TEXT,
     deleted_at TEXT,
     deleted_by TEXT
   )`,
  `CREATE INDEX IF NOT EXISTS messages_by_thread ON messages (thread_id, seq)`,
  `CREATE INDEX IF NOT EXISTS messages_by_client ON messages (thread_id, sender_lc, client_id)`,
];

const HUB_PAGE_SIZE = 50;
const HUB_MAX_TEXT = 4000;
const HUB_MAX_GROUP_NAME = 80;

function hubJson(obj, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json', ...extraHeaders } });
}

export class MessagingHub extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx;
    this.env = env;
    this.sql = ctx.storage.sql;
    for (const statement of HUB_SCHEMA) this.sql.exec(statement);
    // Answered without waking the object, so idle connections stay free.
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping', 'pong'));
    ctx.blockConcurrencyWhile(async () => {
      try { await this.migrateFromKvIfNeeded(); }
      catch (e) { console.error('Messaging migration failed; will retry on next start:', e); }
    });
  }

  /* ---------- small SQL helpers ---------- */
  bind(values) { return values.map(v => (v === undefined ? null : v)); }
  rows(query, ...values) { return this.sql.exec(query, ...this.bind(values)).toArray(); }
  one(query, ...values) { return this.rows(query, ...values)[0] || null; }
  run(query, ...values) { this.sql.exec(query, ...this.bind(values)); }
  now() { return new Date().toISOString(); }

  getThread(id) { return this.one(`SELECT * FROM threads WHERE id = ?`, id); }
  getMembers(threadId) {
    return this.rows(`SELECT rowid AS rid, * FROM members WHERE thread_id = ? ORDER BY joined_at, rid`, threadId);
  }
  getMember(threadId, usernameLc) {
    return this.one(`SELECT * FROM members WHERE thread_id = ? AND username_lc = ?`, threadId, usernameLc);
  }
  formerParticipants(threadId, members) {
    const current = new Set(members.map(m => m.username_lc));
    return this.rows(`SELECT sender, MIN(seq) AS first_seq FROM messages WHERE thread_id = ? GROUP BY sender_lc ORDER BY first_seq`, threadId)
      .map(r => r.sender)
      .filter(name => !current.has(String(name).toLowerCase()));
  }
  threadOut(t) {
    const members = this.getMembers(t.id);
    return {
      id: t.id,
      type: t.type,
      name: t.name,
      participants: members.map(m => m.username),
      formerParticipants: this.formerParticipants(t.id, members),
      creatorUsername: t.creator,
      createdAt: t.created_at,
      lastActivityAt: t.last_message_at || t.created_at,
      deleted: !!t.deleted,
      deletedAt: t.deleted_at || null,
      deletedBy: t.deleted_by || null,
    };
  }
  messageOut(m, reveal) {
    const deleted = !!m.deleted_at;
    return {
      id: m.id,
      seq: m.seq,
      sender: m.sender,
      text: deleted && !reveal ? '' : m.text,
      timestamp: m.timestamp,
      deleted,
      deletedAt: m.deleted_at || null,
      clientId: m.client_id || null,
    };
  }
  lastMessage(threadId) {
    return this.one(`SELECT * FROM messages WHERE thread_id = ? ORDER BY seq DESC LIMIT 1`, threadId);
  }
  threadLabel(t) {
    if (t.type === 'group') return t.name || 'Group';
    const members = this.getMembers(t.id).map(m => m.username);
    const names = [...members, ...this.formerParticipants(t.id, this.getMembers(t.id))];
    return names.join(' & ') || 'Conversation';
  }

  /* ---------- live connections ---------- */
  broadcast(usernamesLc, event) {
    const payload = JSON.stringify(event);
    for (const lc of new Set(usernamesLc)) {
      for (const ws of this.ctx.getWebSockets(lc)) {
        try { ws.send(payload); } catch (e) { /* closed socket */ }
      }
    }
  }
  memberLcs(threadId) { return this.getMembers(threadId).map(m => m.username_lc); }

  async webSocketMessage(ws, message) { /* clients only send pings, answered automatically */ }
  async webSocketClose(ws, code, reason) {
    try { ws.close(code, reason); } catch (e) { /* already closed */ }
  }
  async webSocketError(ws) {
    try { ws.close(1011, 'error'); } catch (e) { /* already closed */ }
  }

  /* ---------- users ---------- */
  // null = no such account; undefined = couldn't check right now.
  async lookupUser(username) {
    if (!username) return null;
    try { return await getUserByUsername(this.env, username); } catch (e) { return undefined; }
  }
  nextCreator(threadId, excludeLc) {
    return this.getMembers(threadId).find(m => m.username_lc !== excludeLc) || null;
  }
  // Removes one person from a conversation. A group whose creator leaves
  // passes to its longest-standing member; one left empty is closed.
  removeMemberSync(t, usernameLc, actor) {
    this.run(`DELETE FROM members WHERE thread_id = ? AND username_lc = ?`, t.id, usernameLc);
    if (t.type === 'group' && String(t.creator).toLowerCase() === usernameLc) {
      const heir = this.nextCreator(t.id, usernameLc);
      if (heir) this.run(`UPDATE threads SET creator = ? WHERE id = ?`, heir.username, t.id);
      else this.run(`UPDATE threads SET deleted = 1, deleted_at = ?, deleted_by = ? WHERE id = ?`, this.now(), actor, t.id);
    }
  }
  userDeletedSync(usernameLc, threadIds) {
    for (const id of threadIds) {
      const t = this.getThread(id);
      if (t) this.removeMemberSync(t, usernameLc, '(account removed)');
    }
  }

  /* ---------- one-time move from KV ---------- */
  async migrateFromKvIfNeeded() {
    if (this.one(`SELECT value FROM meta WHERE key = 'kv_migrated'`)) return;
    const kv = this.env.STOP_KV;
    if (!kv) {
      this.run(`INSERT OR REPLACE INTO meta (key, value) VALUES ('kv_migrated', ?)`, this.now() + ' (no KV binding)');
      return;
    }
    const keys = [];
    let cursor;
    do {
      const page = await kv.list({ prefix: 'thread:', cursor });
      keys.push(...page.keys.map(k => k.name));
      cursor = page.list_complete ? null : page.cursor;
    } while (cursor);

    const userCache = new Map();
    const userExists = async (name) => {
      const lc = String(name).toLowerCase();
      if (!userCache.has(lc)) {
        const raw = await kv.get(`user:${lc}`);
        userCache.set(lc, raw ? (JSON.parse(raw).username || name) : null);
      }
      return userCache.get(lc);
    };
    const indexCache = new Map();
    const readIndex = async (name) => {
      const lc = String(name).toLowerCase();
      if (!indexCache.has(lc)) {
        const raw = await kv.get(`userthreads:${lc}`);
        let list = [];
        try { list = raw ? JSON.parse(raw) : []; } catch (e) { list = []; }
        indexCache.set(lc, Array.isArray(list) ? list : []);
      }
      return indexCache.get(lc);
    };

    const plans = [];
    for (const key of keys) {
      const raw = await kv.get(key);
      if (!raw) continue;
      let thread;
      try { thread = JSON.parse(raw); } catch (e) { continue; }
      if (!thread || !thread.id || !Array.isArray(thread.participants)) continue;
      const msgRaw = await kv.get(`messages:${thread.id}`);
      let messages = [];
      try { messages = msgRaw ? JSON.parse(msgRaw) : []; } catch (e) { messages = []; }
      const members = [];
      for (const p of thread.participants) {
        const canonical = await userExists(p);
        if (!canonical) continue;
        const entry = (await readIndex(p)).find(e => e.threadId === thread.id);
        members.push({ username: canonical, lastReadAt: entry ? entry.lastReadAt : null });
      }
      plans.push({ thread, messages: Array.isArray(messages) ? messages : [], members });
    }

    this.ctx.storage.transactionSync(() => {
      for (const { thread, messages, members } of plans) {
        if (this.getThread(thread.id)) continue;
        const createdAt = thread.createdAt || this.now();
        this.run(`INSERT INTO threads (id, type, name, creator, created_at) VALUES (?, ?, ?, ?, ?)`,
          thread.id, thread.type === 'group' ? 'group' : 'dm', thread.type === 'group' ? (thread.name || 'Group') : null,
          thread.creatorUsername || (members[0] && members[0].username) || '(unknown)', createdAt);
        const ordered = [...messages].reverse(); // KV kept newest first
        for (const m of ordered) {
          if (!m || !m.id || !m.sender) continue;
          this.run(`INSERT OR IGNORE INTO messages (id, thread_id, sender, sender_lc, text, timestamp) VALUES (?, ?, ?, ?, ?, ?)`,
            m.id, thread.id, m.sender, String(m.sender).toLowerCase(), String(m.text || ''), m.timestamp || createdAt);
        }
        const last = this.lastMessage(thread.id);
        if (last) this.run(`UPDATE threads SET last_seq = ?, last_message_at = ? WHERE id = ?`, last.seq, last.timestamp, thread.id);
        const creatorLc = String(thread.creatorUsername || '').toLowerCase();
        const sortedMembers = [...members].sort((a, b) => (a.username.toLowerCase() === creatorLc ? -1 : b.username.toLowerCase() === creatorLc ? 1 : 0));
        sortedMembers.forEach((mem, i) => {
          let readSeq = 0;
          if (mem.lastReadAt) {
            const r = this.one(`SELECT MAX(seq) AS s FROM messages WHERE thread_id = ? AND timestamp <= ?`, thread.id, mem.lastReadAt);
            readSeq = (r && r.s) || 0;
          }
          const joined = new Date(new Date(createdAt).getTime() + i).toISOString();
          this.run(`INSERT OR IGNORE INTO members (thread_id, username, username_lc, joined_at, last_read_seq) VALUES (?, ?, ?, ?, ?)`,
            thread.id, mem.username, mem.username.toLowerCase(), joined, readSeq);
        });
        const t = this.getThread(thread.id);
        if (t.type === 'group' && !this.getMember(t.id, String(t.creator).toLowerCase())) {
          const heir = this.nextCreator(t.id, '');
          if (heir) this.run(`UPDATE threads SET creator = ? WHERE id = ?`, heir.username, t.id);
        }
        if (!this.getMembers(t.id).length) {
          this.run(`UPDATE threads SET deleted = 1, deleted_at = ?, deleted_by = '(no remaining members)' WHERE id = ?`, this.now(), t.id);
        }
      }
      this.run(`INSERT OR REPLACE INTO meta (key, value) VALUES ('kv_migrated', ?)`, `${this.now()} (${plans.length} conversations)`);
    });
  }

  /* ---------- request routing ---------- */
  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    const who = {
      me: request.headers.get('X-Hub-User') || '',
      oversight: request.headers.get('X-Hub-Oversight') === '1',
      demo: request.headers.get('X-Hub-Demo') === '1',
    };
    who.meLc = who.me.toLowerCase();
    try {
      if (path === '/messages/socket') return this.acceptSocket(who);
      if (path === '/internal/user-deleted' && request.method === 'POST') {
        const body = await request.json().catch(() => ({}));
        const lc = String((body && body.username) || '').toLowerCase();
        if (!lc) return hubJson({ ok: false, error: 'Missing username.' }, 400);
        const ids = this.rows(`SELECT thread_id FROM members WHERE username_lc = ?`, lc).map(r => r.thread_id);
        this.ctx.storage.transactionSync(() => this.userDeletedSync(lc, ids));
        for (const id of ids) this.broadcast(this.memberLcs(id), { type: 'thread-updated', threadId: id });
        this.broadcast([lc], { type: 'signed-out' });
        return hubJson({ ok: true, threads: ids.length });
      }

      const body = request.method === 'POST' ? await request.json().catch(() => null) : null;
      if (request.method === 'POST' && body === null) return hubJson({ ok: false, error: 'Invalid JSON' }, 400);

      if (path === '/messages/oversight' && request.method === 'GET') return this.oversightList(who);
      if (path === '/messages/threads' && request.method === 'GET') return this.listThreads(who);
      if (path === '/messages/threads' && request.method === 'POST') return this.createThread(who, body);

      let m;
      if ((m = path.match(/^\/messages\/threads\/([a-zA-Z0-9-]+)$/)) && request.method === 'GET') return this.threadDetail(who, m[1], url);
      if ((m = path.match(/^\/messages\/threads\/([a-zA-Z0-9-]+)\/messages$/)) && request.method === 'POST') return this.sendMessage(who, m[1], body);
      if ((m = path.match(/^\/messages\/threads\/([a-zA-Z0-9-]+)\/read$/)) && request.method === 'POST') return this.markRead(who, m[1], body);
      if ((m = path.match(/^\/messages\/threads\/([a-zA-Z0-9-]+)\/hide$/)) && request.method === 'POST') return this.hideThread(who, m[1]);
      if ((m = path.match(/^\/messages\/threads\/([a-zA-Z0-9-]+)\/leave$/)) && request.method === 'POST') return this.leaveThread(who, m[1]);
      if ((m = path.match(/^\/messages\/threads\/([a-zA-Z0-9-]+)\/rename$/)) && request.method === 'POST') return this.renameThread(who, m[1], body);
      if ((m = path.match(/^\/messages\/threads\/([a-zA-Z0-9-]+)\/members$/)) && request.method === 'POST') return this.updateMembers(who, m[1], body);
      if ((m = path.match(/^\/messages\/threads\/([a-zA-Z0-9-]+)\/delete$/)) && request.method === 'POST') return this.deleteThread(who, m[1]);
      if ((m = path.match(/^\/messages\/messages\/([a-zA-Z0-9-]+)\/delete$/)) && request.method === 'POST') return this.deleteMessage(who, m[1], body);
      return hubJson({ ok: false, error: 'Not found.' }, 404);
    } catch (e) {
      console.error('MessagingHub error', e);
      return hubJson({ ok: false, error: 'Messaging error. Please try again.' }, 500);
    }
  }

  requireUser(who) {
    return who.me ? null : hubJson({ ok: false, error: 'Messaging needs a staff login (not the master password).' }, 403);
  }

  acceptSocket(who) {
    if (!who.me) return hubJson({ ok: false, error: 'Not authorized.' }, 403);
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server, [who.meLc]);
    server.serializeAttachment({ username: who.me });
    server.send(JSON.stringify({ type: 'hello' }));
    return new Response(null, { status: 101, webSocket: client });
  }

  listThreads(who) {
    const denied = this.requireUser(who);
    if (denied) return denied;
    const rows = this.rows(
      `SELECT t.*, mb.last_read_seq, mb.hidden_seq FROM threads t
       JOIN members mb ON mb.thread_id = t.id
       WHERE mb.username_lc = ? AND t.deleted = 0`, who.meLc);
    const out = [];
    for (const t of rows) {
      if (t.hidden_seq !== null && t.hidden_seq !== undefined && t.last_seq <= t.hidden_seq) continue;
      const last = this.lastMessage(t.id);
      const unread = this.one(
        `SELECT COUNT(*) AS n FROM messages WHERE thread_id = ? AND seq > ? AND sender_lc != ? AND deleted_at IS NULL`,
        t.id, t.last_read_seq || 0, who.meLc);
      out.push({
        ...this.threadOut(t),
        lastMessage: last ? this.messageOut(last, false) : null,
        unreadCount: unread ? unread.n : 0,
      });
    }
    out.sort((a, b) => String(b.lastActivityAt).localeCompare(String(a.lastActivityAt)));
    return hubJson(out);
  }

  insertMessageSync(t, sender, text, clientId) {
    const senderLc = sender.toLowerCase();
    if (clientId) {
      const existing = this.one(`SELECT * FROM messages WHERE thread_id = ? AND sender_lc = ? AND client_id = ?`, t.id, senderLc, clientId);
      if (existing) return { row: existing, duplicate: true };
    }
    const id = crypto.randomUUID();
    const ts = this.now();
    this.run(`INSERT INTO messages (id, thread_id, sender, sender_lc, text, timestamp, client_id) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      id, t.id, sender, senderLc, text, ts, clientId || null);
    const row = this.one(`SELECT * FROM messages WHERE id = ?`, id);
    this.run(`UPDATE threads SET last_seq = ?, last_message_at = ? WHERE id = ?`, row.seq, ts, t.id);
    this.run(`UPDATE members SET last_read_seq = ? WHERE thread_id = ? AND username_lc = ?`, row.seq, t.id, senderLc);
    return { row, duplicate: false };
  }

  cleanText(value) {
    const text = String(value == null ? '' : value).replace(/\r\n?/g, '\n').slice(0, HUB_MAX_TEXT);
    return text.trim() ? text.replace(/^\s+|\s+$/g, '') : '';
  }
  cleanClientId(value) {
    const id = String(value || '').slice(0, 64);
    return /^[a-zA-Z0-9_-]{6,64}$/.test(id) ? id : null;
  }

  async createThread(who, body) {
    const denied = this.requireUser(who);
    if (denied) return denied;
    if (who.demo) return hubJson({ ok: false, error: "Demo accounts can't start conversations." }, 403);
    const { type, participantUsernames, name, firstMessage } = body || {};
    if (type !== 'dm' && type !== 'group') return hubJson({ ok: false, error: 'Invalid conversation type.' }, 400);
    if (!Array.isArray(participantUsernames) || !participantUsernames.length) return hubJson({ ok: false, error: 'Choose at least one person.' }, 400);

    const people = new Map([[who.meLc, who.me]]);
    for (const raw of participantUsernames) {
      const u = await this.lookupUser(String(raw || ''));
      if (u === undefined) return hubJson({ ok: false, error: "Couldn't check that person right now. Please try again." }, 503);
      if (!u) return hubJson({ ok: false, error: `User "${raw}" not found.` }, 400);
      people.set(u.username.toLowerCase(), u.username);
    }
    if (type === 'dm' && people.size !== 2) return hubJson({ ok: false, error: 'A direct message needs exactly one other person.' }, 400);
    const groupName = type === 'group' ? String(name || '').trim().slice(0, HUB_MAX_GROUP_NAME) : null;
    if (type === 'group' && !groupName) return hubJson({ ok: false, error: 'Enter a group name.' }, 400);
    const text = firstMessage ? this.cleanText(firstMessage.text) : '';
    const clientId = firstMessage ? this.cleanClientId(firstMessage.clientId) : null;

    let thread, messageRow = null, created = false, duplicate = false;
    this.ctx.storage.transactionSync(() => {
      if (type === 'dm') {
        const lcs = [...people.keys()];
        thread = this.one(
          `SELECT t.* FROM threads t
           WHERE t.type = 'dm' AND t.deleted = 0
             AND (SELECT COUNT(*) FROM members m WHERE m.thread_id = t.id) = 2
             AND EXISTS (SELECT 1 FROM members m WHERE m.thread_id = t.id AND m.username_lc = ?)
             AND EXISTS (SELECT 1 FROM members m WHERE m.thread_id = t.id AND m.username_lc = ?)
           LIMIT 1`, lcs[0], lcs[1]);
        if (thread) this.run(`UPDATE members SET hidden_seq = NULL WHERE thread_id = ? AND username_lc = ?`, thread.id, who.meLc);
      }
      if (!thread) {
        const id = crypto.randomUUID();
        const now = this.now();
        this.run(`INSERT INTO threads (id, type, name, creator, created_at) VALUES (?, ?, ?, ?, ?)`, id, type, groupName, who.me, now);
        [...people.values()].forEach((username, i) => {
          const joined = new Date(Date.now() + i).toISOString();
          this.run(`INSERT INTO members (thread_id, username, username_lc, joined_at) VALUES (?, ?, ?, ?)`, id, username, username.toLowerCase(), joined);
        });
        thread = this.getThread(id);
        created = true;
      }
      if (text) {
        const r = this.insertMessageSync(thread, who.me, text, clientId);
        messageRow = r.row;
        duplicate = r.duplicate;
      }
    });
    const lcs = this.memberLcs(thread.id);
    if (created) this.broadcast(lcs, { type: 'thread-updated', threadId: thread.id });
    const message = messageRow ? this.messageOut(messageRow, false) : null;
    if (message && !duplicate) this.broadcast(lcs, { type: 'message', threadId: thread.id, message });
    return hubJson({ ok: true, created, thread: this.threadOut(this.getThread(thread.id)), message });
  }

  async threadDetail(who, threadId, url) {
    let t = this.getThread(threadId);
    if (!t || (t.deleted && !who.oversight)) return hubJson({ ok: false, error: 'Conversation not found.' }, 404);
    const member = who.me ? this.getMember(threadId, who.meLc) : null;
    if (!member && !who.oversight) return hubJson({ ok: false, error: 'Not authorized.' }, 403);

    // A group whose creator's account no longer exists passes to the
    // longest-standing member (covers accounts removed by a backup restore).
    if (t.type === 'group' && !t.deleted && (await this.lookupUser(t.creator)) === null) {
      const lc = String(t.creator).toLowerCase();
      this.ctx.storage.transactionSync(() => this.removeMemberSync(t, lc, '(account removed)'));
      t = this.getThread(threadId);
    }

    const reveal = who.oversight && url.searchParams.get('view') === 'oversight';
    const limit = Math.min(200, Math.max(1, parseInt(url.searchParams.get('limit') || HUB_PAGE_SIZE, 10) || HUB_PAGE_SIZE));
    const beforeRaw = parseInt(url.searchParams.get('before') || '', 10);
    const before = Number.isFinite(beforeRaw) ? beforeRaw : null;
    const page = before === null
      ? this.rows(`SELECT * FROM messages WHERE thread_id = ? ORDER BY seq DESC LIMIT ?`, threadId, limit + 1)
      : this.rows(`SELECT * FROM messages WHERE thread_id = ? AND seq < ? ORDER BY seq DESC LIMIT ?`, threadId, before, limit + 1);
    const hasMore = page.length > limit;
    const messages = page.slice(0, limit).map(m => this.messageOut(m, reveal));

    if (member && before === null && (member.last_read_seq || 0) < t.last_seq) {
      this.run(`UPDATE members SET last_read_seq = ? WHERE thread_id = ? AND username_lc = ?`, t.last_seq, threadId, who.meLc);
      this.broadcast([who.meLc], { type: 'read', threadId });
    }
    const headers = {};
    if (!member && before === null) {
      headers['X-Hub-Log'] = encodeURIComponent(`Viewed conversation "${this.threadLabel(t)}" (oversight)`);
    }
    return hubJson({ ok: true, thread: this.threadOut(t), messages, hasMore, isMember: !!member }, 200, headers);
  }

  sendMessage(who, threadId, body) {
    const denied = this.requireUser(who);
    if (denied) return denied;
    const t = this.getThread(threadId);
    if (!t || t.deleted) return hubJson({ ok: false, error: 'This conversation no longer exists.' }, 404);
    if (!this.getMember(threadId, who.meLc)) return hubJson({ ok: false, error: "You're no longer in this conversation." }, 403);
    const text = this.cleanText(body.text);
    if (!text) return hubJson({ ok: false, error: 'Message is empty.' }, 400);
    const clientId = this.cleanClientId(body.clientId);
    if (who.demo) {
      return hubJson({ ok: true, demo: true, message: { id: `demo-${crypto.randomUUID()}`, seq: null, sender: who.me, text, timestamp: this.now(), deleted: false, deletedAt: null, clientId } });
    }
    let r;
    this.ctx.storage.transactionSync(() => { r = this.insertMessageSync(t, who.me, text, clientId); });
    const message = this.messageOut(r.row, false);
    if (!r.duplicate) this.broadcast(this.memberLcs(threadId), { type: 'message', threadId, message });
    return hubJson({ ok: true, message, duplicate: r.duplicate });
  }

  markRead(who, threadId, body) {
    const denied = this.requireUser(who);
    if (denied) return denied;
    const t = this.getThread(threadId);
    const member = t ? this.getMember(threadId, who.meLc) : null;
    if (!member) return hubJson({ ok: false, error: 'Not authorized.' }, 403);
    const wanted = Number.isFinite(body && body.seq) ? Math.min(body.seq, t.last_seq) : t.last_seq;
    if ((member.last_read_seq || 0) < wanted) {
      this.run(`UPDATE members SET last_read_seq = ? WHERE thread_id = ? AND username_lc = ?`, wanted, threadId, who.meLc);
      this.broadcast([who.meLc], { type: 'read', threadId });
    }
    return hubJson({ ok: true });
  }

  hideThread(who, threadId) {
    const denied = this.requireUser(who);
    if (denied) return denied;
    const t = this.getThread(threadId);
    if (!t || !this.getMember(threadId, who.meLc)) return hubJson({ ok: false, error: 'Not authorized.' }, 403);
    this.run(`UPDATE members SET hidden_seq = ?, last_read_seq = MAX(last_read_seq, ?) WHERE thread_id = ? AND username_lc = ?`, t.last_seq, t.last_seq, threadId, who.meLc);
    this.broadcast([who.meLc], { type: 'thread-updated', threadId });
    return hubJson({ ok: true });
  }

  leaveThread(who, threadId) {
    const denied = this.requireUser(who);
    if (denied) return denied;
    const t = this.getThread(threadId);
    if (!t || t.deleted || !this.getMember(threadId, who.meLc)) return hubJson({ ok: false, error: 'Not authorized.' }, 403);
    if (t.type !== 'group') return hubJson({ ok: false, error: 'Use Hide for a direct message.' }, 400);
    if (who.demo) return hubJson({ ok: true });
    const before = this.memberLcs(threadId);
    this.ctx.storage.transactionSync(() => this.removeMemberSync(t, who.meLc, who.me));
    this.broadcast(before, { type: 'thread-updated', threadId });
    return hubJson({ ok: true });
  }

  canManage(who, t) {
    return who.oversight || (!!who.me && String(t.creator).toLowerCase() === who.meLc);
  }

  renameThread(who, threadId, body) {
    const t = this.getThread(threadId);
    if (!t || t.deleted) return hubJson({ ok: false, error: 'Conversation not found.' }, 404);
    if (t.type !== 'group') return hubJson({ ok: false, error: 'Only groups have names.' }, 400);
    if (!this.canManage(who, t)) return hubJson({ ok: false, error: 'Only the group creator can rename it.' }, 403);
    const name = String((body && body.name) || '').trim().slice(0, HUB_MAX_GROUP_NAME);
    if (!name) return hubJson({ ok: false, error: 'Enter a group name.' }, 400);
    if (who.demo) return hubJson({ ok: true, thread: this.threadOut(t) });
    this.run(`UPDATE threads SET name = ? WHERE id = ?`, name, threadId);
    this.broadcast(this.memberLcs(threadId), { type: 'thread-updated', threadId });
    return hubJson({ ok: true, thread: this.threadOut(this.getThread(threadId)) });
  }

  async updateMembers(who, threadId, body) {
    const t = this.getThread(threadId);
    if (!t || t.deleted) return hubJson({ ok: false, error: 'Conversation not found.' }, 404);
    if (t.type !== 'group') return hubJson({ ok: false, error: 'Only groups have members to manage.' }, 400);
    if (!this.canManage(who, t)) return hubJson({ ok: false, error: 'Only the group creator can manage members.' }, 403);
    const { action, username } = body || {};
    if (!username) return hubJson({ ok: false, error: 'Missing username.' }, 400);
    if (who.demo) return hubJson({ ok: true, thread: this.threadOut(t) });
    const before = this.memberLcs(threadId);
    if (action === 'add') {
      const u = await this.lookupUser(username);
      if (u === undefined) return hubJson({ ok: false, error: "Couldn't check that person right now. Please try again." }, 503);
      if (!u) return hubJson({ ok: false, error: 'User not found.' }, 400);
      const fresh = this.getThread(threadId);
      this.run(`INSERT OR IGNORE INTO members (thread_id, username, username_lc, joined_at, last_read_seq) VALUES (?, ?, ?, ?, ?)`,
        threadId, u.username, u.username.toLowerCase(), this.now(), fresh.last_seq);
    } else if (action === 'remove') {
      const lc = String(username).toLowerCase();
      if (!this.getMember(threadId, lc)) return hubJson({ ok: true, thread: this.threadOut(t) });
      this.ctx.storage.transactionSync(() => this.removeMemberSync(t, lc, who.me || 'Master'));
    } else {
      return hubJson({ ok: false, error: 'Invalid action.' }, 400);
    }
    this.broadcast([...before, ...this.memberLcs(threadId)], { type: 'thread-updated', threadId });
    return hubJson({ ok: true, thread: this.threadOut(this.getThread(threadId)) });
  }

  deleteThread(who, threadId) {
    const t = this.getThread(threadId);
    if (!t || t.deleted) return hubJson({ ok: true });
    if (!this.canManage(who, t)) return hubJson({ ok: false, error: 'Only the person who started this can delete it.' }, 403);
    if (who.demo) return hubJson({ ok: true });
    this.run(`UPDATE threads SET deleted = 1, deleted_at = ?, deleted_by = ? WHERE id = ?`, this.now(), who.me || 'Master', threadId);
    this.broadcast(this.memberLcs(threadId), { type: 'thread-updated', threadId });
    return hubJson({ ok: true });
  }

  deleteMessage(who, msgId, body) {
    const denied = this.requireUser(who);
    if (denied) return denied;
    const threadId = body && body.threadId;
    const m = this.one(`SELECT * FROM messages WHERE id = ? AND thread_id = ?`, msgId, threadId || '');
    if (!m) return hubJson({ ok: false, error: 'Message not found.' }, 404);
    if (m.sender_lc !== who.meLc) return hubJson({ ok: false, error: 'You can only delete your own messages.' }, 403);
    if (who.demo || m.deleted_at) return hubJson({ ok: true });
    this.run(`UPDATE messages SET deleted_at = ?, deleted_by = ? WHERE id = ?`, this.now(), who.me, msgId);
    this.broadcast(this.memberLcs(threadId), { type: 'message-deleted', threadId, messageId: msgId });
    return hubJson({ ok: true });
  }

  oversightList(who) {
    if (!who.oversight) return hubJson({ ok: false, error: 'Not authorized.' }, 403);
    const threads = this.rows(`SELECT * FROM threads`).map(t => {
      const counts = this.one(
        `SELECT COUNT(*) AS total, SUM(CASE WHEN deleted_at IS NOT NULL THEN 1 ELSE 0 END) AS removed FROM messages WHERE thread_id = ?`, t.id);
      const last = this.lastMessage(t.id);
      return {
        ...this.threadOut(t),
        messageCount: counts ? counts.total : 0,
        deletedMessageCount: counts ? (counts.removed || 0) : 0,
        lastMessage: last ? this.messageOut(last, true) : null,
      };
    });
    threads.sort((a, b) => String(b.lastActivityAt).localeCompare(String(a.lastActivityAt)));
    return hubJson(threads);
  }
}
