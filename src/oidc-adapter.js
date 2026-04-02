import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { deleteClient, findClientById, upsertClientMetadata } from './db.js';

const storePath = 'data/oauth/oidc-store.json';
const storeSeedPath = 'bootstrap-data/oauth/oidc-store.json';

const grantable = new Set([
  'AccessToken',
  'AuthorizationCode',
  'RefreshToken',
  'DeviceCode',
  'BackchannelAuthenticationRequest',
]);

function defaultStore() {
  return {
    records: {},
  };
}

function loadStore() {
  if (!existsSync(storePath)) {
    return defaultStore();
  }

  const raw = readFileSync(storePath, 'utf8').trim();
  if (!raw) {
    return defaultStore();
  }

  const parsed = JSON.parse(raw);
  return {
    records: parsed && typeof parsed === 'object' && parsed.records && typeof parsed.records === 'object'
      ? parsed.records
      : {},
  };
}

function saveStore(store) {
  writeFileSync(storePath, `${JSON.stringify(store, null, 2)}\n`);
}

function isExpired(entry) {
  return typeof entry?.expiresAt === 'number' && entry.expiresAt <= Date.now();
}

function ensureModelBucket(store, model) {
  if (!store.records[model] || typeof store.records[model] !== 'object') {
    store.records[model] = {};
  }
  return store.records[model];
}

function cleanupExpired(store) {
  let changed = false;
  for (const bucket of Object.values(store.records)) {
    for (const [id, entry] of Object.entries(bucket)) {
      if (isExpired(entry)) {
        delete bucket[id];
        changed = true;
      }
    }
  }
  if (changed) {
    saveStore(store);
  }
}

function cleanupExpiredInPlace(store) {
  let changed = false;
  for (const bucket of Object.values(store.records)) {
    for (const [id, entry] of Object.entries(bucket)) {
      if (isExpired(entry)) {
        delete bucket[id];
        changed = true;
      }
    }
  }
  return changed;
}

export function ensureOidcStore() {
  if (!existsSync(storePath)) {
    mkdirSync('data/oauth', { recursive: true });
    if (existsSync(storeSeedPath)) {
      copyFileSync(storeSeedPath, storePath);
    } else {
      saveStore(defaultStore());
    }
  }
  const store = loadStore();
  cleanupExpired(store);
}

export class JsonAdapter {
  constructor(model) {
    this.model = model;
  }

  async destroy(id) {
    if (this.model === 'Client') {
      try {
        deleteClient(id);
      } catch {
        // Ignore missing clients to mirror adapter contract.
      }
      return;
    }

    const store = loadStore();
    const bucket = ensureModelBucket(store, this.model);
    delete bucket[id];
    saveStore(store);
  }

  async consume(id) {
    const store = loadStore();
    const bucket = ensureModelBucket(store, this.model);
    const entry = bucket[id];
    if (!entry || isExpired(entry)) {
      if (entry) {
        delete bucket[id];
        saveStore(store);
      }
      return;
    }

    entry.payload.consumed = Math.floor(Date.now() / 1000);
    saveStore(store);
  }

  async find(id) {
    if (this.model === 'Client') {
      const client = findClientById(id);
      return client || undefined;
    }

    const store = loadStore();
    const bucket = ensureModelBucket(store, this.model);
    const entry = bucket[id];
    if (!entry) {
      return undefined;
    }
    if (isExpired(entry)) {
      delete bucket[id];
      saveStore(store);
      return undefined;
    }
    return entry.payload;
  }

  async findByUid(uid) {
    const store = loadStore();
    const bucket = ensureModelBucket(store, this.model);
    for (const [id, entry] of Object.entries(bucket)) {
      if (isExpired(entry)) {
        delete bucket[id];
        continue;
      }
      if (entry.payload?.uid === uid) {
        saveStore(store);
        return entry.payload;
      }
    }
    saveStore(store);
    return undefined;
  }

  async findByUserCode(userCode) {
    const store = loadStore();
    const bucket = ensureModelBucket(store, this.model);
    for (const [id, entry] of Object.entries(bucket)) {
      if (isExpired(entry)) {
        delete bucket[id];
        continue;
      }
      if (entry.payload?.userCode === userCode) {
        saveStore(store);
        return entry.payload;
      }
    }
    saveStore(store);
    return undefined;
  }

  async upsert(id, payload, expiresIn) {
    if (this.model === 'Client') {
      upsertClientMetadata({
        ...(payload && typeof payload === 'object' ? payload : {}),
        client_id: String(id || payload?.client_id || '').trim(),
      });
      return;
    }

    const store = loadStore();
    const bucket = ensureModelBucket(store, this.model);
    bucket[id] = {
      payload,
      expiresAt: typeof expiresIn === 'number' ? Date.now() + (expiresIn * 1000) : null,
    };
    saveStore(store);
  }

  async revokeByGrantId(grantId) {
    const store = loadStore();
    let changed = false;

    for (const [model, bucket] of Object.entries(store.records)) {
      if (!grantable.has(model)) {
        continue;
      }
      for (const [id, entry] of Object.entries(bucket)) {
        if (isExpired(entry) || entry.payload?.grantId === grantId) {
          delete bucket[id];
          changed = true;
        }
      }
    }

    if (changed) {
      saveStore(store);
    }
  }
}

export function listOidcStoreOverview() {
  const store = loadStore();
  const changed = cleanupExpiredInPlace(store);
  if (changed) {
    saveStore(store);
  }

  const records = store.records || {};
  const sessionsBucket = records.Session && typeof records.Session === 'object' ? records.Session : {};
  const grantsBucket = records.Grant && typeof records.Grant === 'object' ? records.Grant : {};
  const accessTokenBucket = records.AccessToken && typeof records.AccessToken === 'object' ? records.AccessToken : {};
  const refreshTokenBucket = records.RefreshToken && typeof records.RefreshToken === 'object' ? records.RefreshToken : {};
  const authorizationCodeBucket = records.AuthorizationCode && typeof records.AuthorizationCode === 'object' ? records.AuthorizationCode : {};

  const tokenCountsBySessionUid = {};
  const grantCountsBySessionUid = {};
  const addCount = (map, key) => {
    if (!key) return;
    map[key] = (map[key] || 0) + 1;
  };

  for (const entry of Object.values(accessTokenBucket)) {
    const uid = entry?.payload?.sessionUid || '';
    addCount(tokenCountsBySessionUid, `access:${uid}`);
    addCount(grantCountsBySessionUid, `grant:${entry?.payload?.grantId || ''}`);
  }
  for (const entry of Object.values(refreshTokenBucket)) {
    const uid = entry?.payload?.sessionUid || '';
    addCount(tokenCountsBySessionUid, `refresh:${uid}`);
    addCount(grantCountsBySessionUid, `grant:${entry?.payload?.grantId || ''}`);
  }
  for (const entry of Object.values(authorizationCodeBucket)) {
    const uid = entry?.payload?.sessionUid || '';
    addCount(tokenCountsBySessionUid, `code:${uid}`);
    addCount(grantCountsBySessionUid, `grant:${entry?.payload?.grantId || ''}`);
  }

  const sessions = Object.entries(sessionsBucket)
    .map(([id, entry]) => {
      const payload = entry?.payload || {};
      const uid = String(payload.uid || '');
      const authorizations = payload.authorizations && typeof payload.authorizations === 'object'
        ? payload.authorizations
        : {};
      const clients = Object.keys(authorizations);
      const grantIds = Object.values(authorizations)
        .map((value) => String(value?.grantId || ''))
        .filter(Boolean);

      return {
        id,
        uid,
        accountId: String(payload.accountId || ''),
        loginTs: Number(payload.loginTs || 0) || null,
        expiresAt: Number(entry?.expiresAt || 0) || null,
        clients,
        grantIds,
        accessTokenCount: tokenCountsBySessionUid[`access:${uid}`] || 0,
        refreshTokenCount: tokenCountsBySessionUid[`refresh:${uid}`] || 0,
        authorizationCodeCount: tokenCountsBySessionUid[`code:${uid}`] || 0,
      };
    })
    .sort((left, right) => (right.loginTs || 0) - (left.loginTs || 0));

  const recordsByModel = {};
  for (const [model, bucket] of Object.entries(records)) {
    recordsByModel[model] = Object.keys(bucket || {}).length;
  }

  const grants = Object.entries(grantsBucket)
    .map(([id, entry]) => ({
      id,
      accountId: String(entry?.payload?.accountId || ''),
      clientId: String(entry?.payload?.clientId || ''),
      expiresAt: Number(entry?.expiresAt || 0) || null,
      linkedArtifacts: grantCountsBySessionUid[`grant:${id}`] || 0,
    }))
    .sort((left, right) => (right.expiresAt || 0) - (left.expiresAt || 0));

  return {
    generatedAt: new Date().toISOString(),
    totals: {
      sessions: sessions.length,
      grants: grants.length,
    },
    recordsByModel,
    sessions,
    grants,
  };
}

export function removeOidcRecord(model, id) {
  const bucketName = String(model || '').trim();
  const recordId = String(id || '').trim();
  if (!bucketName || !recordId) return false;

  const store = loadStore();
  const bucket = ensureModelBucket(store, bucketName);
  if (!bucket[recordId]) return false;
  delete bucket[recordId];
  saveStore(store);
  return true;
}

export function revokeOidcByGrantId(grantId) {
  const targetGrantId = String(grantId || '').trim();
  if (!targetGrantId) return 0;

  const store = loadStore();
  let deleted = 0;
  for (const [model, bucket] of Object.entries(store.records || {})) {
    const isGrantRecord = model === 'Grant';
    const isGrantableRecord = grantable.has(model);
    for (const [id, entry] of Object.entries(bucket || {})) {
      if (isExpired(entry)) {
        delete bucket[id];
        deleted += 1;
        continue;
      }
      if (isGrantRecord && id === targetGrantId) {
        delete bucket[id];
        deleted += 1;
        continue;
      }
      if (isGrantableRecord && String(entry?.payload?.grantId || '') === targetGrantId) {
        delete bucket[id];
        deleted += 1;
      }
    }
  }

  if (deleted > 0) {
    saveStore(store);
  }
  return deleted;
}

export function revokeOidcBySessionUid(sessionUid) {
  const targetSessionUid = String(sessionUid || '').trim();
  if (!targetSessionUid) return 0;

  const store = loadStore();
  let deleted = 0;
  for (const [model, bucket] of Object.entries(store.records || {})) {
    for (const [id, entry] of Object.entries(bucket || {})) {
      if (isExpired(entry)) {
        delete bucket[id];
        deleted += 1;
        continue;
      }
      const payload = entry?.payload || {};
      const isSession = model === 'Session' && String(payload.uid || '') === targetSessionUid;
      const isLinked = String(payload.sessionUid || '') === targetSessionUid;
      if (isSession || isLinked) {
        delete bucket[id];
        deleted += 1;
      }
    }
  }

  if (deleted > 0) {
    saveStore(store);
  }
  return deleted;
}
