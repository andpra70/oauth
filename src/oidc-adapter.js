import { existsSync, readFileSync, writeFileSync } from 'node:fs';

const storePath = 'data/oauth/oidc-store.json';

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

export function ensureOidcStore() {
  const store = loadStore();
  cleanupExpired(store);
  if (!existsSync(storePath)) {
    saveStore(store);
  }
}

export class JsonAdapter {
  constructor(model) {
    this.model = model;
  }

  async destroy(id) {
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
