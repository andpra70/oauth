import { useState } from 'react';
import { completePasskey, passkeyOptions, verifyPasskey } from './auth-api.js';

function decode(value) {
  const normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(normalized + '==='.slice((normalized.length + 3) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0)).buffer;
}

function encode(value) {
  const binary = Array.from(new Uint8Array(value), (byte) => String.fromCharCode(byte)).join('');
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function PasskeyLogin({ basePath, uid, username, onComplete, onError }) {
  const [busy, setBusy] = useState(false);
  const supported = Boolean(window.PublicKeyCredential && navigator.credentials);
  const run = async () => {
    if (!username.trim()) { onError('Inserisci lo username prima di usare la passkey'); return; }
    setBusy(true); onError('');
    try {
      const options = await passkeyOptions(basePath, uid, username.trim());
      const publicKey = { ...options.publicKey, challenge: decode(options.publicKey.challenge) };
      publicKey.allowCredentials = (publicKey.allowCredentials || []).map((item) => ({ ...item, id: decode(item.id) }));
      const credential = await navigator.credentials.get({ publicKey });
      const assertion = credential.response;
      const verified = await verifyPasskey(basePath, uid, { token: options.token, credential: { id: credential.id, rawId: encode(credential.rawId), type: credential.type, response: { clientDataJSON: encode(assertion.clientDataJSON), authenticatorData: encode(assertion.authenticatorData), signature: encode(assertion.signature), userHandle: assertion.userHandle ? encode(assertion.userHandle) : null }, clientExtensionResults: credential.getClientExtensionResults?.() || {}, authenticatorAttachment: credential.authenticatorAttachment || null } });
      onComplete(await completePasskey(basePath, uid, verified.completionToken));
    } catch (error) { onError(error.message || 'Accesso con passkey non riuscito'); }
    finally { setBusy(false); }
  };
  return <><p className="separator">oppure</p><button type="button" className="secondary wide" disabled={!supported || busy} onClick={run}>{busy ? 'Attendi…' : supported ? 'Accedi con passkey' : 'Passkey non supportata'}</button></>;
}
