import { useState } from 'react';
import { consent } from './auth-api.js';
import { follow } from './auth-model.js';

export function ConsentView({ context, basePath, uid, onError }) {
  const [busy, setBusy] = useState(false);
  const decide = async (decision) => { setBusy(true); onError(''); try { follow(await consent(basePath, uid, decision)); } catch (error) { onError(error.message); setBusy(false); } };
  return <><h1>Autorizzazione</h1><p><strong>{context.client.name}</strong> richiede: {context.scope.join(', ')}</p><div className="actions"><button disabled={busy} onClick={() => decide('allow')}>Consenti</button><button className="secondary" disabled={busy} onClick={() => decide('deny')}>Nega</button></div></>;
}
