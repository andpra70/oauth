import { useEffect, useState } from 'react';
import { completeGoogle, getInteraction } from './auth-api.js';
import { follow, readAuthUiConfig } from './auth-model.js';
import { ConsentView } from './ConsentView.jsx';
import { LoginView } from './LoginView.jsx';

export function AuthUiApp() {
  const [{ basePath, uid, googleToken, initialError }] = useState(readAuthUiConfig);
  const [context, setContext] = useState(null);
  const [error, setError] = useState(initialError);
  const [loginState, setLoginState] = useState(null);
  useEffect(() => { if (!uid) { setError('Interazione mancante'); return; } getInteraction(basePath, uid).then((result) => { if (!follow(result)) setContext(result); }).catch((reason) => setError(reason.message)); }, [basePath, uid]);
  useEffect(() => { if (context?.prompt === 'login' && context.loginMethod === 'google' && context.googleStartUrl && !googleToken) window.location.assign(context.googleStartUrl); }, [context, googleToken]);
  useEffect(() => { if (!uid || !googleToken) return; completeGoogle(basePath, uid, googleToken).then((result) => { if (!follow(result)) setLoginState(result); window.history.replaceState({}, '', `${window.location.pathname}?uid=${encodeURIComponent(uid)}`); }).catch((reason) => setError(reason.message)); }, [basePath, uid, googleToken]);
  return <main><section className="card">{!context && !error ? <p>Caricamento…</p> : null}{context?.prompt === 'login' ? <LoginView context={context} basePath={basePath} uid={uid} onError={setError} initialState={loginState} /> : null}{context?.prompt === 'consent' ? <ConsentView context={context} basePath={basePath} uid={uid} onError={setError} /> : null}{error && <p className="error">{error}</p>}</section></main>;
}
