import { useEffect, useState } from 'react';
import { confirmPasswordReset, validateResetToken } from './password-reset-api.js';
import { readResetConfig } from './password-reset-model.js';
export function ResetPasswordApp() {
  const [{ basePath, token }] = useState(readResetConfig); const [valid, setValid] = useState(null); const [password, setPassword] = useState(''); const [confirmation, setConfirmation] = useState(''); const [error, setError] = useState(''); const [complete, setComplete] = useState(false);
  useEffect(() => { if (!token) { setValid(false); return; } validateResetToken(basePath, token).then(() => setValid(true)).catch((reason) => { setError(reason.message); setValid(false); }); }, [basePath, token]);
  const submit = async (event) => { event.preventDefault(); setError(''); try { await confirmPasswordReset(basePath, { token, password, passwordConfirmation: confirmation }); sessionStorage.removeItem('oauth.password-reset-token'); setComplete(true); } catch (reason) { setError(reason.message); } };
  return <main><section className="card"><h1>Reimposta password</h1>{valid === null && <p>Verifica del link…</p>}{valid && !complete && <form onSubmit={submit}><label>Nuova password<input type="password" minLength="12" required value={password} onChange={(event) => setPassword(event.target.value)} /></label><label>Conferma password<input type="password" minLength="12" required value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></label><button>Conferma nuova password</button></form>}{complete && <p className="success">Password aggiornata. Puoi tornare all’applicazione ed effettuare il login.</p>}{valid === false && <p>Il link non è valido o è scaduto.</p>}{error && <p className="error">{error}</p>}</section></main>;
}
