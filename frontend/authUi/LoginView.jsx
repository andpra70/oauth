import { useEffect, useState } from 'react';
import { follow, } from './auth-model.js';
import { login, register } from './auth-api.js';
import { PasskeyLogin } from './PasskeyLogin.jsx';

export function LoginView({ context, basePath, uid, onError, initialState }) {
  const [mode, setMode] = useState('login');
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({ username: '', password: '', email: '', otp: '', challenge: '' });
  useEffect(() => { if (initialState?.status === 'totp_required') setForm((value) => ({ ...value, challenge: initialState.challenge })); }, [initialState]);
  const change = (key) => (event) => setForm((value) => ({ ...value, [key]: event.target.value }));
  const submit = async (event) => {
    event.preventDefault(); setBusy(true); onError('');
    try {
      const result = mode === 'register' ? await register(basePath, uid, form) : await login(basePath, uid, form);
      if (result.status === 'totp_required') { setForm((value) => ({ ...value, challenge: result.challenge, password: '' })); setBusy(false); return; }
      follow(result);
    } catch (error) { if (error.payload?.status === 'totp_required') setForm((value) => ({ ...value, challenge: error.payload.challenge, password: '' })); onError(error.message); setBusy(false); }
  };
  return <>
    <h1>{mode === 'register' ? 'Crea account' : 'Accedi'}</h1>
    <form onSubmit={submit}>
      {!form.challenge && <label>Username<input autoComplete="username" value={form.username} onChange={change('username')} required /></label>}
      {mode === 'register' && !form.challenge && <label>Email<input type="email" autoComplete="email" value={form.email} onChange={change('email')} /></label>}
      {!form.challenge && <label>Password<input type="password" autoComplete={mode === 'register' ? 'new-password' : 'current-password'} value={form.password} onChange={change('password')} required /></label>}
      {(context.features.twoFactor || form.challenge) && <label>Codice Authenticator<input inputMode="numeric" pattern="[0-9]{6}" maxLength="6" value={form.otp} onChange={change('otp')} required={Boolean(form.challenge)} /></label>}
      <button disabled={busy}>{busy ? 'Attendi…' : form.challenge ? 'Verifica' : mode === 'register' ? 'Registrati' : 'Continua'}</button>
    </form>
    <div className="actions">
      <button className="secondary" onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setForm({ username: '', password: '', email: '', otp: '', challenge: '' }); }}>{mode === 'login' ? 'Crea account' : 'Torna al login'}</button>
      {context.features.google && <a className="button" href={context.googleStartUrl}>Continua con Google</a>}
    </div>
    {mode === 'login' && !form.challenge && context.features.passkey && <PasskeyLogin basePath={basePath} uid={uid} username={form.username} onComplete={(result) => { if (result.status === 'totp_required') setForm((value) => ({ ...value, challenge: result.challenge })); else follow(result); }} onError={onError} />}
  </>;
}
