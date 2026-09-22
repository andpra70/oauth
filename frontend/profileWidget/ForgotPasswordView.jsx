import { useState } from 'react';
export function ForgotPasswordView({ busy, onBack, onRequest }) {
  const [email, setEmail] = useState(''); const [sent, setSent] = useState(false);
  const submit = async (event) => { event.preventDefault(); await onRequest(email); setSent(true); };
  return <div className="login-content"><p className="login-intro">Inserisci l’email associata all’account. Se esiste, riceverai un link monouso.</p>{sent ? <p className="reset-success">Controlla la posta. Il messaggio può richiedere qualche minuto.</p> : <form className="reset-form" onSubmit={submit}><label>Email<input type="email" required value={email} onChange={(event) => setEmail(event.target.value)} /></label><button type="submit" disabled={busy}>{busy ? 'Invio…' : 'Invia link di reset'}</button></form>}<button className="text-button" type="button" onClick={onBack}>Torna al login</button></div>;
}
