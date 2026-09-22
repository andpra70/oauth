import { useEffect, useState } from 'react';
import { ForgotPasswordView } from './ForgotPasswordView.jsx';

const methods = [
  { id: 'account', icon: '●', title: 'Account', description: 'Username, password e codice Authenticator quando richiesto.' },
  { id: 'passkey', icon: '◆', title: 'Passkey', description: 'Accedi con impronta, riconoscimento facciale o chiave di sicurezza.' },
  { id: 'google', icon: 'G', title: 'Google', description: 'Continua usando il tuo account Google.' },
];

export function LoginModal({ features, busy, error, onClose, onLogin, onPasswordReset }) {
  const [forgotPassword, setForgotPassword] = useState(false);
  const visibleMethods = methods.filter((method) => {
    if (method.id === 'passkey') return features.passkeyEnabled;
    if (method.id === 'google') return features.googleEnabled;
    return true;
  });
  useEffect(() => {
    const closeOnEscape = (event) => event.key === 'Escape' && onClose();
    window.addEventListener('keydown', closeOnEscape);
    return () => window.removeEventListener('keydown', closeOnEscape);
  }, [onClose]);

  return (
    <div className="backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <section className="modal login-modal" role="dialog" aria-modal="true" aria-labelledby="login-title">
        <header>
          <div className="identity">
            <span aria-hidden="true">U</span>
            <div><strong id="login-title">Accedi</strong><small>Scegli come continuare</small></div>
          </div>
          <button className="icon-button" type="button" onClick={onClose} aria-label="Chiudi">×</button>
        </header>
        {forgotPassword ? <ForgotPasswordView busy={busy} onBack={() => setForgotPassword(false)} onRequest={onPasswordReset} /> : <div className="login-content">
          <p className="login-intro">L’autenticazione prosegue sul provider OIDC in modo sicuro.</p>
          <div className="login-methods">
            {visibleMethods.map((method) => (
              <button key={method.id} type="button" disabled={busy} onClick={() => onLogin(method.id)}>
                <span className="login-method-icon" aria-hidden="true">{method.icon}</span>
                <span><strong>{method.title}</strong><small>{method.description}</small></span>
                <b aria-hidden="true">›</b>
              </button>
            ))}
          </div>
          {features.passwordResetEnabled && <button className="text-button" type="button" onClick={() => setForgotPassword(true)}>Password dimenticata?</button>}
          {error && <p className="error" role="alert">{error}</p>}
        </div>}
      </section>
    </div>
  );
}
