import { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import UsersAdminView from './components/UsersAdminView.jsx';
import OidcSessionsAdminView from './components/OidcSessionsAdminView.jsx';

const OIDC_UI_STYLE = `
:root{color-scheme:dark}*{box-sizing:border-box}body{font-family:system-ui,sans-serif;max-width:460px;margin:40px auto;padding:0 16px;background:#0f172a;color:#e2e8f0}.box{border:1px solid #334155;border-radius:12px;padding:20px;background:#111827}label{display:block;margin-top:12px;font-size:14px}input,select{width:100%;margin-top:6px;padding:10px;border-radius:8px;border:1px solid #475569;background:#0b1220;color:#e2e8f0}button,.button-link{margin-top:16px;width:100%;padding:10px;border:0;border-radius:8px;background:#2563eb;color:#fff;font-weight:600;cursor:pointer;box-sizing:border-box;text-align:center;display:block;text-decoration:none}.secondary{background:#374151}.error{color:#fca5a5;margin-top:12px;font-size:14px}.hint{color:#94a3b8;font-size:13px;margin-top:8px}a{color:#93c5fd}.actions{display:grid;gap:8px;margin-top:16px}.separator{margin:20px 0 8px;color:#94a3b8;font-size:13px;text-align:center}.auth-grid{display:grid;grid-template-columns:1fr;gap:16px;align-items:start}.qr-panel{border:1px solid #334155;border-radius:12px;padding:12px;background:#0b1220}pre{margin:0;padding:12px;border-radius:12px;background:#111827;color:#e2e8f0;white-space:pre-wrap;word-break:break-word}body:has(.admin-main){max-width:none}.admin-main{width:min(1180px,calc(100% - 32px));margin:24px auto;display:grid;gap:16px}.shell{display:grid;grid-template-columns:320px minmax(0,1fr);gap:16px;align-items:start}.panel{border:1px solid #334155;background:#111827;padding:18px}.topbar{display:flex;justify-content:space-between;gap:12px;align-items:center}.muted{color:#94a3b8}.list{display:grid;gap:8px;margin-top:16px}.user-link{display:grid;gap:2px;padding:10px 12px;text-decoration:none;color:#e2e8f0;border:1px solid #334155;background:#0b1220}.user-link.active{border-color:#60a5fa;background:#172033}.form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-top:16px}.field{display:grid;gap:6px}.field.full{grid-column:1/-1}.message{margin-top:12px;padding:10px 12px;border:1px solid #334155;background:#0b1220}.message.error{border-color:#7f1d1d;color:#fecaca}.meta{display:grid;gap:6px;margin-top:16px;color:#94a3b8;font-size:13px}.danger{background:#991b1b}@media (min-width:860px){.box{max-width:920px;margin:0 auto}}@media (max-width:860px){.shell{grid-template-columns:1fr}.form-grid{grid-template-columns:1fr}}
`;

function resolvePath(basePath, path) {
  const normalizedBase = basePath === '/' ? '' : String(basePath || '').replace(/\/+$/g, '');
  const normalizedPath = String(path || '/').startsWith('/') ? String(path || '/') : `/${String(path || '/')}`;
  return normalizedBase ? `${normalizedBase}${normalizedPath}` : normalizedPath;
}

function b64urlToArrayBuffer(value) {
  const normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '==='.slice((normalized.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function arrayBufferToB64url(value) {
  const bytes = new Uint8Array(value);
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function BackUrlCta({ backUrl }) {
  if (!backUrl) return null;
  return <p className="hint"><a href={backUrl}>Back to application</a></p>;
}

function PasskeyLogin({
  basePath,
  uid,
  username,
  password = '',
  otp = '',
  twoFactorEnabled = false,
}) {
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [showSetupHint, setShowSetupHint] = useState(false);
  const supported = typeof window !== 'undefined' && !!window.PublicKeyCredential && !!navigator.credentials;

  async function run() {
    setBusy(true);
    setError('');
    setShowSetupHint(false);
    if (!username.trim()) {
      setError('Inserisci username prima di usare la passkey');
      setBusy(false);
      return;
    }
    try {
      const optionsResponse = await fetch(resolvePath(basePath, `/interaction/${uid}/passkey/options`), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username: username.trim() }),
      });
      const optionsPayload = await optionsResponse.json();
      if (!optionsResponse.ok) {
        const message = optionsPayload.error || 'Unable to start passkey flow';
        if (String(message).toLowerCase().includes('no passkey credentials are registered')) {
          if (!password.trim()) {
            setShowSetupHint(true);
            throw new Error('Nessuna passkey registrata. Inserisci la password per creare una nuova passkey.');
          }

          const enrollResponse = await fetch(resolvePath(basePath, `/interaction/${uid}/passkey/enroll`), {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              username: username.trim(),
              password,
              otp: twoFactorEnabled ? otp : '',
            }),
          });
          const enrollPayload = await enrollResponse.json();
          if (!enrollResponse.ok) throw new Error(enrollPayload.error || 'Unable to start passkey enrollment');
          if (enrollPayload.redirectTo) {
            window.location.assign(enrollPayload.redirectTo);
            return;
          }
          throw new Error('Unable to start passkey enrollment');
        }
        throw new Error(message);
      }

      const publicKey = optionsPayload.publicKey;
      publicKey.challenge = b64urlToArrayBuffer(publicKey.challenge);
      if (Array.isArray(publicKey.allowCredentials)) {
        publicKey.allowCredentials = publicKey.allowCredentials.map((item) => ({ ...item, id: b64urlToArrayBuffer(item.id) }));
      }

      const credential = await navigator.credentials.get({ publicKey });
      if (!credential) throw new Error('Passkey not available');
      const assertion = credential.response;

      const verifyResponse = await fetch(resolvePath(basePath, `/interaction/${uid}/passkey/verify`), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          token: optionsPayload.token,
          credential: {
            id: credential.id,
            rawId: arrayBufferToB64url(credential.rawId),
            type: credential.type,
            response: {
              clientDataJSON: arrayBufferToB64url(assertion.clientDataJSON),
              authenticatorData: arrayBufferToB64url(assertion.authenticatorData),
              signature: arrayBufferToB64url(assertion.signature),
              userHandle: assertion.userHandle ? arrayBufferToB64url(assertion.userHandle) : null,
            },
            clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
            authenticatorAttachment: credential.authenticatorAttachment || null,
          },
        }),
      });
      const verifyResult = await verifyResponse.json();
      if (!verifyResponse.ok) throw new Error(verifyResult.error || 'Passkey verification failed');
      if (verifyResult.redirectTo) window.location.assign(verifyResult.redirectTo);
      else window.location.reload();
    } catch (err) {
      const message = err?.message || 'Passkey login failed';
      setError(message);
      if (String(message).toLowerCase().includes('no passkey credentials are registered')) {
        setShowSetupHint(true);
      }
      setBusy(false);
    }
  }

  return (
    <>
      <p className="separator">Passkey</p>
      <button className="secondary" type="button" onClick={run} disabled={busy || !supported}>
        {supported ? 'Accedi con Passkey' : 'Passkey non supportato su questo browser'}
      </button>
      {error ? <p className="error">{error}</p> : null}
      {showSetupHint ? (
        <p className="hint">
          Nessuna passkey registrata. Vai su <a href={resolvePath(basePath, '/app')}>OAuth Console</a> per registrare una passkey.
        </p>
      ) : null}
    </>
  );
}

function LoginView({ payload }) {
  const {
    basePath = '',
    uid = '',
    twoFactorEnabled = true,
    passkeyEnabled = false,
    registerUrl = '',
    backUrl = '',
    error = '',
    username = '',
    otp = '',
    qrSetupUrl = '',
    googleLoginUrl = '',
    googleRegisterUrl = '',
    googleChallenge = '',
    googleAccountLabel = '',
  } = payload || {};
  const isGoogleTotp = Boolean(googleChallenge);
  const [usernameValue, setUsernameValue] = useState(username);
  const [passwordValue, setPasswordValue] = useState('');
  const [otpValue, setOtpValue] = useState(otp);
  const googleAuthUrl = googleLoginUrl || googleRegisterUrl;
  const loginHint = twoFactorEnabled
    ? 'Use your username, password and Authenticator code in one step. Google login registers or updates the user and then returns here for TOTP verification.'
    : 'Use your username and password to sign in. Google login registers or updates the user and completes the session without TOTP.';

  return (
    <div className="box">
      <h2>Sign in</h2>
      <p className="hint">{loginHint}</p>
      <div className="auth-grid">
        <form method="post" action={resolvePath(basePath, `/interaction/${uid}/login`)}>
          {isGoogleTotp ? <input type="hidden" name="challenge" value={googleChallenge} /> : null}
          {isGoogleTotp ? (
            <p className="hint">Account: <strong>{googleAccountLabel || username}</strong></p>
          ) : (
            <>
              <label>Username
                <input name="username" autoComplete="username" required value={usernameValue} onChange={(e) => setUsernameValue(e.target.value)} />
              </label>
              <label>Password
                <input name="password" type="password" autoComplete="current-password" required value={passwordValue} onChange={(e) => setPasswordValue(e.target.value)} />
              </label>
            </>
          )}
          {twoFactorEnabled ? (
            <label>Authenticator code
              <input name="otp" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} placeholder="123456" required={isGoogleTotp} value={otpValue} onChange={(e) => setOtpValue(e.target.value)} />
            </label>
          ) : null}
          <button type="submit">{isGoogleTotp ? 'Verify and sign in' : 'Continue'}</button>
          {qrSetupUrl ? <p className="hint"><a href={qrSetupUrl} target="_blank" rel="noreferrer">Open TOTP setup QR</a></p> : null}
        </form>
      </div>
      {!isGoogleTotp && passkeyEnabled ? <PasskeyLogin basePath={basePath} uid={uid} username={usernameValue} password={passwordValue} otp={otpValue} twoFactorEnabled={twoFactorEnabled} /> : null}
      {!isGoogleTotp && googleAuthUrl ? <p className="separator">Google OAuth</p> : null}
      {!isGoogleTotp ? (
        <div className="actions">
          {registerUrl ? <a className="button-link secondary" href={registerUrl}>Create account</a> : null}
          {googleAuthUrl ? <a className="button-link secondary" href={googleAuthUrl}>Continua con Google</a> : null}
        </div>
      ) : null}
      <BackUrlCta backUrl={backUrl} />
      {error ? <p className="error">{error}</p> : null}
    </div>
  );
}

function RegisterView({ payload }) {
  const {
    basePath = '',
    uid = '',
    loginUrl = '',
    googleRegisterUrl = '',
    backUrl = '',
    passkeyEnabled = false,
    error = '',
    formValues = {},
  } = payload || {};
  const username = String(formValues.username || '');
  const email = String(formValues.email || '');
  const googleAuthUrl = googleRegisterUrl;
  return (
    <div className="box">
      <h2>Create account</h2>
      <p className="hint">Create a local account with username and password{passkeyEnabled ? ', then optionally register a passkey.' : '.'}</p>
      <form method="post" action={resolvePath(basePath, `/interaction/${uid}/register`)}>
        <label>Username
          <input name="username" autoComplete="username" required defaultValue={username} />
        </label>
        <label>Email
          <input name="email" type="email" autoComplete="email" defaultValue={email} />
        </label>
        <label>Password
          <input name="password" type="password" autoComplete="new-password" minLength={12} required />
        </label>
        <button type="submit">Create account</button>
      </form>
      <div className="actions">
        {loginUrl ? <a className="button-link secondary" href={loginUrl}>Back to sign in</a> : null}
        {googleAuthUrl ? <a className="button-link secondary" href={googleAuthUrl}>Continue with Google</a> : null}
      </div>
      <BackUrlCta backUrl={backUrl} />
      {error ? <p className="error">{error}</p> : null}
    </div>
  );
}

function PasskeyOnboardingView({ payload }) {
  const { basePath = '', uid = '', token = '', username = '', backUrl = '', error = '' } = payload || {};
  const [busy, setBusy] = useState(false);
  const [localError, setLocalError] = useState('');
  const supported = typeof window !== 'undefined' && !!window.PublicKeyCredential && !!navigator.credentials;

  async function run() {
    setBusy(true);
    setLocalError('');
    try {
      const optionsResponse = await fetch(resolvePath(basePath, `/interaction/${uid}/passkey/onboarding/options`), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ token }),
      });
      const optionsPayload = await optionsResponse.json();
      if (!optionsResponse.ok) throw new Error(optionsPayload.error || 'Unable to start passkey registration');

      const publicKey = optionsPayload.publicKey;
      publicKey.challenge = b64urlToArrayBuffer(publicKey.challenge);
      if (publicKey.user?.id) publicKey.user.id = b64urlToArrayBuffer(publicKey.user.id);
      if (Array.isArray(publicKey.excludeCredentials)) {
        publicKey.excludeCredentials = publicKey.excludeCredentials.map((item) => ({ ...item, id: b64urlToArrayBuffer(item.id) }));
      }

      const credential = await navigator.credentials.create({ publicKey });
      if (!credential) throw new Error('Passkey registration cancelled');

      const verifyResponse = await fetch(resolvePath(basePath, `/interaction/${uid}/passkey/onboarding/verify`), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          token: optionsPayload.token,
          credential: {
            id: credential.id,
            rawId: arrayBufferToB64url(credential.rawId),
            type: credential.type,
            response: {
              attestationObject: arrayBufferToB64url(credential.response.attestationObject),
              clientDataJSON: arrayBufferToB64url(credential.response.clientDataJSON),
              transports: credential.response.getTransports ? credential.response.getTransports() : [],
            },
            authenticatorAttachment: credential.authenticatorAttachment || null,
            clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
          },
        }),
      });
      const verifyPayload = await verifyResponse.json();
      if (!verifyResponse.ok) throw new Error(verifyPayload.error || 'Passkey registration failed');
      if (verifyPayload.redirectTo) window.location.assign(verifyPayload.redirectTo);
      else window.location.reload();
    } catch (err) {
      setLocalError(err?.message || 'Passkey registration failed');
      setBusy(false);
    }
  }

  return (
    <div className="box">
      <h2>Complete registration</h2>
      <p className="hint">Account <strong>{username}</strong> authenticated. Register a passkey now, then continue. If a passkey already exists, it will be replaced.</p>
      <div className="actions">
        <button type="button" onClick={run} disabled={busy || !supported}>
          {supported ? 'Register passkey and continue' : 'Passkey not supported on this browser'}
        </button>
        <a className="button-link secondary" href={resolvePath(basePath, `/interaction/${uid}/passkey/onboarding/continue?token=${encodeURIComponent(token)}`)}>Continue without passkey</a>
      </div>
      <BackUrlCta backUrl={backUrl} />
      {error ? <p className="error">{error}</p> : null}
      {localError ? <p className="error">{localError}</p> : null}
    </div>
  );
}

function ConsentView({ payload }) {
  const { basePath = '', uid = '', clientName = '', scope = '' } = payload || {};
  return (
    <div className="box">
      <h2>Authorize application</h2>
      <p><strong>{clientName}</strong> requests access.</p>
      <p className="hint">Requested scope: {scope || 'openid'}</p>
      <div className="actions">
        <form method="post" action={resolvePath(basePath, `/interaction/${uid}/confirm`)}>
          <button type="submit">Allow</button>
        </form>
        <form method="post" action={resolvePath(basePath, `/interaction/${uid}/abort`)}>
          <button className="secondary" type="submit">Deny</button>
        </form>
      </div>
    </div>
  );
}

function ExpiredSessionView({ payload }) {
  const { basePath = '' } = payload || {};
  return (
    <div className="box">
      <h2>Session expired</h2>
      <p className="hint">The interaction is no longer valid. Start a new OAuth login flow.</p>
      <div className="actions">
        <form method="get" action={resolvePath(basePath, '/app')}><button type="submit">Open OAuth Console</button></form>
        <form method="get" action={resolvePath(basePath, '/')}><button className="secondary" type="submit">Go to home</button></form>
      </div>
    </div>
  );
}

function RawHtml({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: html || '' }} />;
}

function LogoutView({ payload }) {
  const { host = '', form = '' } = payload || {};
  return (
    <div className="box">
      <h2>Sign out</h2>
      <p className="hint">You are about to close the current authorization session for <strong>{host || 'this provider'}</strong>.</p>
      <div className="actions">
        <RawHtml html={form} />
        <button autoFocus type="submit" form="op.logoutForm" value="yes" name="logout">Yes, sign me out</button>
        <button className="secondary" type="submit" form="op.logoutForm">No, stay signed in</button>
      </div>
    </div>
  );
}

function LogoutSuccessView({ payload }) {
  const { basePath = '', clientName = '' } = payload || {};
  return (
    <div className="box">
      <h2>Signed out</h2>
      <p className="hint">Your session {clientName ? <>for <strong>{clientName}</strong> </> : null}has been closed successfully.</p>
      <div className="actions">
        <form method="get" action={resolvePath(basePath, '/app')}><button type="submit">Open OAuth Console</button></form>
        <form method="get" action={resolvePath(basePath, '/authWidget')}><button className="secondary" type="submit">Open AuthWidget</button></form>
      </div>
    </div>
  );
}

function LogoutAutosubmitView({ payload }) {
  const { form = '' } = payload || {};
  useEffect(() => {
    const currentForm = document.getElementById('op.logoutForm');
    if (!currentForm) return;
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'logout';
    input.value = 'yes';
    currentForm.appendChild(input);
    currentForm.submit();
  }, []);

  return (
    <div className="box">
      <h2>Signing out</h2>
      <p className="hint">Your session is being closed automatically.</p>
      <RawHtml html={form} />
      <div className="actions">
        <button autoFocus type="submit" form="op.logoutForm" value="yes" name="logout">Continue</button>
      </div>
    </div>
  );
}

function TotpQrSetupView({ payload }) {
  const { username = '', otpauthUrl = '', dataUrl = '' } = payload || {};
  return (
    <div className="box">
      <h2>TOTP setup QR</h2>
      <p className="hint">Scan this QR code with your authenticator app{username ? <> for <strong>{username}</strong></> : null}.</p>
      <div className="qr-panel">
        <img src={dataUrl} alt="TOTP setup QR" style={{ width: '100%', maxWidth: '280px', display: 'block', margin: '0 auto 12px', borderRadius: '12px', background: 'white', padding: '12px' }} />
        <p className="hint">If you cannot scan the QR code, use the OTPAuth URL below.</p>
        <pre>{otpauthUrl}</pre>
      </div>
    </div>
  );
}

function ProviderErrorView({ payload }) {
  const {
    error = 'server_error',
    error_description: errorDescription = 'oops! something went wrong',
    state = '',
    iss = '',
    basePath = '',
  } = payload || {};

  return (
    <div className="box">
      <h2>Oops! something went wrong</h2>
      <div className="meta">
        <div><strong>error:</strong> {String(error || '') || '-'}</div>
        <div><strong>error_description:</strong> {String(errorDescription || '') || '-'}</div>
        {state ? <div><strong>state:</strong> {state}</div> : null}
        {iss ? <div><strong>iss:</strong> {iss}</div> : null}
      </div>
      <div className="actions">
        <a className="button-link secondary" href={resolvePath(basePath, '/app')}>Back to app</a>
      </div>
    </div>
  );
}

function UnsupportedView({ view }) {
  return <div className="box"><h2>Unsupported view</h2><p className="error">{view}</p></div>;
}

function OidcUiApp() {
  const config = window.__OIDC_UI__ || {};
  const view = String(config.view || 'login');
  const payload = config.payload || {};

  useEffect(() => {
    if (document.getElementById('oidc-ui-style')) return;
    const style = document.createElement('style');
    style.id = 'oidc-ui-style';
    style.textContent = OIDC_UI_STYLE;
    document.head.appendChild(style);
  }, []);

  switch (view) {
    case 'login': return <LoginView payload={payload} />;
    case 'register': return <RegisterView payload={payload} />;
    case 'passkey_onboarding': return <PasskeyOnboardingView payload={payload} />;
    case 'consent': return <ConsentView payload={payload} />;
    case 'expired_session': return <ExpiredSessionView payload={payload} />;
    case 'logout': return <LogoutView payload={payload} />;
    case 'logout_success': return <LogoutSuccessView payload={payload} />;
    case 'logout_autosubmit': return <LogoutAutosubmitView payload={payload} />;
    case 'totp_qr_setup': return <TotpQrSetupView payload={payload} />;
    case 'provider_error': return <ProviderErrorView payload={payload} />;
    case 'users_admin': return <UsersAdminView payload={payload} resolvePath={resolvePath} />;
    case 'oidc_sessions_admin': return <OidcSessionsAdminView payload={payload} resolvePath={resolvePath} />;
    default: return <UnsupportedView view={view} />;
  }
}

createRoot(document.getElementById('oidc-ui-root')).render(<OidcUiApp />);
