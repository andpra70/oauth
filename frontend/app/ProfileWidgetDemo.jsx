import { useEffect, useState } from 'react';
import { appPath } from '../shared/api.js';

const scriptId = 'ecosystem-profile-widget-script';

function loadProfileWidget(widgetUrl) {
  if (window.ProfileWidget) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const existing = document.getElementById(scriptId);
    if (existing) {
      existing.addEventListener('load', resolve, { once: true });
      existing.addEventListener('error', reject, { once: true });
      return;
    }
    const script = document.createElement('script');
    script.id = scriptId;
    script.src = widgetUrl;
    script.async = true;
    script.addEventListener('load', resolve, { once: true });
    script.addEventListener('error', () => reject(new Error(`Impossibile caricare ${widgetUrl}`)), { once: true });
    document.head.appendChild(script);
  });
}

export default function ProfileWidgetDemo() {
  const widgetUrl = appPath('profile-widget.js');
  const [ready, setReady] = useState(Boolean(window.ProfileWidget));
  const [message, setMessage] = useState('Caricamento del widget condiviso…');

  useEffect(() => {
    let active = true;
    const onToken = (event) => {
      const label = event.detail?.user?.email || event.detail?.user?.name || 'utente autenticato';
      setMessage(`Sessione attiva: ${label}`);
    };
    const onLogout = () => setMessage('Sessione chiusa. Premi l’avatar per accedere.');

    window.addEventListener('oauth:token', onToken);
    window.addEventListener('oauth:logout', onLogout);
    loadProfileWidget(widgetUrl)
      .then(() => {
        if (!active) return;
        setReady(true);
        setMessage('Widget pronto. Usa l’avatar in basso a destra oppure il pulsante qui sotto.');
      })
      .catch((error) => active && setMessage(error.message || 'Profile Widget non disponibile.'));

    return () => {
      active = false;
      window.removeEventListener('oauth:token', onToken);
      window.removeEventListener('oauth:logout', onLogout);
    };
  }, [widgetUrl]);

  return (
    <section className="panel">
      <div className="badge-row">
        <span className="badge">Widget condiviso</span>
        <span className="badge">React + Shadow DOM</span>
      </div>
      <h2>Profile Widget</h2>
      <p className="hint">
        Questa è la stessa integrazione disponibile per galleria, catalogo, minicms e fileserver.
        L’avatar flottante consente login, logout e modifica di nome, cognome e nota.
      </p>
      <div className={`status ${ready ? '' : 'error'}`.trim()}>{message}</div>
      <div className="actions">
        <button className="primary" type="button" disabled={!ready} onClick={() => window.ProfileWidget?.open()}>
          Apri profilo
        </button>
      </div>
      {ready ? <profile-widget issuer={new URL(appPath(''), window.location.origin).toString().replace(/\/$/, '')} client-id="fileserver-web" /> : null}
    </section>
  );
}
