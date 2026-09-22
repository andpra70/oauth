import { useEffect, useState } from 'react';
import { editableProfile } from './profile-model.js';

export function ProfileModal({ profile, saving, error, onClose, onSave, onLogout }) {
  const [tab, setTab] = useState('profile');
  const [form, setForm] = useState(() => editableProfile(profile));

  useEffect(() => setForm(editableProfile(profile)), [profile]);
  useEffect(() => {
    const closeOnEscape = (event) => event.key === 'Escape' && onClose();
    window.addEventListener('keydown', closeOnEscape);
    return () => window.removeEventListener('keydown', closeOnEscape);
  }, [onClose]);

  const change = (field) => (event) => setForm((current) => ({ ...current, [field]: event.target.value }));
  const submit = (event) => { event.preventDefault(); onSave(form); };

  return (
    <div className="backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <section className="modal" role="dialog" aria-modal="true" aria-labelledby="profile-title">
        <header>
          <div className="identity">
            {profile.picture ? <img src={profile.picture} alt="" referrerPolicy="no-referrer" /> : <span>U</span>}
            <div><strong id="profile-title">Profilo</strong><small>{profile.email}</small></div>
          </div>
          <div className="header-actions">
            <button className="logout top-logout" type="button" onClick={onLogout} disabled={saving}>Logout</button>
            <button className="icon-button" type="button" onClick={onClose} aria-label="Chiudi">×</button>
          </div>
        </header>
        <nav aria-label="Sezioni profilo">
          <button type="button" className={tab === 'profile' ? 'active' : ''} onClick={() => setTab('profile')}>Informazioni</button>
          <button type="button" className={tab === 'additional' ? 'active' : ''} onClick={() => setTab('additional')}>Informazioni aggiuntive</button>
        </nav>
        <form onSubmit={submit}>
          {tab === 'profile' ? <div className="fields">
            <label>Nome<input value={form.firstName} maxLength="100" onChange={change('firstName')} /></label>
            <label>Cognome<input value={form.lastName} maxLength="100" onChange={change('lastName')} /></label>
          </div> : <div className="fields">
            <label>Nota<textarea value={form.note} maxLength="2000" rows="7" onChange={change('note')} placeholder="Informazioni aggiuntive sul profilo" /></label>
          </div>}
          {error && <p className="error" role="alert">{error}</p>}
          <footer className="profile-footer">
            <div><button type="button" onClick={onClose}>Annulla</button><button className="primary" type="submit" disabled={saving}>{saving ? 'Salvataggio…' : 'Salva'}</button></div>
          </footer>
        </form>
      </section>
    </div>
  );
}
