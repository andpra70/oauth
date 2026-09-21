export function ProfileIcon({ authenticated, profile, busy, onClick }) {
  const initials = `${profile.firstName?.[0] || ''}${profile.lastName?.[0] || ''}`.toUpperCase() || 'U';
  return (
    <button className="profile-trigger" type="button" onClick={onClick} disabled={busy}
      aria-label={authenticated ? 'Apri profilo utente' : 'Accedi con Google'} title={authenticated ? 'Profilo utente' : 'Accedi con Google'}>
      {authenticated && profile.picture
        ? <img src={profile.picture} alt="" referrerPolicy="no-referrer" />
        : <span aria-hidden="true">{authenticated ? initials : 'G'}</span>}
      <i className={authenticated ? 'online' : ''} aria-hidden="true" />
    </button>
  );
}
