import { useCallback, useEffect, useMemo, useState } from 'react';
import { createProfileApi, getAuthFeatures, requestPasswordReset } from './profile-api.js';
import { DEFAULT_AUTH_FEATURES, EMPTY_PROFILE, normalizeAuthFeatures, normalizeProfile } from './profile-model.js';
import { ProfileIcon } from './ProfileIcon.jsx';
import { ProfileModal } from './ProfileModal.jsx';
import { LoginModal } from './LoginModal.jsx';

export function ProfileWidgetApp({ apiBase, auth }) {
  const [profile, setProfile] = useState(EMPTY_PROFILE);
  const [authenticated, setAuthenticated] = useState(() => auth.isAuthenticated());
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [features, setFeatures] = useState(DEFAULT_AUTH_FEATURES);
  const api = useMemo(() => auth ? createProfileApi(apiBase, auth.getAccessToken) : null, [apiBase, auth]);

  const loadProfile = useCallback(async (currentApi = api) => {
    if (!currentApi) return;
    setBusy(true); setError('');
    try {
      const storedProfile = normalizeProfile(await currentApi.get());
      setProfile(storedProfile);
      setAuthenticated(true);
    }
    catch {
      setAuthenticated(auth.isAuthenticated());
    }
    finally { setBusy(false); }
  }, [api]);

  useEffect(() => {
    let active = true;
    const initialize = async () => {
      try {
        const loadedFeatures = normalizeAuthFeatures(await getAuthFeatures(apiBase));
        if (active) setFeatures(loadedFeatures);
      } catch {
        if (active) setFeatures(DEFAULT_AUTH_FEATURES);
      }
      await auth.initialize();
      if (!active || !auth.isAuthenticated()) return;
      await loadProfile(createProfileApi(apiBase, auth.getAccessToken));
    };
    initialize().catch((reason) => setError(reason.message));
    return () => { active = false; };
  }, [apiBase, auth, loadProfile]);

  useEffect(() => {
    const loggedIn = (event) => {
      setProfile(normalizeProfile(event.detail?.user || EMPTY_PROFILE));
      setAuthenticated(true);
      loadProfile();
    };
    const loggedOut = () => { setAuthenticated(false); setProfile(EMPTY_PROFILE); setOpen(false); };
    const requestOpen = () => setOpen(true);
    const requestClose = () => setOpen(false);
    window.addEventListener('oauth:token', loggedIn);
    window.addEventListener('oauth:logout', loggedOut);
    window.addEventListener('profile-widget:open', requestOpen);
    window.addEventListener('profile-widget:close', requestClose);
    return () => {
      window.removeEventListener('oauth:token', loggedIn); window.removeEventListener('oauth:logout', loggedOut);
      window.removeEventListener('profile-widget:open', requestOpen); window.removeEventListener('profile-widget:close', requestClose);
    };
  }, [auth, authenticated, loadProfile]);

  const activate = () => setOpen(true);
  const login = async (method) => {
    setBusy(true); setError('');
    try { await auth.login(method); }
    catch (reason) { setError(reason.message || 'Impossibile avviare il login.'); setBusy(false); }
  };
  const save = async (changes) => {
    setBusy(true); setError('');
    try {
      const storedProfile = normalizeProfile(await api.update(changes));
      setProfile({ ...storedProfile, picture: storedProfile.picture || profile.picture });
      setOpen(false);
    }
    catch (reason) { setError(reason.message || 'Salvataggio non riuscito'); }
    finally { setBusy(false); }
  };
  const logout = async () => { setBusy(true); await auth.logout(); };
  const forgotPassword = async (email) => { setBusy(true); setError(''); try { return await requestPasswordReset(apiBase, email); } catch (reason) { setError(reason.message || 'Impossibile inviare il messaggio.'); throw reason; } finally { setBusy(false); } };

  return <>
    <ProfileIcon authenticated={authenticated} profile={profile} busy={busy} onClick={activate} />
    {open && !authenticated && <LoginModal features={features} busy={busy} error={error} onClose={() => setOpen(false)} onLogin={login} onPasswordReset={forgotPassword} />}
    {open && authenticated && <ProfileModal profile={profile} saving={busy} error={error} onClose={() => setOpen(false)} onSave={save} onLogout={logout} />}
  </>;
}
