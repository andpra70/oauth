import { useCallback, useEffect, useMemo, useState } from 'react';
import { createProfileApi } from './profile-api.js';
import { EMPTY_PROFILE, normalizeProfile } from './profile-model.js';
import { ProfileIcon } from './ProfileIcon.jsx';
import { ProfileModal } from './ProfileModal.jsx';

function loadScript(src) {
  return new Promise((resolve, reject) => {
    const existing = document.querySelector(`script[data-profile-auth="${src}"]`);
    if (existing) { existing.addEventListener('load', resolve, { once: true }); return; }
    const script = document.createElement('script');
    script.src = src; script.async = true; script.dataset.profileAuth = src;
    script.onload = resolve; script.onerror = () => reject(new Error('Widget OAuth non disponibile'));
    document.head.appendChild(script);
  });
}

export function ProfileWidgetApp({ apiBase, authWidgetUrl }) {
  const [auth, setAuth] = useState(() => window.VfsAuth || null);
  const [profile, setProfile] = useState(() => normalizeProfile(window.VfsAuth?.getUser?.() || EMPTY_PROFILE));
  const [authenticated, setAuthenticated] = useState(() => Boolean(window.VfsAuth?.isAuthenticated()));
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const api = useMemo(() => auth ? createProfileApi(apiBase, auth.getAccessToken) : null, [apiBase, auth]);

  const loadProfile = useCallback(async (currentApi = api) => {
    if (!currentApi) return;
    setBusy(true); setError('');
    try {
      const storedProfile = normalizeProfile(await currentApi.get());
      const oauthProfile = normalizeProfile(window.VfsAuth?.getUser?.() || EMPTY_PROFILE);
      setProfile({ ...storedProfile, picture: storedProfile.picture || oauthProfile.picture });
      setAuthenticated(true);
    }
    catch {
      const oauthProfile = normalizeProfile(window.VfsAuth?.getUser?.() || EMPTY_PROFILE);
      setAuthenticated(Boolean(window.VfsAuth?.isAuthenticated?.()));
      setProfile(oauthProfile);
    }
    finally { setBusy(false); }
  }, [api]);

  useEffect(() => {
    let active = true;
    const initialize = async () => {
      if (!window.VfsAuth) await loadScript(authWidgetUrl);
      if (!active || !window.VfsAuth) return;
      setAuth(window.VfsAuth);
      const currentApi = createProfileApi(apiBase, window.VfsAuth.getAccessToken);
      await loadProfile(currentApi);
    };
    initialize().catch((reason) => setError(reason.message));
    return () => { active = false; };
  }, [apiBase, authWidgetUrl, loadProfile]);

  useEffect(() => {
    const loggedIn = (event) => {
      setProfile(normalizeProfile(event.detail?.user || window.VfsAuth?.getUser?.() || EMPTY_PROFILE));
      setAuthenticated(true);
      loadProfile();
    };
    const loggedOut = () => { setAuthenticated(false); setProfile(EMPTY_PROFILE); setOpen(false); };
    const requestOpen = () => authenticated ? setOpen(true) : auth?.login();
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

  const activate = () => authenticated ? setOpen(true) : auth?.login();
  const save = async (changes) => {
    setBusy(true); setError('');
    try {
      const storedProfile = normalizeProfile(await api.update(changes));
      const oauthProfile = normalizeProfile(window.VfsAuth?.getUser?.() || EMPTY_PROFILE);
      setProfile({ ...storedProfile, picture: storedProfile.picture || oauthProfile.picture || profile.picture });
      setOpen(false);
    }
    catch (reason) { setError(reason.message || 'Salvataggio non riuscito'); }
    finally { setBusy(false); }
  };
  const logout = async () => { setBusy(true); await auth?.logout(); setBusy(false); };

  return <>
    <ProfileIcon authenticated={authenticated} profile={profile} busy={busy} onClick={activate} />
    {open && authenticated && <ProfileModal profile={profile} saving={busy} error={error} onClose={() => setOpen(false)} onSave={save} onLogout={logout} />}
  </>;
}
