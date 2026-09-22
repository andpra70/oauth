import { useEffect, useState } from 'react';
import { CONFIG_KEYS } from '../admin-model.js';
const LABELS = { twoFactorEnabled: 'Autenticazione a due fattori', consentEnabled: 'Richiesta consenso', googleOAuthEnabled: 'Login Google', passkeyEnabled: 'Passkey', confirmLogout: 'Conferma logout' };
export function RuntimePage({ api, report }) {
  const [config, setConfig] = useState(null); useEffect(() => { api.config().then((result) => setConfig(result.config)).catch(report.error); }, []);
  if (!config) return <section className="panel"><p>Caricamento…</p></section>;
  const save = async () => { try { setConfig((await api.updateConfig(config)).config); report.notice('Configurazione aggiornata'); } catch (error) { report.error(error); } };
  return <section className="panel form"><h2>Configurazione runtime</h2>{CONFIG_KEYS.map((key) => <label className="toggle" key={key}><input type="checkbox" checked={Boolean(config[key])} onChange={(event) => setConfig((value) => ({ ...value, [key]: event.target.checked }))} /><span>{LABELS[key]}</span></label>)}<footer><button onClick={save}>Salva</button></footer></section>;
}
