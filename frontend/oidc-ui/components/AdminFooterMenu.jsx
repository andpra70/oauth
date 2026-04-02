import { useMemo } from 'react';

export default function AdminFooterMenu({ basePath = '', setupToken = '', resolvePath, active = '' }) {
  const tokenQuery = useMemo(() => `?token=${encodeURIComponent(setupToken)}`, [setupToken]);
  const links = [
    { id: 'users', label: 'Utenti', href: resolvePath(basePath, `/setup/users${tokenQuery}`) },
    { id: 'sessions', label: 'Sessioni OIDC', href: resolvePath(basePath, `/setup/oidc-sessions${tokenQuery}`) },
    { id: 'config', label: 'Configurazione Redirect', href: resolvePath(basePath, `/setup/config${tokenQuery}`) },
    { id: 'app', label: 'Torna alla app', href: resolvePath(basePath, '/app') },
  ];

  return (
    <section className="panel admin-navbar">
      <nav className="navbar-menu" aria-label="Admin menu">
        {links.map((item) => (
          <a key={item.id} className={`button-link secondary ${item.id === active ? 'active' : ''}`.trim()} href={item.href}>
            {item.label}
          </a>
        ))}
      </nav>
    </section>
  );
}
