import React from 'react';
import { createRoot } from 'react-dom/client';
import styles from './profile-widget.css?inline';
import passwordResetStyles from './password-reset-widget.css?inline';
import { ProfileWidgetApp } from './ProfileWidgetApp.jsx';
import { createOidcClient } from './oidc-client.js';

const scriptUrl = document.currentScript?.src ? new URL(document.currentScript.src) : null;
const inferredBase = scriptUrl
  ? `${scriptUrl.origin}${scriptUrl.pathname.replace(/\/(?:profile-)?widget\.js$/, '')}`
  : window.location.origin;
const globalConfig = window.__PROFILE_WIDGET_CONFIG__ || {};
const auth = createOidcClient({
  issuer: globalConfig.issuer || globalConfig.apiBase || inferredBase,
  clientId: globalConfig.clientId || 'fileserver-web',
  scope: globalConfig.scope,
  redirectUri: globalConfig.redirectUri,
  postLogoutRedirectUri: globalConfig.postLogoutRedirectUri,
});
const ready = auth.initialize();

class ProfileWidgetElement extends HTMLElement {
  connectedCallback() {
    if (this.root) return;
    const shadow = this.attachShadow({ mode: 'open' });
    const style = document.createElement('style'); style.textContent = `${styles}\n${passwordResetStyles}`;
    const host = document.createElement('div'); shadow.append(style, host);
    const config = globalConfig;
    const apiBase = this.getAttribute('issuer') || this.getAttribute('api-base') || config.issuer || config.apiBase || inferredBase;
    const clientId = this.getAttribute('client-id') || config.clientId || 'fileserver-web';
    this.root = createRoot(host);
    this.root.render(<ProfileWidgetApp apiBase={apiBase} clientId={clientId} auth={auth} />);
  }
  disconnectedCallback() { this.root?.unmount(); this.root = null; }
}

if (!customElements.get('profile-widget')) customElements.define('profile-widget', ProfileWidgetElement);

function mount(options = {}) {
  let element = document.querySelector('profile-widget');
  if (!element) {
    element = document.createElement('profile-widget');
    if (options.issuer) element.setAttribute('issuer', options.issuer);
    else if (options.apiBase) element.setAttribute('api-base', options.apiBase);
    if (options.clientId) element.setAttribute('client-id', options.clientId);
    document.body.appendChild(element);
  }
  return element;
}

window.ProfileWidget = Object.freeze({
  ready: () => ready,
  login: auth.login,
  logout: auth.logout,
  refresh: auth.refresh,
  getAccessToken: auth.getAccessToken,
  authenticatedFetch: auth.authenticatedFetch,
  getSession: auth.getSession,
  getUser: auth.getUser,
  isAuthenticated: auth.isAuthenticated,
  mount,
  unmount: () => document.querySelector('profile-widget')?.remove(),
  open: () => window.dispatchEvent(new Event('profile-widget:open')),
  close: () => window.dispatchEvent(new Event('profile-widget:close')),
});

window.VfsAuth = window.ProfileWidget;

const config = globalConfig;
if (config.autoMount) {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => mount(config), { once: true });
  else mount(config);
}
