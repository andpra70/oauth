import React from 'react';
import { createRoot } from 'react-dom/client';
import styles from './profile-widget.css?inline';
import { ProfileWidgetApp } from './ProfileWidgetApp.jsx';

const scriptUrl = document.currentScript?.src ? new URL(document.currentScript.src) : null;
const inferredBase = scriptUrl ? scriptUrl.pathname.replace(/\/profile-widget\.js$/, '') : '/auth';

class ProfileWidgetElement extends HTMLElement {
  connectedCallback() {
    if (this.root) return;
    const shadow = this.attachShadow({ mode: 'open' });
    const style = document.createElement('style'); style.textContent = styles;
    const host = document.createElement('div'); shadow.append(style, host);
    const config = window.__PROFILE_WIDGET_CONFIG__ || {};
    const apiBase = this.getAttribute('api-base') || config.apiBase || inferredBase || '/auth';
    const authWidgetUrl = this.getAttribute('auth-widget-url') || config.authWidgetUrl || `${apiBase.replace(/\/+$/, '')}/widget.js`;
    this.root = createRoot(host);
    this.root.render(<ProfileWidgetApp apiBase={apiBase} authWidgetUrl={authWidgetUrl} />);
  }
  disconnectedCallback() { this.root?.unmount(); this.root = null; }
}

if (!customElements.get('profile-widget')) customElements.define('profile-widget', ProfileWidgetElement);

function mount(options = {}) {
  let element = document.querySelector('profile-widget');
  if (!element) {
    element = document.createElement('profile-widget');
    if (options.apiBase) element.setAttribute('api-base', options.apiBase);
    if (options.authWidgetUrl) element.setAttribute('auth-widget-url', options.authWidgetUrl);
    document.body.appendChild(element);
  }
  return element;
}

window.ProfileWidget = Object.freeze({
  mount,
  unmount: () => document.querySelector('profile-widget')?.remove(),
  open: () => window.dispatchEvent(new Event('profile-widget:open')),
  close: () => window.dispatchEvent(new Event('profile-widget:close')),
});

const config = window.__PROFILE_WIDGET_CONFIG__ || {};
if (config.autoMount) {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => mount(config), { once: true });
  else mount(config);
}
