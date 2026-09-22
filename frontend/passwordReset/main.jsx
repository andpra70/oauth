import React from 'react'; import { createRoot } from 'react-dom/client'; import { ResetPasswordApp } from './ResetPasswordApp.jsx'; import styles from './style.css?inline';
const style = document.createElement('style'); style.textContent = styles; document.head.appendChild(style); createRoot(document.getElementById('reset-password-root')).render(<ResetPasswordApp />);
