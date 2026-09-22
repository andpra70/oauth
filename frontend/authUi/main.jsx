import React from 'react';
import { createRoot } from 'react-dom/client';
import { AuthUiApp } from './AuthUiApp.jsx';
import styles from './style.css?inline';

const style = document.createElement('style');
style.textContent = styles;
document.head.appendChild(style);
createRoot(document.getElementById('auth-ui-root')).render(<AuthUiApp />);
