import React from 'react';
import { createRoot } from 'react-dom/client';
import { AdminApp } from './AdminApp.jsx';
import styles from './style.css?inline';
const style = document.createElement('style'); style.textContent = styles; document.head.appendChild(style);
createRoot(document.getElementById('admin-root')).render(<AdminApp />);
