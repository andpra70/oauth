import nodemailer from 'nodemailer';
import { getMailConfig } from './mail-model.js';
import { resetPasswordMessage } from './reset-password-template.js';

let transport;
export function isMailEnabled() { const config = getMailConfig(); return config.enabled && Boolean(config.host); }
function getTransport() {
  const config = getMailConfig();
  if (!transport) transport = nodemailer.createTransport({ host: config.host, port: config.port, secure: config.secure, auth: config.user ? { user: config.user, pass: config.password } : undefined });
  return transport;
}
export async function sendPasswordResetMail({ email, username, resetUrl }) {
  const config = getMailConfig();
  if (!isMailEnabled()) throw new Error('Mail service is disabled');
  const message = resetPasswordMessage({ username, resetUrl, expiresMinutes: Math.ceil(config.tokenTtlSeconds / 60) });
  await getTransport().sendMail({ from: config.from, to: email, ...message });
}
