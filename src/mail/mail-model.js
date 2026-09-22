export function getMailConfig() {
  return {
    enabled: String(process.env.MAIL_ENABLED || 'false').toLowerCase() === 'true',
    host: process.env.SMTP_HOST || '',
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE || 'false').toLowerCase() === 'true',
    user: process.env.SMTP_USER || '',
    password: process.env.SMTP_PASSWORD || '',
    from: process.env.MAIL_FROM || 'no-reply@localhost',
    resetPublicUrl: process.env.PASSWORD_RESET_PUBLIC_URL || '',
    tokenTtlSeconds: Math.max(300, Number(process.env.PASSWORD_RESET_TOKEN_TTL_SECONDS || 900)),
  };
}
