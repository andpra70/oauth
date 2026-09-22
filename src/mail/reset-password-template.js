export function resetPasswordMessage({ username, resetUrl, expiresMinutes }) {
  const safeName = String(username || 'utente').replace(/[<>&"']/g, '');
  return {
    subject: 'Reimposta la password',
    text: `Ciao ${safeName},\n\nusa questo link entro ${expiresMinutes} minuti per scegliere una nuova password:\n${resetUrl}\n\nSe non hai richiesto il reset, ignora questa email.`,
    html: `<p>Ciao ${safeName},</p><p>usa il pulsante seguente entro ${expiresMinutes} minuti per scegliere una nuova password.</p><p><a href="${resetUrl}">Reimposta password</a></p><p>Se non hai richiesto il reset, ignora questa email.</p>`,
  };
}
