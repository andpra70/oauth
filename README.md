# OAuth2/OIDC Server (with 2FA)

Authorization server separato basato su `oidc-provider` con login username/password + TOTP.

## Avvio locale

```bash
cp .env.example .env
npm install
./localrun.sh
```

In alternativa:

```bash
npm run dev
```

## Avvio con Docker

```bash
docker compose up --build
```

Script disponibili:

```bash
./deploy.sh
./run.sh
./publish.sh
```

## Sicurezza implementata

- Password hashate con Argon2id
- 2FA TOTP (`speakeasy`)
- PKCE `S256` obbligatorio
- Helmet headers
- Rate limit login/2FA
- Cookie firmati e `httpOnly`

## Note

- Discovery: `/.well-known/openid-configuration`
- Health check: `/health`
- DB SQLite persistente in `./data/oauth/oauth.db`
- In Docker il volume host `./data/oauth` viene montato in `/app/data`
- Le variabili runtime sono caricate da `.env`
