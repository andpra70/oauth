# OAuth2/OIDC Server (with 2FA)

Authorization server separato basato su `oidc-provider` con login username/password + TOTP.

## Avvio locale

```bash
cp .env.example .env
npm install
./localrun.sh
```

`ADMIN_PASSWORD` deve essere valorizzata e lunga almeno 12 caratteri.

In alternativa:

```bash
npm run dev
```

## Avvio con Docker

```bash
docker compose up --build
```

UI integrata nello stesso container:

```text
http://localhost:9000/app
```

Example minimale:

```text
http://localhost:9000/example
```

Script disponibili:

```bash
./deploy.sh
./run.sh
./publish.sh
```

## Endpoint

Endpoint applicativi:

- `GET /`
- `GET /app`
- `GET /app/callback`
- `GET /example`
- `GET /example/callback`
- `GET /health`
- `GET /setup/2fa-qr/:username`
- `GET /setup/2fa-qr/:username.json`

Endpoint OIDC/OAuth2:

- `GET /.well-known/openid-configuration`
- `GET /auth`
- `POST /token`
- `GET /me`
- `GET /jwks`
- `POST /token/introspection`
- `POST /token/revocation`
- `GET /session/end`

Endpoint interni di interaction usati dal login browser-based:

- `GET /interaction/:uid`
- `POST /interaction/:uid/login`
- `POST /interaction/:uid/2fa`
- `POST /interaction/:uid/confirm`
- `POST /interaction/:uid/abort`

## Sequenza di autenticazione

Flow supportato: Authorization Code + PKCE `S256`, con login username/password, 2FA TOTP e consenso.

1. Recupera la configurazione OIDC:

```bash
curl http://localhost:9000/.well-known/openid-configuration
```

2. Apri `http://localhost:9000/app`, verifica `client_id=fileserver-web` e `redirect_uri=http://localhost:9000/app/callback`, poi premi `Accedi con OAuth`.

3. La pagina genera `state`, `code_verifier` e `code_challenge` PKCE in JavaScript e apre `/auth`.

4. Il server reindirizza il browser su `GET /interaction/:uid` e mostra il form di login.

5. Invia username e password a `POST /interaction/:uid/login`.

6. Se l'utente ha 2FA attivo, il server mostra il form TOTP e devi inviare il codice a `POST /interaction/:uid/2fa`.

7. Se richiesto, il server mostra il consenso e devi confermare con `POST /interaction/:uid/confirm`.

8. Al termine del login il browser viene reindirizzato a `/app/callback` con il parametro `code`.

9. La pagina JavaScript esegue automaticamente `POST /token`, passando `grant_type=authorization_code`, `code`, `redirect_uri` e `code_verifier`, poi richiama `GET /me`.

10. Se ti serve il flow manuale o un client esterno, costruisci la richiesta verso `/auth` con `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge` e `code_challenge_method=S256`.

Esempio:

```text
http://localhost:9000/auth?client_id=fileserver-web&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fapp%2Fcallback&response_type=code&scope=openid%20profile%20email%20offline_access&code_challenge=...&code_challenge_method=S256&state=...
```

11. Scambia il codice su `POST /token`, passando `grant_type=authorization_code`, `code`, `redirect_uri` e `code_verifier`.

Esempio:

```bash
curl -X POST http://localhost:9000/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data 'grant_type=authorization_code&client_id=fileserver-web&code=AUTH_CODE&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fapp%2Fcallback&code_verifier=CODE_VERIFIER'
```

12. Usa l'`access_token` per leggere le claims utente da `GET /me`.

Esempio:

```bash
curl http://localhost:9000/me \
  -H 'authorization: Bearer ACCESS_TOKEN'
```

## Setup 2FA

Per bootstrap dell'utente admin puoi ottenere il QR code TOTP con la UI su `/app` oppure con:

```bash
curl "http://localhost:9000/setup/2fa-qr/admin?token=replace-with-bootstrap-token"
```

In alternativa puoi passare il token nell'header `x-setup-token`.

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
- Demo UI integrata: `/app`
- DB JSON persistente in `./data/oauth/db.json`
- Stato persistente di `oidc-provider` in `./data/oauth/oidc-store.json`
- In Docker il volume host `./data/oauth` viene montato in `/app/data`
- Le variabili runtime sono caricate da `.env`
- Il client seedato di default usa `client_id=fileserver-web`
- Il redirect URI seedato di default è `http://localhost:9000/app/callback`
- Se `DEFAULT_CLIENT_AUTH_METHOD=none`, lo scambio code -> token usa PKCE senza `client_secret`
