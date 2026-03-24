# OAuth2/OIDC Server (with 2FA)

Authorization server separato basato su `oidc-provider` con login username/password + TOTP oppure Google Sign-In.

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
cp .env.example .env
docker compose up --build
```

`docker-compose.yml` legge la configurazione dal file `./.env`, inclusi secret applicativi come `COOKIE_KEYS`, `ADMIN_PASSWORD`, `DEFAULT_CLIENT_SECRET`, `SETUP_TOKEN` e gli eventuali secret Google.

I path del compose restano relativi alla directory che contiene `docker-compose.yml`. Se vuoi pubblicare il provider sotto un subcontext, imposta `ISSUER` con il path finale e opzionalmente `BASE_PATH`. Esempio: `ISSUER=https://auth.example.com/oauth` e `BASE_PATH=/oauth`.

Se `DEFAULT_CLIENT_REDIRECT_URIS`, `DEFAULT_CLIENT_POST_LOGOUT_REDIRECT_URIS`, `GOOGLE_CALLBACK_PATH` e `GOOGLE_CALLBACK_URL` non sono valorizzate, l'app li deriva automaticamente da `ISSUER` e `BASE_PATH`.

Variabili specifiche del compose:

```bash
OAUTH_SERVER_IMAGE=docker.io/andpra70/oauth-server:latest
OAUTH_SERVER_RESTART=unless-stopped
OAUTH_SERVER_PORT=9000
OAUTH_SERVER_DATA_VOLUME=oauth-server-data
```

Il dato persistente di default usa un volume Docker nominato. In questo modo il contenuto seed copiato in `data/oauth` dentro l'immagine viene inizializzato correttamente nel volume al primo avvio, senza bind mount e senza problemi di permessi host.

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
- `GET /interaction/:uid/login/google`
- `GET /interaction/:uid/register/google`
- `POST /interaction/:uid/2fa`
- `POST /interaction/:uid/confirm`
- `POST /interaction/:uid/abort`
- `GET /auth/google/callback`

## Sequenza di autenticazione

Flow supportato: Authorization Code + PKCE `S256`, con login username/password, 2FA TOTP, Google Sign-In e consenso.

1. Recupera la configurazione OIDC:

```bash
curl http://localhost:9000/.well-known/openid-configuration
```

2. Apri `http://localhost:9000/app`, verifica `client_id=fileserver-web` e `redirect_uri=http://localhost:9000/app/callback`, poi premi `Accedi con OAuth`.

3. La pagina genera `state`, `code_verifier` e `code_challenge` PKCE in JavaScript e apre `/auth`.

4. Il server reindirizza il browser su `GET /interaction/:uid` e mostra il form di login.

5. Invia username e password a `POST /interaction/:uid/login`, oppure usa `Accedi con Google` o `Registrati con Google`.

6. Se fai login locale e l'utente ha 2FA attivo, il server mostra il form TOTP e devi inviare il codice a `POST /interaction/:uid/2fa`.

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

## Setup Google Login

Per abilitare il login con Google:

1. Apri Google Cloud Console e seleziona o crea un progetto.
2. Vai in `APIs & Services` -> `OAuth consent screen` e configura l'app.
3. Se l'app è in testing, aggiungi gli account Google che userai in `Test users`.
4. Vai in `APIs & Services` -> `Credentials` -> `Create Credentials` -> `OAuth client ID`.
5. Scegli `Web application`.
6. Aggiungi tra gli `Authorized redirect URI`:

```text
http://localhost:9000/auth/google/callback
```

Se usi un dominio o una porta diversa, il valore deve coincidere esattamente con `GOOGLE_CALLBACK_URL`.

7. Copia `Client ID` e `Client Secret` nel file `.env`.

Configura queste variabili:

```bash
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GOOGLE_CALLBACK_PATH=/auth/google/callback
GOOGLE_CALLBACK_URL=http://localhost:9000/auth/google/callback
```

Note operative:

- `GOOGLE_CALLBACK_PATH` è il path servito da Express.
- `GOOGLE_CALLBACK_URL` è l'URL assoluto inviato a Google e deve essere registrato nella console Google.
- Il login Google viene mostrato nella pagina `/interaction/:uid` solo se `GOOGLE_CLIENT_ID` e `GOOGLE_CLIENT_SECRET` sono valorizzati.

Avvio locale:

```bash
cp .env.example .env
npm run dev
```

Test del flow:

1. Apri `http://localhost:9000/app`.
2. Avvia il login OAuth come già previsto dalla demo.
3. Nella schermata di autenticazione usa `Accedi con Google` o `Registrati con Google`.
4. Completa il consenso Google.
5. Al ritorno sul server, il login OIDC locale viene completato automaticamente.

Al primo login Google, il server crea o aggiorna automaticamente un utente in `./data/oauth/db.json` con `auth_provider: "google"` e `google_subject`.

Esempio di record utente creato:

```json
{
  "id": "usr_xxxxx",
  "username": "mario.rossi-gmail.com",
  "email": "mario.rossi@gmail.com",
  "auth_provider": "google",
  "google_subject": "123456789012345678901",
  "totp_enabled": 0,
  "created_at": "2026-03-22T12:00:00.000Z",
  "updated_at": "2026-03-22T12:00:00.000Z"
}
```

Il login username/password resta invariato per gli utenti locali già presenti nel database.

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
