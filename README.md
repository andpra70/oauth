# OAuth2/OIDC Server (with optional 2FA)

Authorization server separato basato su `oidc-provider` con login username/password, 2FA TOTP opzionale e Google Sign-In.

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

Nel build Docker, il file `.env.prod` viene copiato dentro l'immagine come `.env`.
Questo significa che in deploy il server usa la configurazione applicativa di produzione già inclusa nell'immagine.

Il file `./.env` accanto a `docker-compose.yml` resta utile per le variabili del compose (es. immagine, porta host, volume), non per i secret applicativi runtime.

## Configurazione `.env`

L'app carica le variabili da `.env` tramite `dotenv`.
In locale usa tipicamente `.env` (copiato da `.env.example`), mentre nell'immagine Docker il `.env` deriva da `.env.prod`.

### Variabili applicative (runtime server)

| Variabile | Default | Significato |
| --- | --- | --- |
| `BASE_PATH` | derivato da pathname di `ISSUER` | Prefisso path del provider (es. `/oauth-server`). Se vuoto o `/`, il provider gira in root. |
| `PORT` | `9000` | Porta HTTP interna del processo Node.js. |
| `ISSUER` | `http://localhost:<PORT>` | Issuer OIDC pubblico. Deve riflettere URL reale (schema, host, porta, path). |
| `TRUST_PROXY` | `true` | Se `true`, Express si fida degli header del reverse proxy (`X-Forwarded-*`). Necessario dietro front-controller/reverse proxy HTTPS. |
| `COOKIE_KEYS` | nessuno | Chiavi cookie firmati, separate da virgola. Obbligatorie almeno 3 chiavi, altrimenti il server non parte. |
| `ALLOWED_ORIGINS` | `http://localhost:9000,http://localhost:8080,http://localhost` | Origin consentite per callback esterne (`callbackUrl`) e uso cross-origin del widget. |
| `TWO_FACTOR_ENABLED` | `true` | Abilita/disabilita la richiesta OTP TOTP durante login (stato iniziale runtime). |
| `CONSENT_ENABLED` | `true` | Mostra/nasconde schermata consenso OIDC (stato iniziale runtime). |
| `GOOGLE_OAUTH_ENABLED` | `true` | Abilita/disabilita pulsanti/flow Google (richiede anche client Google configurato). |
| `PASSKEY_ENABLED` | `false` | Abilita/disabilita login e onboarding passkey (WebAuthn). |
| `CONFIRM_LOGOUT` | `true` | Se `true`, mostra conferma logout prima di chiudere sessione OIDC. |
| `SETUP_TOKEN` | nessuno | Token richiesto dagli endpoint di setup protetti (es. QR 2FA admin). |

Note operative:

- `TWO_FACTOR_ENABLED`, `CONSENT_ENABLED`, `GOOGLE_OAUTH_ENABLED`, `PASSKEY_ENABLED`, `CONFIRM_LOGOUT` impostano lo stato iniziale; puoi modificarli a caldo via `POST /setup/runtime-config`.
- Se pubblichi sotto subpath, usa `ISSUER` completo (es. `https://auth.example.com/oauth`) e opzionalmente `BASE_PATH=/oauth`.

### Bootstrap admin

| Variabile | Default | Significato |
| --- | --- | --- |
| `ADMIN_USERNAME` | `admin` | Username dell'utente admin seed iniziale. |
| `ADMIN_PASSWORD` | nessuno | Password admin seed. Obbligatoria e lunga almeno 12 caratteri. |
| `ADMIN_EMAIL` | `admin@example.local` | Email iniziale admin. |

### Bootstrap client OAuth

| Variabile | Default | Significato |
| --- | --- | --- |
| `DEFAULT_CLIENT_ID` | `fileserver-web` | `client_id` del client creato/aggiornato all'avvio. |
| `DEFAULT_CLIENT_AUTH_METHOD` | `none` | Metodo auth token endpoint (`none` per client pubblico PKCE, altrimenti secret richiesto). |
| `DEFAULT_CLIENT_SECRET` | nessuno | Secret client. Obbligatorio (>=24 char) se `DEFAULT_CLIENT_AUTH_METHOD != none`. |

### Google OAuth (opzionale)

| Variabile | Default | Significato |
| --- | --- | --- |
| `GOOGLE_CLIENT_ID` | vuoto | OAuth Client ID Google. |
| `GOOGLE_CLIENT_SECRET` | vuoto | OAuth Client Secret Google. |
| `GOOGLE_CALLBACK_PATH` | derivata da `BASE_PATH` (`/auth/google/callback`) | Path di callback gestito dal server. |
| `GOOGLE_CALLBACK_URL` | derivata da `ISSUER` + `GOOGLE_CALLBACK_PATH` | URL assoluta callback da registrare lato Google Console. |

### Passkey/WebAuthn (opzionale)

| Variabile | Default | Significato |
| --- | --- | --- |
| `PASSKEY_RP_NAME` | `Local OAuth2 Server` | Nome relying party mostrato all'utente. |
| `PASSKEY_RP_ID` | hostname di `ISSUER` | Relying Party ID WebAuthn. |
| `PASSKEY_ORIGIN` | origin di `ISSUER` | Origin WebAuthn attesa durante challenge/verify. |

### Variabili Docker Compose

Queste variabili sono usate da `docker-compose.yml` (orchestrazione), non dal runtime Node.js:

| Variabile | Default | Significato |
| --- | --- | --- |
| `OAUTH_SERVER_CONTAINER_NAME` | `oauth-server` | Nome container. |
| `OAUTH_SERVER_IMAGE` | `docker.io/andpra70/oauth-server:latest` | Nome/tag immagine. |
| `OAUTH_SERVER_RESTART` | `unless-stopped` | Policy restart container. |
| `OAUTH_SERVER_PORT` | `9000` | Porta host esposta verso la porta interna del server. |
| `OAUTH_SERVER_DATA_VOLUME` | `oauth-server-data` | Nome volume Docker usato per persistenza `data/oauth`. |

Il dato persistente di default usa un volume Docker nominato. In questo modo il contenuto seed copiato in `data/oauth` dentro l'immagine viene inizializzato correttamente nel volume al primo avvio, senza bind mount e senza problemi di permessi host.

UI integrata nello stesso container:

```text
http://localhost:9000/app
```

AuthWidget React:

```text
http://localhost:9000/authWidget
```

Configurazione runtime AuthWidget (cross-origin/embeddable):

- via `window.__AUTH_WIDGET_CONFIG__` prima di caricare `app/assets/authWidget.js`
- oppure via query string su `/authWidget`:
  - `awIssuer`
  - `awClientId`
  - `awRedirectUri`
  - `awOrigin` (base per risolvere URI relative)
  - `awPostLogoutRedirectUri`
  - `awScope`
  - CTA flags: `awShowLogin`, `awShowLogout`, `awShowExpand`, `awShowEditProfile`

Esempio:

```text
http://localhost:9000/authWidget?awIssuer=http://localhost:9000&awClientId=fileserver-web&awOrigin=http://localhost:8080&awRedirectUri=/oauth/callback&awPostLogoutRedirectUri=/logged-out
```

Con `awShowExpand` il widget si espande/collassa cliccando la picture/avatar, mostra i campi profilo e abilita `Edit profile` (se non disabilitato). Il salvataggio usa `PATCH /me` con whitelist dei campi aggiornabili (`preferred_username`, `email`, `picture`).

## Integrazione Login Da Altre App Nello Stesso Stack Compose

Questa sezione descrive come integrare il provider OIDC da applicazioni montate nello stesso `docker-compose.yml`.

### 1) Concetto Chiave: URL Browser vs URL Interno Docker

Nel browser devi usare l'URL pubblico del provider (esempio `http://localhost:9000`).

Dentro la rete Docker tra container puoi usare il nome servizio (esempio `http://oauth-server:9000`).

Regola pratica:

- SPA che chiama `/auth` e `/token` dal browser: usa sempre URL pubblico.
- Backend/BFF che chiama `/token` server-to-server: può usare URL interno Docker.

### 2) Configura Il Client OIDC Della Tua App

Configura il client e le origin consentite nella configurazione runtime del provider (`.env` in locale, `.env.prod` per build Docker).
Le redirect URI vengono derivate automaticamente da `ISSUER` + `BASE_PATH` e, durante `/auth`, possono essere auto-registrate se coerenti con origin richiesta/consentite.

Esempio:

```bash
DEFAULT_CLIENT_ID=fileserver-web
DEFAULT_CLIENT_AUTH_METHOD=none
ALLOWED_ORIGINS=http://localhost:9000,http://localhost:8080,http://localhost
```

Se la redirect URI non è coerente con `ISSUER`/`BASE_PATH` o non passa i controlli di origin, vedrai errori su `/auth` o `/token`.

### 3) Esempio Compose Con App Esterna

```yaml
services:
  oauth-server:
    build: .
    ports:
      - "9000:9000"

  webapp:
    image: node:20-alpine
    working_dir: /app
    volumes:
      - ./my-webapp:/app
    command: ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "8080"]
    ports:
      - "8080:8080"
    environment:
      OIDC_ISSUER_PUBLIC: http://localhost:9000
      OIDC_ISSUER_INTERNAL: http://oauth-server:9000
```

### 4) Flusso Consigliato Per SPA

1. La SPA genera PKCE (`code_verifier` e `code_challenge`).
2. La SPA apre `GET /auth` su issuer pubblico (`http://localhost:9000/auth?...`).
3. Dopo callback, la SPA fa `POST /token` sempre verso issuer pubblico.
4. La SPA usa `access_token` su `GET /me`.

Per una SPA pura non usare `http://oauth-server:9000` nel codice frontend, perché il browser non risolve il nome servizio Docker.

### 5) Flusso Consigliato Per BFF (Backend For Frontend)

1. Frontend manda `code` al backend app.
2. Backend app scambia `code` su `/token`.
3. In questo passaggio backend puoi usare URL interno `http://oauth-server:9000/token`.
4. Il backend gestisce sessione/token e restituisce dati al frontend.

### 6) Callback Di Interaction Per App Esterne

Se vuoi orchestrare il login da una UI esterna, passa `callbackUrl` nella richiesta `/auth`.
L'origin di `callbackUrl` deve essere presente in `ALLOWED_ORIGINS`.

Esempio:

```text
http://localhost:9000/auth?client_id=fileserver-web&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Foauth%2Fcallback&response_type=code&scope=openid%20profile%20email%20offline_access&callbackUrl=http%3A%2F%2Flocalhost%3A8080%2Foauth%2Fstate&code_challenge=...&code_challenge_method=S256&state=...
```

### 7) Checklist Rapida Di Troubleshooting

1. `ISSUER` pubblico raggiungibile dal browser.
2. `BASE_PATH` allineato al contesto pubblico (es. `/oauth-server`).
3. `DEFAULT_CLIENT_AUTH_METHOD=none` per client PKCE pubblico senza secret.
4. Origin della tua app presente in `ALLOWED_ORIGINS`.
5. Dopo modifica della configurazione runtime (`.env` o `.env.prod`), riavvia il provider e ricostruisci l'immagine se usi Docker.
6. Verifica discovery: `curl http://localhost:9000/.well-known/openid-configuration`.

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
- `GET /authWidget`
- `GET /authWidget/callback`
- `GET /health`
- `GET /setup/2fa-qr/:username`
- `GET /setup/2fa-qr/:username.json`
- `GET /setup/runtime-config`
- `POST /setup/runtime-config`
- `POST /setup/passkeys/:username/options`
- `POST /setup/passkeys/:username/verify`

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
- `GET /interaction/:uid/register`
- `POST /interaction/:uid/register`
- `POST /interaction/:uid/login`
- `GET /interaction/:uid/login/google`
- `GET /interaction/:uid/register/google`
- `POST /interaction/:uid/passkey/onboarding/options`
- `POST /interaction/:uid/passkey/onboarding/verify`
- `GET /interaction/:uid/passkey/onboarding/continue`
- `POST /interaction/:uid/passkey/options`
- `POST /interaction/:uid/passkey/verify`
- `GET /interaction/:uid/passkey/continue`
- `POST /interaction/:uid/2fa`
- `POST /interaction/:uid/confirm`
- `POST /interaction/:uid/abort`
- `GET /auth/google/callback`

## Sequenza di autenticazione

Flow supportato: Authorization Code + PKCE `S256`, con login username/password, Google Sign-In, consenso e 2FA TOTP opzionale.

1. Recupera la configurazione OIDC:

```bash
curl http://localhost:9000/.well-known/openid-configuration
```

2. Apri `http://localhost:9000/app`, verifica `client_id=fileserver-web` e `redirect_uri=http://localhost:9000/app/callback`, poi premi `Accedi con OAuth`.

3. La pagina genera `state`, `code_verifier` e `code_challenge` PKCE in JavaScript e apre `/auth`.

4. Il server reindirizza il browser su `GET /interaction/:uid` e mostra il form di login.

5. Invia username e password a `POST /interaction/:uid/login`, oppure usa `Accedi con Google` o `Registrati con Google`.

6. Se `TWO_FACTOR_ENABLED=true` e l'utente ha 2FA attiva, il server richiede il codice TOTP. Se `TWO_FACTOR_ENABLED=false`, il login locale e il login Google completano il flow senza OTP.

7. Se `CONSENT_ENABLED=true` e il client richiede consenso, il server mostra `Authorize application` e devi confermare con `POST /interaction/:uid/confirm`. Se `CONSENT_ENABLED=false`, il consenso viene accettato automaticamente.

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

Se `TWO_FACTOR_ENABLED=true`, per bootstrap dell'utente admin puoi ottenere il QR code TOTP con la UI su `/app` oppure con:

```bash
curl "http://localhost:9000/setup/2fa-qr/admin?token=replace-with-bootstrap-token"
```

In alternativa puoi passare il token nell'header `x-setup-token`.

Per leggere lo stato runtime corrente:

```bash
curl "http://localhost:9000/setup/runtime-config?token=replace-with-bootstrap-token"
```

Per disabilitare la 2FA a caldo:

```bash
curl -X POST "http://localhost:9000/setup/runtime-config?token=replace-with-bootstrap-token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data 'twoFactorEnabled=false'
```

Per riabilitare la 2FA a caldo:

```bash
curl -X POST "http://localhost:9000/setup/runtime-config?token=replace-with-bootstrap-token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data 'twoFactorEnabled=true'
```

Per disabilitare il consenso `Authorize application` a caldo:

```bash
curl -X POST "http://localhost:9000/setup/runtime-config?token=replace-with-bootstrap-token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data 'consentEnabled=false'
```

Per riabilitare il consenso a caldo:

```bash
curl -X POST "http://localhost:9000/setup/runtime-config?token=replace-with-bootstrap-token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data 'consentEnabled=true'
```

Per disabilitare Google OAuth a caldo:

```bash
curl -X POST "http://localhost:9000/setup/runtime-config?token=replace-with-bootstrap-token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data 'googleOAuthEnabled=false'
```

Per riabilitare Google OAuth a caldo:

```bash
curl -X POST "http://localhost:9000/setup/runtime-config?token=replace-with-bootstrap-token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data 'googleOAuthEnabled=true'
```

Per abilitare passkey (WebAuthn) a caldo:

```bash
curl -X POST "http://localhost:9000/setup/runtime-config?token=replace-with-bootstrap-token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data 'passkeyEnabled=true'
```

Per disabilitare passkey a caldo:

```bash
curl -X POST "http://localhost:9000/setup/runtime-config?token=replace-with-bootstrap-token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data 'passkeyEnabled=false'
```

Per disabilitare la conferma su `session/end` e fare logout diretto:

```bash
curl -X POST "http://localhost:9000/setup/runtime-config?token=replace-with-bootstrap-token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data 'confirmLogout=false'
```

Per riabilitare la conferma logout:

```bash
curl -X POST "http://localhost:9000/setup/runtime-config?token=replace-with-bootstrap-token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data 'confirmLogout=true'
```

## Callback di interaction

Puoi passare `callbackUrl` e `backUrl` nella richiesta `/auth`. Entrambi devono appartenere a uno degli origin consentiti in `ALLOWED_ORIGINS`.

Esempio:

```text
http://localhost:9000/auth?client_id=fileserver-web&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fapp%2Fcallback&response_type=code&scope=openid%20profile%20email%20offline_access&callbackUrl=http%3A%2F%2Flocalhost%3A8080%2Foauth%2Fstate&code_challenge=...&code_challenge_method=S256&state=...
```

Esempio con `backUrl` (CTA “Back to application” nelle pagine login/register/onboarding):

```text
http://localhost:9000/auth?client_id=fileserver-web&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Foauth%2Fcallback&response_type=code&scope=openid%20profile%20email%20offline_access&backUrl=http%3A%2F%2Flocalhost%3A8080%2Flogin&code_challenge=...&code_challenge_method=S256&state=...
```

Quando il login è pronto, oppure quando il consenso viene approvato o negato, il browser viene rediretto a `callbackUrl` con questi parametri query:

- `stage`
- `status`
- `uid`
- `continueUrl`

`continueUrl` punta a una route del provider che completa davvero la interaction OIDC. Il flusso esterno può fare il proprio lavoro e poi redirigere il browser su `continueUrl`.

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

7. Copia `Client ID` e `Client Secret` nel file di configurazione runtime (`.env` in locale, `.env.prod` per Docker deploy).

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

## Setup Passkey (WebAuthn)

Variabili disponibili:

```bash
PASSKEY_ENABLED=false
PASSKEY_RP_NAME=Local OAuth2 Server
# PASSKEY_RP_ID defaults to ISSUER hostname
# PASSKEY_ORIGIN defaults to ISSUER origin
# PASSKEY_RP_ID=
# PASSKEY_ORIGIN=
```

Bootstrap registrazione passkey da UI:

1. Apri `http://localhost:9000/app`.
2. Inserisci `Setup token TOTP` e `Admin username`.
3. Premi `Registra Passkey`.
4. Completa la challenge WebAuthn nel browser/dispositivo.

Login passkey:

1. Apri il flow standard `/auth`.
2. Nella schermata `/interaction/:uid` usa `Accedi con Passkey`.
3. Se l'utente ha TOTP attivo e `TWO_FACTOR_ENABLED=true`, dopo passkey viene richiesto OTP.

API bootstrap passkey (alternativa alla UI):

1. `POST /setup/passkeys/:username/options?token=...`
2. Esegui `navigator.credentials.create()` con le opzioni ricevute.
3. `POST /setup/passkeys/:username/verify?token=...` con l'attestation response.

Nota: WebAuthn richiede origin sicuro (`https`) oppure `localhost` in sviluppo.

## Sicurezza implementata

- Password hashate con Argon2id
- 2FA TOTP opzionale (`speakeasy`)
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
- In Docker di default viene usato un volume nominato (`oauth-server-data`) montato in `/app/data/oauth`
- Le variabili runtime sono caricate da `.env` (nel build Docker viene generato da `.env.prod`)
- Il client seedato di default usa `client_id=fileserver-web`
- I redirect URI seedati di default includono `http://localhost:9000/app/callback` e `http://localhost:9000/authWidget/callback`
- Se `DEFAULT_CLIENT_AUTH_METHOD=none`, lo scambio code -> token usa PKCE senza `client_secret`
