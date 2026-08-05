# Local Keycloak realm

`siembiot-realm.json` is imported on container start by `local-stack.compose.yml`.

**Development only.** The realm, its client secret (`CHANGEME_LOCAL_ONLY`) and the
`analist@example.test` user password are documented placeholders for a throwaway
container. They are not credentials for any real system and must never be reused.

Keycloak rejects unknown top-level keys in a realm export, so this note lives here
rather than as a `_comment` field inside the JSON.

| Item | Value |
| --- | --- |
| Realm | `siembiot` |
| Client | `siembiot-web` (confidential, PKCE S256) |
| Redirect URI | `http://localhost:3000/api/v1/auth/callback` |
| Demo user | `analist` / `CHANGEME_LOCAL_ONLY` |
| Admin console | http://localhost:8080 (`admin`) |
