# MAI Rush Politie - Cloudflare Workers migration

Acest pachet este pregatit pentru migrare de la Render la Cloudflare Workers.

## Deploy
1. Urca proiectul intr-un repository GitHub privat.
2. In Cloudflare: Workers & Pages > Create > Import a repository.
3. Selecteaza repository-ul.
4. Build command: `npm install`
5. Deploy command: `npx wrangler deploy`
6. Root directory: `/`
7. Adauga Variables/Secrets conform `CLOUDFLARE_ENV.example`.
8. Pentru primul test foloseste URL-ul `*.workers.dev`.
9. Actualizeaza DISCORD_REDIRECT_URI, CALLSIGN_DASHBOARD_URL si B2_DIRECT_UPLOAD_ORIGIN cu URL-ul real.
10. In Discord Developer Portal adauga acelasi OAuth redirect URI.
11. Dupa testare, conecteaza domeniul final si schimba cele 3 URL-uri la domeniul final.

Nu pune valori reale pentru token-uri/chei in GitHub.
