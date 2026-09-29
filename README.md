# Site Poliția Română

Copie separată pentru serverul Discord 1528758226252988488. Gradele Poliției sunt incluse în `server.js`. Rapoartele și imaginile sunt păstrate în bucketul privat Backblaze B2; browserul încarcă imaginile direct în B2 folosind URL-uri semnate. Linkurile de vizualizare redirecționează către B2 și expiră după 15 minute. Pentru mesajele Discord cu poze ale raziilor/antrenamentelor, serverul citește imaginile din B2 pentru a le atașa pe Discord.

## Publicare

1. Încarcă fișierele din această arhivă în rădăcina unui repository GitHub nou, privat.
2. Creează în Render un serviciu **Web Service** din acel repository. Build command: `npm install`. Start command: `npm start`.
3. În Render > Environment completează valorile din `RENDER_ENV.example`. `SESSION_SECRET` trebuie să aibă minimum 32 de caractere aleatorii. Valorile secrete se pun numai în Render, niciodată în GitHub.
4. După obținerea URL-ului Render, setează `DISCORD_REDIRECT_URI` la `https://NUME.onrender.com/auth/discord/callback` și adaugă exact aceeași adresă în Discord Developer Portal > OAuth2 > Redirects. Setează `B2_DIRECT_UPLOAD_ORIGIN` la `https://NUME.onrender.com` fără slash final și `CALLSIGN_DASHBOARD_URL` la `https://NUME.onrender.com/dashboard`.
5. Pentru upload direct, bucketul privat trebuie să aibă CORS cu originea exactă din `B2_DIRECT_UPLOAD_ORIGIN`, metoda `PUT`, și antetele `Content-Type` și `Cache-Control`. Serverul încearcă să configureze CORS automat la pornire; o cheie restrânsă la un bucket poate să nu aibă permisiunea necesară. Dacă apare eroare CORS în browser, configurează regula din Backblaze > Buckets > mairushro > CORS Rules.
6. `supabase_setup_FIXED_NO_REPORTS.sql` este inclus pentru referință. Dacă SQL-ul a fost deja rulat în proiectul Supabase nou, nu trebuie rulat iar.

Canalele Discord de anunțuri, razii și antrenamente sunt opționale până le configurezi. Nu folosiți cheile aplicației DIICOT în acest proiect.
