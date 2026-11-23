# Hofplaner

Web-App für den Hof mit Anmeldung, Admin- und Benutzerrolle und gemeinsamen Daten.

- `public/index.html` ist die App.
- `src/index.js` ist der Server (Cloudflare Worker) mit Anmeldung und Datenbank (D1).
- `wrangler.jsonc` ist die Konfiguration. Die Datenbank `hofplaner-db` legt Cloudflare beim ersten Deploy selbst an.

## Einmalige Einrichtung

1. In Cloudflare beim Projekt unter Einstellungen, Variablen und Geheimnisse ein **Secret** namens `SETUP_CODE` anlegen (beliebiger Code als Wert).
2. Die Seite öffnen und den ersten Admin anlegen (Einrichtungscode, Benutzername, Passwort).
3. Unter „Benutzer“ weitere Benutzer anlegen.
