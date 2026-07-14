# BUEC Missing Documents Portal

Portal full-stack pentru **British University Educational Consultancy**, construit pentru solicitarea și primirea securizată a documentelor lipsă de la studenți.

Aplicația folosește Django 5.2 LTS, PostgreSQL în producție, Redis pentru rate limiting distribuit, SMTP pentru email, tokenuri single-use și criptare Fernet/MultiFernet pentru fișierele stocate.

## Funcționalități incluse

- rută de administrare configurabilă și nepublicată, de exemplu `/admin-buec-7c91e4f2/`;
- login restricționat implicit la superuser;
- structură pregătită pentru mai mulți utilizatori: fiecare cerere salvează `requested_by` și toate acțiunile importante intră în audit log;
- modal pentru cereri noi cu:
  - student name;
  - student email;
  - Passport, Share code, Proof of address, CV sau Other;
  - descriere opțională pentru Other;
- email HTML + text, cu design BUEC și buton galben;
- link unic, hash-uit în baza de date, expirabil și single-use;
- upload pentru JPG, JPEG, PNG, WEBP, HEIC, HEIF, TIFF, PDF, DOCX, ODT, RTF și TXT;
- validare server-side a extensiei și structurii fișierului;
- blocarea HTML, SVG, JavaScript, executabile, arhive generale și documente Office cu macro-uri;
- scanare ClamAV opțională, cu mod fail-closed;
- criptarea fișierului înainte de stocare;
- fișierele nu sunt servite dintr-un director public;
- download doar după autentificare și doar ca attachment;
- email de confirmare după upload;
- linkul devine inactiv imediat după upload;
- tabel cu search în timp real, status filters și pagination;
- statusuri: Pending, Action required, Completed, Cancelled, Expired;
- acțiuni Resend, Cancel, Download și Complete;
- comandă de expirare a linkurilor;
- comandă de ștergere a fișierelor după perioada de retenție.

## Pornire rapidă cu Docker

### 1. Creează configurația

```bash
cp .env.example .env
```

Generează un secret Django și o cheie de criptare. Comenzile de mai jos pot fi rulate într-un mediu Python în care sunt instalate dependențele proiectului:

```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Completează în `.env` cel puțin:

```dotenv
DJANGO_DEBUG=false
DJANGO_SECRET_KEY=<secretul-generat>
DJANGO_ALLOWED_HOSTS=documents.example.com
DJANGO_CSRF_TRUSTED_ORIGINS=https://documents.example.com
PUBLIC_BASE_URL=https://documents.example.com
ADMIN_PORTAL_SLUG=admin-buec-<sir-lung-aleator>
FILE_ENCRYPTION_KEYS=<cheia-fernet>
POSTGRES_PASSWORD=<parola-puternica-url-safe>
SECURE_SSL_REDIRECT=true
SECURE_HSTS_SECONDS=31536000
```

Configurează și datele SMTP. În producție nu păstra backend-ul de email pe console.

### 2. Pornește serviciile

```bash
docker compose up -d --build
```

### 3. Creează contul tău de superuser

```bash
docker compose exec web python manage.py createsuperuser
```

Portalul va fi disponibil la:

```text
https://documents.example.com/<ADMIN_PORTAL_SLUG>/
```

Nu există link public către această rută.

## Rulare locală fără Docker

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

În development, dacă `DATABASE_URL` este gol, se folosește SQLite. Emailurile sunt afișate în terminal când este activ backend-ul console.

## Configurarea emailului

Exemplu SMTP cu TLS:

```dotenv
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
DEFAULT_FROM_EMAIL=BUEC Document Team <documents@your-domain.co.uk>
EMAIL_REPLY_TO=info@your-domain.co.uk
EMAIL_HOST=smtp.provider.example
EMAIL_PORT=587
EMAIL_HOST_USER=documents@your-domain.co.uk
EMAIL_HOST_PASSWORD=<parola-sau-api-key>
EMAIL_USE_TLS=true
EMAIL_USE_SSL=false
```

Pentru livrare bună, configurează SPF, DKIM și DMARC pe domeniul expeditorului.

## Fluxul cererii

1. Superuser-ul creează cererea din modal.
2. Aplicația generează un token aleator. În baza de date se salvează numai SHA-256-ul tokenului.
3. Studentul primește emailul cu linkul personal.
4. Studentul deschide linkul și încarcă documentul.
5. Serverul reverifică tokenul și statusul într-o tranzacție cu row lock.
6. Fișierul este validat, scanat opțional, criptat și stocat cu nume aleator.
7. Tokenul este invalidat în aceeași tranzacție.
8. Statusul devine `Action required`.
9. Studentul primește confirmarea, iar accesarea din nou a linkului afișează `Nothing to do here`.
10. Utilizatorul portalului descarcă documentul și marchează cererea `Completed`.

## Securitate implementată

- autoescaping Django pentru datele studentului;
- Content Security Policy fără inline scripts și fără resurse externe;
- CSRF pe toate formularele POST;
- cookie-uri de sesiune HttpOnly, SameSite Strict și Secure în producție;
- Argon2 ca primul password hasher;
- rate limiting pentru login, creare cereri, resend, upload și download;
- Redis partajat pentru rate limiting în deployment multi-worker;
- generic login errors, fără user enumeration explicit;
- tokenuri cu entropie mare, hash-uite și single-use;
- expirare configurabilă;
- referrer policy `no-referrer` pentru a nu trimite tokenul către requesturile de assets;
- Gunicorn nu scrie access log implicit, pentru a evita logarea tokenurilor din URL;
- exemplul Nginx dezactivează access log pe `/upload/`;
- URL-urile din email sunt construite din `PUBLIC_BASE_URL`, nu din headerul Host;
- validare de nume, extensie, semnătură/structură și mărime;
- protecție împotriva zip bombs în DOCX/ODT;
- blocarea macro-urilor Office;
- criptare at-rest cu MultiFernet;
- storage privat cu permisiuni restrictive;
- documentele sunt livrate ca `application/octet-stream`, `attachment`, cu `nosniff`;
- audit pentru creare, email, upload, download, completare, anulare și purge;
- IP-urile sunt salvate numai sub formă de HMAC hash.

Nicio aplicație nu poate fi declarată în mod absolut „XSS-proof” sau invulnerabilă. Acest proiect aplică măsuri defensive solide, dar înainte de folosirea cu date reale trebuie făcut un review de deployment, actualizate constant dependențele și rulat un security test extern.

## ClamAV opțional

Poți conecta aplicația la un daemon `clamd` prin TCP sau Unix socket:

```dotenv
CLAMAV_HOST=clamav
CLAMAV_PORT=3310
CLAMAV_UNIX_SOCKET=
CLAMAV_TIMEOUT=20
REQUIRE_MALWARE_SCAN=true
```

Cu `REQUIRE_MALWARE_SCAN=true`, uploadurile sunt refuzate dacă scannerul nu poate fi contactat. În development, scanarea rămâne opțională.

## Reverse proxy și IP real

Folosește [`deploy/nginx.conf.example`](deploy/nginx.conf.example). După ce proxy-ul de încredere suprascrie `X-Real-IP`, setează:

```dotenv
TRUST_X_REAL_IP=true
```

Nu activa această opțiune dacă aplicația poate fi accesată direct din internet, deoarece clientul ar putea falsifica headerul.

## Retenție și expirare

Expiră cererile vechi, recomandat zilnic:

```bash
python manage.py expire_document_requests
```

Vezi ce documente completate ar fi șterse după 90 de zile:

```bash
python manage.py purge_completed_documents --dry-run
```

Șterge efectiv fișierele criptate:

```bash
python manage.py purge_completed_documents --older-than-days 90
```

Metadatele cererii și audit log-ul rămân, dar fișierul, hash-ul și numele original sunt eliminate.

## Rotirea cheii de criptare

`FILE_ENCRYPTION_KEYS` acceptă chei separate prin virgulă. Prima cheie criptează fișierele noi, iar toate cheile pot decripta fișierele existente.

Exemplu de rotație:

```dotenv
FILE_ENCRYPTION_KEYS=<cheia-noua>,<cheia-veche>
```

Nu elimina cheia veche până când documentele criptate cu ea nu au fost recriptate sau eliminate prin politica de retenție.

## Mai mulți utilizatori

Implicit:

```dotenv
PORTAL_SUPERUSER_ONLY=true
```

Pentru a permite și conturi `is_staff`:

```dotenv
PORTAL_SUPERUSER_ONLY=false
```

Fiecare cerere păstrează utilizatorul creator, iar acțiunile administrative păstrează actorul în audit. Crearea și politica rolurilor trebuie administrate separat înainte de activarea acestei opțiuni.

## Teste

```bash
python manage.py test documents.tests --verbosity 2
```

Suita acoperă:

- protecția portalului;
- creare + email;
- escaping pentru input HTML malițios;
- upload valid și criptare;
- link single-use;
- respingerea extensiilor periculoase;
- expirarea linkului;
- download autorizat;
- search și filtrul `Action`.

## Verificare înainte de producție

```bash
python manage.py check --deploy
python manage.py collectstatic --noinput
```

Checklist minim:

- HTTPS valid și redirect HTTP -> HTTPS;
- secret Django și chei Fernet păstrate într-un secret manager;
- PostgreSQL și Redis cu autentificare/rețea privată;
- backup criptat al bazei de date;
- volumul `private_uploads` criptat și inclus în politica de backup doar dacă este necesar;
- access logs dezactivate/redactate pentru `/upload/` și la load balancer/CDN;
- ClamAV fail-closed pentru documente reale;
- SMTP cu SPF/DKIM/DMARC;
- cron pentru expirare și retenție;
- monitorizare pentru erori SMTP, ClamAV, storage și rate limiting;
- actualizări periodice ale pachetelor și imaginii Docker;
- penetration test înainte de procesarea datelor reale.

## Structură principală

```text
config/                  Django settings și URL routing
documents/models.py      Requests + audit log
documents/views_portal.py
                         Login, dashboard, search, filters și acțiuni admin
documents/views_public.py
                         Linkul studentului și uploadul single-use
documents/validators.py  Validarea fișierelor
documents/malware.py     Integrarea opțională ClamAV
documents/crypto.py      Token hashing și criptarea fișierelor
documents/services.py    Emailurile HTML/text și audit helpers
documents/templates/     Portal, upload și email templates
documents/static/        CSS și JavaScript fără dependențe frontend
deploy/                  Exemplu Nginx
docker-compose.yml       Web, PostgreSQL și Redis
```
