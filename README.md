# File Uploader - Bezpieczne narzędzie webowe do zarządzania plikami

Bezpieczne narzędzie webowe do wysyłania i pobierania plików, napisane w Python 3.11 + Flask, chronione hasłem i sesją.

## Funkcjonalności

- 🔐 **Bezpieczne logowanie** - pojedynczy użytkownik "admin" z hasłem z ENV
- 📤 **Upload plików** - wielokrotny upload z drag & drop i progress bar
- 📋 **Lista plików** - sortowanie po dacie modyfikacji z akcjami
- 📥 **Pobieranie plików** - bezpieczne serwowanie z walidacją ścieżek
- 🗑️ **Usuwanie plików** - usuwanie pojedynczych plików
- 🛡️ **Bezpieczeństwo** - CSRF, path traversal protection, nagłówki bezpieczeństwa

## Wymagania

- Python 3.11+
- Linux/Unix system (dla uprawnień plików)

## Instalacja

### 1. Sklonuj repozytorium

```bash
git clone <repo-url>
cd download-upload
```

### 2. Zainstaluj zależności

```bash
pip install -r requirements.txt
```

### 3. Ustaw zmienne środowiskowe

```bash
export ADMIN_PASSWORD="twoje_bezpieczne_haslo"
export SECRET_KEY="twoj_tajny_klucz_sesji"
export UPLOAD_ROOT="./uploads"  # opcjonalne, domyślnie ./uploads
export MAX_CONTENT_LENGTH="512MB"  # opcjonalne, domyślnie 512MB
```

### 4. Uruchom aplikację

```bash
python app.py
```

Aplikacja będzie dostępna pod adresem `http://localhost:5000`

## Konfiguracja

### Zmienne środowiskowe

| Zmienna | Wymagana | Domyślna | Opis |
|---------|----------|----------|------|
| `ADMIN_PASSWORD` | ✅ | - | Hasło administratora |
| `SECRET_KEY` | ✅ | - | Tajny klucz dla sesji i CSRF |
| `UPLOAD_ROOT` | ❌ | `./uploads` | Katalog docelowy dla plików |
| `MAX_CONTENT_LENGTH` | ❌ | `512MB` | Maksymalny rozmiar pliku |

### Format rozmiaru pliku

Możliwe jednostki: `B`, `KB`, `MB`, `GB`, `TB`

Przykłady:
- `512MB` = 512 MB
- `2GB` = 2 GB
- `100KB` = 100 KB

## Wdrożenie produkcyjne

### 1. Gunicorn + Systemd

#### Instalacja Gunicorn

```bash
pip install gunicorn
```

#### Konfiguracja Gunicorn

Plik `deploy/gunicorn.conf.py` jest już przygotowany.

#### Service systemd

```bash
# Skopiuj plik service
sudo cp deploy/fileuploader.service /etc/systemd/system/

# Edytuj ścieżki w pliku service
sudo nano /etc/systemd/system/fileuploader.service

# Włącz i uruchom service
sudo systemctl daemon-reload
sudo systemctl enable fileuploader
sudo systemctl start fileuploader

# Sprawdź status
sudo systemctl status fileuploader
```

#### Logi

```bash
sudo journalctl -u fileuploader -f
```

### 2. Nginx

#### Instalacja

```bash
sudo apt update
sudo apt install nginx
```

#### Konfiguracja

Dodaj zawartość pliku `deploy/nginx-snippet.conf` do konfiguracji Nginx:

```nginx
server {
    listen 80;
    server_name twoja-domena.com;
    
    # Przekierowanie na HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name twoja-domena.com;
    
    # SSL certificates
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    # Include snippet
    include /etc/nginx/snippets/fileuploader.conf;
}
```

#### Test i restart

```bash
sudo nginx -t
sudo systemctl reload nginx
```

### 3. SSL/HTTPS

#### Certbot (Let's Encrypt)

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d twoja-domena.com
```

## Bezpieczeństwo

### Rotacja kluczy

**WAŻNE**: Regularnie zmieniaj `SECRET_KEY` i `ADMIN_PASSWORD`!

```bash
# Generuj nowy SECRET_KEY
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Zmień hasło admin
export ADMIN_PASSWORD="nowe_bezpieczne_haslo"
```

### Backup

Regularnie twórz kopie zapasowe katalogu `UPLOAD_ROOT`:

```bash
# Przykład backupu
tar -czf backup-$(date +%Y%m%d).tar.gz /path/to/uploads
```

### HTTPS

**WYMAGANE** w produkcji! Aplikacja używa `Secure` cookies i nagłówków bezpieczeństwa.

### Uprawnienia plików

- Katalog `UPLOAD_ROOT` ma uprawnienia `0o700` (tylko właściciel)
- Pliki tymczasowe `.part` są automatycznie usuwane
- Symlinki są blokowane

## Rozwiązywanie problemów

### Aplikacja nie startuje

```bash
# Sprawdź zmienne środowiskowe
echo $ADMIN_PASSWORD
echo $SECRET_KEY

# Sprawdź logi
python app.py
```

### Błąd 413 (za duży plik)

```bash
# Zwiększ limit w Nginx
client_max_body_size 512M;

# Zwiększ limit w aplikacji
export MAX_CONTENT_LENGTH="1GB"
```

### Problemy z sesją

```bash
# Wyczyść cookies w przeglądarce
# Sprawdź czy SECRET_KEY się nie zmienił
# Restart aplikacji
sudo systemctl restart fileuploader
```

### Problemy z uprawnieniami

```bash
# Sprawdź właściciela katalogu uploads
ls -la uploads/

# Popraw uprawnienia
chown www-data:www-data uploads/
chmod 700 uploads/
```

## Struktura plików

```
.
├── app.py                 # Główna aplikacja Flask
├── requirements.txt       # Zależności Python
├── templates/            # Szablony HTML
│   ├── base.html        # Bazowy szablon
│   ├── login.html       # Strona logowania
│   └── index.html       # Główna strona
├── static/              # Pliki statyczne
│   └── app.css         # Style CSS
├── deploy/              # Pliki wdrożenia
│   ├── gunicorn.conf.py # Konfiguracja Gunicorn
│   ├── fileuploader.service # Service systemd
│   └── nginx-snippet.conf   # Fragment konfiguracji Nginx
└── README.md            # Ten plik
```

## Testowanie

### Testy ręczne

1. **Brak zmiennych środowiskowych**
   ```bash
   unset ADMIN_PASSWORD
   python app.py  # Powinno zakończyć się błędem
   ```

2. **Autoryzacja**
   - Próba wejścia na `/` bez sesji → redirect do `/login`

3. **Upload**
   - Plik > limitu → błąd 413
   - Nieprawidłowa nazwa → błąd 400

4. **Path traversal**
   - Próba `../../etc/passwd` → błąd 400

5. **CSRF**
   - Nieprawidłowy token → błąd 400

### Testy bezpieczeństwa

```bash
# Test path traversal
curl "http://localhost:5000/download/../../../etc/passwd"

# Test CSRF
curl -X POST "http://localhost:5000/delete" \
  -d "path=test.txt" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

## Licencja

MIT License

## Autor hUps

File Uploader - Bezpieczne narzędzie do zarządzania plikami
