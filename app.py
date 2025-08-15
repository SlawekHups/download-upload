#!/usr/bin/env python3
"""
Prosty serwer HTTP do upload/download plików - bez zewnętrznych zależności
Używa tylko standardowych bibliotek Pythona 3
"""

import os
import sys
import json
import base64
import hashlib
import hmac
import time
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# Konfiguracja z ENV
def get_required_env(name, default=None):
    value = os.environ.get(name, default)
    if value is None:
        print(f"BŁĄD: Wymagana zmienna środowiskowa {name} nie jest ustawiona", file=sys.stderr)
        sys.exit(1)
    return value

def parse_size(size_str):
    """Konwertuje string rozmiaru (np. '512MB') na bajty"""
    size_str = size_str.upper()
    if size_str.endswith('KB'):
        return int(size_str[:-2]) * 1024
    elif size_str.endswith('MB'):
        return int(size_str[:-2]) * 1024 * 1024
    elif size_str.endswith('GB'):
        return int(size_str[:-2]) * 1024 * 1024 * 1024
    else:
        return int(size_str)

# Konfiguracja
ADMIN_PASSWORD = get_required_env('ADMIN_PASSWORD')
SECRET_KEY = get_required_env('SECRET_KEY')
UPLOAD_ROOT = os.environ.get('UPLOAD_ROOT', './uploads')
MAX_CONTENT_LENGTH = parse_size(os.environ.get('MAX_CONTENT_LENGTH', '512MB'))

# Tworzenie katalogu upload
upload_path = Path(UPLOAD_ROOT)
upload_path.mkdir(mode=0o700, exist_ok=True)

# Sesje użytkowników (w pamięci)
sessions = {}

def generate_csrf_token():
    """Generuje token CSRF"""
    timestamp = str(int(time.time()))
    message = f"{timestamp}:{SECRET_KEY}"
    signature = hmac.new(SECRET_KEY.encode(), message.encode(), hashlib.sha256).hexdigest()
    return f"{timestamp}.{signature}"

def verify_csrf_token(token):
    """Weryfikuje token CSRF"""
    try:
        timestamp_str, signature = token.split('.', 1)
        timestamp = int(timestamp_str)
        
        # Token ważny przez 1 godzinę
        if time.time() - timestamp > 3600:
            return False
            
        message = f"{timestamp}:{SECRET_KEY}"
        expected_signature = hmac.new(SECRET_KEY.encode(), message.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected_signature)
    except:
        return False

def safe_path(rel_path):
    """Bezpiecznie sprawdza ścieżkę"""
    if not rel_path or '..' in rel_path:
        return None
    
    abs_path = (upload_path / rel_path).resolve()
    upload_abs = upload_path.resolve()
    
    # Sprawdź czy ścieżka jest w UPLOAD_ROOT
    if not str(abs_path).startswith(str(upload_abs) + os.sep):
        return None
    
    # Sprawdź czy to nie jest symlink
    if abs_path.is_symlink():
        return None
        
    return abs_path

def create_session():
    """Tworzy nową sesję"""
    session_id = base64.b64encode(os.urandom(32)).decode()
    sessions[session_id] = {
        'user': 'admin',
        'csrf_token': generate_csrf_token(),
        'created': time.time()
    }
    return session_id

def get_session(cookie_header):
    """Pobiera sesję z cookie"""
    if not cookie_header:
        return None
    
    for cookie in cookie_header.split(';'):
        if 'session=' in cookie:
            session_id = cookie.split('=')[1].strip()
            if session_id in sessions:
                session = sessions[session_id]
                # Sesja ważna przez 24 godziny
                if time.time() - session['created'] < 86400:
                    return session
                else:
                    del sessions[session_id]
    return None

def set_cookie_headers(session_id):
    """Ustawia nagłówki cookie"""
    return [
        ('Set-Cookie', f'session={session_id}; HttpOnly; Secure; SameSite=Strict; Path=/'),
    ]

class FileUploadHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Obsługuje żądania GET"""
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        
        # Sprawdź sesję
        session = get_session(self.headers.get('Cookie'))
        
        if path == '/login':
            if session:
                self.send_response(302)
                self.send_header('Location', '/')
                self.end_headers()
                return
            self.send_login_page()
            return
            
        if path == '/':
            if not session:
                self.send_response(302)
                self.send_header('Location', '/login')
                self.end_headers()
                return
            self.send_main_page(session)
            return
            
        if path.startswith('/download/'):
            if not session:
                self.send_response(401)
                self.end_headers()
                return
            rel_path = path[10:]  # Usuń '/download/'
            self.send_file(rel_path)
            return
            
        # 404 dla nieznanych ścieżek
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b'404 Not Found')
    
    def do_POST(self):
        """Obsługuje żądania POST"""
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        
        # Pobierz dane POST
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > MAX_CONTENT_LENGTH:
            self.send_response(413)
            self.end_headers()
            self.wfile.write(b'File too large')
            return
            
        post_data = self.rfile.read(content_length)
        
        if path == '/login':
            self.handle_login(post_data)
            return
            
        if path == '/upload':
            session = get_session(self.headers.get('Cookie'))
            if not session:
                self.send_response(401)
                self.end_headers()
                return
            self.handle_upload(post_data, session)
            return
            
        if path == '/delete':
            session = get_session(self.headers.get('Cookie'))
            if not session:
                self.send_response(401)
                self.end_headers()
                return
            self.handle_delete(post_data, session)
            return
            
        if path == '/logout':
            session = get_session(self.headers.get('Cookie'))
            if session:
                # Usuń sesję
                for session_id, sess in list(sessions.items()):
                    if sess == session:
                        del sessions[session_id]
                        break
            self.send_response(302)
            self.send_header('Location', '/login')
            self.end_headers()
            return
    
    def send_login_page(self):
        """Wysyła stronę logowania"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Logowanie - File Upload</title>
            <style>
                body {{ font-family: Arial, sans-serif; background: #1a1a1a; color: #fff; margin: 0; padding: 20px; }}
                .container {{ max-width: 400px; margin: 100px auto; background: #2a2a2a; padding: 30px; border-radius: 10px; }}
                h1 {{ text-align: center; margin-bottom: 30px; }}
                input[type="password"] {{ width: 100%; padding: 12px; margin: 10px 0; border: none; border-radius: 5px; background: #333; color: #fff; }}
                button {{ width: 100%; padding: 12px; background: #007acc; color: white; border: none; border-radius: 5px; cursor: pointer; }}
                button:hover {{ background: #005a9e; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔐 Logowanie</h1>
                <form method="POST" action="/login">
                    <input type="password" name="password" placeholder="Hasło administratora" required>
                    <button type="submit">Zaloguj</button>
                </form>
            </div>
        </body>
        </html>
        """
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))
    
    def send_main_page(self, session):
        """Wysyła główną stronę"""
        # Lista plików
        files = []
        for file_path in upload_path.iterdir():
            if file_path.is_file():
                stat = file_path.stat()
                files.append({
                    'name': file_path.name,
                    'size': stat.st_size,
                    'mtime': stat.st_mtime
                })
        
        # Sortuj po dacie modyfikacji (najnowsze pierwsze)
        files.sort(key=lambda x: x['mtime'], reverse=True)
        
        files_html = ""
        for file_info in files:
            size_mb = file_info['size'] / (1024 * 1024)
            mtime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(file_info['mtime']))
            files_html += f"""
            <tr>
                <td>{file_info['name']}</td>
                <td>{size_mb:.1f} MB</td>
                <td>{mtime}</td>
                <td>
                    <a href="/download/{file_info['name']}" class="btn btn-download">📥 Pobierz</a>
                    <form method="POST" action="/delete" style="display: inline;">
                        <input type="hidden" name="path" value="{file_info['name']}">
                        <button type="submit" class="btn btn-delete" onclick="return confirm('Usunąć plik?')">🗑️ Usuń</button>
                    </form>
                </td>
            </tr>
            """
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>File Upload - Panel administratora</title>
            <style>
                body {{ font-family: Arial, sans-serif; background: #1a1a1a; color: #fff; margin: 0; padding: 20px; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }}
                .upload-area {{ border: 2px dashed #007acc; padding: 40px; text-align: center; border-radius: 10px; margin-bottom: 30px; }}
                .upload-area.dragover {{ background: #007acc20; border-color: #00aaff; }}
                .file-input {{ display: none; }}
                .progress {{ width: 100%; height: 20px; background: #333; border-radius: 10px; overflow: hidden; margin: 10px 0; }}
                .progress-bar {{ height: 100%; background: #007acc; width: 0%; transition: width 0.3s; }}
                table {{ width: 100%; border-collapse: collapse; background: #2a2a2a; border-radius: 10px; overflow: hidden; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #333; }}
                th {{ background: #007acc; }}
                .btn {{ padding: 8px 16px; border: none; border-radius: 5px; cursor: pointer; text-decoration: none; display: inline-block; margin: 2px; }}
                .btn-download {{ background: #28a745; color: white; }}
                .btn-delete {{ background: #dc3545; color: white; }}
                .btn-logout {{ background: #6c757d; color: white; }}
                .btn:hover {{ opacity: 0.8; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📁 Panel administratora</h1>
                    <form method="POST" action="/logout" style="display: inline;">
                        <button type="submit" class="btn btn-logout">🚪 Wyloguj</button>
                    </form>
                </div>
                
                <div class="upload-area" id="uploadArea">
                    <h3>📤 Przeciągnij pliki tutaj lub kliknij aby wybrać</h3>
                    <input type="file" id="fileInput" class="file-input" multiple>
                    <div class="progress" id="progress" style="display: none;">
                        <div class="progress-bar" id="progressBar"></div>
                    </div>
                </div>
                
                <h2>📋 Lista plików</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Nazwa pliku</th>
                            <th>Rozmiar</th>
                            <th>Data modyfikacji</th>
                            <th>Akcje</th>
                        </tr>
                    </thead>
                    <tbody>
                        {files_html}
                    </tbody>
                </table>
            </div>
            
            <script>
                const uploadArea = document.getElementById('uploadArea');
                const fileInput = document.getElementById('fileInput');
                const progress = document.getElementById('progress');
                const progressBar = document.getElementById('progressBar');
                
                uploadArea.addEventListener('click', () => {{
                    fileInput.click();
                }});
                
                uploadArea.addEventListener('dragover', (e) => {{
                    e.preventDefault();
                    uploadArea.classList.add('dragover');
                }});
                
                uploadArea.addEventListener('dragleave', () => {{
                    uploadArea.classList.remove('dragover');
                }});
                
                uploadArea.addEventListener('drop', (e) => {{
                    e.preventDefault();
                    uploadArea.classList.remove('dragover');
                    const files = e.dataTransfer.files;
                    uploadFiles(files);
                }});
                
                fileInput.addEventListener('change', (e) => {{
                    uploadFiles(e.target.files);
                }});
                
                function uploadFiles(files) {{
                    if (files.length === 0) return;
                    
                    progress.style.display = 'block';
                    progressBar.style.width = '0%';
                    
                    const formData = new FormData();
                    for (let file of files) {{
                        formData.append('files', file);
                    }}
                    
                    const xhr = new XMLHttpRequest();
                    xhr.open('POST', '/upload');
                    
                    xhr.upload.addEventListener('progress', (e) => {{
                        if (e.lengthComputable) {{
                            const percent = (e.loaded / e.total) * 100;
                            progressBar.style.width = percent + '%';
                        }}
                    }});
                    
                    xhr.addEventListener('load', () => {{
                        if (xhr.status === 200) {{
                            setTimeout(() => location.reload(), 1000);
                        }} else {{
                            alert('Błąd uploadu: ' + xhr.responseText);
                        }}
                        progress.style.display = 'none';
                    }});
                    
                    xhr.send(formData);
                }}
            </script>
        </body>
        </html>
        """
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))
    
    def handle_login(self, post_data):
        """Obsługuje logowanie"""
        try:
            data = parse_qs(post_data.decode())
            password = data.get('password', [''])[0]
            
            if password == ADMIN_PASSWORD:
                session_id = create_session()
                self.send_response(302)
                self.send_header('Location', '/')
                for header in set_cookie_headers(session_id):
                    self.send_header(*header)
                self.end_headers()
            else:
                self.send_response(302)
                self.send_header('Location', '/login')
                self.end_headers()
        except:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'Bad request')
    
    def handle_upload(self, post_data, session):
        """Obsługuje upload plików"""
        try:
            # Prosty parser multipart/form-data
            boundary = None
            for line in self.headers.get('Content-Type', '').split(';'):
                if 'boundary=' in line:
                    boundary = line.split('=')[1].strip()
                    break
            
            if not boundary:
                self.send_response(400)
                self.end_headers()
                return
            
            # Parsuj dane multipart
            parts = post_data.split(b'--' + boundary.encode())
            uploaded_files = []
            
            for part in parts:
                if b'Content-Disposition: form-data' in part:
                    # Wyciągnij nazwę pliku
                    lines = part.split(b'\r\n')
                    filename = None
                    for line in lines:
                        if b'filename=' in line:
                            filename = line.split(b'filename=')[1].strip(b'"')
                            break
                    
                    if filename:
                        # Wyciągnij zawartość pliku
                        content_start = part.find(b'\r\n\r\n') + 4
                        content_end = part.rfind(b'\r\n')
                        if content_end > content_start:
                            file_content = part[content_start:content_end]
                            
                            # Zapisz plik
                            safe_filename = "".join(c for c in filename.decode() if c.isalnum() or c in '.-_')
                            if safe_filename:
                                file_path = upload_path / safe_filename
                                
                                # Zapis atomowy
                                temp_path = upload_path / f"{safe_filename}.part"
                                with open(temp_path, 'wb') as f:
                                    f.write(file_content)
                                os.replace(temp_path, file_path)
                                
                                uploaded_files.append(safe_filename)
            
            # Odpowiedź
            response = {'uploaded': uploaded_files}
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
            
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f'Upload error: {str(e)}'.encode())
    
    def handle_delete(self, post_data, session):
        """Obsługuje usuwanie plików"""
        try:
            data = parse_qs(post_data.decode())
            rel_path = data.get('path', [''])[0]
            
            if not rel_path:
                self.send_response(400)
                self.end_headers()
                return
            
            file_path = safe_path(rel_path)
            if not file_path or not file_path.is_file():
                self.send_response(400)
                self.end_headers()
                return
            
            # Usuń plik
            file_path.unlink()
            
            self.send_response(302)
            self.send_header('Location', '/')
            self.end_headers()
            
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f'Delete error: {str(e)}'.encode())
    
    def send_file(self, rel_path):
        """Wysyła plik do pobrania"""
        file_path = safe_path(rel_path)
        if not file_path or not file_path.is_file():
            self.send_response(404)
            self.end_headers()
            return
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Disposition', f'attachment; filename="{rel_path}"')
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f'Download error: {str(e)}'.encode())
    
    def log_message(self, format, *args):
        """Wyłącza logowanie"""
        pass

def run_server():
    """Uruchamia serwer"""
    server_address = ('', 80)
    httpd = HTTPServer(server_address, FileUploadHandler)
    print(f"🚀 Serwer uruchomiony na porcie 80")
    print(f"📁 Katalog upload: {upload_path.absolute()}")
    print(f"🔐 Hasło: {ADMIN_PASSWORD}")
    print(f"🌐 Otwórz: http://localhost")
    print("⏹️  Zatrzymaj: Ctrl+C")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Serwer zatrzymany")
        httpd.server_close()

if __name__ == '__main__':
    run_server()
