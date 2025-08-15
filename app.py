#!/usr/bin/env python3
"""
Prosty File Uploader - wszystko w jednym pliku
"""
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from flask import Flask, request, session, redirect, url_for, render_template_string, flash, abort, jsonify, send_file
from itsdangerous import TimestampSigner, BadSignature, SignatureExpired
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

# Konfiguracja z ENV
def get_required_env(key: str) -> str:
    """Pobiera wymaganą zmienną środowiskową"""
    value = os.environ.get(key)
    if not value:
        print(f"BŁĄD: Wymagana zmienna środowiskowa {key} nie jest ustawiona")
        print(f"Ustaw {key} przed uruchomieniem aplikacji")
        exit(1)
    return value

def parse_size(size_str: str) -> int:
    """Konwertuje rozmiar z stringa na bajty (np. '512MB' -> 536870912)"""
    size_str = size_str.upper().strip()
    if size_str.endswith('KB'):
        return int(size_str[:-2]) * 1024
    elif size_str.endswith('MB'):
        return int(size_str[:-2]) * 1024 * 1024
    elif size_str.endswith('GB'):
        return int(size_str[:-2]) * 1024 * 1024 * 1024
    else:
        return int(size_str)

# Pobieranie zmiennych środowiskowych
ADMIN_PASSWORD = get_required_env('ADMIN_PASSWORD')
SECRET_KEY = get_required_env('SECRET_KEY')
UPLOAD_ROOT = os.environ.get('UPLOAD_ROOT', './uploads')
MAX_CONTENT_LENGTH = parse_size(os.environ.get('MAX_CONTENT_LENGTH', '512MB'))

# Tworzenie katalogu uploads
upload_path = Path(UPLOAD_ROOT).resolve()
upload_path.mkdir(mode=0o700, exist_ok=True)

# Inicjalizacja Flask
app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Strict'
)

# ProxyFix dla Nginx
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# CSRF signer
csrf_signer = TimestampSigner(SECRET_KEY)

@app.context_processor
def inject_csrf():
    """Dodaje token CSRF do wszystkich szablonów"""
    return {'csrf_token': generate_csrf_token()}

def generate_csrf_token() -> str:
    """Generuje token CSRF"""
    return csrf_signer.sign('csrf').decode('utf-8')

def validate_csrf_token(token: str) -> bool:
    """Waliduje token CSRF"""
    if not token:
        return False
    try:
        csrf_signer.unsign(token, max_age=3600)
        return True
    except (BadSignature, SignatureExpired):
        return False

def is_authenticated() -> bool:
    """Sprawdza czy użytkownik jest zalogowany"""
    return session.get('user') == 'admin'

def login_required(f):
    """Dekorator wymuszający autoryzację"""
    def decorated_function(*args, **kwargs):
        if not is_authenticated():
            abort(401)
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def safe_path(rel_path: str) -> Optional[Path]:
    """Bezpiecznie waliduje ścieżkę"""
    if not rel_path or rel_path.startswith('/'):
        return None
    
    try:
        abs_path = (upload_path / rel_path).resolve()
        if not str(abs_path).startswith(str(upload_path) + os.sep):
            return None
        if abs_path.is_symlink():
            return None
        return abs_path
    except (RuntimeError, ValueError):
        return None

def format_size(size_bytes: int) -> str:
    """Formatuje rozmiar pliku"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"

# HTML template z wbudowanym CSS
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% if title %}{{ title }} - {% endif %}File Uploader</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a1a; color: #e0e0e0; line-height: 1.6;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; margin-bottom: 30px; }
        .header h1 { color: #4CAF50; font-size: 2.5em; margin-bottom: 10px; }
        .login-form { 
            max-width: 400px; margin: 100px auto; text-align: center;
            background: #2d2d2d; padding: 40px; border-radius: 10px;
        }
        .form-group { margin-bottom: 20px; }
        input[type="password"] { 
            width: 100%; padding: 12px; border: none; border-radius: 5px;
            background: #404040; color: #e0e0e0; font-size: 16px;
        }
        .btn { 
            background: #4CAF50; color: white; padding: 12px 24px;
            border: none; border-radius: 5px; cursor: pointer; font-size: 16px;
            transition: background 0.3s;
        }
        .btn:hover { background: #45a049; }
        .btn-danger { background: #f44336; }
        .btn-danger:hover { background: #da190b; }
        .upload-zone { 
            border: 2px dashed #4CAF50; border-radius: 10px; padding: 40px;
            text-align: center; margin-bottom: 30px; transition: all 0.3s;
        }
        .upload-zone.dragover { background: #2d2d2d; border-color: #45a049; }
        .file-input { display: none; }
        .file-list { 
            background: #2d2d2d; border-radius: 10px; padding: 20px;
            margin-bottom: 30px;
        }
        .file-item { 
            display: flex; justify-content: space-between; align-items: center;
            padding: 15px; border-bottom: 1px solid #404040;
        }
        .file-item:last-child { border-bottom: none; }
        .file-info { flex: 1; }
        .file-name { font-weight: bold; margin-bottom: 5px; }
        .file-meta { color: #888; font-size: 0.9em; }
        .file-actions { display: flex; gap: 10px; }
        .progress-bar { 
            width: 100%; height: 20px; background: #404040; border-radius: 10px;
            overflow: hidden; margin-top: 10px;
        }
        .progress-fill { 
            height: 100%; background: #4CAF50; transition: width 0.3s;
        }
        .flash { 
            padding: 15px; margin-bottom: 20px; border-radius: 5px;
            background: #4CAF50; color: white;
        }
        .flash.error { background: #f44336; }
        .logout-form { text-align: right; margin-bottom: 20px; }
        .logout-form .btn { padding: 8px 16px; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        {% if session.user %}
            <div class="logout-form">
                <form method="POST" action="{{ url_for('logout') }}" style="display: inline;">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                    <button type="submit" class="btn btn-danger">Wyloguj</button>
                </form>
            </div>
            
            <div class="header">
                <h1>📁 File Uploader</h1>
                <p>Zarządzaj plikami bezpiecznie</p>
            </div>

            {% with messages = get_flashed_messages() %}
                {% if messages %}
                    {% for message in messages %}
                        <div class="flash">{{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}

            <div class="upload-zone" id="uploadZone">
                <h3>📤 Przeciągnij pliki tutaj lub kliknij</h3>
                <p>lub</p>
                <input type="file" id="fileInput" class="file-input" multiple>
                <button class="btn" onclick="document.getElementById('fileInput').click()">
                    Wybierz pliki
                </button>
            </div>

            <div class="file-list">
                <h3>📋 Lista plików</h3>
                {% if files %}
                    {% for file in files %}
                        <div class="file-item">
                            <div class="file-info">
                                <div class="file-name">{{ file.name }}</div>
                                <div class="file-meta">
                                    {{ file.size_human }} • 
                                    {{ file.mtime.strftime('%Y-%m-%d %H:%M:%S') }}
                                </div>
                            </div>
                            <div class="file-actions">
                                <a href="{{ url_for('download', rel=file.name) }}" class="btn">
                                    📥 Pobierz
                                </a>
                                <form method="POST" action="{{ url_for('delete') }}" style="display: inline;">
                                    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                                    <input type="hidden" name="path" value="{{ file.name }}">
                                    <button type="submit" class="btn btn-danger" 
                                            onclick="return confirm('Usunąć plik {{ file.name }}?')">
                                        🗑️ Usuń
                                    </button>
                                </form>
                            </div>
                        </div>
                    {% endfor %}
                {% else %}
                    <p style="text-align: center; color: #888; padding: 20px;">
                        Brak plików do wyświetlenia
                    </p>
                {% endif %}
            </div>
        {% else %}
            <div class="login-form">
                <h2>🔐 Logowanie</h2>
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                    <div class="form-group">
                        <input type="password" name="password" placeholder="Hasło" required>
                    </div>
                    <button type="submit" class="btn">Zaloguj</button>
                </form>
            </div>
        {% endif %}
    </div>

    <script>
        // Drag & Drop
        const uploadZone = document.getElementById('uploadZone');
        const fileInput = document.getElementById('fileInput');
        
        if (uploadZone && fileInput) {
            uploadZone.addEventListener('dragover', (e) => {
                e.preventDefault();
                uploadZone.classList.add('dragover');
            });
            
            uploadZone.addEventListener('dragleave', () => {
                uploadZone.classList.remove('dragover');
            });
            
            uploadZone.addEventListener('drop', (e) => {
                e.preventDefault();
                uploadZone.classList.remove('dragover');
                const files = e.dataTransfer.files;
                uploadFiles(files);
            });
            
            fileInput.addEventListener('change', (e) => {
                uploadFiles(e.target.files);
            });
        }
        
        function uploadFiles(files) {
            Array.from(files).forEach(file => {
                const formData = new FormData();
                formData.append('files', file);
                formData.append('csrf_token', '{{ csrf_token }}');
                
                const xhr = new XMLHttpRequest();
                xhr.open('POST', '{{ url_for("upload") }}');
                
                xhr.onload = function() {
                    if (xhr.status === 200) {
                        location.reload();
                    } else {
                        alert('Błąd uploadu: ' + xhr.responseText);
                    }
                };
                
                xhr.send(formData);
            });
        }
    </script>
</body>
</html>
"""

@app.route('/')
@login_required
def index():
    """Główna strona"""
    files = []
    try:
        for file_path in upload_path.iterdir():
            if file_path.is_file():
                stat = file_path.stat()
                files.append({
                    'name': file_path.name,
                    'size': stat.st_size,
                    'mtime': datetime.fromtimestamp(stat.st_mtime),
                    'size_human': format_size(stat.st_size)
                })
        files.sort(key=lambda x: x['mtime'], reverse=True)
    except OSError:
        flash('Błąd podczas odczytu listy plików', 'error')
    
    return render_template_string(HTML_TEMPLATE, files=files, title="Główna")

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Logowanie"""
    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token')):
            flash('Nieprawidłowy token CSRF', 'error')
            return render_template_string(HTML_TEMPLATE, title="Logowanie"), 400
        
        password = request.form.get('password')
        if password == ADMIN_PASSWORD:
            session['user'] = 'admin'
            flash('Zalogowano pomyślnie', 'success')
            return redirect(url_for('index'))
        else:
            flash('Nieprawidłowe hasło', 'error')
            return render_template_string(HTML_TEMPLATE, title="Logowanie"), 401
    
    return render_template_string(HTML_TEMPLATE, title="Logowanie")

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    """Wylogowanie"""
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Nieprawidłowy token CSRF', 'error')
        return redirect(url_for('index')), 400
    
    session.clear()
    flash('Wylogowano pomyślnie', 'success')
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    """Upload plików"""
    if not validate_csrf_token(request.form.get('csrf_token')):
        return jsonify({'error': 'Nieprawidłowy token CSRF'}), 400
    
    if 'files' not in request.files:
        return jsonify({'error': 'Brak plików'}), 400
    
    uploaded_files = request.files.getlist('files')
    results = []
    
    for file in uploaded_files:
        if file.filename == '':
            results.append({'filename': 'unknown', 'status': 'error', 'message': 'Pusta nazwa pliku'})
            continue
        
        filename = secure_filename(file.filename)
        if not filename:
            results.append({'filename': file.filename, 'status': 'error', 'message': 'Nieprawidłowa nazwa pliku'})
            continue
        
        try:
            # Zapis atomowy
            temp_path = upload_path / f"{filename}.part"
            final_path = upload_path / filename
            
            file.save(temp_path)
            os.replace(temp_path, final_path)
            
            results.append({'filename': filename, 'status': 'success'})
        except Exception as e:
            results.append({'filename': filename, 'status': 'error', 'message': str(e)})
    
    return jsonify({'results': results})

@app.route('/download/<path:rel>')
@login_required
def download(rel):
    """Pobieranie pliku"""
    file_path = safe_path(rel)
    if not file_path or not file_path.is_file():
        abort(404)
    
    return send_file(
        file_path,
        as_attachment=True,
        download_name=file_path.name
    )

@app.route('/delete', methods=['POST'])
@login_required
def delete():
    """Usuwanie pliku"""
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Nieprawidłowy token CSRF', 'error')
        return redirect(url_for('index')), 400
    
    rel_path = request.form.get('path')
    if not rel_path:
        flash('Brak ścieżki pliku', 'error')
        return redirect(url_for('index')), 400
    
    file_path = safe_path(rel_path)
    if not file_path or not file_path.is_file():
        flash('Nieprawidłowa ścieżka pliku', 'error')
        return redirect(url_for('index')), 400
    
    try:
        file_path.unlink()
        flash(f'Plik {rel_path} został usunięty', 'success')
    except OSError:
        flash(f'Błąd podczas usuwania pliku {rel_path}', 'error')
    
    return redirect(url_for('index'))

@app.errorhandler(400)
def bad_request(error):
    return render_template_string(HTML_TEMPLATE, title="Błąd 400"), 400

@app.errorhandler(401)
def unauthorized(error):
    return redirect(url_for('login'))

@app.errorhandler(404)
def not_found(error):
    return render_template_string(HTML_TEMPLATE, title="Błąd 404"), 404

@app.errorhandler(413)
def too_large(error):
    flash('Plik jest za duży', 'error')
    return redirect(url_for('index')), 413

@app.errorhandler(500)
def internal_error(error):
    flash('Błąd wewnętrzny serwera', 'error')
    return redirect(url_for('index')), 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=8080)
