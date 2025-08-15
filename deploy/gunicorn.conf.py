#!/usr/bin/env python3
"""
Konfiguracja Gunicorn dla File Uploader
"""

import multiprocessing
import os

# Bind address
bind = "127.0.0.1:8000"

# Workers
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000

# Timeout
timeout = 300  # 5 minut dla dużych plików
keepalive = 2

# Logging
accesslog = "-"  # stdout
errorlog = "-"   # stderr
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = "fileuploader"

# User/Group (odkomentuj jeśli uruchamiasz jako root)
# user = "www-data"
# group = "www-data"

# Preload app
preload_app = True

# Max requests per worker
max_requests = 1000
max_requests_jitter = 100

# Restart workers after max requests
preload_app = True

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Environment variables
raw_env = [
    "ADMIN_PASSWORD=" + os.environ.get("ADMIN_PASSWORD", ""),
    "SECRET_KEY=" + os.environ.get("SECRET_KEY", ""),
    "UPLOAD_ROOT=" + os.environ.get("UPLOAD_ROOT", "./uploads"),
    "MAX_CONTENT_LENGTH=" + os.environ.get("MAX_CONTENT_LENGTH", "512MB"),
]

def when_ready(server):
    """Callback wywoływany gdy serwer jest gotowy"""
    server.log.info("File Uploader started successfully")

def on_starting(server):
    """Callback wywoływany przy starcie serwera"""
    server.log.info("Starting File Uploader...")

def on_exit(server):
    """Callback wywoływany przy wyjściu"""
    server.log.info("File Uploader stopped")
