"""
ASGI config for ai_config project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/asgi/
"""

# import os

# from django.core.asgi import get_asgi_application


# application = get_asgi_application()

import os
import django
from django.core.asgi import get_asgi_application
from fastapi import FastAPI
from fastapi.middleware.wsgi import WSGIMiddleware
from websocket import app as fastapi_app  # Import FastAPI dari websocket.py
from starlette.middleware.cors import CORSMiddleware

# Set environment Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ai_config.settings")
application = get_asgi_application()
# django.setup()

# # Inisialisasi aplikasi Django ASGI
# django_asgi_app = get_asgi_application()

# # Tambahkan middleware jika dibutuhkan
# fastapi_app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# # Mount Django ke dalam FastAPI di root ("/")
# fastapi_app.mount("/", WSGIMiddleware(django_asgi_app))

# # Gabungkan Django ASGI dan FastAPI dalam satu aplikasi
# application = fastapi_app