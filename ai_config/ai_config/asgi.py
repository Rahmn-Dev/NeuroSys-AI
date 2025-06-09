"""
ASGI config for ai_config project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/asgi/
"""

# import os

# from django.core.asgi import get_asgi_application


# application = get_asgi_application()

# import os
# import django
# from django.core.asgi import get_asgi_application
# from fastapi import FastAPI
# from starlette.routing import Mount
# from starlette.middleware.wsgi import WSGIMiddleware
# from starlette.applications import Starlette
# from websocket import app as fastapi_app  # Import FastAPI WebSocket app

# # Set Django settings
# os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ai_config.settings")
# django.setup()

# # Django ASGI application
# django_asgi_app = get_asgi_application()

# # Define the FastAPI app separately
# fastapi_app = FastAPI()

# # Create a single ASGI application combining both
# application = Starlette(
#     routes=[
#         Mount("/api", fastapi_app),  # FastAPI WebSockets & API
#         Mount("/", django_asgi_app),  # Django app (ASGI)
#     ]
# )

import os
import django
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from ai_config.routing import websocket_urlpatterns
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ai_config.settings")
django.setup()

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": URLRouter(websocket_urlpatterns),
})