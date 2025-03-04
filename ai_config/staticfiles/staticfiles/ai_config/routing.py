from django.urls import re_path
from .consumers import SystemMonitorConsumer

websocket_urlpatterns = [
    re_path(r"ws/system-monitor/$", SystemMonitorConsumer.as_asgi()),
   
]