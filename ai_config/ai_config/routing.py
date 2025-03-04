from django.urls import re_path, path
from ai_config.consumers import SystemMonitorConsumer

websocket_urlpatterns = [
    path("ws/system_monitor/", SystemMonitorConsumer.as_asgi()),
   
]