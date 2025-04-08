from django.urls import re_path, path
from ai_config.consumers import SystemMonitorConsumer, SuricataLogConsumer

websocket_urlpatterns = [
    path("ws/system_monitor/", SystemMonitorConsumer.as_asgi()),
    path("ws/suricata_monitor/", SuricataLogConsumer.as_asgi()), 
]