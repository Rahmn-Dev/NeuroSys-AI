from django.urls import re_path, path
from ai_config import consumers

websocket_urlpatterns = [
    path("ws/system_monitor/", consumers.SystemMonitorConsumer.as_asgi()),
    path("ws/suricata_monitor/", consumers.SuricataLogConsumer.as_asgi()), 
    path("ws/services/", consumers.ServiceControlConsumer.as_asgi()), 
]