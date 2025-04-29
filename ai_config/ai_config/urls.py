"""
URL configuration for ai_config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from . import views
from chatbot.api import ChatSessionViewSet, ChatMessageViewSet, SuricataLogsViewSet
from rest_framework.routers import DefaultRouter
from chatbot import views as chatbot_views
router = DefaultRouter()
router.register(r'chat-sessions', ChatSessionViewSet)
router.register(r'chat-sessions/(?P<session_id>[^/.]+)/messages', ChatMessageViewSet, basename='chatmessage')
router.register("suricata-logs", SuricataLogsViewSet, basename="suricata logs")


urlpatterns = [
    path('admin/', admin.site.urls),
    # path('api/', include('chatbot.urls')),
    path('', views.dashboard, name='index'),
    path('chat/', views.chatAI, name='chat'),
    path('services-control/', views.service_control, name='services-control'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
     path('2fa/', views.setup_2fa, name='setup_2fa'),  # Add this line
    path('system_monitor/', views.system_monitor, name='system_monitor'),
    path('api/v1/', include((router.urls, 'api_v1'), namespace='v1')),
    path('api/v1/chat/', chatbot_views.chat_with_ai, name='chat_with_ai'),
    path('api/sudo-command/', views.sudo_command, name='sudo_command'),
    path('api/get-service-config/<str:service_name>/', views.get_service_config, name='get_service_config'),
    path('api/save-service-config/<str:service_name>/', views.save_service_config, name='save_service_config'),
    path('api/v1/system_status/', chatbot_views.system_status, name='system_status'),
    # path('fetch_geolocation/', chatbot_views.fetch_geolocation, name='fetch_geolocation'),
]

