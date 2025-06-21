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
    path('chat2/', views.chatAI2, name='chat'),
    # experimental testing
    path('api/chat/', views.chat_interface, name='chat interface'),
    path('api/react_chat_interface_lc/', views.react_chat_interface_lc, name='react_chat_interface_lc'),
    path('test/', views.sysadmin_prompt, name='sysadmin_prompt'),
    # end
    path('services-control/', views.service_control, name='services-control'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('ai-optimization/', views.ai_optimization, name='ai_optimization'),
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
     path('run-analysis/', views.run_analysis, name='run_analysis'),
     path('logs-report/', views.logs_report, name='logs_report'),
     path('ai-analyze-service/', views.ai_analyze_service, name='ai_analyze_service'),
     path('ai-analyze-service-v2/', views.ai_analyze_service_v2, name='ai_analyze_service_v2'),
     path('ai-fix-service-v2/', views.ai_fix_service_v2, name='ai_fix_service_v2'),
    #  test new
     path('api/process-smart-chat/', views.process_smart_chat, name='process_smart_chat'),
     path('api/ai-admin-chat/', views.ai_admin_chat, name='ai_admin_chat'),
    # new config detector
    path('system-analysis/', views.config_detector, name='config_detector'),
    path('scan/', views.run_scan, name='run_scan'),
    path('fix/<int:issue_id>/', views.auto_fix_issue, name='auto_fix_issue'),
    path('api/results/<int:scan_id>/', views.api_scan_results, name='api_scan_results'),
    path('api/security-stats/', views.security_stats_api, name='security_stats_api'),
    path('network-security/', views.network_Security, name='network_Security'),
]

