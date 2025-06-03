from django.contrib import admin
from .models import ChatSession, ChatMessage, Profile, SuricataLog, AIRecommendation


@admin.register(ChatSession)
class ChatSessionAdmin(admin.ModelAdmin):
    list_display = ('id', 'created_at', 'updated_at')
    search_fields = ('id',)


@admin.register(ChatMessage)
class ChatMessageAdmin(admin.ModelAdmin):
    list_display = ('id', 'session', 'sender', 'short_message', 'created_at')
    list_filter = ('sender', 'created_at')
    search_fields = ('message', 'session__id')

    def short_message(self, obj):
        return obj.message[:50] + ('...' if len(obj.message) > 50 else '')
    short_message.short_description = 'Message Preview'


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'is_active_session')
    search_fields = ('user__username',)

@admin.register(AIRecommendation)
class AIRecommendationAdmin(admin.ModelAdmin):
    list_display = ('category', 'title','description','recommendation' )
    


@admin.register(SuricataLog)
class SuricataLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'message_preview', 'severity', 'source_ip', 'destination_ip', 'protocol', 'priority')
    list_filter = ('severity', 'protocol', 'priority')
    search_fields = ('message', 'source_ip', 'destination_ip')

    def message_preview(self, obj):
        return obj.message[:50] + ('...' if len(obj.message) > 50 else '')
    message_preview.short_description = 'Log Preview'