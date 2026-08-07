from rest_framework import viewsets, status, permissions
from rest_framework.response import Response
from rest_framework.decorators import action
from . import models
from .serializers import ChatSessionSerializer, ChatMessageSerializer
from . import serializers
class ChatSessionViewSet(viewsets.ModelViewSet):
    queryset = models.ChatSession.objects.all().order_by('-updated_at')
    serializer_class = ChatSessionSerializer
    permission_classes = [permissions.AllowAny]

    # Custom action untuk mengirim pesan ke sesi tertentu
    @action(detail=True, methods=['post'])
    def send_message(self, request, pk=None):
        session = self.get_object()  # Ambil sesi berdasarkan UUID
        sender = request.data.get('sender')
        message = request.data.get('message')


        # Validasi sender
        if sender not in ['user', 'ai']:
            return Response({'error': 'Invalid sender. Must be "user" or "ai".'}, status=status.HTTP_400_BAD_REQUEST)

        # Buat pesan baru
        models.ChatMessage.objects.create(session=session, sender=sender, message=message)

        # Kembalikan response sukses
        return Response({'status': 'Message sent successfully'}, status=status.HTTP_201_CREATED)

    # Custom action untuk menghapus semua pesan dalam sesi
    @action(detail=True, methods=['delete'])
    def clear_messages(self, request, pk=None):
        session = self.get_object()  # Ambil sesi berdasarkan UUID
        session.messages.all().delete()  # Hapus semua pesan terkait sesi
        return Response({'status': 'All messages cleared'}, status=status.HTTP_204_NO_CONTENT)

    @action(detail=True, methods=['delete'])
    def delete_session(self, request, pk=None):
        session = self.get_object()
        session.delete()
        return Response({'status': 'Chat session deleted'}, status=status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=['post'])
    def bulk_delete(self, request):
        session_ids = request.data.get('session_ids', [])
        if not isinstance(session_ids, list):
            return Response({'error': 'session_ids must be a list'}, status=status.HTTP_400_BAD_REQUEST)
        
        deleted_count, _ = models.ChatSession.objects.filter(id__in=session_ids).delete()
        return Response({'status': f'{deleted_count} sessions deleted'}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['get'])
    def investigations(self, request, pk=None):
        session = self.get_object()
        investigations = models.Investigation.objects.filter(session=session).order_by('created_at')
        serializer = serializers.InvestigationSerializer(investigations, many=True)
        return Response(serializer.data)


class ChatMessageViewSet(viewsets.ModelViewSet):
    queryset = models.ChatMessage.objects.all()
    serializer_class = ChatMessageSerializer
    permission_classes = [permissions.AllowAny]

    # Override get_queryset untuk filter pesan berdasarkan sesi
    def get_queryset(self):
        session_id = self.kwargs.get('session_id')
        if session_id:
            return models.ChatMessage.objects.filter(session_id=session_id)
        return models.ChatMessage.objects.all()


class SuricataLogsViewSet(viewsets.ModelViewSet):
    queryset = models.SuricataLog.objects.all()
    serializer_class = serializers.SuricataSerializer
    permission_classes = [permissions.IsAuthenticated]
