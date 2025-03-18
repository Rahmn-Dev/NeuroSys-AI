from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import action
from .models import ChatSession, ChatMessage
from .serializers import ChatSessionSerializer, ChatMessageSerializer

class ChatSessionViewSet(viewsets.ModelViewSet):
    queryset = ChatSession.objects.all()
    serializer_class = ChatSessionSerializer

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
        ChatMessage.objects.create(session=session, sender=sender, message=message)

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


class ChatMessageViewSet(viewsets.ModelViewSet):
    queryset = ChatMessage.objects.all()
    serializer_class = ChatMessageSerializer

    # Override get_queryset untuk filter pesan berdasarkan sesi
    def get_queryset(self):
        session_id = self.kwargs.get('session_id')
        if session_id:
            return ChatMessage.objects.filter(session_id=session_id)
        return ChatMessage.objects.all()