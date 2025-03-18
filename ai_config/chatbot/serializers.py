from rest_framework import serializers, viewsets
from rest_framework.response import Response
from rest_framework.decorators import action
from . import models
class ChatMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.ChatMessage
        fields = ['id','sender', 'message', 'created_at']

class ChatSessionSerializer(serializers.ModelSerializer):
    messages = ChatMessageSerializer(many=True, read_only=True)

    class Meta:
        model = models.ChatSession
        fields = ['id', 'created_at', 'updated_at', 'messages']


# class ChatSessionViewSet(viewsets.ModelViewSet):
#     queryset = models.ChatSession.objects.all()
#     serializer_class = ChatSessionSerializer

#     @action(detail=True, methods=['post'])
#     def send_message(self, request, pk=None):
#         session = self.get_object()
#         sender = request.data.get('sender')
#         message = request.data.get('message')

#         if sender not in ['user', 'ai']:
#             return Response({'error': 'Invalid sender'}, status=400)

#         ChatMessage.objects.create(session=session, sender=sender, message=message)
#         return Response({'status': 'message sent'})