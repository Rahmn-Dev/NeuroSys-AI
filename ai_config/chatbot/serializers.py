from rest_framework import serializers, viewsets
from rest_framework.response import Response
from rest_framework.decorators import action
from . import models
class ChatMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.ChatMessage
        fields = ['id', 'sender', 'role', 'message', 'metadata', 'created_at']

class SuricataSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.SuricataLog
        fields = "__all__"

class InvestigationFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.InvestigationFinding
        fields = ['id', 'content', 'created_at']

class InvestigationTaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.InvestigationTask
        fields = ['id', 'title', 'status', 'task_order']

class InvestigationSerializer(serializers.ModelSerializer):
    tasks = InvestigationTaskSerializer(many=True, read_only=True)
    findings = InvestigationFindingSerializer(many=True, read_only=True)

    class Meta:
        model = models.Investigation
        fields = ['id', 'session', 'title', 'status', 'created_at', 'updated_at', 'tasks', 'findings']

class ChatSessionSerializer(serializers.ModelSerializer):
    messages = ChatMessageSerializer(many=True, read_only=True)
    investigations = InvestigationSerializer(many=True, read_only=True)

    class Meta:
        model = models.ChatSession
        fields = ['id', 'title', 'created_at', 'updated_at', 'messages', 'investigations']


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


