from rest_framework import viewsets, status, permissions
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.pagination import LimitOffsetPagination
from django.db.models import Count
from . import models
from .serializers import ChatSessionSerializer, ChatMessageSerializer
from . import serializers
from rest_framework.decorators import api_view, permission_classes
from sre_agent.approvals import request_approval, approve, deny
from sre_agent.security_boundary import audit
from django.db import transaction
class ChatSessionPagination(LimitOffsetPagination):
    default_limit = 50
    max_limit = 200


class ChatSessionViewSet(viewsets.ModelViewSet):
    queryset = models.ChatSession.objects.all().order_by('-updated_at')
    serializer_class = ChatSessionSerializer
    permission_classes = [permissions.AllowAny]
    pagination_class = ChatSessionPagination

    def get_queryset(self):
        return (super().get_queryset()
                .annotate(message_count=Count('messages', distinct=True)))

    def get_serializer_class(self):
        # The sidebar list must be cheap: detail rows (messages + nested
        # investigations) are only needed by the single-session endpoints.
        if self.action == 'list':
            return serializers.ChatSessionListSerializer
        return self.serializer_class

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

    @action(detail=True, methods=['get'], url_path='case-graph', permission_classes=[permissions.IsAuthenticated])
    def case_graph(self, request, pk=None):
        """Return authenticated semantic graph data for a session owned by the active user."""
        session = self.get_object()
        if not session.agent_runs.filter(user_id=str(request.user.id)).exists():
            return Response({'error': 'Session graph not found'}, status=status.HTTP_404_NOT_FOUND)
        cases = list(models.Investigation.objects.filter(session=session).prefetch_related('relations_from').order_by('created_at'))
        nodes, edges, entity_ids = [], [], {}
        for case in cases:
            case_id = f"case:{case.id}"
            nodes.append({
                "id": case_id, "raw_id": case.id, "node_type": "case", "label": case.title,
                "kind": case.case_kind, "status": case.status, "summary": case.context_summary,
            })
            if case.parent_id:
                edges.append({"source": f"case:{case.parent_id}", "target": case_id,
                              "relation": case.relation_type or "context_switch", "confidence": 1.0})
            for relation in case.relations_from.all()[:5]:
                edges.append({"source": case_id, "target": f"case:{relation.target_id}",
                              "relation": relation.relation_type, "confidence": round(relation.confidence, 3),
                              "reason": relation.reason})
            for entity in (case.entities or [])[:12]:
                entity_id = entity_ids.setdefault(entity, f"entity:{len(entity_ids) + 1}")
                if not any(node["id"] == entity_id for node in nodes):
                    nodes.append({"id": entity_id, "node_type": "entity", "label": entity})
                edges.append({"source": case_id, "target": entity_id, "relation": "mentions", "confidence": 1.0})
            for index, evidence in enumerate((case.evidence_digest or [])[:2]):
                evidence_id = f"evidence:{case.id}:{index}"
                nodes.append({"id": evidence_id, "node_type": "evidence", "label": str(evidence)[:180]})
                edges.append({"source": case_id, "target": evidence_id, "relation": "evidence", "confidence": 1.0})
        return Response({"nodes": nodes, "edges": edges})


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


@api_view(["GET", "PUT"])
@permission_classes([permissions.IsAuthenticated])
def agent_permission(request):
    """Read or update the server-authoritative agent authorization preference."""
    profile, _ = models.Profile.objects.get_or_create(user=request.user)
    if request.method == "GET":
        return Response({"mode": profile.agent_permission_mode})

    requested = request.data.get("mode")
    allowed = {value for value, _ in models.Profile.AGENT_PERMISSION_CHOICES}
    if requested not in allowed:
        return Response({"error": "mode must be need_approval or full_access"}, status=400)
    previous = profile.agent_permission_mode
    if requested != previous:
        with transaction.atomic():
            profile = models.Profile.objects.select_for_update().get(pk=profile.pk)
            previous = profile.agent_permission_mode
            profile.agent_permission_mode = requested
            profile.save(update_fields=["agent_permission_mode"])
            record = models.AgentPermissionAudit.objects.create(
                user=request.user, previous_mode=previous, new_mode=requested, source="ui"
            )
        audit("permission_mode_changed", verdict=requested, request_id=record.request_id,
              user_id=request.user.pk)
    return Response({"mode": profile.agent_permission_mode})


@api_view(["POST"])
@permission_classes([permissions.IsAuthenticated])
def approval_request(request):
    data = request.data
    session_id = data.get("session_id")
    tool = data.get("tool")
    args = data.get("args", {})
    if not session_id or not isinstance(tool, str) or not isinstance(args, dict):
        return Response({"error": "session_id, tool, and object args are required"}, status=400)
    try:
        obj = request_approval(session_id=session_id, user_id=request.user.pk,
                               tool_name=tool, args=args, risk=str(data.get("risk", "high")),
                               reason=str(data.get("reason", ""))[:255])
    except PermissionError as exc:
        return Response({"error": str(exc)}, status=403)
    return Response({"id": obj.pk, "tool": obj.tool_name, "target": obj.arguments_preview,
                     "risk": obj.risk, "reason": obj.reason, "status": obj.status,
                     "expires_at": obj.expires_at.isoformat()}, status=201)


@api_view(["POST"])
@permission_classes([permissions.IsAuthenticated])
def approval_allow_once(request, approval_id):
    try:
        obj = approve(approval_id, session_id=request.data.get("session_id"),
                      user_id=request.user.pk)
    except Exception as exc:
        return Response({"error": str(exc)}, status=403)
    return Response({"id": obj.pk, "status": obj.status, "expires_at": obj.expires_at.isoformat()})


@api_view(["POST"])
@permission_classes([permissions.IsAuthenticated])
def approval_deny(request, approval_id):
    try:
        obj = deny(approval_id, session_id=request.data.get("session_id"),
                   user_id=request.user.pk)
    except Exception as exc:
        return Response({"error": str(exc)}, status=403)
    return Response({"id": obj.pk, "status": obj.status})
