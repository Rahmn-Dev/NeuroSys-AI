import uuid
from django.db import models

class ChatSession(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)  # UUID sebagai primary key
    title = models.CharField(max_length=255, default="New Chat")
    workspace = models.ForeignKey('WorkspaceInfo', null=True, blank=True, on_delete=models.SET_NULL, related_name='sessions')
    created_at = models.DateTimeField(auto_now_add=True)  # Waktu sesi chat dibuat
    updated_at = models.DateTimeField(auto_now=True)  # Waktu sesi chat terakhir diupdate

    def __str__(self):
        return f"{self.title} - {self.id}"

class ChatMessage(models.Model):
    SENDER_CHOICES = [
        ('user', 'User'),
        ('ai', 'AI'),
    ]
    ROLE_CHOICES = [
        ('user', 'User'),
        ('assistant', 'Assistant'),
        ('tool', 'Tool'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)  # UUID sebagai primary key
    session = models.ForeignKey(ChatSession, related_name='messages', on_delete=models.CASCADE)  # Relasi ke ChatSession
    sender = models.CharField(max_length=10, choices=SENDER_CHOICES)  # Legacy
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='user')
    message = models.TextField()  # Isi pesan
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)  # Waktu pesan dikirim

    def __str__(self):
        return f"{self.role}: {self.message[:50]}..."
    

from django.db import models
from django.contrib.auth.models import User
from django.dispatch import receiver
from django.db.models.signals import post_save

class Profile(models.Model):
    AGENT_PERMISSION_CHOICES = [
        ('need_approval', 'Need Approval'),
        ('full_access', 'Full Access'),
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    is_active_session = models.BooleanField(default=False)  # Track active session
    image = models.ImageField(upload_to='profile_images/', blank=True, null=True)  # Profile image
    agent_permission_mode = models.CharField(
        max_length=20, choices=AGENT_PERMISSION_CHOICES, default='need_approval'
    )
    suricata_alerts_enabled = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.user.username}'s Profile"

# Signal to create or update a profile when a User instance is created/updated
@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        # Create a profile for new users
        Profile.objects.create(user=instance)
    else:
        # Ensure the profile exists for existing users
        try:
            instance.profile.save()
        except Profile.DoesNotExist:
            Profile.objects.create(user=instance)


class AgentPermissionAudit(models.Model):
    """Append-only record of server-authoritative agent permission changes."""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='agent_permission_audits')
    previous_mode = models.CharField(max_length=20, choices=Profile.AGENT_PERMISSION_CHOICES)
    new_mode = models.CharField(max_length=20, choices=Profile.AGENT_PERMISSION_CHOICES)
    source = models.CharField(max_length=30, default='ui')
    request_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at', '-id']

class SuricataLog(models.Model):
    timestamp = models.DateTimeField()
    message = models.TextField()
    severity = models.CharField(max_length=50, blank=True, null=True)
    source_ip = models.GenericIPAddressField(blank=True, null=True)
    source_port = models.IntegerField(blank=True, null=True)  # Add this field
    destination_ip = models.GenericIPAddressField(blank=True, null=True)
    destination_port = models.IntegerField(blank=True, null=True)  # Add this field
    protocol = models.CharField(max_length=10, blank=True, null=True)
    classification = models.CharField(max_length=100, blank=True, null=True)
    priority = models.IntegerField(blank=True, null=True)

    def __str__(self):
        return f"{self.timestamp} - {self.message[:50]}"

    class Meta:
        ordering = ['-timestamp']
        

class AIRecommendation(models.Model):
    category = models.CharField(max_length=50)  # security / maintenance
    title = models.CharField(max_length=255)
    description = models.TextField()
    recommendation = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.category} - {self.title}"
    


class SystemScan(models.Model):
    hostname = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    os_info = models.TextField()
    scan_type = models.CharField(max_length=50)  # full, quick, security
    scanned_at = models.DateTimeField(auto_now_add=True)
    scanned_by = models.ForeignKey(User, on_delete=models.CASCADE)
    
class ConfigurationIssue(models.Model):
    SEVERITY_CHOICES = [
        ('info', 'Info'),
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    CATEGORY_CHOICES = [
        ('security', 'Security'),
        ('performance', 'Performance'),
        ('network', 'Network'),
        ('system', 'System'),
        ('service', 'Service'),
        ('storage', 'Storage'),
    ]
    
    system_scan = models.ForeignKey(SystemScan, on_delete=models.CASCADE)
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    title = models.CharField(max_length=255)
    description = models.TextField()
    config_file = models.CharField(max_length=512, null=True, blank=True)
    config_line = models.TextField(null=True, blank=True)
    current_value = models.TextField(null=True, blank=True)
    recommended_value = models.TextField(null=True, blank=True)
    fix_command = models.TextField(null=True, blank=True)
    is_auto_fixable = models.BooleanField(default=False)
    is_fixed = models.BooleanField(default=False)
    detected_at = models.DateTimeField(auto_now_add=True)
    ai_risk = models.TextField(null=True, blank=True)
    ai_recommendation = models.JSONField(null=True, blank=True) # Menggunakan JSONField untuk menyimpan object
    ai_impact = models.TextField(null=True, blank=True)

import time
import jsonfield
class ExecutionLog(models.Model):
    user_query = models.TextField()
    goal = models.TextField()
    start_time = models.FloatField(default=time.time)
    end_time = models.FloatField(null=True, blank=True)
    duration = models.FloatField(null=True, blank=True)
    final_status = models.CharField(max_length=50)
    summary = models.TextField(null=True, blank=True)
    steps = jsonfield.JSONField(default=list)  # Menyimpan array langkah-langkah
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    
    def __str__(self):
        return f"{self.user_query[:30]}... - {self.final_status}"
    

class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=200)
    blocked_at = models.DateTimeField(auto_now_add=True)
    blocked_until = models.DateTimeField(null=True, blank=True)
    is_permanent = models.BooleanField(default=False)
    suricata_log = models.ForeignKey('SuricataLog', on_delete=models.SET_NULL, null=True, blank=True)
    
    def __str__(self):
        return f"Blocked: {self.ip_address} - {self.reason}"
    
    class Meta:
        ordering = ['-blocked_at']

class WhitelistedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    description = models.CharField(max_length=200)
    added_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Whitelisted: {self.ip_address}"
    


class AIIntrusionLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    src_ip = models.GenericIPAddressField(null=True, blank=True)
    destination_ip = models.GenericIPAddressField(blank=True, null=True)
    result = models.CharField(max_length=50)
    raw_features = models.JSONField()
    confidence = models.FloatField(null=True, blank=True)  # kalau kamu tambahkan
    notes = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"[{self.timestamp}] {self.result}"


# ---------------------------------------------------------------------------
# SRE Agent Memory Models
# ---------------------------------------------------------------------------

class WorkspaceInfo(models.Model):
    """Persistent workspace analysis results — framework, language, etc."""
    workspace_path = models.CharField(max_length=512, unique=True)
    framework = models.CharField(max_length=100, default="unknown")
    language = models.CharField(max_length=100, default="unknown")
    database = models.CharField(max_length=100, default="unknown")
    web_server = models.CharField(max_length=100, default="unknown")
    dependencies_json = models.TextField(default="[]")
    deployment_json = models.TextField(default="[]")
    has_docker = models.BooleanField(default=False)
    has_nginx = models.BooleanField(default=False)
    context_json = models.TextField(default="{}")
    last_scanned = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Workspace: {self.workspace_path} ({self.framework})"

    class Meta:
        verbose_name = "Workspace Info"
        verbose_name_plural = "Workspace Info"


class AgentIncident(models.Model):
    """Past incidents and solutions — long-term memory for the SRE agent."""
    problem = models.TextField()
    solution = models.TextField()
    tools_used_json = models.TextField(default="[]")
    category = models.CharField(max_length=100, default="general")
    session_id = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"[{self.category}] {self.problem[:60]}..."

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Agent Incident"
        verbose_name_plural = "Agent Incidents"
# ---------------------------------------------------------------------------
# NeuroSysAI v4 New Models
# ---------------------------------------------------------------------------

class ToolExecutionLog(models.Model):
    conversation = models.ForeignKey(ChatSession, related_name='tool_logs', on_delete=models.CASCADE)
    tool_name = models.CharField(max_length=100)
    input_parameters = models.TextField(blank=True)
    output_result = models.TextField(blank=True)
    status = models.CharField(max_length=50) # success, error, blocked
    execution_time = models.FloatField(default=0.0) # in seconds
    risk_level = models.CharField(max_length=20, default="LOW")
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.tool_name} [{self.status}]"

class AgentArtifact(models.Model):
    workspace = models.ForeignKey(WorkspaceInfo, related_name='artifacts', on_delete=models.CASCADE)
    session_id = models.CharField(max_length=255, blank=True, null=True)
    file_path = models.CharField(max_length=1024)
    action_type = models.CharField(max_length=50) # create, edit, delete, rename
    # Which investigation produced this change, so artifacts can be grouped
    # per case instead of one undated pile.
    case_id = models.CharField(max_length=50, blank=True, default='', db_index=True)
    old_content = models.TextField(blank=True, null=True)
    new_content = models.TextField(blank=True, null=True)
    diff = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.action_type}: {self.file_path}"

class AgentEventLog(models.Model):
    conversation = models.ForeignKey(ChatSession, related_name='events', on_delete=models.CASCADE)
    event_type = models.CharField(max_length=100)
    message = models.TextField()
    metadata = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Event {self.event_type} at {self.timestamp}"

class ServerProfile(models.Model):
    name = models.CharField(max_length=255)
    hostname = models.CharField(max_length=255)
    ip = models.GenericIPAddressField()
    os = models.CharField(max_length=100)
    ssh_credential_ref = models.CharField(max_length=255, blank=True)
    last_health_check = models.DateTimeField(auto_now=True)
    services = models.JSONField(default=list, blank=True)

    def __str__(self):
        return self.name

class InfrastructureNode(models.Model):
    NODE_TYPES = [
        ('server', 'Server'),
        ('service', 'Service'),
        ('application', 'Application'),
        ('container', 'Container'),
        ('database', 'Database'),
    ]
    name = models.CharField(max_length=255)
    node_type = models.CharField(max_length=50, choices=NODE_TYPES)
    properties = models.JSONField(default=dict, blank=True)

    def __str__(self):
        return f"[{self.node_type}] {self.name}"

class InfrastructureEdge(models.Model):
    source = models.ForeignKey(InfrastructureNode, related_name='outgoing_edges', on_delete=models.CASCADE)
    target = models.ForeignKey(InfrastructureNode, related_name='incoming_edges', on_delete=models.CASCADE)
    relation_type = models.CharField(max_length=100)
    
    def __str__(self):
        return f"{self.source.name} --{self.relation_type}--> {self.target.name}"


class Investigation(models.Model):
    id = models.CharField(primary_key=True, max_length=50) # e.g. inv_abcdef12
    session = models.ForeignKey(ChatSession, on_delete=models.CASCADE, related_name='investigations')
    title = models.CharField(max_length=255)
    status = models.CharField(max_length=20, default='active') # active, completed, failed
    parent = models.ForeignKey('self', null=True, blank=True, on_delete=models.SET_NULL, related_name='next_cases')
    relation_type = models.CharField(max_length=24, default='new')
    case_kind = models.CharField(max_length=40, default='general', db_index=True)
    goal_signature = models.CharField(max_length=32, blank=True, default='', db_index=True)
    entities = models.JSONField(default=list, blank=True)
    keywords = models.JSONField(default=list, blank=True)
    context_summary = models.TextField(blank=True, default='')
    evidence_digest = models.JSONField(default=list, blank=True)
    context_refs = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.title} - {self.status}"


class SessionMemory(models.Model):
    """Thread memory for one chat session: topic, digest, entities.

    One row per session, updated as the conversation grows. The digest
    compresses old turns into a few lines so the prompt stays small while the
    horizon covers the whole session; the topic makes "what are we talking
    about" explicit instead of re-guessed every turn.
    """
    session = models.OneToOneField(ChatSession, on_delete=models.CASCADE, related_name='thread_memory')
    topic_label = models.CharField(max_length=255, blank=True, default='')
    topic_entities = models.JSONField(default=list, blank=True)
    topic_keywords = models.JSONField(default=list, blank=True)
    topic_history = models.JSONField(default=list, blank=True)
    digest = models.TextField(blank=True, default='')
    digest_upto = models.IntegerField(default=0)
    session_entities = models.JSONField(default=list, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Thread of {self.session_id}: {self.topic_label[:60]}"


class InvestigationRelation(models.Model):
    source = models.ForeignKey(Investigation, on_delete=models.CASCADE, related_name='relations_from')
    target = models.ForeignKey(Investigation, on_delete=models.CASCADE, related_name='relations_to')
    relation_type = models.CharField(max_length=32, default='related')
    confidence = models.FloatField(default=0.0)
    shared_entities = models.JSONField(default=list, blank=True)
    reason = models.CharField(max_length=255, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['source', 'target'], name='unique_investigation_relation')]
        ordering = ['-confidence', 'id']

class InvestigationTask(models.Model):
    investigation = models.ForeignKey(Investigation, on_delete=models.CASCADE, related_name='tasks')
    title = models.CharField(max_length=255)
    status = models.CharField(max_length=20, default='pending') # pending, completed
    task_order = models.IntegerField(default=0)

    class Meta:
        ordering = ['task_order']

    def __str__(self):
        return f"{self.title} ({self.status})"

class InvestigationFinding(models.Model):
    investigation = models.ForeignKey(Investigation, on_delete=models.CASCADE, related_name='findings')
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return f"Finding for {self.investigation.id}"

class AIModel(models.Model):
    PROVIDER_CHOICES = [
        ('9router', '9Router'),
        ('nvidia', 'NVIDIA AI'),
        ('ollama', 'Ollama Local'),
        ('mistral', 'Mistral AI'),
        ('groq', 'Groq'),
        ('openai', 'OpenAI'),
        ('other', 'Other'),
    ]
    ENDPOINT_CHOICES = [
        ('openai', 'OpenAI-compatible'),
        ('anthropic', 'Anthropic native'),
    ]

    name = models.CharField(max_length=100, help_text="Display name for the model option")
    model_id = models.CharField(max_length=100, help_text="Model identifier sent to engine (e.g. OPENCODE, GROQ, mistral-large-latest)")
    provider = models.CharField(max_length=50, choices=PROVIDER_CHOICES, default='9router')
    endpoint_type = models.CharField(max_length=20, choices=ENDPOINT_CHOICES, default='openai',
                                     help_text="Wire protocol: OpenAI-compatible (default) or Anthropic native Messages API")
    base_url = models.CharField(max_length=255, blank=True, null=True, help_text="Optional custom Base URL (e.g. http://localhost:20128/v1)")
    api_key = models.CharField(max_length=255, blank=True, null=True, help_text="Optional API Key for custom provider")
    TOOL_CHOICE_CHOICES = [
        ('any', 'any (force a tool call; Anthropic or langchain-normalised OpenAI)'),
        ('required', 'required (OpenAI standard forced tool call)'),
        ('auto', 'auto (model decides; use for thinking/reasoning models that reject forced calls)'),
    ]
    tool_choice = models.CharField(max_length=16, choices=TOOL_CHOICE_CHOICES, default='any',
                                   help_text="How tools are offered in the ReAct loop. DeepSeek thinking mode rejects 'any'/'required' - use 'auto' there.")
    is_active = models.BooleanField(default=True)
    order = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['order', 'id']

    def __str__(self):
        return f"{self.name} ({self.model_id} - {self.provider})"

class SystemArchitectureCache(models.Model):
    mermaid_diagram = models.TextField(blank=True, null=True)
    services_json = models.TextField(blank=True, null=True)
    insights_json = models.TextField(blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"System Architecture Cache ({self.updated_at})"


class AgentApproval(models.Model):
    """Server-side, single-use authorization for one exact tool invocation."""
    STATUS_CHOICES = [("pending", "Pending"), ("approved", "Approved"),
                      ("denied", "Denied"), ("denied_timeout", "Denied by timeout"),
                      ("consumed", "Consumed"), ("expired", "Expired")]
    session_id = models.CharField(max_length=255)
    user_id = models.CharField(max_length=255)
    request_id = models.CharField(max_length=64, unique=True, default="legacy")
    correlation_id = models.CharField(max_length=64, default="legacy")
    tool_name = models.CharField(max_length=100)
    arguments_hash = models.CharField(max_length=64)
    arguments_preview = models.JSONField(default=dict, blank=True)
    risk = models.CharField(max_length=20, default="high")
    reason = models.CharField(max_length=255, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    consumed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=["session_id", "user_id", "status"])]


class AgentRun(models.Model):
    """Durable provider-neutral lifecycle state for every agent execution."""
    STATUS_CHOICES = [(v, v.replace('_', ' ').title()) for v in (
        'queued', 'running', 'awaiting_approval', 'blocked', 'failed',
        'completed', 'cancelled', 'paused')]
    session = models.ForeignKey(ChatSession, on_delete=models.CASCADE, related_name='agent_runs')
    user_id = models.CharField(max_length=255, blank=True, default='anonymous')
    workspace_path = models.CharField(max_length=1024, blank=True, default='')
    goal = models.TextField()
    summary = models.TextField(blank=True, default='')
    recent_refs = models.JSONField(default=list, blank=True)
    environment = models.JSONField(default=dict, blank=True)
    provider = models.CharField(max_length=50, blank=True, default='')
    model = models.CharField(max_length=150, blank=True, default='')
    mode = models.CharField(max_length=40, default='guided')
    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default='queued')
    current_node = models.CharField(max_length=100, default='context')
    checkpoint_version = models.PositiveIntegerField(default=0)
    plan_version = models.PositiveIntegerField(default=0)
    budget = models.JSONField(default=dict, blank=True)
    retries = models.PositiveIntegerField(default=0)
    approval_refs = models.JSONField(default=list, blank=True)
    security_refs = models.JSONField(default=list, blank=True)
    memory_refs = models.JSONField(default=list, blank=True)
    evidence_refs = models.JSONField(default=list, blank=True)
    artifact_refs = models.JSONField(default=list, blank=True)
    idempotency_key = models.CharField(max_length=128, unique=True)
    state = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [models.Index(fields=['session', 'status']), models.Index(fields=['idempotency_key'])]


class AgentTask(models.Model):
    """Durable task graph node shared by guided and multi-agent execution."""
    STATUS_CHOICES = [(v, v.replace('_', ' ').title()) for v in (
        'pending', 'running', 'awaiting_approval', 'blocked', 'failed',
        'done', 'cancelled')]
    run = models.ForeignKey(AgentRun, on_delete=models.CASCADE, related_name='tasks')
    task_key = models.CharField(max_length=120)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, default='')
    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default='pending')
    dependencies = models.JSONField(default=list, blank=True)
    required_capability = models.CharField(max_length=120, blank=True, default='')
    selected_tool = models.CharField(max_length=120, blank=True, default='')
    attempts = models.PositiveIntegerField(default=0)
    max_attempts = models.PositiveIntegerField(default=3)
    idempotency_key = models.CharField(max_length=128, blank=True, default='')
    evidence = models.JSONField(default=list, blank=True)
    findings = models.JSONField(default=list, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['run', 'task_key'], name='unique_agent_task_key')]
        ordering = ['created_at', 'id']


class AgentTransition(models.Model):
    """Append-only checkpoint/event record used to resume and audit a run."""
    run = models.ForeignKey(AgentRun, on_delete=models.CASCADE, related_name='transitions')
    sequence = models.PositiveIntegerField()
    node = models.CharField(max_length=100)
    from_status = models.CharField(max_length=30, blank=True, default='')
    to_status = models.CharField(max_length=30)
    event_type = models.CharField(max_length=80)
    payload = models.JSONField(default=dict, blank=True)
    correlation_id = models.CharField(max_length=128, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['run', 'sequence'], name='unique_agent_transition_sequence')]
        ordering = ['sequence']


class AgentResourceLock(models.Model):
    """Durable lease preventing concurrent mutation of the same resource."""
    resource_key = models.CharField(max_length=512, unique=True)
    run = models.ForeignKey(AgentRun, on_delete=models.CASCADE, related_name='resource_locks')
    task_key = models.CharField(max_length=120)
    lease_token = models.CharField(max_length=128, unique=True)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=['resource_key', 'expires_at'])]

import os
import shutil
from django.db.models.signals import post_delete

@receiver(post_delete, sender=ChatSession)
def delete_chat_session_files(sender, instance, **kwargs):
    """
    Deletes the physical session directory (.neurosys/sessions/{session_id}) 
    when a ChatSession is deleted from the database.
    """
    session_dir = f".neurosys/sessions/{instance.id}"
    if os.path.exists(session_dir):
        try:
            shutil.rmtree(session_dir)
            print(f"Deleted session files: {session_dir}")
        except Exception as e:
            print(f"Error deleting session directory {session_dir}: {e}")
