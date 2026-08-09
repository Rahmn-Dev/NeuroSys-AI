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
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    is_active_session = models.BooleanField(default=False)  # Track active session
    image = models.ImageField(upload_to='profile_images/', blank=True, null=True)  # Profile image

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
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.title} - {self.status}"

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
        ('openai', 'OpenAI'),
        ('other', 'Other'),
    ]

    name = models.CharField(max_length=100, help_text="Display name for the model option")
    model_id = models.CharField(max_length=100, help_text="Model identifier sent to engine (e.g. OPENCODE, GROQ, mistral-large-latest)")
    provider = models.CharField(max_length=50, choices=PROVIDER_CHOICES, default='9router')
    base_url = models.CharField(max_length=255, blank=True, null=True, help_text="Optional custom Base URL (e.g. http://localhost:20128/v1)")
    is_active = models.BooleanField(default=True)
    order = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['order', 'id']

    def __str__(self):
        return f"{self.name} ({self.model_id} - {self.provider})"

