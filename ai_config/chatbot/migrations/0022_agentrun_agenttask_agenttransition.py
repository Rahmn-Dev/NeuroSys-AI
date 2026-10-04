from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [('chatbot', '0021_agentapproval_request_ids')]
    operations = [
        migrations.AlterField(
            model_name='aimodel', name='provider',
            field=models.CharField(choices=[('9router', '9Router'), ('nvidia', 'NVIDIA AI'), ('ollama', 'Ollama Local'), ('mistral', 'Mistral AI'), ('groq', 'Groq'), ('openai', 'OpenAI'), ('other', 'Other')], default='9router', max_length=50),
        ),
        migrations.CreateModel(
            name='AgentRun',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user_id', models.CharField(blank=True, default='anonymous', max_length=255)),
                ('workspace_path', models.CharField(blank=True, default='', max_length=1024)),
                ('goal', models.TextField()), ('summary', models.TextField(blank=True, default='')),
                ('recent_refs', models.JSONField(blank=True, default=list)), ('environment', models.JSONField(blank=True, default=dict)),
                ('provider', models.CharField(blank=True, default='', max_length=50)), ('model', models.CharField(blank=True, default='', max_length=150)),
                ('mode', models.CharField(default='guided', max_length=40)),
                ('status', models.CharField(choices=[(v, v.replace('_', ' ').title()) for v in ('queued','running','awaiting_approval','blocked','failed','completed','cancelled','paused')], default='queued', max_length=30)),
                ('current_node', models.CharField(default='context', max_length=100)), ('checkpoint_version', models.PositiveIntegerField(default=0)), ('plan_version', models.PositiveIntegerField(default=0)),
                ('budget', models.JSONField(blank=True, default=dict)), ('retries', models.PositiveIntegerField(default=0)),
                ('approval_refs', models.JSONField(blank=True, default=list)), ('security_refs', models.JSONField(blank=True, default=list)), ('memory_refs', models.JSONField(blank=True, default=list)), ('evidence_refs', models.JSONField(blank=True, default=list)), ('artifact_refs', models.JSONField(blank=True, default=list)),
                ('idempotency_key', models.CharField(max_length=128, unique=True)), ('state', models.JSONField(blank=True, default=dict)),
                ('created_at', models.DateTimeField(auto_now_add=True)), ('updated_at', models.DateTimeField(auto_now=True)),
                ('session', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='agent_runs', to='chatbot.chatsession')),
            ],
            options={'indexes': [models.Index(fields=['session', 'status'], name='chatbot_age_session_5d066b_idx'), models.Index(fields=['idempotency_key'], name='chatbot_age_idempot_5629fd_idx')]},
        ),
        migrations.CreateModel(
            name='AgentTask',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('task_key', models.CharField(max_length=120)), ('title', models.CharField(max_length=255)), ('description', models.TextField(blank=True, default='')),
                ('status', models.CharField(choices=[(v, v.replace('_', ' ').title()) for v in ('pending','running','awaiting_approval','blocked','failed','done','cancelled')], default='pending', max_length=30)),
                ('dependencies', models.JSONField(blank=True, default=list)), ('required_capability', models.CharField(blank=True, default='', max_length=120)), ('selected_tool', models.CharField(blank=True, default='', max_length=120)), ('attempts', models.PositiveIntegerField(default=0)), ('max_attempts', models.PositiveIntegerField(default=3)), ('idempotency_key', models.CharField(blank=True, default='', max_length=128)), ('evidence', models.JSONField(blank=True, default=list)), ('findings', models.JSONField(blank=True, default=list)), ('metadata', models.JSONField(blank=True, default=dict)), ('created_at', models.DateTimeField(auto_now_add=True)), ('updated_at', models.DateTimeField(auto_now=True)),
                ('run', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='tasks', to='chatbot.agentrun')),
            ], options={'ordering': ['created_at', 'id']},
        ),
        migrations.CreateModel(
            name='AgentTransition',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('sequence', models.PositiveIntegerField()), ('node', models.CharField(max_length=100)), ('from_status', models.CharField(blank=True, default='', max_length=30)), ('to_status', models.CharField(max_length=30)), ('event_type', models.CharField(max_length=80)), ('payload', models.JSONField(blank=True, default=dict)), ('correlation_id', models.CharField(blank=True, default='', max_length=128)), ('created_at', models.DateTimeField(auto_now_add=True)),
                ('run', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='transitions', to='chatbot.agentrun')),
            ], options={'ordering': ['sequence']},
        ),
        migrations.AddConstraint(model_name='agenttask', constraint=models.UniqueConstraint(fields=('run', 'task_key'), name='unique_agent_task_key')),
        migrations.AddConstraint(model_name='agenttransition', constraint=models.UniqueConstraint(fields=('run', 'sequence'), name='unique_agent_transition_sequence')),
    ]
