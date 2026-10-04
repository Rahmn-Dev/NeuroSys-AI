from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [('chatbot', '0022_agentrun_agenttask_agenttransition')]
    operations = [migrations.CreateModel(
        name='AgentResourceLock',
        fields=[
            ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
            ('resource_key', models.CharField(max_length=512, unique=True)),
            ('task_key', models.CharField(max_length=120)),
            ('lease_token', models.CharField(max_length=128, unique=True)),
            ('expires_at', models.DateTimeField()),
            ('created_at', models.DateTimeField(auto_now_add=True)),
            ('run', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='resource_locks', to='chatbot.agentrun')),
        ],
        options={'indexes': [models.Index(fields=['resource_key', 'expires_at'], name='chatbot_age_resourc_50a498_idx')]},
    )]
