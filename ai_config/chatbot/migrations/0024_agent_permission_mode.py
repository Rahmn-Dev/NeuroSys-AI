import uuid
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('chatbot', '0023_agentresourcelock'),
    ]

    operations = [
        migrations.AddField(
            model_name='profile', name='agent_permission_mode',
            field=models.CharField(
                choices=[('need_approval', 'Need Approval'), ('full_access', 'Full Access')],
                default='need_approval', max_length=20,
            ),
        ),
        migrations.CreateModel(
            name='AgentPermissionAudit',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('previous_mode', models.CharField(choices=[('need_approval', 'Need Approval'), ('full_access', 'Full Access')], max_length=20)),
                ('new_mode', models.CharField(choices=[('need_approval', 'Need Approval'), ('full_access', 'Full Access')], max_length=20)),
                ('source', models.CharField(default='ui', max_length=30)),
                ('request_id', models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='agent_permission_audits', to=settings.AUTH_USER_MODEL)),
            ],
            options={'ordering': ['-created_at', '-id']},
        ),
    ]
