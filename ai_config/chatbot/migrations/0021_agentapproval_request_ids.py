import uuid
from django.db import migrations, models


def populate_request_ids(apps, schema_editor):
    Approval = apps.get_model('chatbot', 'AgentApproval')
    for row in Approval.objects.using(schema_editor.connection.alias).all().iterator():
        row.request_id = uuid.uuid4().hex
        row.correlation_id = row.request_id
        row.save(update_fields=['request_id', 'correlation_id'])


class Migration(migrations.Migration):
    dependencies = [('chatbot', '0020_agentapproval')]
    operations = [
        migrations.AlterField('agentapproval', 'status', models.CharField(choices=[('pending', 'Pending'), ('approved', 'Approved'), ('denied', 'Denied'), ('denied_timeout', 'Denied by timeout'), ('consumed', 'Consumed'), ('expired', 'Expired')], default='pending', max_length=20)),
        migrations.AddField('agentapproval', 'request_id', models.CharField(null=True, max_length=64)),
        migrations.AddField('agentapproval', 'correlation_id', models.CharField(default='legacy', max_length=64)),
        migrations.RunPython(populate_request_ids, migrations.RunPython.noop),
        migrations.AlterField('agentapproval', 'request_id', models.CharField(default='legacy', max_length=64, unique=True)),
    ]
