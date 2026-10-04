from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("chatbot", "0019_aimodel_api_key")]
    operations = [migrations.CreateModel(
        name="AgentApproval",
        fields=[
            ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
            ("session_id", models.CharField(max_length=255)),
            ("user_id", models.CharField(max_length=255)),
            ("tool_name", models.CharField(max_length=100)),
            ("arguments_hash", models.CharField(max_length=64)),
            ("arguments_preview", models.JSONField(blank=True, default=dict)),
            ("risk", models.CharField(default="high", max_length=20)),
            ("reason", models.CharField(blank=True, max_length=255)),
            ("status", models.CharField(choices=[("pending", "Pending"), ("approved", "Approved"), ("denied", "Denied"), ("consumed", "Consumed"), ("expired", "Expired")], default="pending", max_length=20)),
            ("expires_at", models.DateTimeField()),
            ("created_at", models.DateTimeField(auto_now_add=True)),
            ("approved_at", models.DateTimeField(blank=True, null=True)),
            ("consumed_at", models.DateTimeField(blank=True, null=True)),
        ],
        options={"indexes": [models.Index(fields=["session_id", "user_id", "status"], name="chatbot_age_session_7f96a5_idx")]},
    )]
