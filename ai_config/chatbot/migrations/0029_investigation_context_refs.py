from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('chatbot', '0028_remove_time_entities')]
    operations = [
        migrations.AddField(model_name='investigation', name='context_refs',
                            field=models.JSONField(blank=True, default=dict)),
    ]
