from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [('chatbot', '0024_agent_permission_mode')]

    operations = [
        migrations.AddField(model_name='investigation', name='parent',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                                    related_name='next_cases', to='chatbot.investigation')),
        migrations.AddField(model_name='investigation', name='relation_type',
            field=models.CharField(default='new', max_length=24)),
        migrations.AddField(model_name='investigation', name='case_kind',
            field=models.CharField(db_index=True, default='general', max_length=40)),
        migrations.AddField(model_name='investigation', name='goal_signature',
            field=models.CharField(blank=True, db_index=True, default='', max_length=32)),
    ]
