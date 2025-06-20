# Generated by Django 5.1.6 on 2025-06-15 15:20

import jsonfield.fields
import time
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('chatbot', '0007_configurationissue_ai_impact_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='ExecutionLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user_query', models.TextField()),
                ('goal', models.TextField()),
                ('start_time', models.FloatField(default=time.time)),
                ('end_time', models.FloatField(blank=True, null=True)),
                ('duration', models.FloatField(blank=True, null=True)),
                ('final_status', models.CharField(max_length=50)),
                ('summary', models.TextField(blank=True, null=True)),
                ('steps', jsonfield.fields.JSONField(default=list)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
