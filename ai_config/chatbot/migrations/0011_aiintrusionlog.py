# Generated by Django 5.1.6 on 2025-06-26 08:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('chatbot', '0010_whitelistedip_blockedip'),
    ]

    operations = [
        migrations.CreateModel(
            name='AIIntrusionLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('src_ip', models.GenericIPAddressField(blank=True, null=True)),
                ('result', models.CharField(max_length=50)),
                ('raw_features', models.JSONField()),
                ('confidence', models.FloatField(blank=True, null=True)),
                ('notes', models.TextField(blank=True, null=True)),
            ],
        ),
    ]
