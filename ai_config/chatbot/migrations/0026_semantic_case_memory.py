from django.db import migrations, models
import django.db.models.deletion
import re


def backfill_case_memory(apps, schema_editor):
    Investigation = apps.get_model('chatbot', 'Investigation')
    Relation = apps.get_model('chatbot', 'InvestigationRelation')
    entity_pattern = re.compile(r"(?:/[A-Za-z0-9_.@+\-/]+)|(?:\b(?:nginx|apache2?|httpd|postgres(?:ql)?|mysql|mariadb|redis|docker|ssh(?:d)?|systemd|suricata|gunicorn|daphne)\b)|(?:\bport\s*[:=]?\s*\d{1,5}\b)|(?::\d{3,5}\b)|(?:\b(?:400|401|403|404|408|429|500|501|502|503|504)\b)", re.I)
    word_pattern = re.compile(r"[a-zA-Z0-9_.@-]{3,}")
    stop = {'yang', 'dan', 'atau', 'dari', 'untuk', 'dengan', 'pada', 'ini', 'itu', 'saya', 'aku', 'cek', 'apakah', 'error', 'failed', 'service', 'system'}
    for case in Investigation.objects.all().iterator():
        findings = list(case.findings.order_by('-created_at').values_list('content', flat=True)[:4])
        combined = case.title + "\n" + "\n".join(findings)
        entities = sorted({m.group(0).lower().strip() for m in entity_pattern.finditer(combined)})[:24]
        keywords = []
        for word in word_pattern.findall(combined.lower()):
            if word not in stop and word not in keywords:
                keywords.append(word)
        digest = [" ".join(str(item).split())[:500] for item in findings if str(item).strip()][:5]
        case.entities = entities
        case.keywords = keywords[:32]
        case.context_summary = digest[0][:1400] if digest else ''
        case.evidence_digest = digest
        case.save(update_fields=['entities', 'keywords', 'context_summary', 'evidence_digest'])
    session_ids = Investigation.objects.values_list('session_id', flat=True).distinct()
    for session_id in session_ids:
        cases = list(Investigation.objects.filter(session_id=session_id))
        for source in cases:
            source_entities = set(source.entities or [])
            if not source_entities:
                continue
            ranked = []
            for target in cases:
                if target.pk == source.pk:
                    continue
                shared = sorted(source_entities & set(target.entities or []))
                if shared:
                    ranked.append((target, shared, min(1.0, 0.65 + 0.1 * len(shared))))
            for target, shared, confidence in sorted(ranked, key=lambda row: row[2], reverse=True)[:5]:
                Relation.objects.update_or_create(source=source, target=target, defaults={
                    'relation_type': 'same_entity', 'confidence': confidence,
                    'shared_entities': shared, 'reason': ('Shared: ' + ', '.join(shared))[:255],
                })


class Migration(migrations.Migration):
    dependencies = [('chatbot', '0025_investigation_case_graph')]

    operations = [
        migrations.AddField(model_name='investigation', name='entities', field=models.JSONField(blank=True, default=list)),
        migrations.AddField(model_name='investigation', name='keywords', field=models.JSONField(blank=True, default=list)),
        migrations.AddField(model_name='investigation', name='context_summary', field=models.TextField(blank=True, default='')),
        migrations.AddField(model_name='investigation', name='evidence_digest', field=models.JSONField(blank=True, default=list)),
        migrations.CreateModel(
            name='InvestigationRelation',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('relation_type', models.CharField(default='related', max_length=32)),
                ('confidence', models.FloatField(default=0.0)),
                ('shared_entities', models.JSONField(blank=True, default=list)),
                ('reason', models.CharField(blank=True, default='', max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('source', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='relations_from', to='chatbot.investigation')),
                ('target', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='relations_to', to='chatbot.investigation')),
            ],
            options={'ordering': ['-confidence', 'id']},
        ),
        migrations.AddConstraint(model_name='investigationrelation',
            constraint=models.UniqueConstraint(fields=('source', 'target'), name='unique_investigation_relation')),
        migrations.RunPython(backfill_case_memory, migrations.RunPython.noop),
    ]
