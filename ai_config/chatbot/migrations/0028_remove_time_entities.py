from django.db import migrations
import re


def remove_time_entities(apps, schema_editor):
    Investigation = apps.get_model('chatbot', 'Investigation')
    for case in Investigation.objects.all().iterator():
        source = (case.title + "\n" + "\n".join(case.evidence_digest or [])).lower()
        cleaned = []
        for entity in case.entities or []:
            match = re.fullmatch(r"port:(\d{1,2})", str(entity))
            if match and not re.search(rf"\bport\s*[:=]?\s*{re.escape(match.group(1))}\b", source):
                continue
            cleaned.append(entity)
        case.entities = cleaned
        case.save(update_fields=['entities'])


class Migration(migrations.Migration):
    dependencies = [('chatbot', '0027_clean_semantic_entities')]
    operations = [migrations.RunPython(remove_time_entities, migrations.RunPython.noop)]
