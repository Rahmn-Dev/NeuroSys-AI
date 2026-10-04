from django.db import migrations
import re


def clean_entities(apps, schema_editor):
    Investigation = apps.get_model('chatbot', 'Investigation')
    Relation = apps.get_model('chatbot', 'InvestigationRelation')
    pattern = re.compile(r"(?:/[A-Za-z0-9_.@+\-/]+)|(?:\b(?:nginx|apache2?|httpd|postgres(?:ql)?|mysql|mariadb|redis|docker|ssh(?:d)?|systemd|suricata|gunicorn|daphne)\b)|(?:\bport\s*[:=]?\s*\d{1,5}\b)|(?::\d{3,5}\b)|(?:\b(?:400|401|403|404|408|429|500|501|502|503|504)\b)", re.I)
    case_entities = {}
    for case in Investigation.objects.all().iterator():
        source = case.title + "\n" + "\n".join(case.evidence_digest or [])
        entities = set()
        for match in pattern.finditer(source):
            entity = match.group(0).lower().strip()
            number = re.search(r"\d{2,5}", entity)
            if entity.startswith('port') or entity.startswith(':'):
                entity = f"port:{number.group(0)}"
            elif number:
                entity = f"http:{number.group(0)}"
            entities.add(entity)
        case.entities = sorted(entities)[:24]
        case_entities[case.pk] = set(case.entities)
        case.save(update_fields=['entities'])
    # Preserve every relation record while normalizing its supporting entities.
    for relation in Relation.objects.all().iterator():
        relation.shared_entities = sorted(
            case_entities.get(relation.source_id, set()) & case_entities.get(relation.target_id, set())
        )
        if relation.shared_entities:
            relation.reason = ('Shared: ' + ', '.join(relation.shared_entities))[:255]
        relation.save(update_fields=['shared_entities', 'reason'])


class Migration(migrations.Migration):
    dependencies = [('chatbot', '0026_semantic_case_memory')]
    operations = [migrations.RunPython(clean_entities, migrations.RunPython.noop)]
