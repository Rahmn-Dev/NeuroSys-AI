from django.db import migrations
import os
import re


def backfill_context_refs(apps, schema_editor):
    Investigation = apps.get_model('chatbot', 'Investigation')
    AgentRun = apps.get_model('chatbot', 'AgentRun')
    for case in Investigation.objects.filter(context_refs={}).iterator():
        run = AgentRun.objects.filter(
            session_id=case.session_id, goal__startswith=case.title
        ).order_by('-created_at').first()
        if not run:
            continue
        match = re.search(r"file://([^\]\s]+)", run.goal or "")
        file_path = match.group(1) if match else ""
        case.context_refs = {
            "goal": (run.goal or case.title)[:2000],
            "selected_file": file_path,
            "selected_file_name": os.path.basename(file_path) if file_path else "",
            "terminal_cwd": run.workspace_path or "",
            "active_workspace": run.workspace_path or "",
            "mode": run.mode,
        }
        case.save(update_fields=['context_refs'])


class Migration(migrations.Migration):
    dependencies = [('chatbot', '0029_investigation_context_refs')]
    operations = [migrations.RunPython(backfill_context_refs, migrations.RunPython.noop)]
