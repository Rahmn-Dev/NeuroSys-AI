import os
import difflib
from datetime import datetime
from asgiref.sync import sync_to_async

class ArtifactManager:
    """Manages file changes, creates artifacts, and supports rollback."""
    
    def __init__(self, workspace_path: str, session_id: str = None, case_id: str = ""):
        self.workspace_path = workspace_path
        self.session_id = session_id
        self.case_id = case_id or ""
        
    async def _get_workspace(self):
        from chatbot.models import WorkspaceInfo
        ws, _ = await sync_to_async(WorkspaceInfo.objects.get_or_create)(workspace_path=self.workspace_path)
        return ws

    async def create_artifact(self, file_path: str, new_content: str, action_type: str = "edit"):
        """Creates an artifact record for a file change."""
        from chatbot.models import AgentArtifact
        
        abs_path = os.path.join(self.workspace_path, file_path) if not os.path.isabs(file_path) else file_path
        
        old_content = ""
        if os.path.exists(abs_path):
            try:
                with open(abs_path, 'r', encoding='utf-8') as f:
                    old_content = f.read()
            except Exception:
                pass # Binary or unreadable
                
        diff = ""
        if action_type in ["edit", "create"]:
            try:
                diff_lines = list(difflib.unified_diff(
                    old_content.splitlines(keepends=True),
                    new_content.splitlines(keepends=True),
                    fromfile=f"a/{os.path.basename(abs_path)}",
                    tofile=f"b/{os.path.basename(abs_path)}",
                    n=3
                ))
                diff = "".join(diff_lines)
            except Exception:
                diff = ""
            
        ws = await self._get_workspace()
        
        # Save to DB
        artifact = await sync_to_async(AgentArtifact.objects.create)(
            workspace=ws,
            session_id=self.session_id,
            case_id=self.case_id,
            file_path=file_path,
            action_type=action_type,
            old_content=old_content,
            new_content=new_content,
            diff=diff
        )
        return artifact

    async def upsert_artifact(self, file_path: str, new_content: str, action_type: str = "active_state"):
        """Upserts an artifact record, used for active task state to prevent duplicates."""
        from chatbot.models import AgentArtifact
        ws = await self._get_workspace()
        
        def _do_upsert():
            artifact = AgentArtifact.objects.filter(workspace=ws, session_id=self.session_id, file_path=file_path, action_type=action_type).first()
            if artifact:
                artifact.new_content = new_content
                artifact.save(update_fields=['new_content', 'created_at'])
                return artifact
            else:
                return AgentArtifact.objects.create(
                    workspace=ws,
                    session_id=self.session_id,
                    file_path=file_path,
                    action_type=action_type,
                    old_content="",
                    new_content=new_content,
                    diff=""
                )
                
        return await sync_to_async(_do_upsert)()

    async def rollback(self, artifact_id: int):
        """Rollbacks a file to its old content based on an artifact."""
        from chatbot.models import AgentArtifact
        artifact = await sync_to_async(AgentArtifact.objects.get)(id=artifact_id)
        
        abs_path = os.path.join(self.workspace_path, artifact.file_path) if not os.path.isabs(artifact.file_path) else artifact.file_path
        
        if artifact.old_content is not None:
            with open(abs_path, 'w', encoding='utf-8') as f:
                f.write(artifact.old_content)
        elif artifact.action_type == "create":
            if os.path.exists(abs_path):
                os.remove(abs_path)
                
        return True

    async def load_latest_artifact_content(self, file_path: str) -> str:
        """Loads the new_content from the latest artifact matching the file_path."""
        from chatbot.models import AgentArtifact
        ws = await self._get_workspace()
        artifact = await sync_to_async(
            lambda: AgentArtifact.objects.filter(workspace=ws, file_path=file_path).order_by('-created_at').first()
        )()
        if artifact:
            return artifact.new_content
        return ""


def render_task_plan_markdown(plan: dict) -> str:
    """Render a plan dict as a Markdown checklist.

    The .md is DERIVED from plan state on every sync — the model never edits
    it directly, so checkboxes always reflect the real execution state.
    Accepts both guided plans ({"investigation_id","title","tasks":[...]})
    and single-agent phase plans (same shape).
    """
    title = str((plan or {}).get("title", "Task Plan") or "Task Plan")[:120]
    inv_id = str((plan or {}).get("investigation_id", "") or "")
    tasks = (plan or {}).get("tasks", []) or []
    lines = [f"# Task Plan — {title}", ""]
    if inv_id:
        lines.append(f"_Investigation: `{inv_id}`_")
        lines.append("")
    done, total = 0, 0
    for idx, task in enumerate(tasks, start=1):
        total += 1
        status = str(task.get("status", "pending") or "pending").lower()
        desc = str(task.get("description", task.get("title", task.get("task", ""))) or "").strip()
        if status == "completed":
            box, done = "[x]", done + 1
        elif status in {"failed", "error"}:
            box = "[!]"
        elif status == "blocked":
            box = "[b]"
        elif status in {"running", "in_progress"}:
            box = "[>]"
        else:
            box = "[ ]"
        lines.append(f"- {box} {idx}. {desc} ({status})")
    lines += ["", f"_Progress: {done}/{total} completed_"]
    return "\n".join(lines) + "\n"
