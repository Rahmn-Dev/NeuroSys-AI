"""
Parallel Execution Engine — concurrent DAG-based task executor.

Executes independent tasks concurrently using asyncio, respecting
dependency edges in the task DAG.  Workers invoke tools directly
(no LLM call per task); the planner already chose tool + args.

Safety checks still run per-tool before execution.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

from .safety import SafetyLayer, SafetyVerdict
from .tools.registry import ToolRegistry


# ---------------------------------------------------------------------------
# Result container for a single task execution
# ---------------------------------------------------------------------------

@dataclass
class TaskResult:
    task_id: str
    tool_name: str
    tool_args: dict
    output: str
    exit_code: int            # 0 = success, non-zero = failure
    duration: float
    safety_verdict: str       # "approved", "warn", "blocked", "approval_required"
    error: str = ""


# ---------------------------------------------------------------------------
# Parallel Executor
# ---------------------------------------------------------------------------

class ParallelExecutor:
    """
    Executes a DAG of tasks concurrently.

    Each task must have:
        id:          str          unique identifier ("A", "B", ...)
        depends_on:  list[str]    task IDs that must complete first (empty = independent)
        tool:        str          tool name from the registry
        tool_args:   dict         arguments to pass to the tool
        description: str          human-readable description

    The executor:
      1. Validates the DAG (no cycles)
      2. Finds the ready set (tasks with all dependencies met)
      3. Launches ready tasks concurrently (up to MAX_CONCURRENT)
      4. Collects results and unlocks dependents
      5. Prevents duplicate (tool, args) executions
      6. Respects safety layer per-tool
    """

    MAX_CONCURRENT = 5

    def __init__(self, safety: Optional[SafetyLayer] = None):
        self.safety = safety or SafetyLayer()
        self.registry = ToolRegistry()
        self._execution_history: Set[str] = set()   # tracks (tool+args) hashes

    # -- public interface ----------------------------------------------------

    async def execute_dag(
        self,
        tasks: List[dict],
        tool_map: Dict[str, Any],
        on_task_start: Optional[Callable] = None,
        on_task_end: Optional[Callable] = None,
        on_progress: Optional[Callable] = None,
    ) -> List[TaskResult]:
        """
        Execute all tasks in the DAG respecting dependencies.

        Callbacks (all optional, can be sync or async):
          on_task_start(task_id, tool_name, tool_args)
          on_task_end(task_id, result: TaskResult)
          on_progress(completed_count, total_count)

        Returns list of TaskResult for every task.
        """
        if not tasks:
            return []

        # Build structures
        task_index = {t["id"]: t for t in tasks}
        results: Dict[str, TaskResult] = {}
        completed_ids: Set[str] = set()
        semaphore = asyncio.Semaphore(self.MAX_CONCURRENT)

        # Validate DAG (simple cycle check via topological sort feasibility)
        self._validate_dag(tasks, task_index)

        total = len(tasks)

        async def _run_task(task: dict) -> TaskResult:
            async with semaphore:
                return await self._execute_single(task, tool_map, on_task_start, on_task_end)

        # Iterative DAG resolution
        while len(completed_ids) < total:
            # Find tasks whose dependencies are all met
            ready = [
                t for t in tasks
                if t["id"] not in completed_ids
                and all(dep in completed_ids for dep in t.get("depends_on", []))
            ]

            if not ready:
                # Remaining tasks have unmet dependencies — shouldn't happen in valid DAG
                break

            # Launch all ready tasks concurrently
            coros = [_run_task(t) for t in ready]
            batch_results = await asyncio.gather(*coros, return_exceptions=True)

            for task, result in zip(ready, batch_results):
                if isinstance(result, Exception):
                    result = TaskResult(
                        task_id=task["id"],
                        tool_name=task.get("tool", "unknown"),
                        tool_args=task.get("tool_args", {}),
                        output="",
                        exit_code=1,
                        duration=0.0,
                        safety_verdict="error",
                        error=str(result),
                    )
                results[task["id"]] = result
                completed_ids.add(task["id"])

            # Progress callback
            if on_progress:
                await self._maybe_await(on_progress, len(completed_ids), total)

        return [results[t["id"]] for t in tasks if t["id"] in results]

    # -- internal helpers ----------------------------------------------------

    async def _execute_single(
        self,
        task: dict,
        tool_map: Dict[str, Any],
        on_task_start: Optional[Callable],
        on_task_end: Optional[Callable],
    ) -> TaskResult:
        """Execute a single task: safety check → tool invocation → result."""
        task_id = task["id"]
        tool_name = task.get("tool", "")
        tool_args = task.get("tool_args", {})
        description = task.get("description", "")

        # Duplicate prevention
        exec_hash = self._hash_execution(tool_name, tool_args)
        if exec_hash in self._execution_history:
            return TaskResult(
                task_id=task_id,
                tool_name=tool_name,
                tool_args=tool_args,
                output=f"Skipped: duplicate execution of {tool_name}({json.dumps(tool_args)})",
                exit_code=0,
                duration=0.0,
                safety_verdict="skipped",
            )
        self._execution_history.add(exec_hash)

        # Safety check
        meta = self.registry.get_metadata(tool_name)
        if meta:
            check = self.safety.check(meta, tool_args)
            if check.verdict == SafetyVerdict.BLOCKED:
                return TaskResult(
                    task_id=task_id,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    output=f"BLOCKED by safety layer: {check.reason}",
                    exit_code=1,
                    duration=0.0,
                    safety_verdict="blocked",
                )
            if check.verdict == SafetyVerdict.APPROVAL_REQUIRED:
                return TaskResult(
                    task_id=task_id,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    output=f"APPROVAL REQUIRED: {check.reason}",
                    exit_code=1,
                    duration=0.0,
                    safety_verdict="approval_required",
                )
            safety_verdict = check.verdict.value
        else:
            safety_verdict = "unknown_tool"

        # Emit start callback
        if on_task_start:
            await self._maybe_await(on_task_start, task_id, tool_name, tool_args)

        # Execute tool
        start_time = time.time()
        try:
            tool_obj = tool_map.get(tool_name)
            if not tool_obj:
                return TaskResult(
                    task_id=task_id,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    output=f"Tool '{tool_name}' not found in tool_map.",
                    exit_code=1,
                    duration=0.0,
                    safety_verdict=safety_verdict,
                    error=f"Unknown tool: {tool_name}",
                )

            # LangChain tools have an .invoke() method
            output = await asyncio.get_event_loop().run_in_executor(
                None, lambda: tool_obj.invoke(tool_args)
            )
            output_str = str(output) if output else ""
            duration = time.time() - start_time

            result = TaskResult(
                task_id=task_id,
                tool_name=tool_name,
                tool_args=tool_args,
                output=output_str[:4000],
                exit_code=0,
                duration=duration,
                safety_verdict=safety_verdict,
            )
        except Exception as e:
            duration = time.time() - start_time
            result = TaskResult(
                task_id=task_id,
                tool_name=tool_name,
                tool_args=tool_args,
                output="",
                exit_code=1,
                duration=duration,
                safety_verdict=safety_verdict,
                error=str(e),
            )

        # Emit end callback
        if on_task_end:
            await self._maybe_await(on_task_end, task_id, result)

        return result

    def _hash_execution(self, tool_name: str, tool_args: dict) -> str:
        """Create a deterministic hash of (tool_name, tool_args)."""
        key = json.dumps({"t": tool_name, "a": tool_args}, sort_keys=True)
        return hashlib.md5(key.encode()).hexdigest()

    def _validate_dag(self, tasks: List[dict], task_index: Dict[str, dict]) -> None:
        """Ensure no cycles exist (Kahn's algorithm)."""
        in_degree = {t["id"]: 0 for t in tasks}
        adj: Dict[str, List[str]] = {t["id"]: [] for t in tasks}

        for t in tasks:
            for dep in t.get("depends_on", []):
                if dep in task_index:
                    adj[dep].append(t["id"])
                    in_degree[t["id"]] += 1

        queue = [tid for tid, deg in in_degree.items() if deg == 0]
        visited = 0

        while queue:
            node = queue.pop(0)
            visited += 1
            for child in adj[node]:
                in_degree[child] -= 1
                if in_degree[child] == 0:
                    queue.append(child)

        if visited != len(tasks):
            raise ValueError("Task DAG contains a cycle — cannot execute.")

    @staticmethod
    async def _maybe_await(fn: Callable, *args) -> Any:
        """Call fn with args; await if it's a coroutine."""
        result = fn(*args)
        if asyncio.iscoroutine(result):
            return await result
        return result
