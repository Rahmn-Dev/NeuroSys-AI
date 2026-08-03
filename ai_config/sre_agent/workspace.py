"""
Workspace Analyzer — scans the project environment to build context.

Detects framework, language, dependencies, deployment method, database,
and server configuration so the agent can make informed decisions.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Workspace context result
# ---------------------------------------------------------------------------

@dataclass
class WorkspaceContext:
    """Structured summary of the current workspace / environment."""
    path: str = ""
    framework: str = "unknown"
    language: str = "unknown"
    dependencies: List[str] = field(default_factory=list)
    deployment_methods: List[str] = field(default_factory=list)
    database: str = "unknown"
    web_server: str = "unknown"
    has_docker: bool = False
    has_nginx: bool = False
    has_systemd: bool = False
    key_files: List[str] = field(default_factory=list)
    project_structure: Dict[str, Any] = field(default_factory=dict)

    def to_prompt_context(self) -> str:
        """Format as text suitable for injection into an LLM prompt."""
        parts = [
            f"Workspace: {self.path}",
            f"Framework: {self.framework}",
            f"Language: {self.language}",
            f"Database: {self.database}",
            f"Web Server: {self.web_server}",
            f"Deployment: {', '.join(self.deployment_methods) or 'unknown'}",
            f"Docker: {'Yes' if self.has_docker else 'No'}",
            f"Nginx: {'Yes' if self.has_nginx else 'No'}",
            f"Systemd: {'Yes' if self.has_systemd else 'No'}",
        ]
        if self.dependencies:
            parts.append(f"Key Dependencies: {', '.join(self.dependencies[:15])}")
        if self.key_files:
            parts.append(f"Key Files: {', '.join(self.key_files[:15])}")
        return "\n".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "framework": self.framework,
            "language": self.language,
            "dependencies": self.dependencies,
            "deployment_methods": self.deployment_methods,
            "database": self.database,
            "web_server": self.web_server,
            "has_docker": self.has_docker,
            "has_nginx": self.has_nginx,
            "has_systemd": self.has_systemd,
            "key_files": self.key_files,
        }


# ---------------------------------------------------------------------------
# Framework detection markers
# ---------------------------------------------------------------------------

_FRAMEWORK_MARKERS = {
    "django": ["manage.py", "settings.py", "wsgi.py", "asgi.py"],
    "flask": ["app.py", "wsgi.py"],
    "fastapi": ["main.py"],
    "express": ["app.js", "server.js", "index.js"],
    "nextjs": ["next.config.js", "next.config.mjs", "next.config.ts"],
    "rails": ["Gemfile", "Rakefile", "config/routes.rb"],
    "spring": ["pom.xml", "build.gradle"],
    "laravel": ["artisan", "composer.json"],
}

_LANGUAGE_EXTENSIONS = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".rb": "Ruby",
    ".php": "PHP",
    ".c": "C",
    ".cpp": "C++",
}

_DB_MARKERS = {
    "postgresql": ["psycopg", "postgres", "postgresql", "pg_"],
    "mysql": ["mysqlclient", "pymysql", "mysql"],
    "sqlite": ["sqlite3", "db.sqlite"],
    "mongodb": ["pymongo", "mongodb", "mongoose"],
    "redis": ["redis", "celery"],
}


# ---------------------------------------------------------------------------
# Workspace Analyzer
# ---------------------------------------------------------------------------

class WorkspaceAnalyzer:
    """
    Scans a directory and the system environment to build a WorkspaceContext.
    Results are cached per path.
    """

    _cache: Dict[str, WorkspaceContext] = {}

    def __init__(self, path: str = "."):
        self.path = os.path.abspath(path)

    def analyze(self, force: bool = False) -> WorkspaceContext:
        """Run full analysis and return WorkspaceContext. Cached unless force=True."""
        if not force and self.path in self._cache:
            return self._cache[self.path]

        ctx = WorkspaceContext(path=self.path)

        # Scan directory
        all_files = self._scan_directory(self.path, max_depth=3)
        filenames = [os.path.basename(f) for f in all_files]
        ctx.key_files = [f for f in all_files if self._is_key_file(f)][:20]

        # Detect framework
        ctx.framework = self._detect_framework(filenames, all_files)

        # Detect language
        ctx.language = self._detect_language(all_files)

        # Detect dependencies
        ctx.dependencies = self._detect_dependencies(all_files)

        # Detect database
        ctx.database = self._detect_database(ctx.dependencies, all_files)

        # Detect deployment
        ctx.deployment_methods = self._detect_deployment(filenames, all_files)
        ctx.has_docker = any("docker" in m for m in ctx.deployment_methods)

        # Detect web server
        ctx.web_server, ctx.has_nginx = self._detect_web_server()
        ctx.has_systemd = self._detect_systemd()

        self._cache[self.path] = ctx
        return ctx

    # -- scanning -----------------------------------------------------------

    def _scan_directory(self, root: str, max_depth: int = 3) -> List[str]:
        """Walk directory tree up to max_depth, skipping hidden dirs and common noise."""
        skip_dirs = {".git", ".venv", "venv", "node_modules", "__pycache__",
                     ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
                     "staticfiles", ".ipynb_checkpoints", "eggs"}
        results = []
        root_depth = root.rstrip(os.sep).count(os.sep)

        for dirpath, dirnames, filenames in os.walk(root):
            depth = dirpath.rstrip(os.sep).count(os.sep) - root_depth
            if depth >= max_depth:
                dirnames.clear()
                continue
            # Prune skipped directories
            dirnames[:] = [d for d in dirnames if d not in skip_dirs and not d.startswith(".")]
            for f in filenames:
                results.append(os.path.join(dirpath, f))
                if len(results) > 500:  # safety cap
                    return results
        return results

    def _is_key_file(self, path: str) -> bool:
        """Identify important files worth mentioning in context."""
        name = os.path.basename(path)
        key_names = {
            "manage.py", "settings.py", "urls.py", "wsgi.py", "asgi.py",
            "docker-compose.yml", "docker-compose.yaml", "Dockerfile",
            "nginx.conf", "requirements.txt", "Pipfile", "package.json",
            "Makefile", ".env", "gunicorn.conf.py", "supervisord.conf",
            "Procfile", "Vagrantfile", "ansible.cfg",
        }
        key_extensions = {".conf", ".cfg", ".ini", ".yaml", ".yml", ".toml"}
        return name in key_names or os.path.splitext(name)[1] in key_extensions

    # -- detection ----------------------------------------------------------

    def _detect_framework(self, filenames: List[str], all_files: List[str]) -> str:
        """Detect the project framework from marker files."""
        scores: Dict[str, int] = {}
        for framework, markers in _FRAMEWORK_MARKERS.items():
            score = sum(1 for m in markers if m in filenames)
            if score > 0:
                scores[framework] = score

        # Django has extra check — look for settings.py with INSTALLED_APPS
        if "django" in scores:
            for f in all_files:
                if f.endswith("settings.py"):
                    try:
                        with open(f, "r", errors="ignore") as fh:
                            if "INSTALLED_APPS" in fh.read(2000):
                                scores["django"] += 3
                    except:
                        pass

        if scores:
            return max(scores, key=scores.get)
        return "unknown"

    def _detect_language(self, all_files: List[str]) -> str:
        """Detect primary language by file extension frequency."""
        counts: Dict[str, int] = {}
        for f in all_files:
            ext = os.path.splitext(f)[1].lower()
            if ext in _LANGUAGE_EXTENSIONS:
                lang = _LANGUAGE_EXTENSIONS[ext]
                counts[lang] = counts.get(lang, 0) + 1
        if counts:
            return max(counts, key=counts.get)
        return "unknown"

    def _detect_dependencies(self, all_files: List[str]) -> List[str]:
        """Parse dependency files for key packages."""
        deps = []
        for f in all_files:
            name = os.path.basename(f)
            try:
                if name == "requirements.txt":
                    with open(f, "r", errors="ignore") as fh:
                        for line in fh:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                pkg = line.split("==")[0].split(">=")[0].split("<=")[0].split("[")[0].strip()
                                if pkg:
                                    deps.append(pkg)
                elif name == "Pipfile":
                    with open(f, "r", errors="ignore") as fh:
                        in_packages = False
                        for line in fh:
                            if "[packages]" in line:
                                in_packages = True
                                continue
                            if line.startswith("[") and in_packages:
                                break
                            if in_packages and "=" in line:
                                pkg = line.split("=")[0].strip().strip('"')
                                if pkg:
                                    deps.append(pkg)
                elif name == "package.json":
                    with open(f, "r", errors="ignore") as fh:
                        data = json.loads(fh.read())
                        for section in ("dependencies", "devDependencies"):
                            if section in data:
                                deps.extend(data[section].keys())
            except:
                pass
        return list(dict.fromkeys(deps))[:30]  # deduplicate, cap

    def _detect_database(self, dependencies: List[str], all_files: List[str]) -> str:
        """Detect database from dependencies and config files."""
        dep_str = " ".join(dependencies).lower()
        for db, markers in _DB_MARKERS.items():
            if any(m in dep_str for m in markers):
                return db
        # Check for sqlite files
        for f in all_files:
            if f.endswith(".sqlite3") or f.endswith(".db"):
                return "sqlite"
        return "unknown"

    def _detect_deployment(self, filenames: List[str], all_files: List[str]) -> List[str]:
        """Detect deployment methods."""
        methods = []
        if "docker-compose.yml" in filenames or "docker-compose.yaml" in filenames:
            methods.append("docker-compose")
        if "Dockerfile" in filenames:
            methods.append("docker")
        if any(f.endswith(".service") for f in all_files):
            methods.append("systemd")
        if "Procfile" in filenames:
            methods.append("heroku/procfile")
        if "supervisord.conf" in filenames:
            methods.append("supervisor")
        if "gunicorn.conf.py" in filenames or "gunicorn" in " ".join(filenames):
            methods.append("gunicorn")
        return methods or ["manual"]

    def _detect_web_server(self) -> tuple[str, bool]:
        """Detect running web server on the system."""
        try:
            r = subprocess.run(
                "systemctl is-active nginx 2>/dev/null", shell=True,
                capture_output=True, text=True, timeout=5
            )
            if "active" in r.stdout.strip():
                return "nginx", True
        except:
            pass

        try:
            r = subprocess.run(
                "systemctl is-active apache2 2>/dev/null", shell=True,
                capture_output=True, text=True, timeout=5
            )
            if "active" in r.stdout.strip():
                return "apache", False
        except:
            pass

        return "unknown", False

    def _detect_systemd(self) -> bool:
        """Check if systemd is available."""
        try:
            r = subprocess.run("systemctl --version", shell=True,
                               capture_output=True, text=True, timeout=5)
            return r.returncode == 0
        except:
            return False

    # -- cache management ---------------------------------------------------

    @classmethod
    def clear_cache(cls):
        cls._cache.clear()

    def get_cached(self) -> Optional[WorkspaceContext]:
        return self._cache.get(self.path)
