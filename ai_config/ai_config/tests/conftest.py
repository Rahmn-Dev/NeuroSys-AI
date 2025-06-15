# ai_config/tests/conftest.py

import os
import django
import pytest

def pytest_configure():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ai_config.settings')
    django.setup()

@pytest.fixture
def ai_tool_instance():
    """Create an instance of AITools after Django setup."""
    from ai_config.views import AITools  # ← Import di dalam fungsi, setelah Django siap
    return AITools()