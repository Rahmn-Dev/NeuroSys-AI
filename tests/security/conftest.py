from django.conf import settings
import pytest

# The tests create/drop their minimal tables explicitly; allow that access so
# database setup errors are reported separately from assertion failures.
pytestmark = pytest.mark.django_db(transaction=True)


@pytest.fixture(autouse=True)
def allow_explicit_schema_editor(django_db_blocker):
    """The security fixtures create their tables explicitly, outside ORM fixtures."""
    with django_db_blocker.unblock():
        yield

if not settings.configured:
    settings.configure(
        SECRET_KEY="security-test-only",
        INSTALLED_APPS=["django.contrib.auth", "django.contrib.contenttypes", "chatbot"],
        DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
        USE_TZ=True,
        OLLAMA_URL="http://127.0.0.1:11434",
    )

import django
django.setup()
