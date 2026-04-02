import pytest
from unittest.mock import patch, MagicMock

# Patch all external services before any imports
@pytest.fixture(autouse=True, scope="session")
def mock_external_services():
    with patch("supabase.create_client", return_value=MagicMock()), \
         patch("app.services.scheduler.start_scheduler"), \
         patch("app.services.scheduler.stop_scheduler"):
        yield
