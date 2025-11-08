# /home/revant/Projects/cfe-bench/development/frappe-bench/apps/castlecraft/tests/conftest.py
from unittest.mock import MagicMock

import pytest


class MockDoc(dict):
    """A mock object that simulates a Frappe DocType using a dictionary."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__dict__ = self

    def get_password(self, key):
        return self.get(key)


@pytest.fixture(autouse=True)
def mock_frappe(mocker):
    """An autouse fixture that mocks castlecraft.auth.frappe for all tests."""
    # Patch the frappe module where it's used
    mock = mocker.patch("castlecraft.auth.frappe")
    # Pre-configure the cache on this mock to ensure test isolation
    cache_mock = MagicMock()
    cache_mock.get_value.return_value = None
    mock.cache.return_value = cache_mock
    # The mock is now active for the duration of the test.
    # We don't need to return it unless a test specifically needs to inspect it.
