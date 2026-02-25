"""
Shared fixtures for AIAAP unit tests.

Mocks psycopg2 so database.py can be imported without a running postgres.
The mock engine never actually connects - DB access is mocked in each test.
"""

import sys
from unittest.mock import MagicMock

# Stub out psycopg2 before any SQLAlchemy / service module is imported.
# This allows create_engine("postgresql://...") to succeed without a real DB.
if "psycopg2" not in sys.modules:
    psycopg2_mock = MagicMock()
    psycopg2_mock.extensions = MagicMock()
    psycopg2_mock.extras = MagicMock()
    # Provide a fake connect() that returns a mock connection
    psycopg2_mock.connect.return_value = MagicMock()
    sys.modules["psycopg2"] = psycopg2_mock
    sys.modules["psycopg2.extensions"] = psycopg2_mock.extensions
    sys.modules["psycopg2.extras"] = psycopg2_mock.extras
