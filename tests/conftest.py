"""
tests/conftest.py - Pytest configuration and environment setup.
"""
import os

# Enable legacy test routes during test runs so integration/unit tests can verify test endpoints
os.environ["LEASH_TEST_ROUTES"] = "1"
