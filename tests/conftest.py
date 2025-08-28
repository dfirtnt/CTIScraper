"""Pytest configuration and shared fixtures for CTI Scraper tests."""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from database.manager import DatabaseManager
from models.source import Source, SourceConfig


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        db_path = tmp.name
    
    # Set environment variable for test database
    os.environ['DATABASE_URL'] = f'sqlite:///{db_path}'
    
    db_manager = DatabaseManager()
    db_manager.create_tables()
    
    yield db_manager
    
    # Cleanup
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.fixture
def sample_source():
    """Create a sample source for testing."""
    config = SourceConfig(
        rate_limit=60,
        timeout=30,
        max_articles=50
    )
    
    return Source(
        id=1,
        identifier="test_source",
        name="Test Source",
        url="https://example.com",
        rss_url="https://example.com/feed.xml",
        tier=1,
        enabled=True,
        categories=["test"],
        config=config
    )


@pytest.fixture
def mock_http_response():
    """Create a mock HTTP response."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {'content-type': 'text/html'}
    mock_response.text = """
    <html>
        <head><title>Test Article</title></head>
        <body>
            <article>
                <h1>Test Article Title</h1>
                <p>This is test content for the article.</p>
            </article>
        </body>
    </html>
    """
    return mock_response
