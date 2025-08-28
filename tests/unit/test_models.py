"""Tests for Pydantic data models."""

import pytest
from datetime import datetime
from pydantic import ValidationError

from models.article import Article, ArticleCreate
from models.source import Source, SourceConfig


class TestArticleModel:
    """Test suite for Article models."""
    
    def test_article_create_with_valid_data(self):
        """Test creating ArticleCreate with valid data."""
        article_data = {
            "source_id": 1,
            "canonical_url": "https://example.com/article",
            "title": "Test Article",
            "content": "This is test content for the article.",
            "published_at": datetime.now()
        }
        
        article = ArticleCreate(**article_data)
        
        assert article.title == "Test Article"
        assert article.source_id == 1
        assert article.canonical_url == "https://example.com/article"
        assert article.content_hash is not None  # Auto-generated
        assert len(article.content_hash) == 64  # SHA256 hex length
    
    def test_article_create_auto_generates_hash(self):
        """Test that content_hash is auto-generated if not provided."""
        article = ArticleCreate(
            source_id=1,
            canonical_url="https://example.com/test",
            title="Test Title",
            content="Test Content",
            published_at=datetime.now()
        )
        
        # Hash should be generated automatically
        assert article.content_hash is not None
        assert isinstance(article.content_hash, str)
        assert len(article.content_hash) == 64
    
    def test_article_create_with_provided_hash(self):
        """Test ArticleCreate with explicitly provided hash."""
        custom_hash = "a" * 64  # Valid 64-character hash
        
        article = ArticleCreate(
            source_id=1,
            canonical_url="https://example.com/test",
            title="Test Title",
            content="Test Content",
            published_at=datetime.now(),
            content_hash=custom_hash
        )
        
        assert article.content_hash == custom_hash
    
    def test_article_create_validation_errors(self):
        """Test validation errors for invalid data."""
        # Missing required fields
        with pytest.raises(ValidationError):
            ArticleCreate()
        
        # Invalid URL
        with pytest.raises(ValidationError):
            ArticleCreate(
                source_id=1,
                canonical_url="not-a-url",
                title="Test",
                content="Content",
                published_at=datetime.now()
            )


class TestSourceModel:
    """Test suite for Source models."""
    
    def test_source_config_creation(self):
        """Test creating SourceConfig with valid data."""
        config = SourceConfig(
            rate_limit=60,
            timeout=30,
            max_articles=100
        )
        
        assert config.rate_limit == 60
        assert config.timeout == 30
        assert config.max_articles == 100
    
    def test_source_creation(self):
        """Test creating Source with valid data."""
        config = SourceConfig(rate_limit=60)
        
        source = Source(
            id=1,
            identifier="test_source",
            name="Test Source",
            url="https://example.com",
            tier=1,
            enabled=True,
            categories=["test"],
            config=config
        )
        
        assert source.identifier == "test_source"
        assert source.name == "Test Source"
        assert source.tier == 1
        assert source.enabled is True
        assert "test" in source.categories
    
    def test_source_validation_errors(self):
        """Test Source validation errors."""
        # Invalid tier
        with pytest.raises(ValidationError):
            Source(
                id=1,
                identifier="test",
                name="Test",
                url="https://example.com",
                tier=0,  # Invalid tier
                enabled=True,
                categories=[],
                config=SourceConfig()
            )
