"""Tests for content utility functions."""

import pytest
from utils.content import ContentCleaner


class TestContentCleaner:
    """Test suite for ContentCleaner utility."""
    
    def test_html_to_text_basic(self):
        """Test basic HTML to text conversion."""
        html = "<p>This is a <strong>test</strong> paragraph.</p>"
        result = ContentCleaner.html_to_text(html)
        
        assert "This is a test paragraph." in result
        assert "<p>" not in result
        assert "<strong>" not in result
    
    def test_html_to_text_with_line_breaks(self):
        """Test HTML to text with proper line breaks."""
        html = """
        <h1>Title</h1>
        <p>First paragraph.</p>
        <p>Second paragraph.</p>
        """
        result = ContentCleaner.html_to_text(html)
        
        assert "Title" in result
        assert "First paragraph." in result
        assert "Second paragraph." in result
    
    def test_normalize_whitespace(self):
        """Test whitespace normalization."""
        text = "This   has    multiple    spaces\n\n\nand   newlines"
        result = ContentCleaner.normalize_whitespace(text)
        
        expected = "This has multiple spaces and newlines"
        assert result == expected
    
    def test_clean_text_characters(self):
        """Test cleaning of non-printable characters."""
        # Text with control characters
        text = "Normal text\x00with\x01control\x02chars"
        result = ContentCleaner.clean_text_characters(text)
        
        assert result == "Normal textwithcontrolchars"
        assert "\x00" not in result
        assert "\x01" not in result
    
    def test_enhanced_html_clean(self):
        """Test enhanced HTML cleaning."""
        html = """
        <html>
        <head><title>Test</title></head>
        <body>
            <nav>Navigation</nav>
            <article>
                <h1>Article Title</h1>
                <p>Article content goes here.</p>
            </article>
            <footer>Footer content</footer>
            <script>alert('test');</script>
        </body>
        </html>
        """
        
        result = ContentCleaner.enhanced_html_clean(html)
        
        # Should contain article content
        assert "Article Title" in result
        assert "Article content goes here." in result
        
        # Should not contain navigation, footer, or script
        assert "Navigation" not in result
        assert "Footer content" not in result
        assert "alert" not in result
    
    def test_clean_html_integration(self):
        """Test the main clean_html method."""
        html = """
        <article>
            <h1>Important News</h1>
            <p>This is <em>important</em> threat intelligence.</p>
            <script>// This should be removed</script>
        </article>
        """
        
        result = ContentCleaner.clean_html(html)
        
        assert "Important News" in result
        assert "important threat intelligence" in result
        assert "script" not in result.lower()
        assert isinstance(result, str)
