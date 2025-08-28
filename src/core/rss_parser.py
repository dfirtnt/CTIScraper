"""RSS/Atom feed parser for threat intelligence sources."""

import asyncio
from typing import List, Optional, Dict, Any
from datetime import datetime
import feedparser
import logging
from urllib.parse import urljoin

from models.article import Article, ArticleCreate
from models.source import Source
from utils.http import HTTPClient
from utils.content import DateExtractor, ContentCleaner, MetadataExtractor

logger = logging.getLogger(__name__)


class RSSParser:
    """RSS/Atom feed parser with enhanced content extraction."""
    
    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client
    
    async def parse_feed(self, source: Source) -> List[ArticleCreate]:
        """
        Parse RSS/Atom feed and extract articles.
        
        Args:
            source: Source configuration with RSS URL
            
        Returns:
            List of ArticleCreate objects
            
        Raises:
            Exception: If feed cannot be fetched or parsed
        """
        if not source.rss_url:
            raise ValueError(f"Source {source.identifier} has no RSS URL")
        
        logger.info(f"Parsing RSS feed for {source.name}: {source.rss_url}")
        
        try:
            # Fetch RSS feed
            response = await self.http_client.get(source.rss_url)
            response.raise_for_status()
            
            # Parse with feedparser
            feed_data = feedparser.parse(response.text)
            
            if feed_data.bozo and feed_data.bozo_exception:
                logger.warning(f"Feed parsing warning for {source.name}: {feed_data.bozo_exception}")
            
            # Extract articles
            articles = []
            for entry in feed_data.entries:
                try:
                    article = await self._parse_entry(entry, source)
                    if article:
                        articles.append(article)
                except Exception as e:
                    logger.error(f"Failed to parse entry in {source.name}: {e}")
                    continue
            
            logger.info(f"Extracted {len(articles)} articles from {source.name}")
            return articles
            
        except Exception as e:
            logger.error(f"Failed to parse RSS feed for {source.name}: {e}")
            raise
    
    async def _parse_entry(self, entry: Any, source: Source) -> Optional[ArticleCreate]:
        """
        Parse individual RSS entry into ArticleCreate.
        
        Args:
            entry: feedparser entry object
            source: Source configuration
            
        Returns:
            ArticleCreate object or None if parsing fails
        """
        try:
            # Extract basic fields
            title = self._extract_title(entry)
            url = self._extract_url(entry)
            published_at = self._extract_date(entry)
            
            if not title or not url:
                logger.warning(f"Skipping entry with missing title or URL in {source.name}")
                return None
            
            # Extract content
            content = await self._extract_content(entry, url, source)
            if not content:
                logger.warning(f"No content extracted for {url}")
                return None
            
            # Extract metadata
            authors = self._extract_authors(entry)
            tags = self._extract_tags(entry)
            summary = self._extract_summary(entry, content)
            
            # Build article
            article = ArticleCreate(
                source_id=source.id,
                canonical_url=url,
                title=title,
                published_at=published_at or datetime.utcnow(),
                authors=authors,
                tags=tags,
                summary=summary,
                content=content,
                metadata={
                    'feed_entry': {
                        'id': getattr(entry, 'id', ''),
                        'link': getattr(entry, 'link', ''),
                        'published': getattr(entry, 'published', ''),
                        'updated': getattr(entry, 'updated', ''),
                    },
                    'extraction_method': 'rss'
                }
            )
            
            return article
            
        except Exception as e:
            logger.error(f"Error parsing RSS entry: {e}")
            return None
    
    def _extract_title(self, entry: Any) -> Optional[str]:
        """Extract title from RSS entry."""
        title = getattr(entry, 'title', '')
        if title:
            return ContentCleaner.normalize_whitespace(title)
        return None
    
    def _extract_url(self, entry: Any) -> Optional[str]:
        """Extract canonical URL from RSS entry."""
        # Try different URL fields
        url_fields = ['link', 'id', 'guid']
        
        for field in url_fields:
            url = getattr(entry, field, '')
            if url and url.startswith(('http://', 'https://')):
                return url
        
        # Handle guid that might not be a URL
        guid = getattr(entry, 'guid', '')
        if guid and not guid.startswith(('http://', 'https://')):
            # Some feeds use non-URL GUIDs, use link instead
            return getattr(entry, 'link', '')
        
        return None
    
    def _extract_date(self, entry: Any) -> Optional[datetime]:
        """Extract publication date from RSS entry."""
        # Try different date fields
        date_fields = ['published', 'updated', 'created']
        
        for field in date_fields:
            date_str = getattr(entry, field, '')
            if date_str:
                parsed_date = DateExtractor.parse_date(date_str)
                if parsed_date:
                    return parsed_date
        
        # Try parsed date fields
        if hasattr(entry, 'published_parsed') and entry.published_parsed:
            try:
                import time
                timestamp = time.mktime(entry.published_parsed)
                return datetime.fromtimestamp(timestamp)
            except Exception:
                pass
        
        if hasattr(entry, 'updated_parsed') and entry.updated_parsed:
            try:
                import time
                timestamp = time.mktime(entry.updated_parsed)
                return datetime.fromtimestamp(timestamp)
            except Exception:
                pass
        
        return None
    
    async def _extract_content(self, entry: Any, url: str, source: Source) -> Optional[str]:
        """
        Extract content from RSS entry.
        
        Priority:
        1. Full content from feed
        2. Summary/description from feed
        3. Fetch full article from URL (with Red Canary protection)
        """
        # Try to get full content from feed first
        content = self._get_feed_content(entry)
        
        if content and len(ContentCleaner.html_to_text(content).strip()) > 200:
            # We have substantial content from the feed
            return ContentCleaner.clean_html(content)
        
        # Special handling for Red Canary - avoid compressed content issues
        if 'redcanary.com' in url.lower():
            logger.info(f"Red Canary URL detected, using RSS summary only: {url}")
            if hasattr(entry, 'summary') and entry.summary:
                summary_content = f"""Red Canary Article: {entry.title if hasattr(entry, 'title') else 'Unknown Title'}

Summary: {entry.summary}

Note: Full content extraction is disabled for Red Canary due to website compression issues.
Please visit the original article for complete content: {url}
"""
                return ContentCleaner.clean_html(summary_content)
            else:
                return f"Red Canary article - please visit: {url}"
        
        # If feed content is insufficient, fetch from URL
        try:
            response = await self.http_client.get(url)
            response.raise_for_status()
            
            # Use basic content extraction
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'lxml')
            
            # Try common content selectors
            content_selectors = [
                'article',
                '.content',
                '.post-content',
                '.entry-content',
                '.blog-content',
                'main',
                '#content'
            ]
            
            for selector in content_selectors:
                content_elem = soup.select_one(selector)
                if content_elem:
                    extracted_content = str(content_elem)
                    if len(ContentCleaner.html_to_text(extracted_content).strip()) > 100:
                        return ContentCleaner.clean_html(extracted_content)
            
            # Fallback: get body content
            body = soup.find('body')
            if body:
                return ContentCleaner.clean_html(str(body))
            
        except Exception as e:
            logger.warning(f"Failed to fetch full content from {url}: {e}")
        
        # Return feed content even if short
        return ContentCleaner.clean_html(content) if content else None
    
    def _get_feed_content(self, entry: Any) -> Optional[str]:
        """Extract content from feed entry."""
        # Try content field first (Atom)
        if hasattr(entry, 'content') and entry.content:
            if isinstance(entry.content, list) and entry.content:
                return entry.content[0].get('value', '')
            return str(entry.content)
        
        # Try description (RSS)
        if hasattr(entry, 'description') and entry.description:
            return entry.description
        
        # Try summary
        if hasattr(entry, 'summary') and entry.summary:
            return entry.summary
        
        return None
    
    def _extract_authors(self, entry: Any) -> List[str]:
        """Extract authors from RSS entry."""
        authors = []
        
        # Try author field
        if hasattr(entry, 'author') and entry.author:
            authors.append(entry.author)
        
        # Try authors list (some feeds have multiple authors)
        if hasattr(entry, 'authors') and entry.authors:
            for author in entry.authors:
                if isinstance(author, dict):
                    name = author.get('name', '')
                    if name:
                        authors.append(name)
                else:
                    authors.append(str(author))
        
        # Clean and deduplicate
        cleaned_authors = []
        for author in authors:
            author = author.strip()
            if author and author not in cleaned_authors:
                cleaned_authors.append(author)
        
        return cleaned_authors
    
    def _extract_tags(self, entry: Any) -> List[str]:
        """Extract tags/categories from RSS entry."""
        tags = set()
        
        # Try tags field
        if hasattr(entry, 'tags') and entry.tags:
            for tag in entry.tags:
                if isinstance(tag, dict):
                    term = tag.get('term', '')
                    if term:
                        tags.add(term)
                else:
                    tags.add(str(tag))
        
        # Try categories
        if hasattr(entry, 'category') and entry.category:
            tags.add(entry.category)
        
        # Convert to sorted list
        return sorted(list(tags))
    
    def _extract_summary(self, entry: Any, content: str) -> Optional[str]:
        """Extract or generate summary from RSS entry."""
        # Try summary from feed first
        if hasattr(entry, 'summary') and entry.summary:
            summary = ContentCleaner.html_to_text(entry.summary)
            summary = ContentCleaner.normalize_whitespace(summary)
            if len(summary) > 20:  # Ensure it's substantial
                return summary
        
        # Generate from content
        if content:
            return ContentCleaner.extract_summary(content)
        
        return None


class FeedValidator:
    """Utility class for validating RSS/Atom feeds."""
    
    @staticmethod
    async def validate_feed(url: str, http_client: HTTPClient) -> Dict[str, Any]:
        """
        Validate RSS/Atom feed and return metadata.
        
        Returns:
            Dictionary with validation results and feed metadata
        """
        result = {
            'valid': False,
            'feed_type': None,
            'title': None,
            'description': None,
            'entry_count': 0,
            'last_updated': None,
            'errors': []
        }
        
        try:
            # Fetch feed
            response = await http_client.get(url)
            response.raise_for_status()
            
            # Parse with feedparser
            feed_data = feedparser.parse(response.text)
            
            # Check for parsing errors
            if feed_data.bozo and feed_data.bozo_exception:
                result['errors'].append(f"Feed parsing warning: {feed_data.bozo_exception}")
            
            # Check if we have a valid feed
            if not hasattr(feed_data, 'feed') or not feed_data.entries:
                result['errors'].append("No valid feed structure or entries found")
                return result
            
            # Extract feed metadata
            feed_info = feed_data.feed
            result['valid'] = True
            result['feed_type'] = getattr(feed_info, 'version', 'unknown')
            result['title'] = getattr(feed_info, 'title', '')
            result['description'] = getattr(feed_info, 'description', '')
            result['entry_count'] = len(feed_data.entries)
            
            # Extract last updated
            if hasattr(feed_info, 'updated'):
                result['last_updated'] = DateExtractor.parse_date(feed_info.updated)
            
            # Validate entries
            valid_entries = 0
            for entry in feed_data.entries[:5]:  # Check first 5 entries
                if hasattr(entry, 'title') and hasattr(entry, 'link'):
                    valid_entries += 1
            
            if valid_entries == 0:
                result['errors'].append("No valid entries found with title and link")
                result['valid'] = False
            
        except Exception as e:
            result['errors'].append(f"Failed to fetch or parse feed: {e}")
        
        return result
