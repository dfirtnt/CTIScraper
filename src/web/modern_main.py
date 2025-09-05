"""
Modern FastAPI Application for CTI Scraper

Uses async/await, PostgreSQL, and proper connection management.
"""

import os
import sys
import json
import asyncio
import logging
import httpx
import traceback
from pathlib import Path
from typing import List, Optional, Dict, Any
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from collections import defaultdict

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request, Response, File, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, HttpUrl

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

# Add src to path for imports
src_path = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_path))

from src.database.async_manager import async_db_manager
from src.models.source import Source, SourceUpdate, SourceFilter
from src.models.article import Article, ArticleUpdate
from src.worker.celery_app import test_source_connectivity, collect_from_source
from src.utils.search_parser import parse_boolean_search, get_search_help_text
from src.utils.ioc_extractor import HybridIOCExtractor, IOCExtractionResult
from src.utils.behavior_extractor import SecureBERTBehaviorExtractor, BehaviorExtractionResult
from src.core.rss_parser import RSSParser
from src.core.modern_scraper import ModernScraper
from src.utils.http import HTTPClient

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Model mapping for Ollama models
OLLAMA_MODEL_MAPPING = {
    'mistral': 'mistral:7b',
    'llama3.1': 'llama3.1:8b',
    'codellama': 'codellama:7b'
}

# URL Submission Models
class URLSubmissionRequest(BaseModel):
    url: HttpUrl
    name: Optional[str] = None
    description: Optional[str] = None

class URLSubmissionResponse(BaseModel):
    success: bool
    message: str
    article_id: Optional[int] = None
    article_title: Optional[str] = None
    source_name: Optional[str] = None
    errors: Optional[List[str]] = None

def get_ollama_model(frontend_model: str) -> str:
    """Get the Ollama model name from frontend model selection."""
    return OLLAMA_MODEL_MAPPING.get(frontend_model, 'mistral:7b')

async def get_cyber_focused_summary(article, ai_model: str) -> str:
    """Get a cyber-focused summary using a fast model (Mistral) for extraction."""
    try:
        # Use Mistral for fast cyber-focused summarization
        ollama_url = os.getenv('LLM_API_URL', 'http://cti_ollama:11434')
        mistral_model = 'mistral:7b'  # Fast model for summarization
        
        # Smart content truncation for summarization
        content_limit = int(os.getenv('CYBER_SUMMARY_LIMIT', '10000'))
        content = article.content[:content_limit]
        if len(article.content) > content_limit:
            content += f"\n\n[Content truncated at {content_limit:,} characters for summarization.]"
        
        # Cyber-focused summarization prompt
        summary_prompt = f"""Extract and summarize the key cybersecurity and threat hunting elements from this article.

Article Title: {article.title}
Source: {article.canonical_url or 'N/A'}
Published: {article.published_at or 'N/A'}

Article Content:
{content}

Please provide a structured summary focusing on:

1. **Threat Actor/Group**: Who is responsible for the attack?
2. **Attack Techniques**: What methods/tactics were used?
3. **Indicators of Compromise (IOCs)**: IPs, domains, hashes, files
4. **Tactics, Techniques, Procedures (TTPs)**: MITRE ATT&CK techniques
5. **Threat Hunting Opportunities**: What to look for in logs/systems
6. **Key Technical Details**: Commands, registry keys, file paths
7. **Impact/Scope**: What was compromised/affected

Format as a clear, structured summary suitable for threat intelligence analysis."""

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{ollama_url}/api/generate",
                json={
                    "model": mistral_model,
                    "prompt": summary_prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.2,  # Lower temperature for more focused extraction
                        "num_predict": 1500   # Reasonable length for summary
                    }
                },
                timeout=60.0  # Fast model should be quick
            )
            
            if response.status_code != 200:
                logger.warning(f"Failed to get cyber summary from Mistral: {response.status_code}")
                # Fallback to truncated original content
                return content
            
            result = response.json()
            cyber_summary = result.get('response', '')
            
            # Add metadata about the summarization
            cyber_summary += f"\n\n---\n*Cyber-focused summary generated by {mistral_model} for enhanced analysis*"
            
            logger.info(f"Generated cyber summary of {len(cyber_summary)} characters for article {article.id}")
            return cyber_summary
            
    except Exception as e:
        logger.error(f"Error generating cyber summary: {e}")
        # Fallback to truncated original content
        content_limit = int(os.getenv('CYBER_SUMMARY_LIMIT', '10000'))
        return article.content[:content_limit]

# Templates
templates = Jinja2Templates(directory="src/web/templates")

# Custom Jinja2 filter for highlighting keywords
def highlight_keywords(text: str, perfect_matches: list, good_matches: list) -> str:
    """Highlight perfect and good keyword matches in text."""
    import re
    
    if not text:
        return text
    
    # Escape special regex characters in keywords
    def escape_regex(keyword):
        return re.escape(keyword)
    
    # Create highlighting spans
    highlighted_text = text
    
    # Highlight perfect keywords with purple background
    for keyword in perfect_matches:
        if keyword:
            escaped_keyword = escape_regex(keyword)
            pattern = re.compile(escaped_keyword, re.IGNORECASE)
            highlighted_text = pattern.sub(
                f'<span class="bg-purple-200 dark:bg-purple-800 text-purple-900 dark:text-purple-100 px-1 rounded font-semibold">{keyword}</span>',
                highlighted_text
            )
    
    # Highlight good keywords with green background
    for keyword in good_matches:
        if keyword:
            escaped_keyword = escape_regex(keyword)
            pattern = re.compile(escaped_keyword, re.IGNORECASE)
            highlighted_text = pattern.sub(
                f'<span class="bg-green-200 dark:bg-green-800 text-green-900 dark:text-green-100 px-1 rounded font-semibold">{keyword}</span>',
                highlighted_text
            )
    
    return highlighted_text

# Register the custom filter
templates.env.filters["highlight_keywords"] = highlight_keywords

# Application lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    # Startup
    logger.info("Starting CTI Scraper application...")
    
    # Create database tables
    try:
        await async_db_manager.create_tables()
        logger.info("Database tables created/verified successfully")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise
    
    # Health check
    try:
        stats = await async_db_manager.get_database_stats()
        logger.info(f"Database connection successful: {stats['total_sources']} sources, {stats['total_articles']} articles")
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down CTI Scraper application...")
    await async_db_manager.close()
    logger.info("Application shutdown complete")

# Create FastAPI app
app = FastAPI(
    title="CTI Scraper - Modern Threat Intelligence Platform",
    description="Enterprise-grade threat intelligence aggregation and analysis platform",
    version="2.0.0",
    lifespan=lifespan
)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])

# Static files
app.mount("/static", StaticFiles(directory="src/web/static"), name="static")

# Dependency for database session
async def get_db_session() -> AsyncSession:
    """Get database session for dependency injection."""
    async with async_db_manager.get_session() as session:
        yield session

# Health check endpoint
@app.get("/api/health")
async def health_check():
    """Health check endpoint for monitoring."""
    try:
        stats = await async_db_manager.get_database_stats()
        return {
            "status": "healthy",
            "timestamp": "2024-01-01T00:00:00Z",
            "database": {
                "status": "connected",
                "sources": stats["total_sources"],
                "articles": stats["total_articles"]
            },
            "version": "2.0.0"
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unhealthy")

# Dashboard
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page."""
    try:
        stats = await async_db_manager.get_database_stats()
        sources = await async_db_manager.list_sources()
        recent_articles = await async_db_manager.list_articles(limit=5)
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "stats": stats,
                "sources": sources,
                "recent_articles": recent_articles,
                "current_time": current_time
            }
        )
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": str(e)},
            status_code=500
        )

# Settings page
@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Settings page."""
    try:
        return templates.TemplateResponse(
            "settings.html",
            {"request": request}
        )
    except Exception as e:
        logger.error(f"Settings page error: {e}")
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": str(e)},
            status_code=500
        )

# Sources management
@app.get("/sources", response_class=HTMLResponse)
async def sources_list(request: Request):
    """Sources management page."""
    try:
        sources = await async_db_manager.list_sources()
        quality_stats = await async_db_manager.get_source_quality_stats()
        
        # Debug logging
        logger.info(f"Quality stats returned: {len(quality_stats)} entries")
        for stat in quality_stats[:5]:  # Log first 5 entries
            logger.info(f"Source {stat['source_id']}: {stat['name']} - Rejection rate: {stat['rejection_rate']}%")
        
        # Create a lookup for quality stats by source ID
        quality_lookup = {stat["source_id"]: stat for stat in quality_stats}
        
        # Sort sources by acceptance rate (chosen percentage) with 100% at the top
        def get_acceptance_rate(source):
            if source.id in quality_lookup:
                return quality_lookup[source.id]['acceptance_rate']
            return 0  # Sources without stats go to bottom
        
        sources_sorted = sorted(sources, key=get_acceptance_rate, reverse=True)
        
        return templates.TemplateResponse(
            "sources.html",
            {
                "request": request, 
                "sources": sources_sorted,
                "quality_stats": quality_lookup
            }
        )
    except Exception as e:
        logger.error(f"Sources list error: {e}")
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": str(e)},
            status_code=500
        )

@app.get("/api/sources")
async def api_sources_list(filter_params: SourceFilter = Depends()):
    """API endpoint for listing sources."""
    try:
        sources = await async_db_manager.list_sources(filter_params)
        return {"sources": [source.dict() for source in sources]}
    except Exception as e:
        logger.error(f"API sources list error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/sources/{source_id}")
async def api_get_source(source_id: int):
    """API endpoint for getting a specific source."""
    try:
        source = await async_db_manager.get_source(source_id)
        if not source:
            raise HTTPException(status_code=404, detail="Source not found")
        return source.dict()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"API get source error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/sources/{source_id}/toggle")
async def api_toggle_source_status(source_id: int, request: Request):
    """Toggle source active status with optional collection period."""
    try:
        collection_days = None
        try:
            request_data = await request.json()
            collection_days = request_data.get('collection_days')
        except:
            # If no JSON body, collection_days remains None
            pass
        
        result = await async_db_manager.toggle_source_status(source_id, collection_days=collection_days)
        if not result:
            raise HTTPException(status_code=404, detail="Source not found")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"API toggle source status error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/sources/submit-url", response_model=URLSubmissionResponse)
async def api_submit_url(request: URLSubmissionRequest, background_tasks: BackgroundTasks):
    """Submit a URL for single article ingestion."""
    try:
        url_str = str(request.url)
        logger.info(f"Single article submission request for: {url_str}")
        
        # Check if article already exists
        existing_articles = await async_db_manager.list_articles()
        for article in existing_articles:
            if article.canonical_url == url_str:
                return URLSubmissionResponse(
                    success=False,
                    message="This article has already been ingested",
                    errors=[f"Article '{article.title}' already exists in the database"]
                )
        
        # Generate source name if not provided
        if not request.name:
            request.name = "Manual Submission"
        
        # Parse URL for later use
        from urllib.parse import urlparse
        parsed_url = urlparse(url_str)
        
        # Create a temporary source for this single article
        import hashlib
        identifier = f"user_submitted_{hashlib.md5(url_str.encode()).hexdigest()[:8]}"
        
        # Check if we already have a user-submitted source for this domain
        existing_source = await async_db_manager.get_source_by_identifier(identifier)
        
        if not existing_source:
            # Create a temporary source for user-submitted articles
            from src.models.source import SourceCreate, SourceConfig
            
            config = SourceConfig(
                allow=[parsed_url.netloc],
                post_url_regex=[f"^{parsed_url.scheme}://{parsed_url.netloc}/.*"],
                robots={
                    "enabled": True,
                    "user_agent": "CTIScraper/2.0",
                    "respect_delay": True,
                    "max_requests_per_minute": 5,
                    "crawl_delay": 2.0
                },
                extract={
                    "prefer_jsonld": True,
                    "title_selectors": ["h1", "meta[property='og:title']::attr(content)", "title"],
                    "date_selectors": [
                        "meta[property='article:published_time']::attr(content)",
                        "meta[name='article:published_time']::attr(content)",
                        "time[datetime]::attr(datetime)",
                        ".published-date",
                        ".date"
                    ],
                    "body_selectors": [
                        "article",
                        "main",
                        ".content",
                        ".post-content",
                        ".blog-content",
                        ".entry-content"
                    ],
                    "author_selectors": [
                        ".author-name",
                        ".byline",
                        "meta[name='author']::attr(content)",
                        ".author"
                    ]
                }
            )
            
            source_data = SourceCreate(
                identifier=identifier,
                name=request.name,
                url=f"{parsed_url.scheme}://{parsed_url.netloc}",
                rss_url=None,
                check_frequency=86400,  # Daily (won't be used for single articles)
                active=False,  # Inactive since it's just for single articles
                config=config
            )
            
            existing_source = await async_db_manager.create_source(source_data)
            if not existing_source:
                return URLSubmissionResponse(
                    success=False,
                    message="Failed to create temporary source",
                    errors=["Database error occurred"]
                )
        
        # Now scrape the single article
        try:
            async with HTTPClient() as http_client:
                from src.core.modern_scraper import ModernScraper
                
                scraper = ModernScraper(http_client)
                
                # Extract the single article
                article = await scraper._extract_article(url_str, existing_source)
                
                if not article:
                    return URLSubmissionResponse(
                        success=False,
                        message="Failed to extract article content",
                        errors=["Could not extract article from the provided URL"]
                    )
                
                # Process the article through deduplication
                from src.core.processor import ContentProcessor
                processor = ContentProcessor(
                    similarity_threshold=0.85,
                    max_age_days=365,  # Allow older articles for user submissions
                    enable_content_enhancement=True
                )
                
                # Get existing content hashes for deduplication
                existing_hashes = await async_db_manager.get_existing_content_hashes()
                
                # Process the article
                dedup_result = await processor.process_articles([article], existing_hashes)
                
                if not dedup_result.unique_articles:
                    return URLSubmissionResponse(
                        success=False,
                        message="Article was filtered out",
                        errors=["Article was identified as a duplicate or failed quality checks"]
                    )
                
                # Save the article
                saved_article = await async_db_manager.create_article(dedup_result.unique_articles[0])
                
                if not saved_article:
                    return URLSubmissionResponse(
                        success=False,
                        message="Failed to save article to database",
                        errors=["Database error occurred"]
                    )
                
                return URLSubmissionResponse(
                    success=True,
                    message=f"Article '{saved_article.title}' successfully ingested",
                    article_id=saved_article.id,
                    article_title=saved_article.title,
                    source_name=existing_source.name
                )
                
        except Exception as e:
            logger.error(f"Article extraction error: {e}")
            return URLSubmissionResponse(
                success=False,
                message="Failed to extract article content",
                errors=[str(e)]
            )
        
    except Exception as e:
        logger.error(f"URL submission error: {e}")
        return URLSubmissionResponse(
            success=False,
            message="Failed to process URL submission",
            errors=[str(e)]
        )

@app.get("/api/sources/{source_id}/stats")
async def api_source_stats(source_id: int):
    """Get source statistics."""
    try:
        source = await async_db_manager.get_source(source_id)
        if not source:
            raise HTTPException(status_code=404, detail="Source not found")
        
        # Get articles for this source to calculate real stats
        articles = await async_db_manager.list_articles_by_source(source_id)
        
        # Calculate statistics
        total_articles = len(articles)
        avg_content_length = sum(len(article.content or "") for article in articles) // max(total_articles, 1)
        
        # Calculate average hunt score from article metadata
        hunt_scores = []
        for article in articles:
            if article.metadata and 'hunt_score' in article.metadata:
                hunt_scores.append(article.metadata['hunt_score'])
        
        avg_hunt_score = sum(hunt_scores) / len(hunt_scores) if hunt_scores else 0
        
        # Mock quality score for now (in production, this would be calculated from actual quality data)
        avg_quality_score = 65  # Mock value
        
        # Mock articles by date for now
        articles_by_date = {"2024-01-01": total_articles} if total_articles > 0 else {}
        
        stats = {
            "source_id": source_id,
            "source_name": source.name,
            "active": getattr(source, 'active', True),
            "tier": getattr(source, 'tier', 1),
            "collection_method": "RSS" if source.rss_url else "Web Scraping",
            "total_articles": total_articles,
            "avg_content_length": avg_content_length,
            "avg_hunt_score": round(avg_hunt_score, 1),
            "avg_quality_score": avg_quality_score,
            "last_check": source.last_check.isoformat() if source.last_check else None,
            "articles_by_date": articles_by_date
        }
        
        return stats
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"API source stats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Search API endpoint
@app.get("/api/articles/search")
async def api_search_articles(
    q: str,
    source_id: Optional[int] = None,
    classification: Optional[str] = None,
    threat_hunting_min: Optional[int] = None,
    limit: Optional[int] = 100,
    offset: Optional[int] = 0
):
    """Search articles with wildcard and boolean support."""
    try:
        # Get all articles first
        all_articles = await async_db_manager.list_articles()
        
        # Apply basic filters
        filtered_articles = all_articles
        
        if source_id:
            filtered_articles = [a for a in filtered_articles if a.source_id == source_id]
        
        if classification:
            filtered_articles = [a for a in filtered_articles 
                               if a.metadata and a.metadata.get('training_category') == classification]
        
        if threat_hunting_min is not None:
            filtered_articles = [a for a in filtered_articles 
                               if a.metadata and a.metadata.get('threat_hunting_score', 0) >= threat_hunting_min]
        
        # Convert to dict format for search parser
        articles_dict = [
            {
                'id': article.id,
                'title': article.title,
                'content': article.content,
                'source_id': article.source_id,
                'published_at': article.published_at.isoformat() if article.published_at else None,
                'canonical_url': article.canonical_url,
                'metadata': article.metadata
            }
            for article in filtered_articles
        ]
        
        # Apply search with wildcard support
        search_results = parse_boolean_search(q, articles_dict)
        
        # Apply pagination
        total_results = len(search_results)
        paginated_results = search_results[offset:offset + limit]
        
        return {
            "query": q,
            "total_results": total_results,
            "articles": paginated_results,
            "pagination": {
                "offset": offset,
                "limit": limit,
                "has_more": offset + limit < total_results
            }
        }
        
    except Exception as e:
        logger.error(f"Search API error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/search/help")
async def api_search_help():
    """Get search syntax help."""
    return {"help_text": get_search_help_text()}

@app.get("/api/network-info")
async def api_network_info():
    """Get network information for external access."""
    import socket
    import subprocess
    import platform
    
    try:
        # Try to get the local IP address
        # Method 1: Connect to a remote address to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Connect to a remote address (doesn't actually send data)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        except Exception:
            # Fallback method
            local_ip = "192.168.1.100"
        finally:
            s.close()
        
        # Get system info
        system_info = {
            "local_ip": local_ip,
            "port": 8000,
            "platform": platform.system(),
            "hostname": socket.gethostname(),
            "access_url": f"http://{local_ip}:8000"
        }
        
        return system_info
        
    except Exception as e:
        logger.error(f"Error getting network info: {e}")
        # Return fallback info
        return {
            "local_ip": "192.168.1.100",
            "port": 8000,
            "platform": "Unknown",
            "hostname": "Unknown",
            "access_url": "http://192.168.1.100:8000"
        }

# Articles management
@app.get("/articles", response_class=HTMLResponse)
async def articles_list(
    request: Request, 
    search: Optional[str] = None,
    source: Optional[str] = None,
    classification: Optional[str] = None,
    threat_hunting_range: Optional[str] = None,
    sort_by: Optional[str] = "date_published",
    per_page: Optional[int] = 50,
    page: Optional[int] = 1
):
    """Articles listing page."""
    try:
        # Get all articles first for filtering
        all_articles = await async_db_manager.list_articles()
        sources = await async_db_manager.list_sources()
        
        # Create source lookup
        source_lookup = {source.id: source for source in sources}
        
        # Apply filters
        filtered_articles = all_articles
        
        # Search filter with boolean logic
        if search:
            # Convert articles to dict format for the search parser
            articles_dict = [
                {
                    'id': article.id,
                    'title': article.title,
                    'content': article.content,
                    'source_id': article.source_id,
                    'published_at': article.published_at,
                    'canonical_url': article.canonical_url,
                    'metadata': article.metadata
                }
                for article in filtered_articles
            ]
            
            # Apply boolean search filtering
            filtered_dicts = parse_boolean_search(search, articles_dict)
            
            # Convert back to article objects
            filtered_article_ids = {article['id'] for article in filtered_dicts}
            filtered_articles = [
                article for article in filtered_articles
                if article.id in filtered_article_ids
            ]
        
        # Source filter
        if source and source.isdigit():
            source_id = int(source)
            filtered_articles = [
                article for article in filtered_articles
                if article.source_id == source_id
            ]
        
        # Classification filter
        if classification and classification in ['chosen', 'rejected', 'unclassified']:
            if classification == 'unclassified':
                filtered_articles = [
                    article for article in filtered_articles
                    if not article.metadata or 
                    article.metadata.get('training_category') not in ['chosen', 'rejected']
                ]
            else:
                filtered_articles = [
                    article for article in filtered_articles
                    if article.metadata and 
                    article.metadata.get('training_category') == classification
                ]
        
        # Threat Hunting Score filter
        if threat_hunting_range:
            try:
                # Parse range like "60-79" or "40-100"
                if '-' in threat_hunting_range:
                    min_score, max_score = map(float, threat_hunting_range.split('-'))
                    filtered_articles = [
                        article for article in filtered_articles
                        if article.metadata and 
                        min_score <= article.metadata.get('threat_hunting_score', 0) <= max_score
                    ]
            except (ValueError, TypeError):
                # If parsing fails, ignore the filter
                pass
        
        # Apply sorting
        if sort_by == "date_published":
            filtered_articles.sort(key=lambda x: x.published_at or datetime.min, reverse=True)
        elif sort_by == "hunt_score":
            filtered_articles.sort(key=lambda x: (x.metadata.get('threat_hunting_score', 0) if x.metadata else 0, x.id), reverse=True)
        elif sort_by == "content_characters":
            filtered_articles.sort(key=lambda x: len(x.content), reverse=True)
        elif sort_by == "source":
            filtered_articles.sort(key=lambda x: source_lookup.get(x.source_id, {}).get('name', '') if x.source_id in source_lookup else '')
        elif sort_by == "title":
            filtered_articles.sort(key=lambda x: x.title.lower())
        elif sort_by == "classification":
            def get_classification_key(article):
                if not article.metadata:
                    return "unclassified"
                category = article.metadata.get('training_category')
                if category in ['chosen', 'rejected']:
                    return category
                return "unclassified"
            filtered_articles.sort(key=get_classification_key)
        
        # Apply pagination
        total_articles = len(filtered_articles)
        per_page = max(1, min(per_page, 100))  # Limit to 100 per page
        total_pages = max(1, (total_articles + per_page - 1) // per_page)
        page = max(1, min(page, total_pages))
        
        start_idx = (page - 1) * per_page
        end_idx = min(start_idx + per_page, total_articles)
        
        # Get articles for current page
        articles = filtered_articles[start_idx:end_idx]
        
        pagination = {
            "total_articles": total_articles,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "start_idx": start_idx + 1,
            "end_idx": end_idx
        }
        
        # Create filters data
        filters = {
            "search": search or "",
            "source": source or "",
            "classification": classification or "",
            "threat_hunting_range": threat_hunting_range or "",
            "sort_by": sort_by or "date_published"
        }
        
        # Get classification statistics from filtered articles
        chosen_count = sum(1 for article in filtered_articles 
                          if article.metadata and 
                          article.metadata.get('training_category') == 'chosen')
        rejected_count = sum(1 for article in filtered_articles 
                           if article.metadata and 
                           article.metadata.get('training_category') == 'rejected')
        unclassified_count = sum(1 for article in filtered_articles 
                               if not article.metadata or 
                               article.metadata.get('training_category') not in ['chosen', 'rejected'])
        
        stats = {
            "chosen_count": chosen_count,
            "rejected_count": rejected_count,
            "unclassified_count": unclassified_count
        }
        
        return templates.TemplateResponse(
            "articles.html",
            {
                "request": request,
                "articles": articles,
                "sources": sources,
                "source_lookup": source_lookup,
                "pagination": pagination,
                "filters": filters,
                "stats": stats
            }
        )
    except Exception as e:
        logger.error(f"Articles list error: {e}")
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": str(e)},
            status_code=500
        )

@app.get("/articles/{article_id}", response_class=HTMLResponse)
async def article_detail(request: Request, article_id: int):
    """Article detail page."""
    try:
        article = await async_db_manager.get_article(article_id)
        if not article:
            return templates.TemplateResponse(
                "error.html",
                {"request": request, "error": "Article not found"},
                status_code=404
            )
        
        source = await async_db_manager.get_source(article.source_id)
        
        # Simplified article detail without TTP analysis
        return templates.TemplateResponse(
            "article_detail.html",
            {
                "request": request, 
                "article": article, 
                "source": source
            }
        )
    except Exception as e:
        logger.error(f"Article detail error: {e}")
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": str(e)},
            status_code=500
        )

# Analysis page removed - no longer needed after quality scoring removal

@app.get("/api/articles")
async def api_articles_list(limit: Optional[int] = 100):
    """API endpoint for listing articles."""
    try:
        articles = await async_db_manager.list_articles(limit=limit)
        return {"articles": [article.dict() for article in articles]}
    except Exception as e:
        logger.error(f"API articles list error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/articles/next-unclassified")
async def api_get_next_unclassified():
    """API endpoint for getting the next unclassified article with highest threat hunt score."""
    try:
        # Get all articles
        articles = await async_db_manager.list_articles()
        
        # Filter to only unclassified articles
        unclassified_articles = [
            article for article in articles
            if not article.metadata or article.metadata.get('training_category') not in ['chosen', 'rejected']
        ]
        
        if not unclassified_articles:
            return {"article_id": None, "message": "No unclassified articles found"}
        
        # Sort by threat hunt score (highest first), then by ID as tiebreaker
        unclassified_articles.sort(
            key=lambda x: (
                -(x.metadata.get('threat_hunting_score', 0) if x.metadata else 0),  # Negative for descending order
                x.id  # ID as tiebreaker for consistent ordering
            )
        )
        
        # Return the article with the highest threat hunt score
        return {"article_id": unclassified_articles[0].id}
        
    except Exception as e:
        logger.error(f"API get next unclassified error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/articles/{article_id}")
async def api_get_article(article_id: int):
    """API endpoint for getting a specific article."""
    try:
        article = await async_db_manager.get_article(article_id)
        if not article:
            raise HTTPException(status_code=404, detail="Article not found")
        return article.dict()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"API get article error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/articles/{article_id}/export-markdown")
async def api_export_article_markdown(article_id: int):
    """API endpoint for exporting an article to Markdown format."""
    try:
        article = await async_db_manager.get_article(article_id)
        if not article:
            raise HTTPException(status_code=404, detail="Article not found")
        
        # Get source information
        source = await async_db_manager.get_source(article.source_id) if article.source_id else None
        
        # Build markdown content
        classification = article.metadata.get('classification', 'Unclassified') if article.metadata else 'Unclassified'
        
        markdown_content = f"""# {article.title}

**Source:** {source.name if source else article.source_id}  
**URL:** {article.canonical_url or 'N/A'}  
**Published:** {article.published_at.strftime('%Y-%m-%d %H:%M:%S') if article.published_at else 'N/A'}  
**Article ID:** {article.id}  
**Classification:** {classification}  

---

## Content

{article.content}

---

## Metadata

"""
        
        # Add metadata if available
        if article.metadata:
            markdown_content += "### AI Analysis\n\n"
            
            # Add ChatGPT summary if available
            if 'chatgpt_summary' in article.metadata:
                summary_data = article.metadata['chatgpt_summary']
                markdown_content += f"**AI Summary:**\n{summary_data.get('summary', 'N/A')}\n\n"
                markdown_content += f"**Model Used:** {summary_data.get('model_name', 'N/A')}\n\n"
            
            # Add threat hunting score if available
            if 'threat_hunting_score' in article.metadata:
                score = article.metadata['threat_hunting_score']
                markdown_content += f"**Threat Hunting Score:** {score}\n\n"
            
            # Add SIGMA rules if available
            if 'sigma_rules' in article.metadata:
                sigma_data = article.metadata['sigma_rules']
                markdown_content += f"**SIGMA Rules:**\n```yaml\n{sigma_data.get('rules', 'N/A')}\n```\n\n"
            
            # Add IOCs if available
            if 'iocs' in article.metadata:
                iocs_data = article.metadata['iocs']
                markdown_content += "**Indicators of Compromise:**\n\n"
                for ioc_type, iocs in iocs_data.items():
                    if iocs:
                        markdown_content += f"**{ioc_type.title()}:**\n"
                        for ioc in iocs:
                            markdown_content += f"- {ioc}\n"
                        markdown_content += "\n"
        
        # Return as markdown
        return Response(
            content=markdown_content,
            media_type="text/markdown",
            headers={"Content-Disposition": f"attachment; filename=article-{article_id}.md"}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"API export markdown error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/articles/{article_id}/classify")
async def api_classify_article(article_id: int, request: Request):
    """API endpoint for classifying an article."""
    try:
        # Get request body
        body = await request.json()
        category = body.get('category')
        reason = body.get('reason')
        
        if not category or category not in ['chosen', 'rejected', 'unclassified']:
            raise HTTPException(status_code=400, detail="Invalid category. Must be 'chosen', 'rejected', or 'unclassified'")
        
        # Get the article
        article = await async_db_manager.get_article(article_id)
        if not article:
            raise HTTPException(status_code=404, detail="Article not found")
        
        # Prepare metadata update
        from src.models.article import ArticleUpdate
        
        # Get current metadata or create new
        current_metadata = article.metadata.copy() if article.metadata else {}
        
        # Update metadata with classification
        current_metadata['training_category'] = category
        current_metadata['training_reason'] = reason
        current_metadata['training_categorized_at'] = datetime.now().isoformat()
        
        # Create update object
        update_data = ArticleUpdate(metadata=current_metadata)
        
        # Save the updated article
        updated_article = await async_db_manager.update_article(article_id, update_data)
        
        if not updated_article:
            raise HTTPException(status_code=500, detail="Failed to update article")
        
        return {
            "success": True,
            "article_id": article_id,
            "category": category,
            "reason": reason,
            "categorized_at": current_metadata['training_categorized_at']
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"API classify article error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/articles/{article_id}/analyze-threat-hunting")
async def api_analyze_threat_hunting(article_id: int, request: Request):
    """API endpoint for analyzing an article with CustomGPT for threat hunting and detection engineering."""
    try:
        # Get the article
        article = await async_db_manager.get_article(article_id)
        if not article:
            raise HTTPException(status_code=404, detail="Article not found")
        
        # Get request body to determine what to analyze
        body = await request.json()
        analyze_content = body.get('analyze_content', False)  # Default to URL only
        
        # Prepare the analysis prompt
        if analyze_content:
            # Use full content - let the AI model handle the analysis
            content = article.content
            
            # Analyze both URL and content
            prompt = f"""As a cybersecurity expert specializing in threat hunting and detection engineering, analyze this threat intelligence article for its usefulness to security professionals.

Article Title: {article.title}
Source URL: {article.canonical_url or 'N/A'}
Published Date: {article.published_at or 'N/A'}

Article Content:
{content}

Please provide a comprehensive analysis covering:

1. **Threat Hunting Value** (1-10 scale):
   - How useful is this for threat hunters?
   - What indicators of compromise (IOCs) are mentioned?
   - What attack techniques are described?

2. **Detection Engineering Value** (1-10 scale):
   - How useful is this for creating detection rules?
   - What detection opportunities are present?
   - What log sources would be relevant?

3. **Key Technical Details**:
   - Specific malware families, tools, or techniques
   - Network indicators, file hashes, registry keys
   - Process names, command lines, or behaviors

4. **Actionable Intelligence**:
   - Specific detection rules that could be created
   - Threat hunting queries that could be used
   - Recommended monitoring areas

5. **Overall Assessment**:
   - Summary of the article's value
   - Priority level for security teams
   - Recommended next steps

Please be specific and actionable in your analysis."""
        else:
            # Analyze URL and metadata only
            prompt = f"""As a cybersecurity expert specializing in threat hunting and detection engineering, analyze this threat intelligence article for its potential usefulness to security professionals.

Article Title: {article.title}
Source URL: {article.canonical_url or 'N/A'}
Published Date: {article.published_at or 'N/A'}
Source: {article.source_id}
Content Length: {len(article.content)} characters

Based on the title, source, and metadata, please provide an initial assessment:

1. **Potential Threat Hunting Value** (1-10 scale):
   - How promising does this article look for threat hunters?
   - What types of threats might be discussed?

2. **Potential Detection Engineering Value** (1-10 scale):
   - How promising does this look for detection rule creation?
   - What detection opportunities might be present?

3. **Source Credibility**:
   - How reliable is this source typically?
   - What is the source's reputation in the security community?

4. **Recommended Next Steps**:
   - Should the full content be analyzed?
   - What specific aspects should be focused on?

Please provide a brief but insightful analysis based on the available metadata."""
        
        # Get CustomGPT configuration from environment
        customgpt_api_url = os.getenv('CUSTOMGPT_API_URL')
        customgpt_api_key = os.getenv('CUSTOMGPT_API_KEY')
        
        if not customgpt_api_url or not customgpt_api_key:
            # Fallback to Ollama if CustomGPT not configured
            ollama_url = os.getenv('LLM_API_URL', 'http://cti_ollama:11434')
            ollama_model = os.getenv('LLM_MODEL', 'mistral')
            
            logger.info(f"Using Ollama at {ollama_url} with model {ollama_model}")
            
            # Use Ollama API
            async with httpx.AsyncClient() as client:
                try:
                    response = await client.post(
                        f"{ollama_url}/api/generate",
                        json={
                            "model": ollama_model,
                            "prompt": prompt,
                            "stream": False,
                            "options": {
                                "temperature": 0.3,
                                "num_predict": 2048
                            }
                        },
                        timeout=180.0
                    )
                    
                    if response.status_code != 200:
                        logger.error(f"Ollama API error: {response.status_code} - {response.text}")
                        raise HTTPException(status_code=500, detail=f"Failed to get analysis from Ollama: {response.status_code}")
                    
                    result = response.json()
                    analysis = result.get('response', 'No analysis available')
                    logger.info(f"Successfully got analysis from Ollama: {len(analysis)} characters")
                    
                except Exception as e:
                    logger.error(f"Ollama API request failed: {e}")
                    logger.error(f"Exception type: {type(e)}")
                    logger.error(f"Exception args: {e.args}")
                    import traceback
                    logger.error(f"Traceback: {traceback.format_exc()}")
                    raise HTTPException(status_code=500, detail=f"Failed to get analysis from Ollama: {str(e)}")
                
        else:
            # Use CustomGPT API
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{customgpt_api_url}/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {customgpt_api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": "gpt-4",  # or your specific CustomGPT model
                        "messages": [
                            {
                                "role": "system",
                                "content": "You are a cybersecurity expert specializing in threat hunting and detection engineering. Provide clear, actionable analysis of threat intelligence articles."
                            },
                            {
                                "role": "user",
                                "content": prompt
                            }
                        ],
                        "max_tokens": 2048,
                        "temperature": 0.3
                    },
                    timeout=60.0
                )
                
                if response.status_code != 200:
                    raise HTTPException(status_code=500, detail="Failed to get analysis from CustomGPT")
                
                result = response.json()
                analysis = result['choices'][0]['message']['content']
        
        # Store the analysis in article metadata
        current_metadata = article.metadata.copy() if article.metadata else {}
        current_metadata['threat_hunting_analysis'] = {
            'analysis': analysis,
            'analyzed_at': datetime.now().isoformat(),
            'analyzed_content': analyze_content,
            'model_used': 'customgpt' if customgpt_api_url else 'ollama',
            'model_name': 'gpt-4' if customgpt_api_url else ollama_model
        }
        
        # Update the article
        update_data = ArticleUpdate(metadata=current_metadata)
        await async_db_manager.update_article(article_id, update_data)
        
        return {
            "success": True,
            "article_id": article_id,
            "analysis": analysis,
            "analyzed_at": current_metadata['threat_hunting_analysis']['analyzed_at'],
            "analyzed_content": analyze_content,
            "model_used": current_metadata['threat_hunting_analysis']['model_used'],
            "model_name": current_metadata['threat_hunting_analysis']['model_name']
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"API analyze threat hunting error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/articles/{article_id}/chatgpt-summary")
async def api_chatgpt_summary(article_id: int, request: Request):
    """API endpoint for generating a ChatGPT summary of an article."""
    try:
        # Get the article
        article = await async_db_manager.get_article(article_id)
        if not article:
            raise HTTPException(status_code=404, detail="Article not found")
        
        # Get request body for API key and settings
        body = await request.json()
        api_key = body.get('api_key')  # Get API key from request
        force_regenerate = body.get('force_regenerate', False)  # Force regeneration
        ai_model = body.get('ai_model', 'chatgpt')  # Get AI model from request
        
        logger.info(f"ChatGPT summary request for article {article_id}, api_key provided: {bool(api_key)}, force_regenerate: {force_regenerate}, model: {ai_model}")
        
        # If force regeneration is requested, skip cache check
        if not force_regenerate:
            # Check if summary already exists and return cached version
            existing_summary = article.metadata.get('chatgpt_summary', {}) if article.metadata else {}
            if existing_summary and existing_summary.get('summary'):
                logger.info(f"Returning cached ChatGPT summary for article {article_id}")
                return {
                    "success": True,
                    "article_id": article_id,
                    "summary": existing_summary['summary'],
                    "summarized_at": existing_summary['summarized_at'],
                    "content_type": existing_summary['content_type'],
                    "model_used": existing_summary['model_used'],
                    "model_name": existing_summary['model_name'],
                    "cached": True
                }
        
        # Determine which model to use
        if ai_model == 'chatgpt':
            # Check if API key is provided for ChatGPT
            if not api_key:
                raise HTTPException(status_code=400, detail="OpenAI API key is required. Please configure it in Settings.")
        else:
            # Use Ollama model - no API key required
            api_key = None
        
        # Prepare the summary prompt with minimal content for testing
        # Use a very small limit to ensure reliable processing
        content_limit = 2000  # Minimal limit for testing
        content = article.content[:content_limit]
        if len(article.content) > content_limit:
            content += f"\n\n[Content truncated at {content_limit:,} characters. Full article has {len(article.content):,} characters.]"
        
        # Simple test prompt for debugging
        prompt = f"Summarize this cybersecurity article in 2-3 sentences:\n\nTitle: {article.title}\nContent: {content}"
        
        # Use the selected model
        if ai_model == 'chatgpt':
            # Use ChatGPT API
            chatgpt_api_url = os.getenv('CHATGPT_API_URL', 'https://api.openai.com/v1/chat/completions')
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    chatgpt_api_url,
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": "gpt-4",  # or your specific ChatGPT model
                        "messages": [
                            {
                                "role": "system",
                                "content": "You are a cybersecurity expert specializing in threat intelligence analysis. Provide clear, concise summaries of threat intelligence articles."
                            },
                            {
                                "role": "user",
                                "content": prompt
                            }
                        ],
                        "max_tokens": 2048,
                        "temperature": 0.3
                    },
                    timeout=30.0  # Short timeout for testing
                )
                
                if response.status_code != 200:
                    error_detail = f"Failed to get summary from ChatGPT: {response.status_code}"
                    if response.status_code == 401:
                        error_detail = "Invalid API key. Please check your OpenAI API key in Settings."
                    elif response.status_code == 429:
                        error_detail = "Rate limit exceeded. Please try again later."
                    raise HTTPException(status_code=500, detail=error_detail)
                
                result = response.json()
                summary = result['choices'][0]['message']['content']
                model_name = "gpt-4"
                model_used = "chatgpt"
        else:
            # Use Ollama API
            ollama_url = os.getenv('LLM_API_URL', 'http://cti_ollama:11434')
            ollama_model = get_ollama_model(ai_model)
            
            import requests
            
            logger.info(f"Using Ollama at {ollama_url} with model {ollama_model}")
            
            # Use requests instead of httpx for Ollama
            response = requests.post(
                f"{ollama_url}/api/generate",
                json={
                    "model": ollama_model,
                    "prompt": f"You are a cybersecurity expert specializing in threat intelligence analysis. Provide clear, concise summaries of threat intelligence articles.\n\n{prompt}",
                    "stream": False,
                    "options": {
                        "temperature": 0.3,
                        "num_predict": 512  # Reduce output length
                    }
                },
                timeout=120.0  # Increase timeout to 2 minutes
            )
            
            if response.status_code != 200:
                error_detail = f"Failed to get summary from Ollama: {response.status_code}"
                logger.error(f"Ollama API error: {response.status_code}, response: {response.text}")
                raise HTTPException(status_code=500, detail=error_detail)
                
            result = response.json()
            summary = result.get('response', '')
            model_name = ollama_model
            model_used = "ollama"
        
        # Store the summary in article metadata
        current_metadata = article.metadata.copy() if article.metadata else {}
        current_metadata['chatgpt_summary'] = {
            'summary': summary,
            'summarized_at': datetime.now().isoformat(),
            'content_type': 'full content',
            'model_used': model_used,
            'model_name': model_name
        }
        
        # Update the article
        update_data = ArticleUpdate(metadata=current_metadata)
        await async_db_manager.update_article(article_id, update_data)
        
        return {
            "success": True,
            "article_id": article_id,
            "summary": summary,
            "summarized_at": current_metadata['chatgpt_summary']['summarized_at'],
            "content_type": "full content",
            "model_used": current_metadata['chatgpt_summary']['model_used'],
            "model_name": current_metadata['chatgpt_summary']['model_name']
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"API ChatGPT summary error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/articles/{article_id}/custom-prompt")
async def api_custom_prompt(article_id: int, request: Request):
    """API endpoint for custom AI prompts about an article."""
    try:
        # Get the article
        article = await async_db_manager.get_article(article_id)
        if not article:
            raise HTTPException(status_code=404, detail="Article not found")
        
        # Get request body
        body = await request.json()
        custom_prompt = body.get('prompt')
        api_key = body.get('api_key')
        ai_model = body.get('ai_model', 'chatgpt')  # Default to chatgpt if not specified
        
        if not custom_prompt:
            raise HTTPException(status_code=400, detail="Custom prompt is required")
        
        if not api_key:
            raise HTTPException(status_code=400, detail="OpenAI API key is required")
        
        # Two-stage approach: First get cyber-focused summary, then use for analysis
        cyber_summary = await get_cyber_focused_summary(article, ai_model)
        
        # Use the cyber summary instead of raw content for better analysis
        content = cyber_summary
        
        # Prepare the custom prompt using cyber-focused summary
        full_prompt = f"""As a cybersecurity expert, please answer the following question about this threat intelligence article.

Article Title: {article.title}
Source URL: {article.canonical_url or 'N/A'}
Published Date: {article.published_at or 'N/A'}

Cyber-Focused Summary:
{content}

User Question: {custom_prompt}

Please provide a comprehensive and helpful response based on the cyber-focused summary above. Be specific, actionable, and focus on cybersecurity insights. The summary has already extracted the key threat hunting elements, so you can focus on analysis and recommendations."""
        
        # Use the selected AI model
        if ai_model == 'chatgpt':
            # Use ChatGPT API
            chatgpt_api_url = os.getenv('CHATGPT_API_URL', 'https://api.openai.com/v1/chat/completions')
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    chatgpt_api_url,
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": "gpt-4",
                        "messages": [
                            {
                                "role": "system",
                                "content": "You are a cybersecurity expert specializing in threat intelligence analysis. Provide clear, helpful responses to questions about threat intelligence articles."
                            },
                            {
                                "role": "user",
                                "content": full_prompt
                            }
                        ],
                        "max_tokens": 2048,
                        "temperature": 0.3
                    },
                    timeout=60.0
                )
                
                if response.status_code != 200:
                    error_detail = f"Failed to get response from ChatGPT: {response.status_code}"
                    if response.status_code == 401:
                        error_detail = "Invalid API key. Please check your OpenAI API key in Settings."
                    elif response.status_code == 429:
                        error_detail = "Rate limit exceeded. Please try again later."
                    raise HTTPException(status_code=500, detail=error_detail)
                
                result = response.json()
                ai_response = result['choices'][0]['message']['content']
                model_name = "gpt-4"
                model_used = "chatgpt"
        else:
            # Use Ollama API
            ollama_url = os.getenv('LLM_API_URL', 'http://cti_ollama:11434')
            ollama_model = get_ollama_model(ai_model)
            
            logger.info(f"Using Ollama at {ollama_url} with model {ollama_model}")
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{ollama_url}/api/generate",
                    json={
                        "model": ollama_model,
                        "prompt": f"You are a cybersecurity expert specializing in threat intelligence analysis. Provide clear, helpful responses to questions about threat intelligence articles.\n\n{full_prompt}",
                        "stream": False,
                        "options": {
                            "temperature": 0.3,
                            "num_predict": 2048
                        }
                    },
                    timeout=180.0
                )
                
                if response.status_code != 200:
                    error_detail = f"Failed to get response from Ollama: {response.status_code}"
                    raise HTTPException(status_code=500, detail=error_detail)
                
                result = response.json()
                ai_response = result.get('response', '')
                model_name = ollama_model
                model_used = "ollama"
        
        # Store the custom prompt response in article metadata
        current_metadata = article.metadata.copy() if article.metadata else {}
        if 'custom_prompts' not in current_metadata:
            current_metadata['custom_prompts'] = []
        
        current_metadata['custom_prompts'].append({
            'prompt': custom_prompt,
            'response': ai_response,
            'responded_at': datetime.now().isoformat(),
            'model_used': model_used,
            'model_name': model_name
        })
        
        # Update the article
        update_data = ArticleUpdate(metadata=current_metadata)
        await async_db_manager.update_article(article_id, update_data)
        
        return {
            "success": True,
            "article_id": article_id,
            "response": ai_response,
            "responded_at": current_metadata['custom_prompts'][-1]['responded_at'],
            "model_used": "chatgpt",
            "model_name": "gpt-4"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"API custom prompt error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/test-chatgpt-summary")
async def test_chatgpt_summary(request: Request):
    """Test ChatGPT summary functionality with provided API key."""
    try:
        body = await request.json()
        api_key = body.get('api_key')
        test_prompt = body.get('test_prompt', 'Please provide a brief summary of cybersecurity threats.')
        
        if not api_key:
            raise HTTPException(status_code=400, detail="API key is required")
        
        # Use ChatGPT API with provided key
        chatgpt_api_url = os.getenv('CHATGPT_API_URL', 'https://api.openai.com/v1/chat/completions')
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                chatgpt_api_url,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "gpt-4",
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a cybersecurity expert. Provide brief, helpful responses."
                        },
                        {
                            "role": "user",
                            "content": test_prompt
                        }
                    ],
                    "max_tokens": 100,
                    "temperature": 0.3
                },
                timeout=30.0
            )
            
            if response.status_code == 200:
                result = response.json()
                summary = result['choices'][0]['message']['content']
                return {
                    "success": True, 
                    "message": "ChatGPT Summary is working",
                    "model_name": "gpt-4",
                    "test_summary": summary
                }
            elif response.status_code == 401:
                raise HTTPException(status_code=400, detail="Invalid API key")
            else:
                raise HTTPException(status_code=400, detail=f"API error: {response.status_code}")
                
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Test ChatGPT summary error: {e}")
        raise HTTPException(status_code=500, detail="Failed to test ChatGPT summary")

@app.post("/api/test-openai-key")
async def test_openai_key(request: Request):
    """Test OpenAI API key validity."""
    try:
        body = await request.json()
        api_key = body.get('api_key')
        
        if not api_key:
            raise HTTPException(status_code=400, detail="API key is required")
        
        # Test the API key by making a simple request to OpenAI
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.openai.com/v1/models",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                },
                timeout=10.0
            )
            
            if response.status_code == 200:
                return {"success": True, "message": "API key is valid"}
            elif response.status_code == 401:
                raise HTTPException(status_code=400, detail="Invalid API key")
            else:
                raise HTTPException(status_code=400, detail=f"API error: {response.status_code}")
                
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Test OpenAI API key error: {e}")
        raise HTTPException(status_code=500, detail="Failed to test API key")

@app.post("/api/articles/{article_id}/generate-sigma")
async def api_generate_sigma(article_id: int, request: Request):
    """API endpoint for generating SIGMA detection rules from an article."""
    try:
        # Get the article
        article = await async_db_manager.get_article(article_id)
        if not article:
            raise HTTPException(status_code=404, detail="Article not found")
        
        # Check if article is marked as "chosen" (required for SIGMA generation)
        training_category = article.metadata.get('training_category', '') if article.metadata else ''
        logger.info(f"SIGMA generation request for article {article_id}, training_category: '{training_category}'")
        if training_category != 'chosen':
            raise HTTPException(status_code=400, detail="SIGMA rules can only be generated for articles marked as 'Chosen'. Please classify this article first.")
        
        # Check if SIGMA rules already exist and return cached version
        existing_sigma_rules = article.metadata.get('sigma_rules', {}) if article.metadata else {}
        if existing_sigma_rules and existing_sigma_rules.get('rules'):
            logger.info(f"Returning cached SIGMA rules for article {article_id}")
            return {
                "success": True,
                "article_id": article_id,
                "sigma_rules": existing_sigma_rules['rules'],
                "generated_at": existing_sigma_rules['generated_at'],
                "content_type": existing_sigma_rules['content_type'],
                "model_used": existing_sigma_rules['model_used'],
                "model_name": existing_sigma_rules['model_name'],
                "cached": True
            }
        
        # Get request body
        body = await request.json()
        include_content = body.get('include_content', True)  # Default to full content
        api_key = body.get('api_key')  # Get API key from request
        author_name = body.get('author_name', 'CTIScraper User')  # Get author name from request
        ai_model = body.get('ai_model', 'chatgpt')  # Get AI model from request
        
        logger.info(f"SIGMA generation request for article {article_id}, api_key provided: {bool(api_key)}, author: {author_name}, model: {ai_model}")
        
        # Determine which model to use
        if ai_model == 'chatgpt':
            # Check if API key is provided for ChatGPT
            if not api_key:
                logger.warning(f"SIGMA generation failed: No API key provided for article {article_id}")
                raise HTTPException(status_code=400, detail="OpenAI API key is required. Please configure it in Settings.")
        else:
            # Use Ollama model - no API key required
            api_key = None
        
        # Prepare the SIGMA generation prompt
        if include_content:
            # Two-stage approach: First get cyber-focused summary, then use for SIGMA generation
            cyber_summary = await get_cyber_focused_summary(article, ai_model)
            content = cyber_summary
            
            # Extract attacker behaviors using SecureBERT for more focused SIGMA generation
            logger.info(f"Extracting attacker behaviors for article {article_id}")
            behavior_extractor = SecureBERTBehaviorExtractor()
            behavior_result = behavior_extractor.extract_behaviors(content, article.title)
            
            # Format behaviors for SIGMA prompt
            behavior_summary = behavior_extractor.format_for_sigma(behavior_result)
            
            # Enhanced SIGMA-specific prompt with cyber summary and SecureBERT-extracted behaviors
            prompt = f"""Generate a Sigma detection rule based on this threat intelligence:

**CYBER-FOCUSED SUMMARY:**
{content}

**EXTRACTED ATTACKER BEHAVIORS:**
{behavior_summary}

**ARTICLE DETAILS:**
Article Title: {article.title}
Source URL: {article.canonical_url or 'N/A'}

**INSTRUCTIONS:**
Focus on the cyber-focused summary and extracted attacker behaviors above to create a targeted Sigma detection rule. Use the behaviors, techniques, and tools identified to build precise detection logic.

Create one high-quality Sigma rule in YAML format with:
- title: under 50 chars, title case
- id: valid UUID v4
- status: experimental
- description: what it detects
- author: {author_name}
- date: YYYY/MM/DD
- tags: relevant MITRE ATT&CK tags
- logsource: product and category
- detection: selection and condition
- fields: relevant fields
- falsepositives: potential false positives
- level: high/medium/low

CRITICAL SIGMA SYNTAX REQUIREMENTS:
- Use ONLY valid SIGMA condition syntax: 'selection' or 'selection1 and selection2' or 'selection1 or selection2'
- NEVER use SQL-like syntax like 'count()', 'group by', 'where', 'stats', etc.
- NEVER use aggregation functions in conditions
- Valid conditions: 'selection', 'selection and selection', 'selection or selection', 'all of selection*', '1 of selection*'
- Selection must reference defined filters above it
- Use proper YAML indentation and syntax

EXAMPLE VALID SIGMA STRUCTURE:
```yaml
detection:
  selection:
    EventID: 4688
    CommandLine|contains: 'powershell'
  condition: selection
```

IMPORTANT: Focus on TTPs (Tactics, Techniques, and Procedures) rather than atomic IOCs (Indicators of Compromise). Avoid rules that could easily be replaced by simple IOC matching (specific IP addresses, file hashes, etc.). Instead, focus on:

- Behavioral patterns and techniques
- Process execution chains
- Network communication patterns
- File system activities
- Registry modifications
- Authentication anomalies
- Command execution patterns
- Persistence mechanisms
- Domain/URL patterns (when they indicate technique, not just specific domains)

The rule should detect the technique or behavior, not just specific artifacts. Domain/URL patterns are acceptable when they represent a technique (e.g., specific TLDs, URL structures, or domain patterns that indicate malicious behavior)."""
        else:
            # Metadata-only prompt
            prompt = f"""As a senior cybersecurity detection engineer specializing in SIGMA rule creation and threat hunting, analyze this threat intelligence article metadata and provide guidance for SIGMA rule generation.

Article Title: {article.title}
Source URL: {article.canonical_url or 'N/A'}
Published Date: {article.published_at or 'N/A'}
Source: {article.source_id}
Content Length: {len(article.content)} characters

Based on the article title and metadata, provide:

1. **Potential Detection Opportunities**:
   - What types of threats might be discussed?
   - What detection categories would be most relevant?
   - What log sources should be considered?

2. **Recommended SIGMA Rule Types**:
   - Process creation rules
   - Network activity rules
   - File system rules
   - Registry rules
   - Authentication rules

3. **MITRE ATT&CK Techniques**:
   - Likely techniques based on the title
   - Recommended technique mappings

4. **Next Steps**:
   - Should the full content be analyzed?
   - What specific aspects should be focused on?

Please provide a brief but insightful analysis based on the available metadata."""
        
        # Use the selected model
        if ai_model == 'chatgpt':
            # Use ChatGPT API
            chatgpt_api_url = os.getenv('CHATGPT_API_URL', 'https://api.openai.com/v1/chat/completions')
            
            logger.info(f"Sending SIGMA request to OpenAI for article {article_id}, content length: {len(content) if include_content else 'metadata only'}")
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    chatgpt_api_url,
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": "gpt-4",
                        "messages": [
                            {
                                "role": "system",
                                "content": "You are a senior cybersecurity detection engineer specializing in SIGMA rule creation and threat hunting. Generate high-quality, actionable SIGMA rules based on threat intelligence articles. Always use proper SIGMA syntax and include all required fields according to SigmaHQ standards. Focus on TTPs (Tactics, Techniques, and Procedures) rather than atomic IOCs (Indicators of Compromise). Create rules that detect behavioral patterns and techniques, not just specific artifacts like IP addresses or file hashes. Domain/URL patterns are acceptable when they represent techniques or behavioral patterns.\n\nCRITICAL: Use ONLY valid SIGMA condition syntax. NEVER use SQL-like syntax (count(), group by, where, stats, etc.) or aggregation functions in conditions. Valid conditions are: 'selection', 'selection1 and selection2', 'selection1 or selection2', 'all of selection*', '1 of selection*'. Always reference defined selections above the condition."
                            },
                            {
                                "role": "user",
                                "content": prompt
                            }
                        ],
                        "max_tokens": 2048,  # Reduced from 4096 to stay within limits
                        "temperature": 0.2   # Lower temperature for more consistent rule generation
                    },
                    timeout=120.0  # Longer timeout for SIGMA generation
                )
                
                if response.status_code != 200:
                    error_detail = f"Failed to generate SIGMA rules: {response.status_code}"
                    if response.status_code == 401:
                        error_detail = "Invalid API key. Please check your OpenAI API key in Settings."
                    elif response.status_code == 429:
                        error_detail = "Rate limit exceeded. Please try again later."
                    elif response.status_code == 400:
                        # Log the actual error from OpenAI
                        try:
                            error_response = response.json()
                            logger.error(f"OpenAI API 400 error details: {error_response}")
                            error_detail = f"OpenAI API error: {error_response.get('error', {}).get('message', 'Bad request')}"
                        except:
                            error_detail = "OpenAI API error: Bad request - check prompt format"
                    raise HTTPException(status_code=500, detail=error_detail)
                
                result = response.json()
                sigma_rules = result['choices'][0]['message']['content']
                model_name = "gpt-4"
                model_used = "chatgpt"
        else:
            # Use Ollama API
            ollama_url = os.getenv('LLM_API_URL', 'http://cti_ollama:11434')
            ollama_model = get_ollama_model(ai_model)
            
            logger.info(f"Sending SIGMA request to Ollama at {ollama_url} with model {ollama_model} for article {article_id}")
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{ollama_url}/api/generate",
                    json={
                        "model": ollama_model,
                        "prompt": f"You are a senior cybersecurity detection engineer specializing in SIGMA rule creation and threat hunting. Generate high-quality, actionable SIGMA rules based on threat intelligence articles. Always use proper SIGMA syntax and include all required fields according to SigmaHQ standards. Focus on TTPs (Tactics, Techniques, and Procedures) rather than atomic IOCs (Indicators of Compromise). Create rules that detect behavioral patterns and techniques, not just specific artifacts like IP addresses or file hashes. Domain/URL patterns are acceptable when they represent techniques or behavioral patterns.\n\nCRITICAL: Use ONLY valid SIGMA condition syntax. NEVER use SQL-like syntax (count(), group by, where, stats, etc.) or aggregation functions in conditions. Valid conditions are: 'selection', 'selection1 and selection2', 'selection1 or selection2', 'all of selection*', '1 of selection*'. Always reference defined selections above the condition.\n\n{prompt}",
                        "stream": False,
                        "options": {
                            "temperature": 0.2,
                            "num_predict": 2048
                        }
                    },
                    timeout=180.0  # Longer timeout for SIGMA generation
                )
                
                if response.status_code != 200:
                    error_detail = f"Failed to generate SIGMA rules from Ollama: {response.status_code}"
                    raise HTTPException(status_code=500, detail=error_detail)
                
                result = response.json()
                sigma_rules = result.get('response', '')
                model_name = ollama_model
                model_used = "ollama"
        
        # Store the SIGMA rules and behavior extraction in article metadata
        current_metadata = article.metadata.copy() if article.metadata else {}
        current_metadata['sigma_rules'] = {
            'rules': sigma_rules,
            'generated_at': datetime.now().isoformat(),
            'content_type': 'full content' if include_content else 'metadata only',
            'model_used': model_used,
            'model_name': model_name
        }
        
        # Store behavior extraction results
        current_metadata['behavior_extraction'] = {
            'techniques': behavior_result.techniques,
            'tactics': behavior_result.tactics,
            'behaviors': behavior_result.behaviors,
            'tools': behavior_result.tools,
            'processes': behavior_result.processes,
            'confidence_scores': behavior_result.confidence_scores,
            'extraction_method': behavior_result.extraction_method,
            'processing_time': behavior_result.processing_time,
            'extracted_at': datetime.now().isoformat()
        }
        
        # Update the article
        update_data = ArticleUpdate(metadata=current_metadata)
        await async_db_manager.update_article(article_id, update_data)
        
        return {
            "success": True,
            "article_id": article_id,
            "sigma_rules": sigma_rules,
            "generated_at": current_metadata['sigma_rules']['generated_at'],
            "content_type": current_metadata['sigma_rules']['content_type'],
            "model_used": current_metadata['sigma_rules']['model_used'],
            "model_name": current_metadata['sigma_rules']['model_name'],
            "behavior_extraction": {
                "techniques": behavior_result.techniques,
                "tactics": behavior_result.tactics,
                "behaviors": behavior_result.behaviors,
                "tools": behavior_result.tools,
                "processes": behavior_result.processes,
                "extraction_method": behavior_result.extraction_method,
                "processing_time": behavior_result.processing_time
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"SIGMA generation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/articles/{article_id}/extract-iocs")
async def api_extract_iocs(article_id: int, request: Request):
    """API endpoint for extracting IOCs from an article using hybrid approach."""
    try:
        # Get the article
        article = await async_db_manager.get_article(article_id)
        if not article:
            raise HTTPException(status_code=404, detail="Article not found")
        
        # Get request body
        body = await request.json()
        include_content = body.get('include_content', True)  # Default to full content
        api_key = body.get('api_key')  # Get API key from request
        force_regenerate = body.get('force_regenerate', False)  # Force regeneration
        use_llm_validation = body.get('use_llm_validation', True)  # Use LLM validation
        ai_model = body.get('ai_model', 'ollama')  # Get AI model from request, default to ollama
        
        logger.info(f"IOC extraction request for article {article_id}, api_key provided: {bool(api_key)}, force_regenerate: {force_regenerate}, use_llm_validation: {use_llm_validation}, ai_model: {ai_model}")
        
        # If force regeneration is requested, skip cache check
        if not force_regenerate:
            # Check if IOCs already exist and return cached version
            existing_iocs = article.metadata.get('extracted_iocs', {}) if article.metadata else {}
            if existing_iocs and existing_iocs.get('iocs'):
                logger.info(f"Returning cached IOCs for article {article_id}")
                return {
                    "success": True,
                    "article_id": article_id,
                    "iocs": existing_iocs['iocs'],
                    "extracted_at": existing_iocs['extracted_at'],
                    "content_type": existing_iocs['content_type'],
                    "model_used": existing_iocs['model_used'],
                    "model_name": existing_iocs['model_name'],
                    "extraction_method": existing_iocs.get('extraction_method', 'unknown'),
                    "confidence": existing_iocs.get('confidence', 0.0),
                    "cached": True
                }
        
        # Initialize hybrid IOC extractor
        ioc_extractor = HybridIOCExtractor(use_llm_validation=use_llm_validation)
        
        # Prepare content for extraction
        if include_content:
            content = article.content
        else:
            # Metadata-only content
            content = f"Title: {article.title}\nURL: {article.canonical_url or 'N/A'}\nPublished: {article.published_at or 'N/A'}\nSource: {article.source_id}"
        
        # Extract IOCs using hybrid approach
        extraction_result = await ioc_extractor.extract_iocs(content, api_key, ai_model)
        
        # Store the IOCs in article metadata
        current_metadata = article.metadata.copy() if article.metadata else {}
        current_metadata['extracted_iocs'] = {
            'iocs': extraction_result.iocs,
            'extracted_at': datetime.now().isoformat(),
            'content_type': 'full content' if include_content else 'metadata only',
            'model_used': 'hybrid' if extraction_result.extraction_method == 'hybrid' else 'regex',
            'model_name': 'gpt-4' if extraction_result.extraction_method == 'hybrid' and ai_model == 'chatgpt' else ('ollama' if extraction_result.extraction_method == 'hybrid' else 'custom-regex'),
            'extraction_method': extraction_result.extraction_method,
            'confidence': extraction_result.confidence,
            'processing_time': extraction_result.processing_time,
            'raw_count': extraction_result.raw_count,
            'validated_count': extraction_result.validated_count,
            'metadata': extraction_result.metadata
        }
        
        # Update the article
        update_data = ArticleUpdate(metadata=current_metadata)
        await async_db_manager.update_article(article_id, update_data)
        
        return {
            "success": True,
            "article_id": article_id,
            "iocs": extraction_result.iocs,
            "extracted_at": current_metadata['extracted_iocs']['extracted_at'],
            "content_type": current_metadata['extracted_iocs']['content_type'],
            "model_used": current_metadata['extracted_iocs']['model_used'],
            "model_name": current_metadata['extracted_iocs']['model_name'],
            "extraction_method": extraction_result.extraction_method,
            "confidence": extraction_result.confidence,
            "processing_time": extraction_result.processing_time,
            "raw_count": extraction_result.raw_count,
            "validated_count": extraction_result.validated_count
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"IOC extraction error: {e}")
        logger.error(f"IOC extraction error type: {type(e)}")
        logger.error(f"IOC extraction error traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))

# Text Highlight Endpoints
@app.post("/api/articles/{article_id}/highlights")
async def api_create_text_highlight(article_id: int, request: Request):
    """API endpoint for creating a text highlight."""
    try:
        data = await request.json()
        
        # Validate required fields
        required_fields = ['selected_text', 'start_offset', 'end_offset', 'is_huntable']
        for field in required_fields:
            if field not in data:
                raise HTTPException(status_code=400, detail=f"Missing required field: {field}")
        
        # Validate offsets
        if data['start_offset'] < 0 or data['end_offset'] < 0:
            raise HTTPException(status_code=400, detail="Offsets must be non-negative")
        
        if data['start_offset'] >= data['end_offset']:
            raise HTTPException(status_code=400, detail="Start offset must be less than end offset")
        
        # Get article to validate it exists and get content length
        async with async_db_manager.get_session() as session:
            article_result = await session.execute(
                text("SELECT id, content FROM articles WHERE id = :article_id"),
                {"article_id": article_id}
            )
            article = article_result.fetchone()
            
            if not article:
                raise HTTPException(status_code=404, detail="Article not found")
            
            # Validate offsets against content length
            content_length = len(article.content)
            if data['end_offset'] > content_length:
                raise HTTPException(status_code=400, detail="End offset exceeds article content length")
            
            # Create text highlight
            result = await session.execute(
                text("""
                    INSERT INTO text_highlights (article_id, selected_text, start_offset, end_offset, is_huntable, categorized_at)
                    VALUES (:article_id, :selected_text, :start_offset, :end_offset, :is_huntable, NOW())
                    RETURNING id, article_id, selected_text, start_offset, end_offset, is_huntable, categorized_at, created_at, updated_at
                """),
                {
                    "article_id": article_id,
                    "selected_text": data['selected_text'],
                    "start_offset": data['start_offset'],
                    "end_offset": data['end_offset'],
                    "is_huntable": data['is_huntable']
                }
            )
            
            highlight = result.fetchone()
            await session.commit()
            
            return {
                "success": True,
                "message": "Text highlight created successfully",
                "highlight": {
                    "id": highlight.id,
                    "article_id": highlight.article_id,
                    "selected_text": highlight.selected_text,
                    "start_offset": highlight.start_offset,
                    "end_offset": highlight.end_offset,
                    "is_huntable": highlight.is_huntable,
                    "categorized_at": highlight.categorized_at.isoformat() if highlight.categorized_at else None,
                    "created_at": highlight.created_at.isoformat(),
                    "updated_at": highlight.updated_at.isoformat()
                }
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Text highlight creation error: {e}")
        logger.error(f"Text highlight creation error traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/articles/{article_id}/highlights")
async def api_get_text_highlights(article_id: int):
    """API endpoint for getting all text highlights for an article."""
    try:
        async with async_db_manager.get_session() as session:
            result = await session.execute(
                text("""
                    SELECT id, article_id, selected_text, start_offset, end_offset, is_huntable, 
                           categorized_at, created_at, updated_at
                    FROM text_highlights 
                    WHERE article_id = :article_id
                    ORDER BY created_at DESC
                """),
                {"article_id": article_id}
            )
            
            highlights = result.fetchall()
            
            return {
                "success": True,
                "highlights": [
                    {
                        "id": highlight.id,
                        "article_id": highlight.article_id,
                        "selected_text": highlight.selected_text,
                        "start_offset": highlight.start_offset,
                        "end_offset": highlight.end_offset,
                        "is_huntable": highlight.is_huntable,
                        "categorized_at": highlight.categorized_at.isoformat() if highlight.categorized_at else None,
                        "created_at": highlight.created_at.isoformat(),
                        "updated_at": highlight.updated_at.isoformat()
                    }
                    for highlight in highlights
                ]
            }
            
    except Exception as e:
        logger.error(f"Get text highlights error: {e}")
        logger.error(f"Get text highlights error traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/api/highlights/{highlight_id}")
async def api_update_text_highlight(highlight_id: int, request: Request):
    """API endpoint for updating a text highlight categorization."""
    try:
        data = await request.json()
        
        if 'is_huntable' not in data:
            raise HTTPException(status_code=400, detail="Missing required field: is_huntable")
        
        async with async_db_manager.get_session() as session:
            result = await session.execute(
                text("""
                    UPDATE text_highlights 
                    SET is_huntable = :is_huntable, categorized_at = NOW(), updated_at = NOW()
                    WHERE id = :highlight_id
                    RETURNING id, article_id, selected_text, start_offset, end_offset, is_huntable, 
                              categorized_at, created_at, updated_at
                """),
                {
                    "highlight_id": highlight_id,
                    "is_huntable": data['is_huntable']
                }
            )
            
            highlight = result.fetchone()
            
            if not highlight:
                raise HTTPException(status_code=404, detail="Text highlight not found")
            
            await session.commit()
            
            return {
                "success": True,
                "message": "Text highlight updated successfully",
                "highlight": {
                    "id": highlight.id,
                    "article_id": highlight.article_id,
                    "selected_text": highlight.selected_text,
                    "start_offset": highlight.start_offset,
                    "end_offset": highlight.end_offset,
                    "is_huntable": highlight.is_huntable,
                    "categorized_at": highlight.categorized_at.isoformat() if highlight.categorized_at else None,
                    "created_at": highlight.created_at.isoformat(),
                    "updated_at": highlight.updated_at.isoformat()
                }
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Text highlight update error: {e}")
        logger.error(f"Text highlight update error traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/highlights/{highlight_id}")
async def api_delete_text_highlight(highlight_id: int):
    """API endpoint for deleting a text highlight."""
    try:
        async with async_db_manager.get_session() as session:
            result = await session.execute(
                text("DELETE FROM text_highlights WHERE id = :highlight_id RETURNING id"),
                {"highlight_id": highlight_id}
            )
            
            deleted = result.fetchone()
            
            if not deleted:
                raise HTTPException(status_code=404, detail="Text highlight not found")
            
            await session.commit()
            
            return {
                "success": True,
                "message": "Text highlight deleted successfully"
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Text highlight deletion error: {e}")
        logger.error(f"Text highlight deletion error traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/highlighting-logs")
async def api_log_highlighting_action(request: Request):
    """API endpoint for logging highlighting actions (optional server-side logging)."""
    try:
        log_data = await request.json()
        
        # Log to server logs for debugging/monitoring
        logger.info(f"Highlighting action logged: {log_data}")
        
        # In a production system, you might want to store these in a database
        # For now, we'll just acknowledge receipt
        return {
            "message": "Highlighting action logged successfully",
            "logged_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Highlighting log error: {e}")
        # Don't raise HTTPException here - this is optional logging
        return {
            "message": "Logging failed but action completed",
            "error": str(e)
        }


@app.post("/api/database/backup")
async def api_database_backup():
    """Create a database backup and return it as a downloadable file."""
    try:
        import tempfile
        import os
        from datetime import datetime
        from sqlalchemy import text
        
        # Get database connection details
        db_name = os.getenv('POSTGRES_DB', 'cti_scraper')
        db_user = os.getenv('POSTGRES_USER', 'cti_user')
        
        # Create a temporary file for the backup
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.sql', delete=False) as temp_file:
            backup_file = temp_file.name
        
        try:
            # Use SQLAlchemy to create a backup by dumping all tables
            async with async_db_manager.get_session() as session:
                # Start the backup file with header
                backup_content = f"""-- CTI Scraper Database Backup
-- Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
-- Database: {db_name}
-- User: {db_user}

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

-- Drop existing objects
DROP SCHEMA IF EXISTS public CASCADE;
CREATE SCHEMA public;
GRANT ALL ON SCHEMA public TO postgres;
GRANT ALL ON SCHEMA public TO public;

"""
                
                # Get all tables
                tables_result = await session.execute(text("""
                    SELECT table_name 
                    FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    ORDER BY table_name
                """))
                tables = [row[0] for row in tables_result.fetchall()]
                
                # Dump each table
                for table in tables:
                    # Get table structure
                    structure_result = await session.execute(text(f"""
                        SELECT column_name, data_type, is_nullable, column_default
                        FROM information_schema.columns 
                        WHERE table_name = '{table}' AND table_schema = 'public'
                        ORDER BY ordinal_position
                    """))
                    columns = structure_result.fetchall()
                    
                    # Create table structure
                    backup_content += f"\n-- Table: {table}\n"
                    backup_content += f"CREATE TABLE {table} (\n"
                    
                    column_definitions = []
                    for col in columns:
                        col_name, data_type, is_nullable, default_val = col
                        nullable = "NULL" if is_nullable == "YES" else "NOT NULL"
                        default = f" DEFAULT {default_val}" if default_val else ""
                        column_definitions.append(f"    {col_name} {data_type} {nullable}{default}")
                    
                    backup_content += ",\n".join(column_definitions)
                    backup_content += "\n);\n\n"
                    
                    # Get table data
                    data_result = await session.execute(text(f"SELECT * FROM {table}"))
                    rows = data_result.fetchall()
                    
                    if rows:
                        # Get column names from the first row
                        if rows:
                            column_names = list(rows[0]._mapping.keys())
                            
                            # Insert data
                            backup_content += f"-- Data for table {table}\n"
                            for row in rows:
                                values = []
                                for col_name in column_names:
                                    value = row._mapping[col_name]
                                    if value is None:
                                        values.append("NULL")
                                    elif isinstance(value, str):
                                        # Escape single quotes
                                        escaped_value = value.replace("'", "''")
                                        values.append(f"'{escaped_value}'")
                                    else:
                                        values.append(str(value))
                                
                                backup_content += f"INSERT INTO {table} ({', '.join(column_names)}) VALUES ({', '.join(values)});\n"
                            backup_content += "\n"
                
                # Write backup content to file
                with open(backup_file, 'w', encoding='utf-8') as f:
                    f.write(backup_content)
                
                # Read the backup file as bytes
                with open(backup_file, 'rb') as f:
                    backup_content_bytes = f.read()
                
                # Clean up temporary file
                os.unlink(backup_file)
                
                # Create filename with timestamp
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"cti_scraper_backup_{timestamp}.sql"
                
                # Return the backup as a downloadable file
                from fastapi.responses import Response
                return Response(
                    content=backup_content_bytes,
                    media_type='application/sql',
                    headers={
                        'Content-Disposition': f'attachment; filename="{filename}"',
                        'Content-Length': str(len(backup_content_bytes))
                    }
                )
            
        except Exception as e:
            logger.error(f"Database backup error: {e}")
            # Clean up temporary file if it exists
            if os.path.exists(backup_file):
                os.unlink(backup_file)
            raise HTTPException(status_code=500, detail=f"Database backup failed: {str(e)}")
            
    except Exception as e:
        logger.error(f"Database backup endpoint error: {e}")
        raise HTTPException(status_code=500, detail=f"Backup failed: {str(e)}")


@app.post("/api/database/restore")
async def api_database_restore(backup_file: UploadFile = File(...)):
    """Restore database from a backup file."""
    try:
        import tempfile
        import os
        import subprocess
        from sqlalchemy import text
        
        # Validate file type
        if not backup_file.filename.endswith('.sql'):
            raise HTTPException(status_code=400, detail="Only .sql files are supported")
        
        # Get database connection details
        db_name = os.getenv('POSTGRES_DB', 'cti_scraper')
        db_user = os.getenv('POSTGRES_USER', 'cti_user')
        db_password = os.getenv('POSTGRES_PASSWORD', 'cti_password')
        
        # Create a temporary file for the backup
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.sql', delete=False) as temp_file:
            restore_file = temp_file.name
        
        try:
            # Read the uploaded file content
            content = await backup_file.read()
            
            # Write content to temporary file
            with open(restore_file, 'wb') as f:
                f.write(content)
            
            # Use docker exec to run psql in the postgres container
            cmd = [
                'docker', 'exec', '-i', 'cti_postgres',
                'psql',
                '-U', db_user,
                '-d', db_name,
                '--no-password'
            ]
            
            logger.info(f"Running restore command: {' '.join(cmd)}")
            
            # Set PGPASSWORD environment variable for the docker exec
            env = os.environ.copy()
            env['PGPASSWORD'] = db_password
            
            # Run the restore command
            with open(restore_file, 'r') as f:
                result = subprocess.run(cmd, env=env, stdin=f, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                logger.error(f"psql restore failed: {result.stderr}")
                raise HTTPException(status_code=500, detail=f"Database restore failed: {result.stderr}")
            
            # Clean up temporary file
            os.unlink(restore_file)
            
            logger.info("Database restore completed successfully")
            
            return {"message": "Database restored successfully", "details": result.stdout}
            
        except subprocess.TimeoutExpired:
            logger.error("Database restore timed out")
            raise HTTPException(status_code=500, detail="Database restore timed out")
        except Exception as e:
            logger.error(f"Database restore error: {e}")
            # Clean up temporary file if it exists
            if os.path.exists(restore_file):
                os.unlink(restore_file)
            raise HTTPException(status_code=500, detail=f"Database restore failed: {str(e)}")
            
    except Exception as e:
        logger.error(f"Database restore endpoint error: {e}")
        raise HTTPException(status_code=500, detail=f"Restore failed: {str(e)}")


# Health Check Endpoints
@app.get("/api/health")
async def api_health_check():
    """Basic health check endpoint."""
    try:
        # Test database connection
        async with async_db_manager.get_session() as session:
            await session.execute(text("SELECT 1"))
        
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "version": "1.0.0",
            "services": {
                "database": "healthy",
                "web": "healthy"
            }
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "error": str(e),
            "services": {
                "database": "unhealthy",
                "web": "healthy"
            }
        }

@app.get("/api/health/database")
async def api_database_health():
    """Comprehensive database health check."""
    try:
        # Test database connection
        async with async_db_manager.get_session() as session:
            # Get basic statistics
            articles_count = await session.execute(text("SELECT COUNT(*) FROM articles"))
            total_articles = articles_count.scalar()
            
            sources_count = await session.execute(text("SELECT COUNT(*) FROM sources"))
            total_sources = sources_count.scalar()
            
            # Test deduplication system
            duplicate_check = await session.execute(
                text("SELECT COUNT(*) as total, COUNT(DISTINCT canonical_url) as unique_urls, COUNT(DISTINCT content_hash) as unique_hashes FROM articles")
            )
            dedup_stats = duplicate_check.fetchone()
            
            # Test SimHash system
            simhash_check = await session.execute(
                text("SELECT COUNT(*) as articles_with_simhash FROM articles WHERE simhash IS NOT NULL")
            )
            simhash_stats = simhash_check.fetchone()
            
            # Test index performance
            performance_check = await session.execute(text("SELECT test_index_performance()"))
            performance_results = performance_check.fetchall()
            
            # Process performance results safely
            performance_data = []
            for result in performance_results:
                if result and len(result) >= 4:
                    performance_data.append({
                        "test": str(result[0]),
                        "query_time_ms": float(result[1]),
                        "rows_returned": int(result[2]),
                        "index_used": str(result[3])
                    })
        
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "database": {
                "connection": "healthy",
                "total_articles": int(total_articles),
                "total_sources": int(total_sources),
                "deduplication": {
                    "total_articles": int(dedup_stats[0]),
                    "unique_urls": int(dedup_stats[1]),
                    "unique_content_hashes": int(dedup_stats[2]),
                    "duplicate_rate": f"{((int(dedup_stats[0]) - int(dedup_stats[1])) / int(dedup_stats[0]) * 100):.2f}%" if int(dedup_stats[0]) > 0 else "0%"
                },
                "simhash": {
                    "articles_with_simhash": int(simhash_stats[0]),
                    "coverage": f"{(int(simhash_stats[0]) / int(dedup_stats[0]) * 100):.2f}%" if int(dedup_stats[0]) > 0 else "0%"
                },
                "performance": performance_data
            }
        }
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "error": str(e),
            "database": {
                "connection": "unhealthy"
            }
        }

@app.get("/api/health/deduplication")
async def api_deduplication_health():
    """Detailed deduplication system health check."""
    try:
        async with async_db_manager.get_session() as session:
            # SimHash bucket analysis
            bucket_analysis = await session.execute(text("""
                SELECT bucket_id, COUNT(*) as articles_per_bucket 
                FROM simhash_buckets 
                GROUP BY bucket_id 
                ORDER BY articles_per_bucket DESC
            """))
            bucket_stats = bucket_analysis.fetchall()
            
            # Find potential near-duplicates
            near_duplicate_check = await session.execute(text("""
                SELECT COUNT(*) as potential_near_duplicates
                FROM (
                    SELECT simhash, COUNT(*) as count
                    FROM articles 
                    WHERE simhash IS NOT NULL
                    GROUP BY simhash
                    HAVING COUNT(*) > 1
                ) duplicates
            """))
            near_duplicate_stats = near_duplicate_check.fetchone()
            
            # Content hash analysis
            content_hash_analysis = await session.execute(text("""
                SELECT content_hash, COUNT(*) as count
                FROM articles 
                GROUP BY content_hash
                HAVING COUNT(*) > 1
                ORDER BY count DESC
                LIMIT 5
            """))
            content_hash_duplicates = content_hash_analysis.fetchall()
        
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "deduplication": {
                "exact_duplicates": {
                    "content_hash_duplicates": len(content_hash_duplicates),
                    "duplicate_details": [
                        {"hash": str(row[0])[:8] + "...", "count": int(row[1])}
                        for row in content_hash_duplicates
                    ]
                },
                "near_duplicates": {
                    "potential_near_duplicates": int(near_duplicate_stats[0]),
                    "simhash_coverage": "100%" if near_duplicate_stats[0] == 0 else "Needs review"
                },
                "simhash_buckets": {
                    "total_buckets": len(bucket_stats),
                    "bucket_distribution": [
                        {"bucket_id": int(row[0]), "articles_count": int(row[1])}
                        for row in bucket_stats[:10]  # Top 10 buckets
                    ],
                    "most_active_bucket": {"bucket_id": int(bucket_stats[0][0]), "articles_count": int(bucket_stats[0][1])} if bucket_stats else None
                }
            }
        }
    except Exception as e:
        logger.error(f"Deduplication health check failed: {e}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }

@app.get("/api/health/services")
async def api_services_health():
    """Check health of external services."""
    try:
        services_status = {}
        
        # Check Ollama service
        try:
            ollama_url = os.getenv('LLM_API_URL', 'http://cti_ollama:11434')
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{ollama_url}/api/tags", timeout=5.0)
                if response.status_code == 200:
                    models = response.json().get('models', [])
                    services_status['ollama'] = {
                        "status": "healthy",
                        "models_available": len(models),
                        "models": [model['name'] for model in models[:5]]  # First 5 models
                    }
                else:
                    services_status['ollama'] = {"status": "unhealthy", "error": f"HTTP {response.status_code}"}
        except Exception as e:
            services_status['ollama'] = {"status": "unhealthy", "error": str(e)}
        
        # Check Redis service
        try:
            import redis
            redis_client = redis.Redis(host='cti_redis', port=6379, db=0, password='cti_redis_2024')
            redis_client.ping()
            services_status['redis'] = {
                "status": "healthy",
                "info": redis_client.info('memory')
            }
        except Exception as e:
            services_status['redis'] = {"status": "unhealthy", "error": str(e)}
        
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "services": services_status
        }
    except Exception as e:
        logger.error(f"Services health check failed: {e}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }

@app.get("/api/health/celery")
async def api_celery_health():
    """Check health of Celery workers and tasks."""
    try:
        from src.worker.celery_app import celery_app
        
        celery_status = {}
        
        # Check Celery workers
        try:
            inspect = celery_app.control.inspect()
            active_workers = inspect.active()
            registered_workers = inspect.registered()
            stats = inspect.stats()
            
            if active_workers:
                celery_status['workers'] = {
                    "status": "healthy",
                    "active_workers": len(active_workers),
                    "worker_details": []
                }
                
                for worker_name, tasks in active_workers.items():
                    worker_stats = stats.get(worker_name, {})
                    celery_status['workers']['worker_details'].append({
                        "name": worker_name,
                        "active_tasks": len(tasks),
                        "total_tasks": worker_stats.get('total', {}).get('tasks.succeeded', 0) + worker_stats.get('total', {}).get('tasks.failed', 0),
                        "pool": worker_stats.get('pool', {}).get('processes', 'N/A'),
                        "rusage": worker_stats.get('rusage', {})
                    })
            else:
                celery_status['workers'] = {
                    "status": "unhealthy",
                    "error": "No active workers found"
                }
        except Exception as e:
            celery_status['workers'] = {
                "status": "unhealthy",
                "error": str(e)
            }
        
        # Check Celery broker (Redis)
        try:
            broker_url = celery_app.conf.broker_url
            celery_status['broker'] = {
                "status": "healthy",
                "url": broker_url.split('@')[1] if '@' in broker_url else broker_url  # Hide password
            }
        except Exception as e:
            celery_status['broker'] = {
                "status": "unhealthy",
                "error": str(e)
            }
        
        # Check Celery result backend
        try:
            result_backend = celery_app.conf.result_backend
            celery_status['result_backend'] = {
                "status": "healthy",
                "backend": result_backend.split('@')[1] if '@' in result_backend else result_backend
            }
        except Exception as e:
            celery_status['result_backend'] = {
                "status": "unhealthy",
                "error": str(e)
            }
        
        # Check recent task activity
        try:
            # Get task statistics from the last hour
            from datetime import datetime, timedelta
            from celery import states
            
            # This is a simplified check - in production you might want to query task results
            celery_status['recent_activity'] = {
                "status": "healthy",
                "note": "Task activity monitoring available via Celery monitoring tools"
            }
        except Exception as e:
            celery_status['recent_activity'] = {
                "status": "unhealthy",
                "error": str(e)
            }
        
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "celery": celery_status
        }
    except Exception as e:
        logger.error(f"Celery health check failed: {e}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }

@app.get("/api/health/ingestion")
async def api_ingestion_analytics():
    """Get article ingestion analytics and trends."""
    try:
        async with async_db_manager.get_session() as session:
            # Get ingestion data for the last 30 days
            ingestion_query = await session.execute(text("""
                SELECT 
                    DATE(published_at) as date,
                    COUNT(*) as articles_count,
                    COUNT(DISTINCT source_id) as sources_count
                FROM articles 
                WHERE published_at >= CURRENT_DATE - INTERVAL '30 days'
                GROUP BY DATE(published_at)
                ORDER BY date DESC
            """))
            daily_data = ingestion_query.fetchall()
            
            # Get hourly distribution for today
            hourly_query = await session.execute(text("""
                SELECT 
                    EXTRACT(HOUR FROM published_at) as hour,
                    COUNT(*) as articles_count
                FROM articles 
                WHERE DATE(published_at) = CURRENT_DATE
                GROUP BY EXTRACT(HOUR FROM published_at)
                ORDER BY hour
            """))
            hourly_data = hourly_query.fetchall()
            
            # Get source breakdown for last 7 days
            source_query = await session.execute(text("""
                SELECT 
                    s.name as source_name,
                    COUNT(a.id) as articles_count,
                    AVG(CAST(a.article_metadata->>'threat_hunting_score' AS FLOAT)) as avg_hunt_score,
                    COUNT(CASE WHEN a.article_metadata->>'training_category' = 'chosen' THEN 1 END) as chosen_count,
                    COUNT(CASE WHEN a.article_metadata->>'training_category' = 'rejected' THEN 1 END) as rejected_count,
                    COUNT(CASE WHEN a.article_metadata->>'training_category' IS NULL OR a.article_metadata->>'training_category' = '' OR a.article_metadata->>'training_category' NOT IN ('chosen', 'rejected') THEN 1 END) as unclassified_count
                FROM articles a
                JOIN sources s ON a.source_id = s.id
                WHERE a.published_at >= CURRENT_DATE - INTERVAL '7 days'
                GROUP BY s.id, s.name
                ORDER BY articles_count DESC
                LIMIT 10
            """))
            source_data = source_query.fetchall()
            
            # Get total statistics
            total_query = await session.execute(text("""
                SELECT 
                    COUNT(*) as total_articles,
                    COUNT(DISTINCT source_id) as total_sources,
                    MIN(published_at) as earliest_article,
                    MAX(published_at) as latest_article
                FROM articles
            """))
            total_stats = total_query.fetchone()
            
            return {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "ingestion": {
                    "daily_trends": [
                        {
                            "date": str(row[0]),
                            "articles_count": int(row[1]),
                            "sources_count": int(row[2])
                        }
                        for row in daily_data
                    ],
                    "hourly_distribution": [
                        {
                            "hour": int(row[0]),
                            "articles_count": int(row[1])
                        }
                        for row in hourly_data
                    ],
                    "source_breakdown": [
                        {
                            "source_name": str(row[0]),
                            "articles_count": int(row[1]),
                            "avg_hunt_score": float(row[2]) if row[2] else 0.0,
                            "chosen_count": int(row[3]),
                            "rejected_count": int(row[4]),
                            "unclassified_count": int(row[5]),
                            "chosen_ratio": f"{(int(row[3]) / int(row[1]) * 100):.1f}%" if int(row[1]) > 0 else "0%",
                            "rejected_ratio": f"{(int(row[4]) / int(row[1]) * 100):.1f}%" if int(row[1]) > 0 else "0%",
                            "unclassified_ratio": f"{(int(row[5]) / int(row[1]) * 100):.1f}%" if int(row[1]) > 0 else "0%"
                        }
                        for row in source_data
                    ],
                    "total_stats": {
                        "total_articles": int(total_stats[0]),
                        "total_sources": int(total_stats[1]),
                        "earliest_article": str(total_stats[2]) if total_stats[2] else None,
                        "latest_article": str(total_stats[3]) if total_stats[3] else None
                    }
                }
            }
    except Exception as e:
        logger.error(f"Ingestion analytics failed: {e}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }

@app.get("/health")
async def health_checks_page(request: Request):
    """Health checks page."""
    return templates.TemplateResponse("health_checks.html", {"request": request})

# Error handlers
@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException):
    """Handle 404 errors."""
    return templates.TemplateResponse(
        "error.html",
        {"request": request, "error": "Page not found"},
        status_code=404
    )

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc: HTTPException):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {exc}")
    return templates.TemplateResponse(
        "error.html",
        {"request": request, "error": "Internal server error"},
        status_code=500
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "src.web.modern_main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
