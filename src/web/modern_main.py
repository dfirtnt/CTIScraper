"""
Modern FastAPI Application for CTI Scraper

Uses async/await, PostgreSQL, and proper connection management.
"""

import os
import sys
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any
from contextlib import asynccontextmanager
from datetime import datetime
from collections import defaultdict

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from sqlalchemy.ext.asyncio import AsyncSession

# Add src to path for imports
src_path = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_path))

from src.database.async_manager import async_db_manager
from src.models.source import Source, SourceUpdate, SourceFilter
from src.models.article import Article
from src.worker.celery_app import test_source_connectivity, collect_from_source

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Templates
templates = Jinja2Templates(directory="src/web/templates")

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
@app.get("/health")
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

# Sources management
@app.get("/sources", response_class=HTMLResponse)
async def sources_list(request: Request):
    """Sources management page."""
    try:
        sources = await async_db_manager.list_sources()
        return templates.TemplateResponse(
            "sources.html",
            {"request": request, "sources": sources}
        )
    except Exception as e:
        logger.error(f"Sources list error: {e}")
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": str(e)},
            status_code=500
        )

@app.get("/api/sources")
async def api_sources_list(filter_params: Optional[SourceFilter] = Depends()):
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
async def api_toggle_source_status(source_id: int):
    """Toggle source active status."""
    try:
        result = await async_db_manager.toggle_source_status(source_id)
        if not result:
            raise HTTPException(status_code=404, detail="Source not found")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"API toggle source status error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/sources/{source_id}/test")
async def api_test_source(source_id: int, background_tasks: BackgroundTasks):
    """Test source connectivity."""
    try:
        # Add background task for testing
        background_tasks.add_task(test_source_connectivity.delay, source_id)
        
        return {
            "message": "Source connectivity test started",
            "source_id": source_id,
            "task_type": "connectivity_test"
        }
    except Exception as e:
        logger.error(f"API test source error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/sources/{source_id}/stats")
async def api_source_stats(source_id: int):
    """Get source statistics."""
    try:
        source = await async_db_manager.get_source(source_id)
        if not source:
            raise HTTPException(status_code=404, detail="Source not found")
        
        # TODO: Implement actual statistics calculation
        stats = {
            "source_id": source_id,
            "source_name": source.name,
            "total_articles": source.total_articles or 0,
            "success_rate": source.success_rate or 0.0,
            "average_response_time": source.average_response_time or 0.0,
            "last_check": source.last_check.isoformat() if source.last_check else None,
            "last_success": source.last_success.isoformat() if source.last_success else None,
            "consecutive_failures": source.consecutive_failures or 0
        }
        
        return stats
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"API source stats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Articles management
@app.get("/articles", response_class=HTMLResponse)
async def articles_list(request: Request, limit: Optional[int] = 100):
    """Articles listing page."""
    try:
        articles = await async_db_manager.list_articles(limit=limit)
        sources = await async_db_manager.list_sources()
        
        # Create source lookup
        source_lookup = {source.id: source for source in sources}
        
        # Create pagination data
        total_articles = len(articles)
        page = 1
        per_page = limit
        total_pages = max(1, (total_articles + per_page - 1) // per_page)
        start_idx = 1
        end_idx = min(per_page, total_articles)
        
        pagination = {
            "total_articles": total_articles,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "start_idx": start_idx,
            "end_idx": end_idx
        }
        
        # Create filters data (empty for now)
        filters = {
            "search": "",
            "source": "",
            "quality_min": ""
        }
        
        return templates.TemplateResponse(
            "articles.html",
            {
                "request": request,
                "articles": articles,
                "sources": sources,
                "source_lookup": source_lookup,
                "pagination": pagination,
                "filters": filters
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
        
        # Implement actual TTP analysis for individual article
        from src.utils.ttp_extractor import ThreatHuntingDetector
        
        if article.content and len(article.content) > 100:
            try:
                hunting_detector = ThreatHuntingDetector()
                
                # Safely concatenate title and content
                title = str(article.title) if article.title else ""
                content = str(article.content) if article.content else ""
                full_text = f"{title} {content}".strip()
                
                analysis = hunting_detector.detect_hunting_techniques(
                    full_text,
                    article.id
                )
                
                ttp_analysis = {
                    "total_techniques": analysis.total_techniques,
                    "overall_confidence": analysis.overall_confidence,
                    "hunting_priority": analysis.hunting_priority,
                    "techniques_by_category": {
                        category: [
                            {
                                "technique_name": tech.technique_name,
                                "confidence": tech.confidence,
                                "hunting_guidance": tech.hunting_guidance
                            } for tech in techniques
                        ] for category, techniques in analysis.techniques_by_category.items()
                    }
                }
                
                # Calculate quality analysis
                quality_analysis = hunting_detector.calculate_ttp_quality_score(content)
                # Ensure we only sum numeric values
                numeric_values = [v for v in quality_analysis.values() if isinstance(v, (int, float))]
                total_score = sum(numeric_values) if numeric_values else 0
                
                if total_score >= 60:
                    quality_level = "Excellent"
                elif total_score >= 40:
                    quality_level = "Good"
                elif total_score >= 20:
                    quality_level = "Fair"
                else:
                    quality_level = "Limited"
                
                quality_data = {
                    "total_score": total_score,
                    "max_possible": 75,
                    "quality_level": quality_level,
                    "sigma_rules_present": quality_analysis.get('sigma_rules_present', 0),
                    "mitre_attack_mapping": quality_analysis.get('mitre_attack_mapping', 0),
                    "iocs_present": quality_analysis.get('iocs_present', 0),
                    "recommendation": f"Quality score: {total_score}/75 - {quality_level} analysis potential"
                }
                
            except Exception as e:
                logger.warning(f"TTP analysis failed for article {article.id}: {e}")
                ttp_analysis = {
                    "total_techniques": 0,
                    "overall_confidence": 0.0,
                    "hunting_priority": "Analysis Failed",
                    "techniques_by_category": {}
                }
                quality_data = {
                    "total_score": 0,
                    "max_possible": 75,
                    "quality_level": "Analysis Failed",
                    "sigma_rules_present": 0,
                    "mitre_attack_mapping": 0,
                    "iocs_present": 0,
                    "recommendation": "TTP analysis encountered an error"
                }
        else:
            ttp_analysis = {
                "total_techniques": 0,
                "overall_confidence": 0.0,
                "hunting_priority": "Insufficient Content",
                "techniques_by_category": {}
            }
            quality_data = {
                "total_score": 0,
                "max_possible": 75,
                "quality_level": "Insufficient Content",
                "sigma_rules_present": 0,
                "mitre_attack_mapping": 0,
                "iocs_present": 0,
                "recommendation": "Article content too short for meaningful analysis"
            }
        
        return templates.TemplateResponse(
            "article_detail.html",
            {
                "request": request, 
                "article": article, 
                "source": source,
                "ttp_analysis": ttp_analysis,
                "quality_data": quality_data
            }
        )
    except Exception as e:
        logger.error(f"Article detail error: {e}")
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": str(e)},
            status_code=500
        )

# TTP Analysis page
@app.get("/analysis", response_class=HTMLResponse)
async def ttp_analysis(request: Request):
    """TTP Analysis page."""
    try:
        stats = await async_db_manager.get_database_stats()
        articles = await async_db_manager.list_articles(limit=20)
        
        # Implement actual TTP analysis aggregation
        from src.utils.ttp_extractor import ThreatHuntingDetector
        hunting_detector = ThreatHuntingDetector()
        
        # Analyze articles for TTP content
        total_techniques_detected = 0
        high_priority_articles = 0
        quality_scores = []
        technique_categories = defaultdict(int)
        recent_analyses = []
        
        for article in articles:
            if article.content and len(article.content) > 100:
                try:
                    # Run TTP analysis
                    # Safely concatenate title and content
                    title = str(article.title) if article.title else ""
                    content = str(article.content) if article.content else ""
                    full_text = f"{title} {content}".strip()
                    
                    analysis = hunting_detector.detect_hunting_techniques(
                        full_text,
                        article.id
                    )
                    
                    total_techniques_detected += analysis.total_techniques
                    
                    if analysis.hunting_priority in ["High", "Medium"]:
                        high_priority_articles += 1
                    
                    # Count technique categories
                    for category, techniques in analysis.techniques_by_category.items():
                        technique_categories[category] += len(techniques)
                    
                    # Calculate quality score
                    quality_analysis = hunting_detector.calculate_ttp_quality_score(content)
                    # Ensure we only sum numeric values
                    numeric_values = [v for v in quality_analysis.values() if isinstance(v, (int, float))]
                    total_score = sum(numeric_values) if numeric_values else 0
                    quality_scores.append(total_score)
                    
                    # Add to recent analyses (top 5)
                    if len(recent_analyses) < 5:
                        recent_analyses.append({
                            "article": article,
                            "analysis": analysis,
                            "quality_score": total_score
                        })
                    
                except Exception as e:
                    logger.warning(f"TTP analysis failed for article {article.id}: {e}")
                    continue
        
        # Calculate summary statistics
        avg_quality = sum(quality_scores) / len(quality_scores) if quality_scores else 0.0
        
        # Quality distribution (based on 75-point scale)
        distribution = {"Excellent": 0, "Good": 0, "Fair": 0, "Limited": 0}
        for score in quality_scores:
            if score >= 60:
                distribution["Excellent"] += 1
            elif score >= 40:
                distribution["Good"] += 1
            elif score >= 20:
                distribution["Fair"] += 1
            else:
                distribution["Limited"] += 1
        
        analysis_summary = {
            "total_techniques_detected": total_techniques_detected,
            "high_priority_articles": high_priority_articles,
            "mitre_coverage": len([cat for cat in technique_categories if "MITRE" in cat.upper()]),
            "recent_analysis": recent_analyses
        }
        
        quality_stats = {
            "average_score": avg_quality,
            "total_analyzed": len(quality_scores),
            "distribution": distribution
        }
        
        return templates.TemplateResponse(
            "analysis.html",
            {
                "request": request,
                "stats": stats,
                "articles": articles,
                "analysis_summary": analysis_summary,
                "quality_stats": quality_stats,
                "analyses": recent_analyses  # Add this for the template
            }
        )
    except Exception as e:
        logger.error(f"Analysis page error: {e}")
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": str(e)},
            status_code=500
        )

@app.get("/api/articles")
async def api_articles_list(limit: Optional[int] = 100):
    """API endpoint for listing articles."""
    try:
        articles = await async_db_manager.list_articles(limit=limit)
        return {"articles": [article.dict() for article in articles]}
    except Exception as e:
        logger.error(f"API articles list error: {e}")
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
