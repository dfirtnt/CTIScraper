"""
Modern Async Database Manager for CTI Scraper

Uses PostgreSQL with SQLAlchemy async for production-grade performance.
"""

import asyncio
import logging
from typing import List, Optional, Dict, Any, AsyncGenerator
from datetime import datetime, timedelta
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    create_async_engine, 
    AsyncSession, 
    async_sessionmaker,
    AsyncEngine
)
from sqlalchemy import select, update, delete, func, and_, or_, desc
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.orm import selectinload

from src.database.models import Base, SourceTable, ArticleTable, SourceCheckTable
from src.models.source import Source, SourceCreate, SourceUpdate, SourceFilter
from src.models.article import Article, ArticleCreate, ArticleUpdate

logger = logging.getLogger(__name__)


class AsyncDatabaseManager:
    """Modern async database manager with connection pooling and proper transaction handling."""
    
    def __init__(
        self,
        database_url: str = os.getenv("DATABASE_URL", "postgresql+asyncpg://cti_user:cti_password_2024@postgres:5432/cti_scraper"),
        echo: bool = False,
        pool_size: int = 20,
        max_overflow: int = 30,
        pool_pre_ping: bool = True,
        pool_recycle: int = 3600
    ) -> None:
        """
        Initialize the async database manager.
        
        Args:
            database_url: PostgreSQL connection string
            echo: Enable SQL query logging
            pool_size: Database connection pool size
            max_overflow: Maximum overflow connections
            pool_pre_ping: Enable connection health checks
            pool_recycle: Connection recycle time in seconds
        """
        self.database_url = database_url
        self.echo = echo
        
        # Create async engine with connection pooling
        self.engine: AsyncEngine = create_async_engine(
            database_url,
            echo=echo,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_pre_ping=pool_pre_ping,
            pool_recycle=pool_recycle,
            future=True
        )
        
        # Create async session factory
        self.AsyncSessionLocal = async_sessionmaker(
            bind=self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False
        )
        
        logger.info(f"Initialized async database manager with pool size {pool_size}")
    
    @asynccontextmanager
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get an async database session with proper cleanup."""
        session = self.AsyncSessionLocal()
        try:
            yield session
        except Exception as e:
            await session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            await session.close()
    
    async def create_tables(self):
        """Create all database tables asynchronously."""
        try:
            async with self.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Failed to create tables: {e}")
            raise
    
    async def get_database_stats(self) -> Dict[str, Any]:
        """Get comprehensive database statistics."""
        try:
            async with self.get_session() as session:
                # Count sources
                sources_result = await session.execute(
                    select(func.count(SourceTable.id))
                )
                total_sources = sources_result.scalar()
                
                # Count active sources
                active_sources_result = await session.execute(
                    select(func.count(SourceTable.id)).where(SourceTable.active == True)
                )
                active_sources = active_sources_result.scalar()
                
                # Count articles
                articles_result = await session.execute(
                    select(func.count(ArticleTable.id))
                )
                total_articles = articles_result.scalar()
                
                # Articles in last 24h
                yesterday = datetime.now() - timedelta(days=1)
                recent_articles_result = await session.execute(
                    select(func.count(ArticleTable.id)).where(
                        ArticleTable.discovered_at >= yesterday
                    )
                )
                articles_last_24h = recent_articles_result.scalar()
                
                # Database size (approximate)
                db_size_mb = 0.0  # Would need actual DB size query
                
                return {
                    "total_sources": total_sources or 0,
                    "active_sources": active_sources or 0,
                    "total_articles": total_articles or 0,
                    "articles_last_24h": articles_last_24h or 0,
                    "database_size_mb": db_size_mb
                }
                
        except Exception as e:
            logger.error(f"Failed to get database stats: {e}")
            return {
                "total_sources": 0,
                "active_sources": 0,
                "total_articles": 0,
                "articles_last_24h": 0,
                "database_size_mb": 0.0
            }
    
    async def list_sources(self, filter_params: Optional[SourceFilter] = None) -> List[Source]:
        """List all sources with optional filtering."""
        try:
            async with self.get_session() as session:
                query = select(SourceTable)
                
                if filter_params:
                    if filter_params.tier:
                        query = query.where(SourceTable.tier == filter_params.tier)
                    if filter_params.active is not None:
                        query = query.where(SourceTable.active == filter_params.active)
                    if filter_params.identifier_contains:
                        query = query.where(
                            SourceTable.identifier.contains(filter_params.identifier_contains)
                        )
                    if filter_params.name_contains:
                        query = query.where(
                            SourceTable.name.contains(filter_params.name_contains)
                        )
                
                query = query.order_by(SourceTable.tier, SourceTable.name)
                result = await session.execute(query)
                db_sources = result.scalars().all()
                
                return [self._db_source_to_model(db_source) for db_source in db_sources]
                
        except Exception as e:
            logger.error(f"Failed to list sources: {e}")
            return []
    
    async def get_source(self, source_id: int) -> Optional[Source]:
        """Get a specific source by ID."""
        try:
            async with self.get_session() as session:
                result = await session.execute(
                    select(SourceTable).where(SourceTable.id == source_id)
                )
                db_source = result.scalar_one_or_none()
                
                if db_source:
                    return self._db_source_to_model(db_source)
                return None
                
        except Exception as e:
            logger.error(f"Failed to get source {source_id}: {e}")
            return None
    
    async def update_source(self, source_id: int, update_data: SourceUpdate) -> Optional[Source]:
        """Update a source with proper transaction handling."""
        try:
            async with self.get_session() as session:
                # Get the source
                result = await session.execute(
                    select(SourceTable).where(SourceTable.id == source_id)
                )
                db_source = result.scalar_one_or_none()
                
                if not db_source:
                    return None
                
                # Update fields
                update_dict = update_data.dict(exclude_unset=True)
                for field, value in update_dict.items():
                    if field == 'config' and value:
                        setattr(db_source, field, value.dict())
                    else:
                        setattr(db_source, field, value)
                
                # Update timestamp
                db_source.updated_at = datetime.now()
                
                await session.commit()
                await session.refresh(db_source)
                
                logger.info(f"Successfully updated source: {db_source.identifier}")
                return self._db_source_to_model(db_source)
                
        except Exception as e:
            logger.error(f"Failed to update source {source_id}: {e}")
            raise
    
    async def toggle_source_status(self, source_id: int) -> Optional[Dict[str, Any]]:
        """Toggle source active status with proper transaction handling."""
        try:
            async with self.get_session() as session:
                # Get the source
                result = await session.execute(
                    select(SourceTable).where(SourceTable.id == source_id)
                )
                db_source = result.scalar_one_or_none()
                
                if not db_source:
                    return None
                
                # Toggle the status
                old_status = db_source.active
                new_status = not old_status
                db_source.active = new_status
                db_source.updated_at = datetime.now()
                
                # Commit the transaction
                await session.commit()
                await session.refresh(db_source)
                
                logger.info(f"Successfully toggled source {source_id} from {old_status} to {new_status}")
                
                return {
                    "source_id": source_id,
                    "source_name": db_source.name,
                    "old_status": old_status,
                    "new_status": new_status,
                    "success": True
                }
                
        except Exception as e:
            logger.error(f"Failed to toggle source {source_id}: {e}")
            raise
    
    async def list_articles(self, limit: Optional[int] = None) -> List[Article]:
        """List articles with optional limit."""
        try:
            async with self.get_session() as session:
                query = select(ArticleTable).order_by(desc(ArticleTable.discovered_at))
                
                if limit:
                    query = query.limit(limit)
                
                result = await session.execute(query)
                db_articles = result.scalars().all()
                
                return [self._db_article_to_model(db_article) for db_article in db_articles]
                
        except Exception as e:
            logger.error(f"Failed to list articles: {e}")
            return []
    
    async def get_article(self, article_id: int) -> Optional[Article]:
        """Get a specific article by ID."""
        try:
            async with self.get_session() as session:
                result = await session.execute(
                    select(ArticleTable).where(ArticleTable.id == article_id)
                )
                db_article = result.scalar_one_or_none()
                
                if db_article:
                    return self._db_article_to_model(db_article)
                return None
                
        except Exception as e:
            logger.error(f"Failed to get article {article_id}: {e}")
            return None
    
    async def get_article_by_url(self, canonical_url: str) -> Optional[Article]:
        """Get a specific article by canonical URL."""
        try:
            async with self.get_session() as session:
                result = await session.execute(
                    select(ArticleTable).where(ArticleTable.canonical_url == canonical_url)
                )
                db_article = result.scalar_one_or_none()
                
                if db_article:
                    return self._db_article_to_model(db_article)
                return None
                
        except Exception as e:
            logger.error(f"Failed to get article by URL {canonical_url}: {e}")
            return None
    
    def _db_source_to_model(self, db_source: SourceTable) -> Source:
        """Convert database source to Pydantic model."""
        from src.models.source import SourceConfig
        
        return Source(
            id=db_source.id,
            identifier=db_source.identifier,
            name=db_source.name,
            url=db_source.url,
            rss_url=db_source.rss_url,
            tier=db_source.tier,
            weight=db_source.weight,
            check_frequency=db_source.check_frequency,
            active=db_source.active,
            config=SourceConfig.parse_obj(db_source.config),
            last_check=db_source.last_check,
            last_success=db_source.last_success,
            consecutive_failures=db_source.consecutive_failures,
            total_articles=db_source.total_articles,
            success_rate=db_source.success_rate,
            average_response_time=db_source.average_response_time
        )
    
    def _db_article_to_model(self, db_article: ArticleTable) -> Article:
        """Convert database article to Pydantic model."""
        return Article(
            id=db_article.id,
            source_id=db_article.source_id,
            canonical_url=db_article.canonical_url,
            title=db_article.title,
            published_at=db_article.published_at,
            modified_at=db_article.modified_at,
            authors=db_article.authors,
            tags=db_article.tags,
            summary=db_article.summary,
            content=db_article.content,
            content_hash=db_article.content_hash,
            metadata=db_article.article_metadata,
            discovered_at=db_article.discovered_at,
            processing_status=db_article.processing_status
        )
    
    async def close(self):
        """Close database connections properly."""
        await self.engine.dispose()
        logger.info("Database connections closed")


# Global instance for easy access
async_db_manager = AsyncDatabaseManager()
