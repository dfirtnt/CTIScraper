"""
Celery Application for CTI Scraper Background Tasks

Handles source checking, article collection, and other async operations.
"""

import os
from celery import Celery
from celery.schedules import crontab

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('CELERY_CONFIG_MODULE', 'src.worker.celeryconfig')

# Create the Celery app
celery_app = Celery('cti_scraper')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
celery_app.config_from_object('src.worker.celeryconfig')

# Load task modules from all registered app configs.
celery_app.autodiscover_tasks()

# Define periodic tasks
@celery_app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    """Setup periodic tasks for the CTI Scraper."""
    
    # Check all sources every hour
    sender.add_periodic_task(
        crontab(minute=0),  # Every hour at minute 0
        check_all_sources.s(),
        name='check-all-sources-hourly'
    )
    
    # Check Tier 1 sources every 15 minutes
    sender.add_periodic_task(
        crontab(minute='*/15'),  # Every 15 minutes
        check_tier1_sources.s(),
        name='check-tier1-sources-quarterly'
    )
    
    # Clean up old data daily at 2 AM
    sender.add_periodic_task(
        crontab(hour=2, minute=0),  # Daily at 2 AM
        cleanup_old_data.s(),
        name='cleanup-old-data-daily'
    )
    
    # Generate daily reports at 6 AM
    sender.add_periodic_task(
        crontab(hour=6, minute=0),  # Daily at 6 AM
        generate_daily_report.s(),
        name='generate-daily-report'
    )


@celery_app.task(bind=True, max_retries=3)
def check_all_sources(self):
    """Check all active sources for new content."""
    try:
        import asyncio
        from src.database.async_manager import AsyncDatabaseManager
        from src.core.rss_parser import RSSParser
        from src.utils.http import HTTPClient
        
        async def run_source_check():
            """Run the actual source checking."""
            db = AsyncDatabaseManager()
            try:
                # Get all active sources
                sources = await db.list_sources()
                active_sources = [s for s in sources if getattr(s, 'active', True)]
                
                logger.info(f"Checking {len(active_sources)} active sources for new content...")
                
                if not active_sources:
                    return {"status": "success", "message": "No active sources to check"}
                
                total_new_articles = 0
                
                async with HTTPClient() as http_client:
                    rss_parser = RSSParser(http_client)
                    
                    for source in active_sources:
                        try:
                            # Parse RSS feed for new articles
                            articles = await rss_parser.parse_feed(source)
                            
                            if articles:
                                # Store new articles
                                for article in articles:
                                    try:
                                        # Check if article already exists
                                        existing = await db.get_article_by_url(article.canonical_url)
                                        if not existing:
                                            await db.create_article(article)
                                            total_new_articles += 1
                                    except Exception as e:
                                        logger.error(f"Error storing article from {source.name}: {e}")
                                        continue
                                        
                            logger.info(f"  ✓ {source.name}: {len(articles) if articles else 0} articles found")
                            
                        except Exception as e:
                            logger.error(f"  ✗ {source.name}: Error - {e}")
                            continue
                
                return {
                    "status": "success", 
                    "message": f"Checked {len(active_sources)} sources, found {total_new_articles} new articles"
                }
                
            except Exception as e:
                logger.error(f"Source checking failed: {e}")
                raise e
            finally:
                await db.close()
        
        # Run the async function
        result = asyncio.run(run_source_check())
        return result
        
    except Exception as exc:
        logger.error(f"Source check task failed: {exc}")
        # Retry with exponential backoff
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@celery_app.task(bind=True, max_retries=3)
def check_tier1_sources(self):
    """Check Tier 1 sources more frequently."""
    try:
        logger.info("Checking Tier 1 sources for new content...")
        
        # TODO: Implement Tier 1 source checking
        # This would check high-priority sources more frequently
        
        return {"status": "success", "message": "Tier 1 sources checked"}
        
    except Exception as exc:
        raise self.retry(exc=exc, countdown=30 * (2 ** self.request.retries))


@celery_app.task(bind=True, max_retries=2)
def cleanup_old_data(self):
    """Clean up old articles and source check data."""
    try:
        logger.info("Cleaning up old data...")
        
        # TODO: Implement data cleanup logic
        # - Remove articles older than X days
        # - Clean up old source check records
        # - Archive old data if needed
        
        return {"status": "success", "message": "Old data cleaned up"}
        
    except Exception as exc:
        raise self.retry(exc=exc, countdown=300 * (2 ** self.request.retries))


@celery_app.task(bind=True, max_retries=2)
def generate_daily_report(self):
    """Generate daily threat intelligence report."""
    try:
        logger.info("Generating daily threat intelligence report...")
        
        # TODO: Implement daily report generation
        # - Collect statistics from the past 24 hours
        # - Generate TTP analysis summary
        # - Create executive summary
        # - Send notifications if configured
        
        return {"status": "success", "message": "Daily report generated"}
        
    except Exception as exc:
        raise self.retry(exc=exc, countdown=600 * (2 ** self.request.retries))


@celery_app.task(bind=True, max_retries=3)
def test_source_connectivity(self, source_id: int):
    """Test connectivity to a specific source."""
    try:
        logger.info(f"Testing connectivity to source {source_id}...")
        
        # TODO: Implement source connectivity testing
        # - Test main URL accessibility
        # - Test RSS feed if available
        # - Measure response times
        # - Update source health metrics
        
        return {"status": "success", "source_id": source_id, "message": "Connectivity test completed"}
        
    except Exception as exc:
        raise self.retry(exc=exc, countdown=30 * (2 ** self.request.retries))


@celery_app.task(bind=True, max_retries=3)
def collect_from_source(self, source_id: int):
    """Collect new content from a specific source."""
    try:
        logger.info(f"Collecting content from source {source_id}...")
        
        # TODO: Implement content collection
        # - Fetch RSS feed or scrape website
        # - Extract new articles
        # - Process and store content
        # - Update source statistics
        
        return {"status": "success", "source_id": source_id, "message": "Content collection completed"}
        
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


if __name__ == '__main__':
    celery_app.start()
