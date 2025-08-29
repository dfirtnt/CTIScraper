# 🛡️ CTI Scraper - Modern Threat Intelligence Platform

**Enterprise-grade threat intelligence aggregation and analysis platform built with modern technologies.**

## 🚀 **What's New in Version 2.0**

### **Architecture Improvements**
- **PostgreSQL Database**: Replaced SQLite with production-grade PostgreSQL
- **Async/Await**: Full async support with FastAPI and SQLAlchemy
- **Connection Pooling**: Efficient database connection management
- **Background Tasks**: Celery worker system for async operations
- **Redis Caching**: High-performance caching and message queuing
- **Docker Containerization**: Production-ready container orchestration
- **Nginx Reverse Proxy**: Professional-grade web server with rate limiting

### **Performance Enhancements**
- **Concurrent Operations**: Handle multiple users and operations simultaneously
- **Database Locking**: Eliminated SQLite locking issues
- **Connection Management**: Proper session handling and cleanup
- **Task Queuing**: Asynchronous processing of heavy operations
- **Health Monitoring**: Built-in health checks and monitoring

## 🏗️ **Technology Stack**

### **Backend**
- **FastAPI 2.0**: Modern, fast web framework with async support
- **PostgreSQL 15**: Production database with connection pooling
- **Redis 7**: Caching and message broker
- **SQLAlchemy 2.0**: Async ORM with proper transaction handling
- **Celery**: Background task processing and scheduling

### **Frontend**
- **Jinja2 Templates**: Server-side rendering
- **Tailwind CSS**: Modern, utility-first CSS framework
- **HTMX**: Dynamic content updates without JavaScript
- **Chart.js**: Interactive data visualization

### **Infrastructure**
- **Docker & Docker Compose**: Container orchestration
- **Nginx**: Reverse proxy with rate limiting and compression
- **Uvicorn**: ASGI server for FastAPI
- **Alembic**: Database migrations

## 📦 **Quick Start**

### **Option 1: Production Stack (Docker)**
```bash
# Start the complete production stack
./start_production.sh

# Access the application
open http://localhost
```

### **Option 2: Development Environment**
```bash
# Start local development environment
./start_development.sh

# Access the application
open http://localhost:8000
```

### **Option 3: Manual Setup**
```bash
# Install dependencies
pip install -r requirements.txt

# Start PostgreSQL and Redis
brew services start postgresql@15
brew services start redis

# Create database
createdb cti_scraper

# Start the application
python src/web/modern_main.py
```

## 🔧 **Configuration**

### **Environment Variables**
Copy `config.production.env` to `.env` and modify as needed:

```bash
# Database
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/dbname
POSTGRES_PASSWORD=your_password

# Redis
REDIS_URL=redis://:password@localhost:6379/0
REDIS_PASSWORD=your_redis_password

# Application
ENVIRONMENT=production
LOG_LEVEL=INFO
SECRET_KEY=your-secret-key
```

### **Database Configuration**
```bash
# PostgreSQL connection settings
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=30
DB_POOL_PRE_PING=true
DB_POOL_RECYCLE=3600
```

## 🗄️ **Database Schema**

### **Core Tables**
- **`sources`**: Threat intelligence sources and configuration
- **`articles`**: Collected threat intelligence articles
- **`source_checks`**: Source health and connectivity monitoring
- **`content_hashes`**: Content deduplication
- **`url_tracking`**: URL processing history

### **Modern Features**
- **Async Operations**: Non-blocking database operations
- **Connection Pooling**: Efficient connection management
- **Transaction Management**: Proper ACID compliance
- **Migration Support**: Alembic for schema evolution

## 🔄 **Background Tasks**

### **Scheduled Tasks**
- **Hourly**: Check all sources for new content
- **15 Minutes**: Check Tier 1 (high-priority) sources
- **Daily 2 AM**: Clean up old data
- **Daily 6 AM**: Generate threat intelligence reports

### **Task Queues**
- **`source_checks`**: Source connectivity testing
- **`priority_checks`**: High-priority source monitoring
- **`collection`**: Content collection and processing
- **`maintenance`**: System maintenance tasks
- **`reports`**: Report generation

## 📊 **API Endpoints**

### **Core API**
```bash
# Health and monitoring
GET /health                    # System health check
GET /api/sources              # List all sources
GET /api/articles             # List all articles

# Source management
POST /api/sources/{id}/toggle # Toggle source status
POST /api/sources/{id}/test   # Test source connectivity
GET /api/sources/{id}/stats   # Get source statistics

# Article management
GET /api/articles/{id}        # Get specific article
```

### **Web Interface**
```bash
# Main pages
/                    # Dashboard
/sources             # Source management
/articles            # Article listing
/articles/{id}       # Article detail
```

## 🐳 **Docker Services**

### **Service Architecture**
```yaml
postgres:    # PostgreSQL database
redis:       # Redis cache and message broker
web:         # FastAPI web application
worker:      # Celery worker for background tasks
scheduler:   # Celery beat for scheduled tasks
nginx:       # Reverse proxy and load balancer
```

### **Management Commands**
```bash
# View logs
docker-compose logs -f [service]

# Restart service
docker-compose restart [service]

# Stop all services
docker-compose down

# Rebuild and start
docker-compose up --build -d
```

## 📈 **Monitoring & Health**

### **Health Checks**
- **Database**: Connection and query performance
- **Redis**: Cache and message broker status
- **Web Service**: API responsiveness
- **Background Workers**: Task processing status

### **Metrics**
- **Source Health**: Success rates and response times
- **Content Collection**: Articles per source and time
- **System Performance**: Response times and throughput
- **Error Rates**: Failed operations and exceptions

## 🔒 **Security Features**

### **Built-in Security**
- **Rate Limiting**: API and web request throttling
- **CORS Protection**: Cross-origin request handling
- **Input Validation**: Pydantic model validation
- **SQL Injection Protection**: Parameterized queries
- **XSS Protection**: Template escaping and sanitization

### **Production Hardening**
- **Environment Isolation**: Separate dev/prod configs
- **Secret Management**: Environment variable configuration
- **Access Control**: Database user permissions
- **Network Security**: Container network isolation

## 🚀 **Performance Features**

### **Optimization**
- **Connection Pooling**: Efficient database connections
- **Async Processing**: Non-blocking I/O operations
- **Caching**: Redis-based result caching
- **Compression**: Gzip compression for responses
- **Background Processing**: Heavy operations offloaded

### **Scalability**
- **Horizontal Scaling**: Multiple worker processes
- **Load Balancing**: Nginx reverse proxy
- **Queue Management**: Celery task distribution
- **Database Sharding**: Ready for future expansion

## 🧪 **Testing & Development**

### **Development Tools**
```bash
# Run tests
pytest

# Code formatting
black src/

# Linting
flake8 src/

# Type checking
mypy src/
```

### **Local Development**
```bash
# Start development environment
./start_development.sh

# Hot reload enabled
# Code changes automatically reload
```

## 📚 **Documentation**

### **API Documentation**
- **Interactive Docs**: Available at `/docs` (Swagger UI)
- **ReDoc**: Alternative docs at `/redoc`
- **OpenAPI Schema**: Machine-readable API specification

### **Code Documentation**
- **Type Hints**: Full Python type annotations
- **Docstrings**: Comprehensive function documentation
- **Examples**: Usage examples in docstrings

## 🤝 **Contributing**

### **Development Setup**
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests and documentation
5. Submit a pull request

### **Code Standards**
- **Python**: PEP 8 compliance
- **Type Hints**: Required for all functions
- **Documentation**: Docstrings for all public APIs
- **Testing**: Unit tests for new features

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 **Support**

### **Common Issues**
- **Database Connection**: Check PostgreSQL service status
- **Redis Connection**: Verify Redis service is running
- **Port Conflicts**: Ensure ports 8000, 5432, 6379 are available
- **Permission Issues**: Check file permissions and ownership

### **Getting Help**
- **Issues**: GitHub issue tracker
- **Documentation**: This README and inline code docs
- **Community**: GitHub discussions and discussions

---

## 🎯 **Next Steps**

1. **Start the Production Stack**: `./start_production.sh`
2. **Explore the API**: Visit `http://localhost/docs`
3. **Monitor Health**: Check `http://localhost/health`
4. **Configure Sources**: Add your threat intelligence sources
5. **Customize Alerts**: Set up notification preferences

**Welcome to the future of threat intelligence! 🚀**
