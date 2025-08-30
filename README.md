# 🛡️ CTI Scraper - Modern Threat Intelligence Platform

**Enterprise-grade threat intelligence aggregation and analysis platform built with modern technologies.**

[![CI/CD Pipeline](https://github.com/your-username/CTIScraper/workflows/CI/badge.svg)](https://github.com/your-username/CTIScraper/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Technology Stack](#technology-stack)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Documentation](#api-documentation)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

CTI Scraper is a comprehensive threat intelligence platform that automatically collects, analyzes, and processes threat intelligence from various sources. Built with modern async Python technologies, it provides enterprise-grade performance, scalability, and security.

### Key Capabilities

- **Automated Collection**: RSS feed parsing and web scraping with anti-bot protection
- **Content Analysis**: LLM-powered quality assessment and TTP extraction
- **Real-time Processing**: Async architecture with background task processing
- **Modern Web Interface**: HTMX-powered dashboard with real-time analytics
- **Production Ready**: Docker containerization with PostgreSQL and Redis

## ✨ Features

### 🔍 **Intelligence Collection**
- **Multi-source RSS/Atom feed parsing**
- **Advanced web scraping with anti-bot detection**
- **Content deduplication and quality validation**
- **Source health monitoring and alerting**

### 🤖 **AI-Powered Analysis**
- **LLM-based content quality assessment**
- **TTP (Tactics, Techniques, Procedures) extraction**
- **Multi-model AI chatbot with source attribution**
- **Threat hunting priority scoring**

### 🏗️ **Modern Architecture**
- **Async/await throughout the stack**
- **PostgreSQL with connection pooling**
- **Redis caching and message queuing**
- **Celery background task processing**

### 🛡️ **Security & Compliance**
- **Environment-based configuration**
- **Input validation and sanitization**
- **Rate limiting and CORS protection**
- **Comprehensive audit logging**

### 📊 **Web Dashboard**
- **Real-time analytics and metrics**
- **Source management interface**
- **Article browsing and search**
- **TTP analysis visualization**

## 🏗️ Technology Stack

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

## 🚀 Quick Start

### **Option 1: Production Stack (Docker)**
```bash
# Clone the repository
git clone https://github.com/your-username/CTIScraper.git
cd CTIScraper

# Copy environment template
cp env.example .env
# Edit .env with your configuration

# Start the complete production stack
./start_production.sh

# Access the application
open http://localhost
```

### **Option 2: Development Environment**
```bash
# Clone and setup
git clone https://github.com/your-username/CTIScraper.git
cd CTIScraper

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Setup environment
cp env.example .env
# Edit .env with your settings

# Start services
brew services start postgresql@15  # macOS
brew services start redis

# Create database
createdb cti_scraper

# Start the application
python src/web/modern_main.py
```

## 📦 Installation

### **Prerequisites**
- Python 3.9+
- PostgreSQL 15+
- Redis 7+
- Docker & Docker Compose (for production)

### **System Dependencies**
```bash
# macOS
brew install postgresql@15 redis

# Ubuntu/Debian
sudo apt-get install postgresql-15 redis-server

# CentOS/RHEL
sudo yum install postgresql15-server redis
```

### **Python Dependencies**
```bash
# Install Python packages
pip install -r requirements.txt

# For development
pip install -r requirements-test.txt
```

## ⚙️ Configuration

### **Environment Variables**
Copy `env.example` to `.env` and configure:

```bash
# Database Configuration
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/dbname
POSTGRES_PASSWORD=your_secure_password

# Redis Configuration
REDIS_URL=redis://:password@localhost:6379/0
REDIS_PASSWORD=your_redis_password

# Application Configuration
ENVIRONMENT=production
SECRET_KEY=your-super-secret-key-change-this
```

### **Source Configuration**
Add threat intelligence sources via the web interface or API:

```python
# Example source configuration
{
    "name": "The DFIR Report",
    "url": "https://thedfirreport.com/feed/",
    "type": "rss",
    "tier": 1,
    "check_frequency": 900  # 15 minutes
}
```

## 🎮 Usage

### **Web Interface**
- **Dashboard**: `http://localhost:8000/`
- **Sources**: `http://localhost:8000/sources`
- **Articles**: `http://localhost:8000/articles`
- **Chat**: `http://localhost:8000/chat`

### **CLI Commands**
```bash
# List sources
python -m src.cli.main sources list

# Collect from all sources
python -m src.cli.main collect

# Analyze articles for TTPs
python -m src.cli.main analyze

# Export articles
python -m src.cli.main export --format csv

# Monitor sources continuously
python -m src.cli.main monitor --interval 3600
```

### **API Usage**
```bash
# Health check
curl http://localhost:8000/health

# List sources
curl http://localhost:8000/api/sources

# Get articles
curl http://localhost:8000/api/articles

# Chat with AI
curl -X POST http://localhost:8000/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What are the latest ransomware trends?"}'
```

## 📚 API Documentation

### **Interactive Documentation**
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI Schema**: `http://localhost:8000/openapi.json`

### **Core Endpoints**
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
POST /api/articles/search     # Search articles
GET /api/articles/export      # Export articles

# AI Chat
POST /api/chat               # Send message to chatbot
GET /api/chat/history        # Get conversation history
POST /api/chat/clear         # Clear conversation history
```

## 🔒 Security

### **Built-in Security Features**
- **Input Validation**: Pydantic model validation
- **SQL Injection Protection**: Parameterized queries
- **XSS Protection**: Template escaping
- **Rate Limiting**: API and web request throttling
- **CORS Protection**: Cross-origin request handling
- **Environment Variables**: No hardcoded secrets

### **Security Best Practices**
1. **Use HTTPS in production**
2. **Keep dependencies updated**
3. **Monitor logs for suspicious activity**
4. **Use strong, unique passwords**
5. **Enable security features**

### **Reporting Security Issues**
**Do not report security vulnerabilities through public GitHub issues.**

Please report security issues via email to `security@ctiscraper.com`. See our [Security Policy](.github/SECURITY.md) for details.

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### **Quick Start for Contributors**
```bash
# Fork and clone
git clone https://github.com/your-username/CTIScraper.git
cd CTIScraper

# Setup development environment
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-test.txt

# Run tests
pytest

# Format code
black src/
isort src/

# Create feature branch
git checkout -b feature/your-feature
```

### **Development Guidelines**
- Follow PEP 8 with Black formatting
- Use type hints for all functions
- Write tests for new features
- Update documentation
- Follow security best practices

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### **Getting Help**
- **Issues**: [GitHub Issues](https://github.com/your-username/CTIScraper/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-username/CTIScraper/discussions)
- **Documentation**: This README and inline code docs
- **Security**: See [SECURITY.md](.github/SECURITY.md)

### **Common Issues**
- **Database Connection**: Check PostgreSQL service status
- **Redis Connection**: Verify Redis service is running
- **Port Conflicts**: Ensure ports 8000, 5432, 6379 are available
- **Permission Issues**: Check file permissions and ownership

## 🏆 Acknowledgments

- **Contributors**: All who have contributed to this project
- **Open Source**: Built on amazing open source technologies
- **Security Community**: For feedback and security improvements

---

## 📈 Roadmap

### **Upcoming Features**
- [ ] Advanced threat correlation
- [ ] Machine learning-based threat detection
- [ ] Integration with SIEM platforms
- [ ] Mobile application
- [ ] Advanced reporting and analytics

### **Version History**
See [CHANGELOG.md](CHANGELOG.md) for detailed version history and migration guides.

---

**CTI Scraper** - Making threat intelligence accessible and actionable. 🚀
