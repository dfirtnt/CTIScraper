# Security Policy

## 🛡️ Security Overview

The CTI Scraper project takes security seriously. This document outlines our security practices, how to report vulnerabilities, and what to expect from our security response process.

## 🔍 Supported Versions

We actively maintain security updates for the following versions:

| Version | Supported          | Support Level |
| ------- | ------------------ | ------------- |
| 1.x.x   | ✅ Yes             | Full support  |
| 0.x.x   | ⚠️ Limited         | Critical fixes only |

## 🚨 Reporting Security Vulnerabilities

**Please do NOT report security vulnerabilities through public GitHub issues.**

### Preferred Reporting Method

Send security vulnerability reports to: **security@[your-domain].com**

### Alternative Reporting Methods

1. **GitHub Security Advisories**: Use the "Security" tab → "Report a vulnerability"
2. **Direct Email**: Contact the maintainers directly
3. **Encrypted Communication**: PGP key available upon request

### Information to Include

Please include as much of the following information as possible:

- **Type of vulnerability** (e.g., RCE, SQL injection, XSS, etc.)
- **Location** of the affected source code (file names and line numbers)
- **Step-by-step instructions** to reproduce the issue
- **Proof of concept or exploit code** (if available)
- **Impact assessment** - what an attacker could achieve
- **Suggested fix** (if you have one)

## ⏱️ Response Timeline

We aim to respond to security reports according to the following timeline:

| Severity | Initial Response | Investigation | Fix & Release |
|----------|------------------|---------------|---------------|
| Critical | 24 hours         | 72 hours      | 7 days        |
| High     | 48 hours         | 1 week        | 2 weeks       |
| Medium   | 1 week           | 2 weeks       | 1 month       |
| Low      | 2 weeks          | 1 month       | Next release  |

## 🔒 Security Measures

### Current Security Practices

#### **Input Validation & Sanitization**
- ✅ Pydantic models validate all input data
- ✅ HTML content is sanitized using BeautifulSoup
- ✅ URL validation using the `validators` library
- ✅ SQL injection prevention via SQLAlchemy ORM

#### **Authentication & Authorization**
- ✅ No default passwords or hardcoded credentials
- ✅ Environment variable configuration for sensitive data
- ✅ Optional API key support for external services
- ✅ Rate limiting to prevent abuse

#### **Network Security**
- ✅ HTTPS-only connections for data collection
- ✅ Configurable request timeouts
- ✅ User-Agent identification
- ✅ Robots.txt compliance

#### **Data Protection**
- ✅ Content deduplication prevents data bloat
- ✅ Configurable data retention policies
- ✅ No sensitive data logged in production
- ✅ Optional content encryption support

#### **Dependency Management**
- ✅ Pinned dependency versions
- ✅ Regular dependency updates
- ✅ Automated vulnerability scanning
- ✅ Security-focused dependency selection

### Security Scanning

We regularly perform:

- **Static Analysis**: Bandit for Python security scanning
- **Dependency Scanning**: Safety for known vulnerabilities
- **Code Quality**: SonarQube analysis
- **Container Scanning**: If using Docker deployments

## 🚫 Security Considerations

### Known Limitations

1. **Web Scraping Risks**: 
   - Content from external sources is sanitized but may contain malicious patterns
   - Always review collected content before analysis

2. **Database Security**:
   - Default SQLite configuration - secure file permissions recommended
   - No built-in database encryption (use filesystem encryption)

3. **Network Exposure**:
   - CLI tool not designed for network exposure
   - No built-in authentication for multi-user scenarios

### Recommended Security Practices

#### **For Development**
```bash
# Use virtual environments
python -m venv venv
source venv/bin/activate

# Regular security scans
bandit -r src/
safety check

# Secure dependency updates
pip-audit
```

#### **For Production**
```bash
# Use environment-specific configuration
cp .env.example .env.production

# Secure file permissions
chmod 600 .env.production
chmod 755 threat-intel

# Database security
chmod 600 threat_intel.db

# Regular updates
pip install --upgrade -r requirements.txt
```

#### **For Deployment**
- Use dedicated service accounts with minimal permissions
- Implement file system encryption for sensitive data
- Configure firewall rules to restrict network access
- Enable audit logging for security events
- Regularly rotate API keys and credentials

## 🔧 Security Configuration

### Environment Variables

Secure your deployment by configuring these environment variables:

```bash
# Database security
DATABASE_URL=postgresql://user:pass@localhost/db  # Use encrypted connections

# API security  
VIRUSTOTAL_API_KEY=your-key-here  # Rotate regularly
SHODAN_API_KEY=your-key-here      # Monitor usage

# Application security
LOG_LEVEL=WARNING                 # Reduce information disclosure
DEBUG=false                       # Disable debug mode
ENCRYPTION_KEY=your-secret-key    # Use strong random keys
```

### Content Security

```python
# config/sources.yaml security settings
source_name:
  config:
    max_articles: 100        # Limit resource consumption
    timeout: 30             # Prevent hanging requests
    rate_limit: 60          # Respect external services
    user_agent: "CTI-Bot"   # Identify your requests
```

## 🏆 Security Recognition

We appreciate security researchers who help keep CTI Scraper secure. Contributors who report valid security vulnerabilities will be:

1. **Credited** in our security advisories (with permission)
2. **Listed** in our Hall of Fame (if desired)
3. **Notified** when fixes are released

### Hall of Fame

*Security researchers who have contributed to CTI Scraper security will be listed here.*

## 📚 Additional Resources

### Security Tools & Integrations

- **SAST**: Bandit, SonarQube, CodeQL
- **Dependency Scanning**: Safety, Snyk, GitHub Dependabot
- **Container Security**: Trivy, Clair
- **Infrastructure**: Terraform security scanning

### Security Best Practices

1. **[OWASP Top 10](https://owasp.org/www-project-top-ten/)**
2. **[Python Security Guidelines](https://python-security.readthedocs.io/)**
3. **[Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)**

## 📞 Contact Information

- **Security Team**: security@[your-domain].com
- **General Questions**: [GitHub Discussions](https://github.com/yourusername/ctiscraper/discussions)
- **Bug Reports**: [GitHub Issues](https://github.com/yourusername/ctiscraper/issues)

---

**Last Updated**: 2025-01-XX  
**Next Review**: 2025-XX-XX
