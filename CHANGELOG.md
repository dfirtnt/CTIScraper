# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- GitHub-ready project structure with comprehensive documentation
- MIT License for open-source distribution
- GitHub Actions CI/CD pipeline with multi-Python testing
- Security policy and vulnerability reporting guidelines
- Contributing guidelines with development standards
- Comprehensive .gitignore covering Python, IDEs, and security files
- Environment variable configuration with .env.example template
- Pinned dependencies for security and reproducibility

### Changed
- Updated requirements.txt with exact version pinning
- Enhanced project documentation with professional README.md

### Security
- Added security scanning with Bandit and Safety
- Implemented environment variable security practices
- Added dependency vulnerability scanning to CI pipeline

## [1.0.0] - 2025-01-XX

### Added
- **Three-tier content collection strategy**
  - Tier 1: RSS/Atom feed parsing with feedparser
  - Tier 2: Modern web scraping with JavaScript support
  - Tier 3: Legacy HTML parsing for older sites
  
- **Core Components**
  - Asynchronous HTTP client with rate limiting and robots.txt compliance
  - Intelligent content extraction and cleaning using readability-lxml
  - Advanced deduplication with SHA256 content fingerprinting
  - Quality scoring for automated content assessment
  - SQLite database with structured data models

- **CLI Interface**
  - Rich command-line interface with progress indicators
  - Virtual environment enforcement for security
  - Auto-activating shell wrapper for convenience
  - Comprehensive source management commands
  - Flexible export capabilities (JSON, CSV, YAML)

- **Data Models**
  - Pydantic-based validation for all data structures
  - Comprehensive source configuration with YAML support
  - Article models with metadata and content tracking
  - Health monitoring and collection statistics

- **Security Features**
  - Input validation and sanitization
  - No hardcoded credentials or secrets
  - Configurable rate limiting and timeouts
  - Content cleaning and normalization

- **Pre-configured Sources**
  - CISA Cybersecurity Advisories
  - The DFIR Report
  - SpecterOps Blog
  - Red Canary Blog
  - Huntress Cybersecurity Blog
  - And 10+ additional threat intelligence sources

### Technical Details

#### Architecture
- **Languages**: Python 3.8+
- **Database**: SQLite with SQLAlchemy ORM
- **HTTP**: httpx for async HTTP requests
- **Parsing**: feedparser, BeautifulSoup, lxml
- **Validation**: Pydantic for data models
- **CLI**: Click and Rich for user interface

#### Performance
- Asynchronous processing for high throughput
- Connection pooling and keep-alive connections
- Intelligent caching and deduplication
- Configurable rate limiting per domain

#### Security
- Environment variable configuration
- Input validation on all data paths
- Content sanitization and cleaning
- Virtual environment enforcement
- Dependency pinning for reproducible builds

### Known Issues
- Red Canary website serves compressed content that requires special handling
- Some legacy sources may require manual configuration updates
- Virtual environment auto-detection may need manual override in some shells

### Migration Notes
This is the initial release - no migration required.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for information on how to contribute to this project.

## Security

See [SECURITY.md](.github/SECURITY.md) for our security policy and how to report vulnerabilities.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
