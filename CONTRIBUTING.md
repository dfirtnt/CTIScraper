# 🤝 Contributing to CTI Scraper

Thank you for your interest in contributing to CTI Scraper! This document provides guidelines and information for contributors.

## 📋 Table of Contents

- [Code of Conduct](#-code-of-conduct)
- [Getting Started](#-getting-started)
- [Development Setup](#-development-setup)
- [Contributing Guidelines](#-contributing-guidelines)
- [Code Standards](#-code-standards)
- [Testing](#-testing)
- [Documentation](#-documentation)
- [Submitting Changes](#-submitting-changes)

## 🤝 Code of Conduct

We are committed to providing a welcoming and inclusive environment for all contributors. Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

### Our Pledge

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Maintain professionalism in all interactions

## 🚀 Getting Started

### Ways to Contribute

- 🐛 **Bug Reports**: Found a bug? Let us know!
- ✨ **Feature Requests**: Have an idea? We'd love to hear it!
- 📝 **Documentation**: Help improve our docs
- 🔧 **Code Contributions**: Submit bug fixes or new features
- 🧪 **Testing**: Help test new features and report issues
- 🎨 **UX/UI**: Improve the CLI interface and user experience

### Before You Start

1. **Check existing issues** to avoid duplicate work
2. **Join the discussion** in relevant GitHub issues
3. **Read the documentation** to understand the project
4. **Set up your development environment**

## 🛠️ Development Setup

### Quick Setup

```bash
# 1. Fork and clone the repository
git clone https://github.com/yourusername/ctiscraper.git
cd ctiscraper

# 2. Automated setup
python3 setup_env.py

# 3. Activate virtual environment
source venv/bin/activate

# 4. Verify installation
./threat-intel --help
```

### Manual Setup

```bash
# 1. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Install development tools
pip install pre-commit

# 4. Set up pre-commit hooks
pre-commit install
```

### Development Dependencies

The following tools are used for development:

- **black**: Code formatting
- **flake8**: Linting and style checking
- **mypy**: Static type checking
- **pytest**: Testing framework
- **bandit**: Security scanning
- **safety**: Dependency vulnerability scanning

## 📋 Contributing Guidelines

### Issue Guidelines

#### Bug Reports

When reporting bugs, please include:

```markdown
**Bug Description**
A clear description of what the bug is.

**Reproduction Steps**
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

**Expected Behavior**
What you expected to happen.

**Actual Behavior**
What actually happened.

**Environment**
- OS: [e.g. macOS 12.0]
- Python version: [e.g. 3.11.0]
- CTI Scraper version: [e.g. 1.0.0]

**Additional Context**
Add any other context about the problem here.
```

#### Feature Requests

For new features, please provide:

```markdown
**Feature Description**
A clear description of the feature you'd like to see.

**Use Case**
Explain why this feature would be useful.

**Proposed Solution**
Describe how you envision this working.

**Alternatives Considered**
Any alternative solutions you've considered.

**Additional Context**
Screenshots, mockups, or examples if applicable.
```

### Pull Request Guidelines

1. **Create a feature branch** from `develop`
2. **Make your changes** with appropriate tests
3. **Follow code standards** (see below)
4. **Update documentation** if needed
5. **Add tests** for new functionality
6. **Ensure all tests pass**
7. **Submit a pull request**

#### Pull Request Template

```markdown
## Description
Brief description of changes made.

## Type of Change
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that causes existing functionality to not work as expected)
- [ ] Documentation update

## Testing
- [ ] Tests pass locally
- [ ] New tests added for new functionality
- [ ] Manual testing performed

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review of code completed
- [ ] Code is commented where necessary
- [ ] Documentation updated
- [ ] No new security vulnerabilities introduced
```

## ✅ Code Standards

### Python Style Guide

We follow [PEP 8](https://pep8.org/) with some modifications:

```python
# Good: Clear, descriptive names
def collect_threat_intelligence(source: Source) -> List[Article]:
    """Collect threat intelligence from a specific source."""
    pass

# Good: Type hints for all functions
async def fetch_rss_feed(url: str, timeout: int = 30) -> Optional[Dict[str, Any]]:
    """Fetch and parse RSS feed from URL."""
    pass

# Good: Proper error handling
try:
    result = await process_article(article)
except ValidationError as e:
    logger.error(f"Article validation failed: {e}")
    return None
```

### Code Formatting

```bash
# Format code with black
black src/ tests/

# Check formatting
black --check src/ tests/

# Sort imports
isort src/ tests/
```

### Type Hints

All functions should include type hints:

```python
from typing import List, Optional, Dict, Any
from models.article import Article, ArticleCreate

def process_articles(
    articles: List[ArticleCreate], 
    quality_threshold: float = 0.5
) -> Dict[str, Any]:
    """Process articles and return statistics."""
    pass
```

### Documentation Standards

#### Docstrings

Use Google-style docstrings:

```python
def extract_content(html: str, selectors: List[str]) -> Optional[str]:
    """Extract content from HTML using CSS selectors.
    
    Args:
        html: Raw HTML content to parse
        selectors: List of CSS selectors to try in order
        
    Returns:
        Extracted text content or None if extraction fails
        
    Raises:
        ValueError: If HTML is empty or invalid
        
    Example:
        >>> extract_content("<p>Hello</p>", ["p"])
        "Hello"
    """
    pass
```

#### Comments

```python
# Good: Explain complex logic
# Calculate content hash using title and content to improve deduplication
# accuracy for articles that may have minor formatting differences
content_hash = hashlib.sha256(f"{title}\n{content}".encode()).hexdigest()

# Good: Explain business logic
# Red Canary serves compressed content that corrupts during extraction,
# so we use RSS summaries instead of fetching full articles
if 'redcanary.com' in url.lower():
    return self._use_rss_summary(entry)
```

## 🧪 Testing

### Test Structure

```
tests/
├── unit/              # Unit tests
│   ├── test_models/
│   ├── test_core/
│   └── test_utils/
├── integration/       # Integration tests
├── fixtures/          # Test data
└── conftest.py       # Pytest configuration
```

### Writing Tests

```python
import pytest
from unittest.mock import Mock, patch
from models.article import ArticleCreate

class TestArticleModel:
    """Test suite for Article model."""
    
    def test_article_creation_with_valid_data(self):
        """Test creating article with valid data."""
        article_data = {
            "source_id": 1,
            "canonical_url": "https://example.com/article",
            "title": "Test Article",
            "content": "Test content",
            "published_at": datetime.now()
        }
        
        article = ArticleCreate(**article_data)
        assert article.title == "Test Article"
        assert article.content_hash is not None
    
    @pytest.mark.asyncio
    async def test_rss_parser_with_mock_response(self):
        """Test RSS parser with mocked HTTP response."""
        with patch('httpx.AsyncClient.get') as mock_get:
            mock_response = Mock()
            mock_response.text = "<rss>...</rss>"
            mock_get.return_value = mock_response
            
            parser = RSSParser()
            result = await parser.parse_feed("https://example.com/feed")
            
            assert result is not None
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/unit/test_models/test_article.py

# Run specific test
pytest tests/unit/test_models/test_article.py::TestArticleModel::test_article_creation

# Run tests in parallel
pytest -n auto
```

## 📝 Documentation

### Documentation Types

1. **Code Documentation**: Docstrings and comments
2. **User Documentation**: README, usage guides
3. **Developer Documentation**: Architecture, contributing
4. **API Documentation**: Generated from docstrings

### Documentation Updates

When contributing, please update:

- **README.md**: For user-facing changes
- **CHANGELOG.md**: For all changes
- **Code comments**: For complex logic
- **Docstrings**: For new functions/classes

## 📤 Submitting Changes

### Commit Messages

Use conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Examples:
```
feat(rss): add support for Atom feeds
fix(cli): resolve virtual environment detection issue
docs(readme): update installation instructions
test(parser): add tests for content extraction
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `test`: Testing
- `refactor`: Code refactoring
- `style`: Code style changes
- `chore`: Maintenance tasks

### Branch Naming

```
feature/add-rss-support
bugfix/fix-content-extraction
hotfix/security-vulnerability
docs/update-contributing-guide
```

### Review Process

1. **Automated Checks**: CI/CD pipeline runs automatically
2. **Code Review**: Maintainers review the code
3. **Testing**: Manual testing for complex features
4. **Documentation Review**: Ensure docs are updated
5. **Security Review**: For security-related changes

## 🎯 Development Areas

### High-Priority Areas

- **Performance optimization**: Async processing improvements
- **Source support**: Adding new threat intelligence sources
- **Content quality**: Improving content extraction and cleaning
- **Testing**: Expanding test coverage
- **Documentation**: User guides and examples

### Good First Issues

Look for issues labeled:
- `good first issue`: Perfect for newcomers
- `help wanted`: Community help needed
- `documentation`: Documentation improvements
- `testing`: Test-related tasks

### Advanced Contributions

- **Architecture improvements**: Core system enhancements
- **Security features**: Authentication, encryption
- **Scalability**: Database optimizations, caching
- **New scrapers**: Support for additional source types

## 🏆 Recognition

Contributors are recognized in:

- **CHANGELOG.md**: All contributors listed
- **README.md**: Major contributors highlighted
- **GitHub Contributors**: Automatic GitHub recognition
- **Release Notes**: Significant contributions mentioned

## 📞 Getting Help

### Communication Channels

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For questions and discussions
- **Documentation**: Check the docs first
- **Code Review**: Ask questions in pull requests

### Mentoring

New contributors can:

- **Ask questions** in issues or discussions
- **Request mentoring** for complex contributions
- **Join pair programming** sessions (when available)
- **Attend community meetings** (if organized)

## 📚 Additional Resources

### Learning Resources

- **Python**: [Official Python Tutorial](https://docs.python.org/3/tutorial/)
- **Async Programming**: [Real Python Async Guide](https://realpython.com/async-io-python/)
- **SQLAlchemy**: [SQLAlchemy Tutorial](https://docs.sqlalchemy.org/en/14/tutorial/)
- **Pydantic**: [Pydantic Documentation](https://pydantic-docs.helpmanual.io/)

### Tools & Extensions

- **VS Code Extensions**: Python, GitLens, Docker
- **PyCharm Plugins**: Recommended for advanced development
- **Command Line Tools**: git, curl, jq for testing

Thank you for contributing to CTI Scraper! 🚀
