# Contributing to CTI Scraper

Thank you for your interest in contributing to CTI Scraper! This document provides guidelines and information for contributors.

## 🚀 Getting Started

### Prerequisites
- Python 3.11+
- Docker and Docker Compose
- Git

### Development Setup
1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/ctiscraper.git`
3. Create a virtual environment: `python -m venv venv`
4. Activate it: `source venv/bin/activate` (Linux/Mac) or `venv\Scripts\activate` (Windows)
5. Install dependencies: `pip install -r requirements.txt`
6. Copy environment: `cp env.example .env`
7. Start services: `docker-compose up -d`

## 🔧 Development Workflow

### 1. Create a Feature Branch
```bash
git checkout -b feature/your-feature-name
```

### 2. Make Your Changes
- Follow the coding standards below
- Add tests for new functionality
- Update documentation as needed

### 3. Test Your Changes
```bash
# Run tests
pytest

# Run linting
flake8 src/
black --check src/
isort --check-only src/
mypy src/

# Run security checks
bandit -r src/
safety check
```

### 4. Commit Your Changes
```bash
git add .
git commit -m "feat: add new feature description"
```

### 5. Push and Create PR
```bash
git push origin feature/your-feature-name
# Create Pull Request on GitHub
```

## 📝 Coding Standards

### Python Code Style
- Follow [PEP 8](https://pep8.org/) guidelines
- Use [Black](https://black.readthedocs.io/) for code formatting
- Use [isort](https://pycqa.github.io/isort/) for import sorting
- Maximum line length: 88 characters (Black default)

### Type Hints
- Use type hints for all function parameters and return values
- Use `Optional[T]` for nullable values
- Use `Union[T1, T2]` for multiple types
- Use `List[T]`, `Dict[K, V]`, etc. for collections

### Documentation
- Use Google-style docstrings for all public functions
- Include examples in docstrings
- Update README.md for user-facing changes
- Add inline comments for complex logic

### Example
```python
def process_articles(articles: List[Article], limit: Optional[int] = None) -> Dict[str, int]:
    """
    Process a list of articles and return statistics.
    
    Args:
        articles: List of articles to process
        limit: Maximum number of articles to process (None for all)
    
    Returns:
        Dictionary containing processing statistics
        
    Example:
        >>> articles = [Article(id=1, title="Test")]
        >>> stats = process_articles(articles, limit=10)
        >>> print(stats)
        {'processed': 1, 'errors': 0}
    """
    # Implementation here
    pass
```

## 🧪 Testing

### Test Structure
- Tests go in `tests/` directory
- Test files should be named `test_*.py`
- Use descriptive test function names
- Group related tests in classes

### Test Examples
```python
import pytest
from src.core.rss_parser import RSSParser

class TestRSSParser:
    """Test RSS parser functionality."""
    
    @pytest.fixture
    def parser(self):
        """Create RSS parser instance for testing."""
        return RSSParser()
    
    def test_parse_feed_success(self, parser):
        """Test successful RSS feed parsing."""
        # Test implementation
        pass
    
    def test_parse_feed_empty(self, parser):
        """Test parsing empty RSS feed."""
        # Test implementation
        pass
```

### Running Tests
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_rss_parser.py

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test
pytest tests/test_rss_parser.py::TestRSSParser::test_parse_feed_success
```

## 🔒 Security

### Before Submitting
- Ensure no hardcoded credentials
- Use environment variables for configuration
- Validate all user inputs
- Follow OWASP security guidelines

### Security Checklist
- [ ] No secrets in code
- [ ] Input validation implemented
- [ ] SQL injection prevention
- [ ] XSS protection
- [ ] Rate limiting configured
- [ ] CORS properly configured

## 📚 Documentation

### Code Documentation
- All public functions must have docstrings
- Include parameter types and return types
- Provide usage examples
- Document exceptions that may be raised

### User Documentation
- Update README.md for new features
- Add configuration examples
- Include troubleshooting guides
- Keep installation instructions current

## 🚫 What Not to Do

- Don't commit large binary files
- Don't commit environment files (.env)
- Don't commit database files
- Don't commit temporary files
- Don't commit secrets or credentials
- Don't break existing functionality without discussion

## 🤝 Pull Request Guidelines

### PR Title Format
- `feat:` for new features
- `fix:` for bug fixes
- `docs:` for documentation changes
- `style:` for formatting changes
- `refactor:` for code refactoring
- `test:` for adding tests
- `chore:` for maintenance tasks

### PR Description Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tests pass locally
- [ ] Added new tests
- [ ] Updated existing tests

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No breaking changes
```

## 🐛 Bug Reports

### Before Reporting
1. Check existing issues
2. Search documentation
3. Try to reproduce the issue
4. Check if it's a configuration issue

### Bug Report Template
```markdown
## Bug Description
Clear description of the issue

## Steps to Reproduce
1. Step 1
2. Step 2
3. Step 3

## Expected Behavior
What should happen

## Actual Behavior
What actually happens

## Environment
- OS: [e.g., Ubuntu 20.04]
- Python: [e.g., 3.11.0]
- CTI Scraper: [e.g., 1.0.0]

## Additional Information
Logs, screenshots, etc.
```

## 💡 Feature Requests

### Before Requesting
1. Check if feature already exists
2. Search existing issues
3. Consider if it fits project scope
4. Think about implementation approach

### Feature Request Template
```markdown
## Feature Description
Clear description of the feature

## Use Case
Why this feature is needed

## Proposed Implementation
How you think it could be implemented

## Alternatives Considered
Other approaches you considered

## Additional Context
Any other relevant information
```

## 🏷️ Release Process

### Versioning
We use [Semantic Versioning](https://semver.org/):
- `MAJOR.MINOR.PATCH`
- `MAJOR`: Breaking changes
- `MINOR`: New features, backward compatible
- `PATCH`: Bug fixes, backward compatible

### Release Checklist
- [ ] All tests pass
- [ ] Documentation updated
- [ ] Changelog updated
- [ ] Version bumped
- [ ] Release notes written
- [ ] Security review completed

## 📞 Getting Help

### Communication Channels
- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For questions and discussions
- **Pull Requests**: For code contributions

### Code Review Process
1. Automated checks must pass
2. At least one maintainer review
3. All feedback addressed
4. Tests pass after changes
5. Documentation updated

## 🎉 Recognition

Contributors will be:
- Listed in the README
- Mentioned in release notes
- Credited in documentation
- Invited to join the project

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to CTI Scraper! 🚀
