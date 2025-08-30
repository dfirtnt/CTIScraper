# 🧪 CTI Scraper Testing Guide

Comprehensive automated testing suite for the CTI Scraper application.

## 🎯 Overview

This testing suite provides complete coverage of all UI capabilities, API endpoints, and system integration points. It eliminates the need for manual UI testing and provides automated quality assurance.

## 🚀 Quick Start

### 1. Install Test Dependencies

```bash
# Install Python test dependencies
pip install -r requirements-test.txt

# Install Playwright browsers
playwright install
```

### 2. Run Tests

```bash
# Run all tests
python run_tests.py --all

# Run specific test categories
python run_tests.py --smoke      # Quick health check
python run_tests.py --api        # API endpoint tests
python run_tests.py --ui         # UI flow tests
python run_tests.py --integration # System integration tests
python run_tests.py --coverage   # Tests with coverage report
```

## 📋 Test Categories

### 🔥 Smoke Tests (`--smoke`)
- **Purpose**: Quick health check of critical functionality
- **Scope**: Core endpoints, basic navigation, essential features
- **Duration**: ~30 seconds
- **Use Case**: Pre-deployment verification, daily health checks

### 🌐 API Tests (`--api`)
- **Purpose**: Test all API endpoints and data consistency
- **Scope**: JSON API responses, error handling, data validation
- **Duration**: ~1-2 minutes
- **Use Case**: API development, integration testing

### 🖥️ UI Tests (`--ui`)
- **Purpose**: End-to-end user interface testing with Playwright
- **Scope**: User flows, responsive design, accessibility, error handling
- **Duration**: ~3-5 minutes
- **Use Case**: UI development, user experience validation

### 🔗 Integration Tests (`--integration`)
- **Purpose**: Test system-wide data flow and component interaction
- **Scope**: Database connectivity, service integration, data consistency
- **Duration**: ~2-3 minutes
- **Use Case**: System integration, end-to-end validation

### 📊 Coverage Tests (`--coverage`)
- **Purpose**: Comprehensive testing with code coverage analysis
- **Scope**: All test categories + coverage reporting
- **Duration**: ~5-8 minutes
- **Use Case**: Quality assurance, development completion

## 🛠️ Test Infrastructure

### Test Dependencies
- **pytest**: Core testing framework
- **pytest-asyncio**: Async test support
- **pytest-playwright**: UI testing with Playwright
- **httpx**: Async HTTP client for API testing
- **faker**: Test data generation
- **coverage**: Code coverage analysis

### Test Structure
```
tests/
├── conftest.py              # Shared fixtures and configuration
├── api/                     # API endpoint tests
│   ├── test_endpoints.py   # Comprehensive API testing
│   └── data/               # API test data
├── ui/                      # UI flow tests
│   ├── test_ui_flows.py    # Playwright-based UI testing
│   ├── pages/              # Page object models
│   └── flows/              # User flow definitions
├── integration/             # System integration tests
│   └── test_system_integration.py
└── utils/                   # Test utilities
    └── test_data_generator.py
```

## 🎭 Playwright UI Testing

### Browser Support
- **Chromium**: Default browser for testing
- **Firefox**: Cross-browser compatibility
- **WebKit**: Safari compatibility

### Test Capabilities
- **Navigation Testing**: Page routing, URL validation
- **User Interaction**: Click, type, form submission
- **Visual Testing**: Element visibility, layout validation
- **Responsive Design**: Mobile, tablet, desktop viewports
- **Accessibility**: ARIA labels, keyboard navigation
- **Performance**: Load time measurement, chart rendering

### Example UI Test
```python
@pytest.mark.ui
async def test_dashboard_navigation(self, page: Page):
    """Test navigation between dashboard sections."""
    await page.goto("http://localhost:8000/")
    
    # Verify dashboard loads
    await expect(page).to_have_title("CTI Scraper")
    
    # Test navigation to articles
    await page.click("text=Articles")
    await expect(page).to_have_url("http://localhost:8000/articles")
```

## 🔌 API Testing

### Endpoint Coverage
- **Dashboard**: `/`, `/dashboard`
- **Articles**: `/articles`, `/articles/{id}`, `/api/articles`
- **Analysis**: `/analysis`
- **Sources**: `/sources`
- **Error Handling**: 404, 500, invalid parameters

### Test Features
- **Status Code Validation**: HTTP response codes
- **Content Validation**: Response body structure
- **Data Consistency**: HTML vs JSON endpoint consistency
- **Error Handling**: Malicious input, invalid parameters
- **Performance**: Response time measurement

### Example API Test
```python
@pytest.mark.api
async def test_api_articles(self, async_client: httpx.AsyncClient):
    """Test the articles API endpoint."""
    response = await async_client.get("/api/articles")
    assert response.status_code == 200
    
    data = response.json()
    assert "articles" in data
    assert isinstance(data["articles"], list)
```

## 🔄 CI/CD Integration

### GitHub Actions Workflow
- **Automated Testing**: Runs on push, PR, and schedule
- **Service Containers**: PostgreSQL, Redis for testing
- **Test Artifacts**: HTML reports, coverage data, Playwright reports
- **Security Scanning**: Bandit, Safety for vulnerability detection
- **Performance Testing**: Load testing with Locust

### Workflow Triggers
```yaml
on:
  push: [main, develop]
  pull_request: [main, develop]
  schedule: # Daily at 2 AM UTC
    - cron: '0 2 * * *'
  workflow_dispatch: # Manual trigger
```

## 📊 Test Reports

### HTML Reports
- **Location**: `test-results/report.html`
- **Content**: Test results, failures, execution time
- **Features**: Searchable, filterable, exportable

### Coverage Reports
- **Location**: `htmlcov/index.html`
- **Content**: Code coverage by file, function, line
- **Target**: 80% minimum coverage

### Playwright Reports
- **Location**: `playwright-report/`
- **Content**: UI test screenshots, traces, video recordings
- **Features**: Interactive debugging, failure analysis

## 🧹 Test Data Management

### Test Data Generation
- **Faker Integration**: Realistic test data
- **TTP Indicators**: Security-focused content
- **Mock Responses**: HTTP response simulation
- **Database Fixtures**: Test database setup

### Data Isolation
- **Test Database**: Separate from production
- **Cleanup**: Automatic test data cleanup
- **Fixtures**: Reusable test data sets

## 🚨 Error Handling

### Test Failures
- **Detailed Logging**: Comprehensive error information
- **Screenshot Capture**: UI test failure visualization
- **Stack Traces**: Python exception details
- **Retry Logic**: Flaky test handling

### Common Issues
- **Service Dependencies**: Database, Redis connectivity
- **Timing Issues**: Async operation synchronization
- **Browser Compatibility**: Playwright browser setup
- **Environment Variables**: Test configuration

## 🔧 Customization

### Test Configuration
```ini
# pytest.ini
[tool:pytest]
testpaths = tests
markers =
    slow: marks tests as slow
    ui: marks tests as UI tests
    api: marks tests as API tests
    integration: marks tests as integration tests
```

### Environment Variables
```bash
# .env
TESTING=true
DATABASE_URL=postgresql://user:pass@localhost/test_db
REDIS_URL=redis://localhost:6379
```

### Custom Test Markers
```python
@pytest.mark.slow
async def test_performance():
    """Marked as slow for separate execution."""
    pass

@pytest.mark.regression
async def test_bug_fix():
    """Marked for regression testing."""
    pass
```

## 📈 Performance Testing

### Load Testing
- **Concurrent Users**: Simulate multiple users
- **Response Times**: Performance measurement
- **Resource Usage**: Memory, CPU monitoring
- **Scalability**: Performance under load

### Performance Metrics
- **Page Load Time**: < 5 seconds target
- **API Response**: < 2 seconds target
- **Concurrent Requests**: 10+ users support
- **Chart Rendering**: < 3 seconds target

## 🔒 Security Testing

### Input Validation
- **SQL Injection**: Malicious database queries
- **XSS Prevention**: Script injection attempts
- **Path Traversal**: Directory access attempts
- **Parameter Pollution**: Invalid input handling

### Security Tools
- **Bandit**: Python security linting
- **Safety**: Dependency vulnerability scanning
- **Custom Tests**: Security-specific test cases

## 🎯 Best Practices

### Test Design
- **Single Responsibility**: One assertion per test
- **Descriptive Names**: Clear test purpose
- **Setup/Teardown**: Proper test isolation
- **Mock External**: External service simulation

### Test Execution
- **Parallel Execution**: pytest-xdist for speed
- **Selective Testing**: Mark-based test selection
- **Failure Isolation**: Stop on first failure
- **Debug Mode**: Verbose output for debugging

### Maintenance
- **Regular Updates**: Keep dependencies current
- **Test Data**: Refresh test data regularly
- **Coverage Goals**: Maintain coverage targets
- **Performance Baselines**: Track performance trends

## 🚀 Advanced Usage

### Custom Test Suites
```bash
# Run tests by custom markers
pytest -m "not slow"           # Exclude slow tests
pytest -m "ui or api"          # Run UI and API tests
pytest -k "dashboard"          # Run tests with "dashboard" in name
```

### Test Debugging
```bash
# Debug mode with Playwright
PWDEBUG=1 pytest tests/ui/ -s

# Verbose output
pytest -v -s --tb=long

# Stop on first failure
pytest --maxfail=1
```

### Continuous Testing
```bash
# Watch mode for development
pytest-watch tests/ -- -v

# Coverage monitoring
pytest --cov=src --cov-report=term-missing --cov-fail-under=80
```

## 📚 Additional Resources

### Documentation
- [pytest Documentation](https://docs.pytest.org/)
- [Playwright Documentation](https://playwright.dev/)
- [pytest-asyncio](https://pytest-asyncio.readthedocs.io/)

### Examples
- [Test Examples](tests/)
- [CI/CD Configuration](.github/workflows/)
- [Test Runner](run_tests.py)

### Support
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **Documentation**: This guide and inline code comments

---

## 🎉 Getting Started Checklist

- [ ] Install test dependencies: `pip install -r requirements-test.txt`
- [ ] Install Playwright browsers: `playwright install`
- [ ] Verify app is running: `python run_tests.py --check-app`
- [ ] Run smoke tests: `python run_tests.py --smoke`
- [ ] Explore test reports: `test-results/report.html`
- [ ] Set up CI/CD: Push to GitHub for automated testing

**Happy Testing! 🧪✨**

# Testing Guide

## Overview

This guide covers comprehensive testing of the CTI Scraper platform, including the new AI chatbot and model management features.

## AI Chatbot Testing

### **Model Management Testing**

#### **List Available Models**
```bash
python3 -m src.cli.model_management list
```
**Expected Output**: Table showing all available models with descriptions

#### **Model Information**
```bash
python3 -m src.cli.model_management info mistral
```
**Expected Output**: Detailed configuration table for the specified model

#### **Model Testing**
```bash
python3 -m src.cli.model_management test gpt-oss-20b
```
**Expected Output**: Model configuration details and readiness status

### **Content-Focused Response Testing**

#### **Test 1: Strict Content Adherence**
**Query**: "What are the latest ransomware trends?"
**Expected Behavior**:
- Response starts with "Based on the collected web content..." or "According to [URL]..."
- ONLY references actual collected articles
- Always cites source URLs using "According to [URL], [information]" format
- No made-up statistics, fake sources, or hallucinated information
- If no relevant content exists, responds with "I don't have information about that in my available content"

#### **Test 2: Source Attribution**
**Query**: "Tell me about machine learning evaluation methodologies"
**Expected Behavior**:
- Always cites source URLs using "According to [URL], [information]" format
- References specific blog names and authors when available
- Includes publication dates when available
- Uses quotation marks for direct quotes
- Distinguishes between different sources
- Notes when information comes from multiple sources

#### **Test 3: No Speculation Test**
**Query**: "What is the latest APT group activity in 2025?"
**Expected Behavior**:
- If no relevant content exists, responds with "I don't have information about that in my available content"
- No made-up information about future events
- No hallucinated sources or statistics
- Clear indication of content limitations
- Does not use general knowledge to supplement missing information

#### **Test 4: Blog Content Prioritization**
**Query**: "What are the newest malware families?"
**Expected Behavior**:
- Prioritizes blog content over general articles
- Higher relevance scores for blog sources
- Includes blog metadata in responses

### **Web Interface Testing**

#### **Chat Interface**
1. **Access**: Navigate to `http://localhost:8000/chat`
2. **Train Button**: Click "Train on Blog Content" button
3. **Conversation**: Send test messages
4. **History**: Check conversation history
5. **Export**: Test chat export functionality

#### **API Endpoints**
```bash
# Test chat API
curl -X POST http://localhost:8000/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What are the latest threats?"}'

# Test history API
curl http://localhost:8000/api/chat/history

# Test clear API
curl -X POST http://localhost:8000/api/chat/clear

# Test training API
curl -X POST http://localhost:8000/api/chat/train
```

### **Model Switching Testing**

#### **Test Different Models**
```python
# Test with different models
from src.utils.chatbot import ThreatIntelligenceChatbot
from src.database.async_manager import async_db_manager

# Test Mistral
chatbot1 = ThreatIntelligenceChatbot(async_db_manager, model_name="mistral")

# Test GPT OSS 20B (if available)
chatbot2 = ThreatIntelligenceChatbot(async_db_manager, model_name="gpt-oss-20b")

# Test with custom configuration
custom_config = {
    "name": "test-model",
    "url": "http://localhost:11434/api/generate",
    "temperature": 0.2,
    "max_tokens": 1024,
    "top_p": 0.9
}
chatbot3 = ThreatIntelligenceChatbot(async_db_manager, custom_config=custom_config)
```

## Content Quality Testing

### **Quality Scoring Validation**
1. **High-Quality Content**: Should get higher relevance scores
2. **Blog Content**: Should receive priority boosts
3. **Recent Content**: Should get recency bonuses
4. **Author Attribution**: Should be properly extracted and used

### **Content Extraction Testing**
1. **Metadata Extraction**: Author, blog name, publication date
2. **Content Relevance**: Proper keyword matching
3. **Context Building**: Detailed content context
4. **Source Attribution**: Proper URL and source tracking

## Performance Testing

### **Response Time Testing**
```bash
# Test response times for different models
time curl -X POST http://localhost:8000/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Test query"}'
```

### **Memory Usage Testing**
```bash
# Monitor memory usage during chat sessions
docker stats cti_ollama
```

### **Concurrent User Testing**
```bash
# Test multiple simultaneous chat sessions
for i in {1..5}; do
  curl -X POST http://localhost:8000/api/chat \
    -H "Content-Type: application/json" \
    -d "{\"message\": \"Test query $i\"}" &
done
```

## Error Handling Testing

### **Model Unavailable**
```bash
# Test behavior when model is not available
docker stop cti_ollama
curl -X POST http://localhost:8000/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Test query"}'
```

### **Invalid Model Configuration**
```python
# Test invalid configuration handling
invalid_config = {
    "name": "invalid-model",
    "url": "http://invalid-url/api/generate"
}
# Should raise validation error
```

### **Empty Content Database**
```python
# Test behavior with no content
# Should return appropriate "no content available" message
```

## Integration Testing

### **End-to-End Workflow**
1. **Content Collection**: Run content collection
2. **Quality Assessment**: Verify quality scoring
3. **Chatbot Training**: Train on collected content
4. **Query Testing**: Test various queries
5. **Response Validation**: Verify content adherence

### **Model Configuration Integration**
1. **Environment Variables**: Test model switching via env vars
2. **Configuration Files**: Test custom model configurations
3. **CLI Integration**: Test model management commands
4. **Web Interface**: Test model selection in UI

## Regression Testing

### **Content-First Approach**
- Ensure no model hallucination
- Verify source attribution
- Check content adherence
- Validate evidence-based responses

### **Model Flexibility**
- Test model switching
- Verify configuration loading
- Check parameter validation
- Ensure backward compatibility

## Test Data

### **Sample Queries**
```python
test_queries = [
    "What are the latest ransomware trends?",
    "Tell me about machine learning evaluation methodologies",
    "What are the newest malware families?",
    "How to hunt for persistence techniques?",
    "What are recent APT activities?",
    "Explain threat hunting methodologies",
    "What are the latest vulnerabilities?",
    "How does incident response work?"
]
```

### **Expected Response Patterns**
- Start with "Based on the collected web content..." or "According to [URL]..."
- Always include source URL citations using "According to [URL], [information]" format
- Use quotation marks for direct quotes
- Reference authors and dates when available
- No speculation, hallucination, or made-up information
- Clear "I don't have information about that in my available content" when appropriate

## Continuous Testing

### **Automated Tests**
```bash
# Run all tests
pytest tests/ -v

# Run specific test categories
pytest tests/test_chatbot.py -v
pytest tests/test_model_management.py -v
pytest tests/test_content_quality.py -v
```

### **Monitoring**
- Response quality metrics
- Model performance tracking
- Content relevance scoring
- User satisfaction metrics

This comprehensive testing ensures the AI chatbot maintains high quality, content adherence, and model flexibility across all scenarios.
