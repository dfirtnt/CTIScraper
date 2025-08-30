# 🧪 Manual Test Checklist for CTI Scraper

This document provides a comprehensive manual testing guide for the CTI Scraper web application. Use this checklist to systematically test all functionality and ensure quality.

## 📋 Pre-Testing Setup

- [ ] Application is running on `http://localhost:8000`
- [ ] Database is accessible and contains test data
- [ ] All services (PostgreSQL, Redis, Celery) are running
- [ ] Browser is ready with developer tools open

## 🏠 Dashboard Testing (`/`)

### Page Load & Display
- [ ] Page loads within 3 seconds
- [ ] Navigation menu is visible and properly styled
- [ ] CTI Scraper logo and title are displayed
- [ ] Page title shows "Dashboard - CTI Scraper"

### Statistics Cards
- [ ] Total Articles card displays correct number
- [ ] Active Sources card shows accurate count
- [ ] Last 24h activity card shows recent activity
- [ ] Database Size card displays size in MB
- [ ] All cards have proper hover effects

### Recent Articles Section
- [ ] Recent articles are displayed (if any exist)
- [ ] Article titles are clickable links
- [ ] Article content is truncated appropriately
- [ ] Source information is displayed
- [ ] "View all articles" link works

### Quick Actions
- [ ] TTP Analysis button navigates to `/analysis`
- [ ] Manage Sources button navigates to `/sources`
- [ ] Refresh Data button reloads the page
- [ ] All buttons have proper hover states

### Source Status
- [ ] Source status indicators are visible
- [ ] Active sources show green dots
- [ ] Inactive sources show red dots
- [ ] Source tier information is displayed
- [ ] "View all sources" link works

### System Health
- [ ] System health metrics are displayed
- [ ] All metrics show reasonable values
- [ ] Auto-refresh works every 30 seconds

## 📰 Articles Page Testing (`/articles`)

### Page Load & Display
- [ ] Page loads within 3 seconds
- [ ] "Articles" heading is displayed
- [ ] "Browse Articles" subtitle is shown
- [ ] Navigation breadcrumbs work

### Article Listings
- [ ] Articles are displayed in a grid/list format
- [ ] Article titles are clickable
- [ ] Article content previews are shown
- [ ] Source information is displayed for each article
- [ ] Publication dates are formatted correctly

### Pagination (if applicable)
- [ ] Pagination controls are visible (if many articles)
- [ ] Page navigation works correctly
- [ ] Articles per page limit is respected

### Filters & Search
- [ ] Search box is present and functional
- [ ] Source filter dropdown works
- [ ] Quality score filter works
- [ ] Filter results update the display

### Article Cards
- [ ] Article cards have proper spacing
- [ ] Hover effects work on cards
- [ ] Content truncation works properly
- [ ] Quality indicators are visible

## 🔍 Article Detail Testing (`/articles/{id}`)

### Page Load & Display
- [ ] Page loads within 3 seconds
- [ ] Article title is prominently displayed
- [ ] Article metadata is shown (source, date, author)
- [ ] Navigation back to articles list works

### Article Content
- [ ] Full article content is displayed
- [ ] Content is properly formatted
- [ ] Links within content are clickable
- [ ] Images (if any) are displayed correctly

### Threat Hunting Analysis
- [ ] TTP Analysis section is visible
- [ ] MITRE ATT&CK techniques are listed
- [ ] Hunting guidance is provided
- [ ] Confidence scores are displayed
- [ ] Hunting priority is indicated

### TTP Quality Assessment
- [ ] Quality score breakdown is shown
- [ ] TTP score is displayed (0-75)
- [ ] Quality level is indicated (Excellent/Good/Fair/Limited)
- [ ] Progress bars are properly styled

### LLM Quality Assessment
- [ ] LLM quality score is displayed
- [ ] Combined quality score is calculated
- [ ] Tactical vs Strategic classification is shown
- [ ] Recommendations are listed
- [ ] Hunting priority is indicated

### Navigation
- [ ] Previous/Next article buttons work (if applicable)
- [ ] Back to Articles link works
- [ ] Breadcrumb navigation is functional

## 📊 Analysis Dashboard Testing (`/analysis`)

### Page Load & Display
- [ ] Page loads within 3 seconds
- [ ] "Threat Hunting Analysis Dashboard" heading is displayed
- [ ] All quality metric cards are visible
- [ ] Charts are properly rendered

### Quality Metrics Cards
- [ ] Combined Quality card shows average score
- [ ] TTP Quality card displays TTP-specific score
- [ ] LLM Quality card shows LLM assessment score
- [ ] All cards have proper styling and colors

### Quality Distribution Chart
- [ ] Chart canvas is visible
- [ ] Chart renders without errors
- [ ] Data labels are readable
- [ ] Chart is interactive (hover effects)

### Tactical vs Strategic Distribution Chart
- [ ] Chart canvas is visible
- [ ] Three categories are displayed (Tactical/Strategic/Hybrid)
- [ ] Chart renders without errors
- [ ] Data is properly distributed

### Top Articles Section
- [ ] Articles with huntable techniques are listed
- [ ] Technique counts are displayed
- [ ] Confidence scores are shown
- [ ] Hunting priorities are indicated
- [ ] Technique categories are expanded

### Technique Categories Chart
- [ ] Chart shows different technique types
- [ ] Data is properly categorized
- [ ] Chart renders without errors
- [ ] Interactive elements work

## 🔗 Sources Management Testing (`/sources`)

### Page Load & Display
- [ ] Page loads within 3 seconds
- [ ] "Sources" heading is displayed
- [ ] "Manage Sources" subtitle is shown
- [ ] Source list is displayed

### Source Listings
- [ ] All configured sources are visible
- [ ] Source names and URLs are displayed
- [ ] Source status indicators work
- [ ] Source tier information is shown
- [ ] RSS URLs are displayed (if applicable)

### Source Actions
- [ ] **Edit button** opens edit interface
- [ ] **Test button** tests source connectivity
- [ ] **Stats button** shows source statistics
- [ ] All buttons have proper styling

### Test Source Functionality
- [ ] Click Test button on a source
- [ ] Modal opens with "Testing Source" message
- [ ] Test results are displayed
- [ ] RSS feed test shows success/failure
- [ ] Website test shows success/failure
- [ ] Response times are displayed
- [ ] Error messages are clear (if any)

### Source Statistics
- [ ] Click Stats button on a source
- [ ] Modal opens with source statistics
- [ ] Total articles count is displayed
- [ ] Average content length is shown
- [ ] Average quality score is displayed
- [ ] Recent activity chart is visible
- [ ] All data is accurate

### Source Management
- [ ] Toggle source status works
- [ ] Source configuration can be edited
- [ ] New sources can be added
- [ ] Sources can be deleted (if applicable)

### Source Statistics Overview
- [ ] Active Sources count is accurate
- [ ] RSS Sources count is correct
- [ ] Tier 1 Sources count is displayed
- [ ] All statistics are properly calculated

## 🔌 API Endpoint Testing

### Health Check (`/health`)
- [ ] Returns 200 status
- [ ] JSON response contains "status": "healthy"
- [ ] Response time is under 1 second

### Articles API (`/api/articles`)
- [ ] Returns 200 status
- [ ] JSON response contains "articles" array
- [ ] Articles have required fields (id, title, content)
- [ ] Limit parameter works correctly
- [ ] Response time is under 2 seconds

### Article Detail API (`/api/articles/{id}`)
- [ ] Returns 200 for valid IDs
- [ ] Returns 404 for invalid IDs
- [ ] JSON response contains complete article data
- [ ] Response time is under 1 second

### Sources API (`/api/sources`)
- [ ] Returns 200 status
- [ ] JSON response contains "sources" array
- [ ] Sources have required fields (id, name, url)
- [ ] Response time is under 2 seconds

### Source Detail API (`/api/sources/{id}`)
- [ ] Returns 200 for valid IDs
- [ ] Returns 404 for invalid IDs
- [ ] JSON response contains complete source data
- [ ] Response time is under 1 second

### Source Test API (`/api/sources/{id}/test`)
- [ ] Returns 200 for valid POST requests
- [ ] JSON response contains test results
- [ ] Test data includes success status and response times
- [ ] Response time is under 3 seconds

### Source Stats API (`/api/sources/{id}/stats`)
- [ ] Returns 200 for valid GET requests
- [ ] JSON response contains statistics
- [ ] Stats include article counts and quality scores
- [ ] Response time is under 2 seconds

### Source Toggle API (`/api/sources/{id}/toggle`)
- [ ] Returns 200 for valid POST requests
- [ ] JSON response indicates status change
- [ ] Source status is actually updated
- [ ] Response time is under 2 seconds

## 🎨 UI Component Testing

### Navigation Menu
- [ ] All navigation links work correctly
- [ ] Active page is highlighted
- [ ] Hover effects work properly
- [ ] Mobile responsive design works

### Buttons & Interactive Elements
- [ ] All buttons have proper hover states
- [ ] Click effects are visible
- [ ] Disabled states are properly styled
- [ ] Loading states are shown during operations

### Forms & Inputs
- [ ] Input fields accept text properly
- [ ] Validation messages are displayed
- [ ] Required field indicators work
- [ ] Form submission works correctly

### Modals & Popups
- [ ] Modals open and close properly
- [ ] Modal content is properly displayed
- [ ] Backdrop clicks close modals
- [ ] Escape key closes modals

### Charts & Visualizations
- [ ] All charts render without errors
- [ ] Chart data is accurate
- [ ] Interactive elements work
- [ ] Responsive design works on different screen sizes

### Responsive Design
- [ ] Mobile viewport works correctly
- [ ] Tablet viewport is properly styled
- [ ] Desktop layout is optimal
- [ ] Navigation adapts to screen size

## 🚨 Error Handling Testing

### 404 Errors
- [ ] Invalid URLs return 404 status
- [ ] 404 page is properly styled
- [ ] Error message is helpful
- [ ] Navigation back to working pages works

### Invalid Parameters
- [ ] Invalid article IDs are handled gracefully
- [ ] Invalid source IDs return proper errors
- [ ] Malformed query parameters don't crash
- [ ] Error messages are user-friendly

### Database Errors
- [ ] Database connection failures are handled
- [ ] Missing data scenarios are handled
- [ ] Error messages are informative
- [ ] Fallback content is displayed

### Network Errors
- [ ] Slow connections are handled
- [ ] Timeout errors are managed
- [ ] Retry mechanisms work
- [ ] User is informed of issues

## 🔒 Security Testing

### Input Validation
- [ ] SQL injection attempts are blocked
- [ ] XSS attempts are sanitized
- [ ] Path traversal attempts are prevented
- [ ] Special characters are handled safely

### Authentication (if implemented)
- [ ] Protected routes require authentication
- [ ] Login/logout functionality works
- [ ] Session management is secure
- [ ] Password requirements are enforced

### Data Exposure
- [ ] Sensitive data is not exposed in URLs
- [ ] API responses don't leak internal information
- [ ] Error messages don't reveal system details
- [ ] User permissions are properly enforced

## 📱 Cross-Browser Testing

### Chrome/Chromium
- [ ] All functionality works correctly
- [ ] Styling is consistent
- [ ] JavaScript functions execute properly
- [ ] Performance is acceptable

### Firefox
- [ ] All functionality works correctly
- [ ] Styling is consistent
- [ ] JavaScript functions execute properly
- [ ] Performance is acceptable

### Safari
- [ ] All functionality works correctly
- [ ] Styling is consistent
- [ ] JavaScript functions execute properly
- [ ] Performance is acceptable

### Edge
- [ ] All functionality works correctly
- [ ] Styling is consistent
- [ ] JavaScript functions execute properly
- [ ] Performance is acceptable

## 📊 Performance Testing

### Page Load Times
- [ ] Dashboard loads in under 3 seconds
- [ ] Articles page loads in under 3 seconds
- [ ] Analysis page loads in under 4 seconds
- [ ] Sources page loads in under 3 seconds

### API Response Times
- [ ] Health check responds in under 1 second
- [ ] Articles API responds in under 2 seconds
- [ ] Sources API responds in under 2 seconds
- [ ] Source test API responds in under 3 seconds

### Concurrent Users
- [ ] Multiple browser tabs work correctly
- [ ] Concurrent API requests are handled
- [ ] Database connections are managed properly
- [ ] No race conditions occur

## 🧹 Data Integrity Testing

### Article Data
- [ ] Article content is preserved correctly
- [ ] Metadata is accurate
- [ ] Links work properly
- [ ] Content hash validation works

### Source Data
- [ ] Source configuration is saved correctly
- [ ] RSS feeds are properly configured
- [ ] Status changes are persisted
- [ ] Statistics are calculated accurately

### Quality Assessment
- [ ] TTP scores are calculated correctly
- [ ] LLM quality scores are reasonable
- [ ] Combined scores are accurate
- [ ] Quality levels are properly categorized

## 📝 Test Results Documentation

### Test Execution
- [ ] Date and time of testing
- [ ] Tester name and role
- [ ] Environment details (browser, OS, etc.)
- [ ] Test data used

### Issues Found
- [ ] Description of each issue
- [ ] Steps to reproduce
- [ ] Expected vs actual behavior
- [ ] Severity level (Critical/High/Medium/Low)

### Recommendations
- [ ] Suggested improvements
- [ ] Priority for fixes
- [ ] Additional testing needed
- [ ] Performance optimizations

## ✅ Test Completion Checklist

- [ ] All core routes tested
- [ ] All API endpoints tested
- [ ] All UI components verified
- [ ] Error handling scenarios tested
- [ ] Security aspects verified
- [ ] Cross-browser compatibility checked
- [ ] Performance metrics recorded
- [ ] Data integrity verified
- [ ] Issues documented
- [ ] Recommendations provided

---

## 🎯 Quick Test Commands

```bash
# Run automated tests
python3 run_tests.py --all

# Run specific test categories
python3 run_tests.py --api
python3 run_tests.py --ui
python3 run_tests.py --integration

# Run with coverage
python3 run_tests.py --coverage

# Check application health
curl http://localhost:8000/health
```

## 📞 Support & Issues

If you encounter issues during testing:

1. **Check the application logs** for error messages
2. **Verify all services are running** (PostgreSQL, Redis, Celery)
3. **Check browser console** for JavaScript errors
4. **Review the test documentation** for known issues
5. **Report bugs** with detailed reproduction steps

---

**Happy Testing! 🧪✨**

## AI Chatbot and Model Management Testing

### **Model Management CLI Testing**

- [ ] **List Models Command**
  - [ ] Run `python3 -m src.cli.model_management list`
  - [ ] Verify all 5 models are listed (mistral, gpt-oss-20b, llama2, openai-gpt4, anthropic-claude)
  - [ ] Check descriptions are accurate and helpful

- [ ] **Model Info Command**
  - [ ] Run `python3 -m src.cli.model_management info mistral`
  - [ ] Verify configuration table shows all parameters
  - [ ] Test with invalid model name (should show error)
  - [ ] Check URL, temperature, max_tokens, top_p, top_k values

- [ ] **Model Test Command**
  - [ ] Run `python3 -m src.cli.model_management test mistral`
  - [ ] Verify model configuration is loaded correctly
  - [ ] Check API URL and parameters are correct
  - [ ] Test with unavailable model (should handle gracefully)

### **Content-Focused Chatbot Testing**

- [ ] **Strict Content Adherence Test**
  - [ ] Ask: "What are the latest ransomware trends?"
  - [ ] Verify response starts with "Based on the collected web content..." or "According to [URL]..."
  - [ ] Check response ONLY references actual collected articles
  - [ ] Confirm no made-up statistics, fake sources, or hallucinated information
  - [ ] Verify source URL citations use "According to [URL], [information]" format
  - [ ] If no relevant content exists, confirm response is "I don't have information about that in my available content"

- [ ] **Source Attribution Test**
  - [ ] Ask: "Tell me about machine learning evaluation methodologies"
  - [ ] Check response always cites source URLs using "According to [URL], [information]" format
  - [ ] Verify publication dates are included when available
  - [ ] Confirm relevant passages are quoted with quotation marks
  - [ ] Check different sources are distinguished
  - [ ] Verify multiple sources are noted when information comes from several places

- [ ] **No Speculation Test**
  - [ ] Ask: "What is the latest APT group activity in 2025?"
  - [ ] Verify response is "I don't have information about that in my available content" if no relevant content exists
  - [ ] Confirm no made-up information about future events
  - [ ] Check no hallucinated sources or statistics
  - [ ] Verify clear indication of content limitations
  - [ ] Confirm model does not use general knowledge to supplement missing information

- [ ] **Blog Content Prioritization Test**
  - [ ] Ask: "What are the newest malware families?"
  - [ ] Verify blog content is prioritized over general articles
  - [ ] Check blog metadata is included in responses
  - [ ] Confirm higher relevance scores for blog sources

### **Web Interface Testing**

- [ ] **Chat Page Access**
  - [ ] Navigate to `http://localhost:8000/chat`
  - [ ] Verify page loads without errors
  - [ ] Check "Train on Blog Content" button is visible
  - [ ] Confirm chat interface is functional

- [ ] **Train Button Functionality**
  - [ ] Click "Train on Blog Content" button
  - [ ] Verify button shows "Training..." state
  - [ ] Check training completion message appears
  - [ ] Confirm training message is added to chat history

- [ ] **Chat Interaction**
  - [ ] Send a test message
  - [ ] Verify response is received
  - [ ] Check response follows content-first approach
  - [ ] Confirm conversation history is maintained

- [ ] **Quick Action Buttons**
  - [ ] Test "Latest Ransomware Trends" button
  - [ ] Test "Recent APT Activities" button
  - [ ] Test "New Malware Families" button
  - [ ] Verify buttons populate input field and send message

- [ ] **Export Functionality**
  - [ ] Have a conversation with multiple messages
  - [ ] Click export button
  - [ ] Verify chat export downloads correctly
  - [ ] Check exported file contains all messages

### **API Endpoint Testing**

- [ ] **Chat API**
  ```bash
  curl -X POST http://localhost:8000/api/chat \
    -H "Content-Type: application/json" \
    -d '{"message": "What are the latest threats?"}'
  ```
  - [ ] Verify response is received
  - [ ] Check response format is correct
  - [ ] Confirm content adherence in response

- [ ] **History API**
  ```bash
  curl http://localhost:8000/api/chat/history
  ```
  - [ ] Verify conversation history is returned
  - [ ] Check history format is correct
  - [ ] Confirm metadata is included

- [ ] **Clear API**
  ```bash
  curl -X POST http://localhost:8000/api/chat/clear
  ```
  - [ ] Verify history is cleared
  - [ ] Check success message is returned
  - [ ] Confirm new conversation starts fresh

- [ ] **Train API**
  ```bash
  curl -X POST http://localhost:8000/api/chat/train
  ```
  - [ ] Verify training is initiated
  - [ ] Check training result is returned
  - [ ] Confirm training context is added

### **Model Configuration Testing**

- [ ] **Default Model (Mistral)**
  - [ ] Verify Mistral is used by default
  - [ ] Check temperature is set to 0.3
  - [ ] Confirm max_tokens is 2048
  - [ ] Verify top_p is 0.8 and top_k is 30

- [ ] **Model Switching**
  - [ ] Test switching to different model configurations
  - [ ] Verify parameters are applied correctly
  - [ ] Check API calls use correct endpoints
  - [ ] Confirm responses maintain content adherence

- [ ] **Custom Configuration**
  - [ ] Test with custom model configuration
  - [ ] Verify validation works for invalid configs
  - [ ] Check error handling for missing parameters
  - [ ] Confirm custom parameters are applied

### **Content Quality Integration**

- [ ] **Quality Scoring Impact**
  - [ ] Verify high-quality content gets higher relevance scores
  - [ ] Check blog content receives priority boosts
  - [ ] Confirm recent content gets recency bonuses
  - [ ] Test author attribution is properly extracted

- [ ] **Metadata Extraction**
  - [ ] Check author information is captured
  - [ ] Verify blog name is extracted
  - [ ] Confirm publication dates are included
  - [ ] Test quality scores are calculated

- [ ] **Context Building**
  - [ ] Verify detailed context is built from search results
  - [ ] Check metadata is included in context
  - [ ] Confirm content previews are meaningful
  - [ ] Test relevance scores are displayed

### **Error Handling**

- [ ] **Model Unavailable**
  - [ ] Stop Ollama container
  - [ ] Test chat API response
  - [ ] Verify graceful error handling
  - [ ] Check fallback responses work

- [ ] **Invalid Queries**
  - [ ] Test empty message handling
  - [ ] Verify malformed JSON handling
  - [ ] Check timeout handling
  - [ ] Confirm error messages are helpful

- [ ] **Empty Database**
  - [ ] Test behavior with no collected content
  - [ ] Verify appropriate "no content" message
  - [ ] Check training with empty database
  - [ ] Confirm graceful degradation

### **Performance Testing**

- [ ] **Response Time**
  - [ ] Measure response time for typical queries
  - [ ] Test with different model configurations
  - [ ] Verify response times are acceptable
  - [ ] Check timeout handling

- [ ] **Memory Usage**
  - [ ] Monitor memory usage during chat sessions
  - [ ] Test with different model sizes
  - [ ] Verify memory limits are respected
  - [ ] Check cleanup after sessions

- [ ] **Concurrent Users**
  - [ ] Test multiple simultaneous chat sessions
  - [ ] Verify no conflicts between users
  - [ ] Check conversation isolation
  - [ ] Confirm performance under load

### **Regression Testing**

- [ ] **Strict Content-First Approach**
  - [ ] Verify no model hallucination occurs
  - [ ] Check mandatory source URL attribution is maintained
  - [ ] Confirm strict content adherence across all models
  - [ ] Test evidence-based responses
  - [ ] Verify "I don't have information about that in my available content" responses

- [ ] **Model Flexibility**
  - [ ] Test model switching functionality
  - [ ] Verify configuration loading works
  - [ ] Check parameter validation
  - [ ] Confirm backward compatibility

### **Documentation Verification**

- [ ] **README Updates**
  - [ ] Verify AI chatbot section is complete
  - [ ] Check model management documentation
  - [ ] Confirm CLI command examples work
  - [ ] Test API endpoint documentation

- [ ] **Configuration Files**
  - [ ] Check model_config.py is properly documented
  - [ ] Verify all models have descriptions
  - [ ] Confirm parameter explanations are clear
  - [ ] Test configuration validation

- [ ] **Code Comments**
  - [ ] Verify chatbot.py has clear comments
  - [ ] Check model management code is documented
  - [ ] Confirm content-focused approach is explained
  - [ ] Test inline documentation accuracy

## Test Results Summary

### **Passed Tests**
- [ ] List all tests that passed

### **Failed Tests**
- [ ] List any tests that failed with details

### **Issues Found**
- [ ] Document any issues discovered during testing

### **Recommendations**
- [ ] Suggest improvements based on testing results

### **Next Steps**
- [ ] Plan follow-up testing if needed
- [ ] Schedule retesting for failed items
- [ ] Update documentation based on findings
