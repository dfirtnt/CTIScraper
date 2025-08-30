# Balanced Content Guidelines

## Overview

The CTI Scraper AI chatbot implements balanced content-focused guidelines to ensure responses are based on collected web content while providing comprehensive and helpful summaries, eliminating hallucination and ensuring proper source attribution.

## Core Principles

### **Content-Based Responses**
- **Primary Source**: Information comes from scraped web content with comprehensive summaries
- **No General Knowledge**: Never use pre-trained knowledge to supplement responses
- **Helpful Summaries**: Provide meaningful analysis and insights from available content
- **No Speculation**: No predictions or opinions not found in content

### **Mandatory Source Attribution**
- **URL Citations**: Always cite source URLs using "According to [URL], [information]"
- **Direct Quotes**: Use quotation marks for exact text from sources
- **Multiple Sources**: Cite all relevant sources when information appears in multiple places
- **Publication Dates**: Include dates when available for context

### **Transparent Limitations**
- **Clear Decline**: "I don't have information about that in my available content"
- **Scope Awareness**: Acknowledge when requests are outside collected content
- **No Fabrication**: Never invent sources, statistics, or information
- **Honest Uncertainty**: Admit when information is incomplete or conflicting
- **Helpful Summaries**: Provide comprehensive information when content is available

## Implementation Details

### **System Prompt**
The chatbot uses a comprehensive system prompt that includes:

```
## Core Guidelines
- Use information from the scraped web content provided to you
- If information is not available in the scraped content, respond with: "I don't have information about that in my available content."
- Provide meaningful summaries and analysis of the content
- Synthesize information from multiple sources when relevant
- Be helpful and informative while staying within the content scope

## Response Format
- Always cite the source URL when providing information
- Use this format: "According to [URL], [information]"
- Provide comprehensive summaries of articles when requested
- Include key points, findings, and insights from the content
- Keep responses informative and well-structured
```

### **Response Generation**
1. **Content Validation**: Check if search results exist before generating responses
2. **Balanced Prompting**: Include detailed instructions in every API call
3. **Optimized Temperature**: Use 0.3 temperature for better summarization while maintaining accuracy
4. **Fallback Handling**: All fallback methods provide comprehensive summaries when content is available

### **Model Configuration**
- **Temperature**: 0.3 (balanced for summarization and accuracy)
- **Top-p**: 0.8 (controlled randomness)
- **Top-k**: 30 (limited token selection)
- **Max Tokens**: 2048 (reasonable response length)

## Response Examples

### **Correct Response (Content Available)**
```
According to https://example.com/security-blog, "Ransomware attacks increased by 150% in Q3 2024, with healthcare organizations being the primary target." The article published on 2024-10-15 provides a comprehensive analysis of the attack landscape, noting that "attackers are increasingly using double extortion techniques" and that "healthcare organizations face unique challenges due to the critical nature of their services."

The research also highlights emerging trends in attack methodologies and provides detailed mitigation strategies for organizations.

This information is based on the collected web content.
```

### **Correct Response (No Content Available)**
```
I don't have information about the latest APT group activities in 2025 in my available content. The collected web content does not contain information about future threat activities or current APT group operations.
```

### **Incorrect Response (Hallucination)**
```
According to a recent survey by Cybersecurity Research Institute, 67% of organizations reported increased ransomware attacks in 2024...
```
*This would be incorrect if the "Cybersecurity Research Institute" and the 67% statistic are not in the actual collected content.*

## Quality Assurance

### **Testing Procedures**
1. **Content Adherence Tests**: Verify responses only use actual collected content
2. **Source Attribution Tests**: Confirm proper URL citations
3. **Hallucination Detection**: Check for fake sources or statistics
4. **Limitation Tests**: Verify proper decline responses

### **Validation Criteria**
- ✅ Response cites actual source URLs
- ✅ Information appears in collected content
- ✅ No fake sources or statistics
- ✅ Clear attribution format used
- ✅ Proper decline when content unavailable

### **Error Detection**
- ❌ Fake survey citations
- ❌ Made-up statistics
- ❌ Non-existent organizations
- ❌ Future predictions not in content
- ❌ General knowledge supplementation

## Model-Agnostic Implementation

### **Universal Application**
The strict guidelines work with any LLM model:

1. **Prompt Engineering**: Same strict instructions for all models
2. **Content Validation**: Universal content checking
3. **Source Attribution**: Consistent citation format
4. **Response Formatting**: Standardized output structure
5. **Error Handling**: Uniform fallback behavior

### **Configuration Flexibility**
- **Local Models**: Mistral, GPT OSS 20B, Llama2
- **Cloud Models**: OpenAI GPT-4, Anthropic Claude
- **Custom Models**: Any model with proper API interface

## Benefits

### **Accuracy**
- **No Hallucination**: Eliminates fake information
- **Source Verification**: All claims traceable to actual content
- **Factual Responses**: Only information from real sources
- **Reliable Output**: Consistent, trustworthy responses

### **Transparency**
- **Clear Attribution**: Always know where information comes from
- **Honest Limitations**: Clear when information isn't available
- **Source Tracking**: Easy to verify claims
- **Confidence Levels**: Understand response reliability

### **Compliance**
- **Audit Trail**: All responses traceable to sources
- **Data Integrity**: No contamination from external knowledge
- **Source Control**: Complete control over information sources
- **Quality Assurance**: Systematic validation of responses

## Best Practices

### **Content Collection**
- **Quality Sources**: Collect from reputable, authoritative sources
- **Regular Updates**: Maintain fresh, relevant content
- **Metadata Capture**: Include URLs, dates, authors, and quality scores
- **Diverse Sources**: Multiple perspectives and viewpoints

### **Response Monitoring**
- **Regular Testing**: Periodic validation of response quality
- **Source Verification**: Check that cited sources exist
- **Content Audits**: Review collected content for accuracy
- **User Feedback**: Monitor user satisfaction and accuracy reports

### **Continuous Improvement**
- **Guideline Refinement**: Update based on testing results
- **Model Evaluation**: Assess performance across different models
- **Content Expansion**: Add relevant sources as needed
- **Process Optimization**: Streamline content collection and validation

This strict content-focused approach ensures the AI chatbot provides reliable, accurate, and properly attributed information while maintaining transparency about its limitations.
