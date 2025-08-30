import asyncio
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import re
from dataclasses import dataclass
import httpx
import json

from src.database.async_manager import AsyncDatabaseManager
from src.models.article import Article
from src.utils.model_config import get_model_config, validate_model_config

logger = logging.getLogger(__name__)

@dataclass
class ChatMessage:
    """Represents a chat message."""
    role: str  # 'user' or 'assistant'
    content: str
    timestamp: datetime
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class SearchResult:
    """Represents a search result from the database."""
    article: Article
    relevance_score: float
    matched_text: str
    context: str

class ThreatIntelligenceChatbot:
    """Chatbot for querying threat intelligence database using RAG and various LLM models."""
    
    def __init__(self, db_manager: AsyncDatabaseManager, model_name: str = "mistral", custom_config: Optional[Dict[str, Any]] = None):
        self.db_manager = db_manager
        self.conversation_history: List[ChatMessage] = []
        
        # Get model configuration
        if custom_config:
            if not validate_model_config(custom_config):
                raise ValueError("Invalid custom model configuration")
            self.model_config = custom_config
        else:
            self.model_config = get_model_config(model_name)
        
        # Set model parameters
        self.model_name = self.model_config["name"]
        self.api_url = self.model_config["url"]
        self.temperature = self.model_config["temperature"]
        self.max_tokens = self.model_config["max_tokens"]
        self.top_p = self.model_config["top_p"]
        self.top_k = self.model_config.get("top_k")
        
        # System prompt for the chatbot
        self.system_prompt = """You are a specialized AI assistant that provides information based on the collected web content in your knowledge base. Your responses should be helpful and informative while staying within the content scope.

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

## When to Decline
Respond with "I don't have information about that in my available content" when:
- The question asks about topics completely outside the scraped content scope
- The question requires knowledge beyond what's available in the sources
- You're asked to make predictions about future events not covered in content
- The request asks for real-time information newer than the available content

## Source Attribution
- Always include the source URL for any factual claims
- If quoting directly, use quotation marks and cite the source
- Indicate when information comes from multiple sources
- Note publication dates when relevant

## Quality Guidelines
- Provide comprehensive summaries when requested
- Extract key insights and findings from articles
- Present information in a clear, organized manner
- Maintain objectivity and present information as found in sources
- Be helpful and informative while staying within content boundaries

Remember: Your role is to provide useful information from the collected content while maintaining proper attribution and staying within the content scope.

Current date: {current_date}"""

    async def chat(self, user_message: str) -> str:
        """Process a user message and return a response."""
        try:
            # Add user message to history
            self.conversation_history.append(ChatMessage(
                role="user",
                content=user_message,
                timestamp=datetime.now()
            ))
            
            # Search for relevant articles
            search_results = await self._search_articles(user_message)
            
            # Generate response using GPT OSS 20B
            response = await self._generate_response_with_gpt_oss(user_message, search_results)
            
            # Add assistant response to history
            self.conversation_history.append(ChatMessage(
                role="assistant",
                content=response,
                timestamp=datetime.now(),
                metadata={"sources": [r.article.canonical_url for r in search_results[:3]]}
            ))
            
            return response
            
        except Exception as e:
            logger.error(f"Error in chatbot: {e}")
            return f"I apologize, but I encountered an error: {str(e)}"

    async def _generate_response_with_gpt_oss(self, user_message: str, search_results: List[SearchResult]) -> str:
        """Generate response using strict content-based guidelines."""
        try:
            # If no search results, decline to answer
            if not search_results:
                return "I don't have information about that in my available content."
            
            # Build detailed context from search results
            context = self._build_context_from_results(search_results)
            
            # Create balanced instruction prompt
            balanced_prompt = f"""You are a specialized AI assistant that provides information based on the collected web content in your knowledge base.

CORE GUIDELINES:
- Use information from the scraped web content provided below
- If information is not available in the scraped content, respond with: "I don't have information about that in my available content."
- Provide meaningful summaries and analysis of the content
- Synthesize information from multiple sources when relevant
- Be helpful and informative while staying within the content scope

RESPONSE FORMAT:
- Always cite the source URL when providing information
- Use this format: "According to [URL], [information]"
- Provide comprehensive summaries of articles when requested
- Include key points, findings, and insights from the content
- Keep responses informative and well-structured

WHEN TO DECLINE:
Respond with "I don't have information about that in my available content" when:
- The question asks about topics completely outside the scraped content scope
- The question requires knowledge beyond what's available in the sources
- You're asked to make predictions about future events not covered in content
- The request asks for real-time information newer than the available content

SOURCE ATTRIBUTION:
- Always include the source URL for any factual claims
- If quoting directly, use quotation marks and cite the source
- Indicate when information comes from multiple sources
- Note publication dates when relevant

QUALITY GUIDELINES:
- Provide comprehensive summaries when requested
- Extract key insights and findings from articles
- Present information in a clear, organized manner
- Maintain objectivity and present information as found in sources
- Be helpful and informative while staying within content boundaries

COLLECTED WEB CONTENT:
{context}

USER QUESTION: {user_message}

Your response (provide comprehensive summaries and analysis based on the content above, cite sources appropriately):"""

            # Call model API with the balanced prompt
            payload = {
                "model": self.model_name,
                "messages": [{"role": "user", "content": balanced_prompt}],
                "stream": False,
                "options": {
                    "temperature": 0.3,  # Slightly higher for better summarization
                    "num_predict": self.max_tokens,
                    "top_p": 0.8,
                    "top_k": 30
                }
            }
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(self.api_url, json=payload)
                response.raise_for_status()
                
                result = response.json()
                
                if "message" in result:
                    return result["message"]["content"]
                elif "response" in result:
                    return result["response"]
                else:
                    raise ValueError("Unexpected response format from model")
            
        except Exception as e:
            logger.error(f"Error generating response: {e}")
            # Fallback to template-based response
            return self._generate_fallback_response(user_message, search_results)

    def _prepare_messages(self, user_message: str, context: str) -> List[Dict[str, str]]:
        """Prepare messages for GPT OSS 20B API."""
        messages = []
        
        # Add system message
        system_message = self.system_prompt.format(current_date=datetime.now().strftime("%Y-%m-%d"))
        messages.append({"role": "system", "content": system_message})
        
        # Add context as a system message
        if context:
            context_message = f"""You have access to the following threat intelligence context:

{context}

Use this information to provide accurate, detailed responses. Always cite the sources when referencing specific information."""
            messages.append({"role": "system", "content": context_message})
        
        # Add conversation history (last 5 messages to stay within context limits)
        for msg in self.conversation_history[-5:]:
            messages.append({"role": msg.role, "content": msg.content})
        
        # Add current user message
        messages.append({"role": "user", "content": user_message})
        
        return messages

    async def _call_gpt_oss_api(self, messages: List[Dict[str, str]]) -> str:
        """Call GPT OSS 20B API via Ollama."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Build options based on model type
                options = {
                    "temperature": self.temperature,
                    "num_predict": self.max_tokens,
                    "top_p": self.top_p
                }
                
                # Add top_k only if supported by the model
                if self.top_k is not None:
                    options["top_k"] = self.top_k
                
                payload = {
                    "model": self.model_name,
                    "messages": messages,
                    "stream": False,
                    "options": options
                }
                
                response = await client.post(self.api_url, json=payload)
                response.raise_for_status()
                
                result = response.json()
                
                if "message" in result:
                    return result["message"]["content"]
                elif "response" in result:
                    return result["response"]
                else:
                    raise ValueError("Unexpected response format from GPT OSS 20B")
                    
        except httpx.RequestError as e:
            logger.error(f"Request error calling GPT OSS 20B: {e}")
            raise
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error calling GPT OSS 20B: {e}")
            raise
        except Exception as e:
            logger.error(f"Error calling GPT OSS 20B: {e}")
            raise

    def _generate_fallback_response(self, user_message: str, search_results: List[SearchResult]) -> str:
        """Generate fallback response following strict content guidelines."""
        if not search_results:
            return "I don't have information about that in my available content."
        
        # Use template-based approach as fallback, but with strict content adherence
        context = self._build_context_from_results(search_results)
        query_type = self._classify_query(user_message)
        
        if query_type == "threat_info":
            return self._generate_threat_info_response(user_message, context, search_results)
        elif query_type == "technical":
            return self._generate_technical_response(user_message, context, search_results)
        elif query_type == "trend":
            return self._generate_trend_response(user_message, context, search_results)
        else:
            return self._generate_general_response(user_message, context, search_results)

    async def _search_articles(self, query: str) -> List[SearchResult]:
        """Search for relevant articles using semantic and keyword matching."""
        try:
            # Get all articles
            articles = await self.db_manager.list_articles()
            
            # Simple keyword-based search (can be enhanced with embeddings later)
            query_terms = self._extract_keywords(query.lower())
            results = []
            
            for article in articles:
                relevance_score = self._calculate_relevance(article, query_terms)
                
                if relevance_score > 0.1:  # Minimum relevance threshold
                    matched_text = self._extract_relevant_context(article, query_terms)
                    context = self._generate_context(article, matched_text)
                    
                    results.append(SearchResult(
                        article=article,
                        relevance_score=relevance_score,
                        matched_text=matched_text,
                        context=context
                    ))
            
            # Sort by relevance and return top results
            results.sort(key=lambda x: x.relevance_score, reverse=True)
            return results[:5]  # Return top 5 most relevant
            
        except Exception as e:
            logger.error(f"Error searching articles: {e}")
            return []

    def _extract_keywords(self, query: str) -> List[str]:
        """Extract relevant keywords from the query."""
        # Remove common words and extract meaningful terms
        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'is', 'are', 'was', 'were', 'be', 'been', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should', 'may', 'might', 'can', 'what', 'when', 'where', 'why', 'how', 'who', 'which', 'that', 'this', 'these', 'those'}
        
        words = re.findall(r'\b\w+\b', query.lower())
        keywords = [word for word in words if word not in stop_words and len(word) > 2]
        
        # Add cybersecurity-specific terms
        cyber_terms = ['malware', 'ransomware', 'phishing', 'apt', 'threat', 'attack', 'vulnerability', 'exploit', 'ioc', 'ttp', 'mitre', 'att&ck', 'crowdstrike', 'fireeye', 'palo alto', 'unit 42', 'dfir', 'incident', 'breach', 'compromise', 'persistence', 'lateral', 'exfiltration', 'machine learning', 'evaluation', 'model', 'training', 'validation', 'approach', 'method']
        
        for term in cyber_terms:
            if term in query.lower():
                keywords.append(term)
        
        return keywords

    def _calculate_relevance(self, article: Article, query_terms: List[str]) -> float:
        """Calculate relevance score between article and query terms."""
        if not article.content:
            return 0.0
        
        content_lower = article.content.lower()
        title_lower = article.title.lower() if article.title else ""
        
        score = 0.0
        
        # Title matches (higher weight)
        for term in query_terms:
            if term in title_lower:
                score += 2.0
        
        # Content matches
        for term in query_terms:
            count = content_lower.count(term)
            score += count * 0.1
        
        # Recency bonus (newer articles get higher scores)
        if article.published_at:
            days_old = (datetime.now() - article.published_at).days
            if days_old <= 30:
                score *= 1.5
            elif days_old <= 90:
                score *= 1.2
        
        # Quality score bonus
        if article.metadata and 'quality_score' in article.metadata:
            quality_score = article.metadata['quality_score']
            score *= (1 + quality_score)
        
        return score

    def _extract_relevant_context(self, article: Article, query_terms: List[str]) -> str:
        """Extract the most relevant text context from an article."""
        if not article.content:
            return ""
        
        # Find sentences containing query terms
        sentences = re.split(r'[.!?]+', article.content)
        relevant_sentences = []
        
        for sentence in sentences:
            sentence_lower = sentence.lower()
            for term in query_terms:
                if term in sentence_lower and len(sentence.strip()) > 20:
                    relevant_sentences.append(sentence.strip())
                    break
        
        if relevant_sentences:
            return " ".join(relevant_sentences[:3])  # Return up to 3 relevant sentences
        else:
            # Fallback: return first 200 characters
            return article.content[:200] + "..."

    def _generate_context(self, article: Article, matched_text: str) -> str:
        """Generate context information about the article."""
        context_parts = []
        
        if article.title:
            context_parts.append(f"Title: {article.title}")
        
        if article.published_at:
            context_parts.append(f"Published: {article.published_at.strftime('%Y-%m-%d')}")
        
        if article.canonical_url:
            context_parts.append(f"Source: {article.canonical_url}")
        
        if article.metadata and 'quality_score' in article.metadata:
            context_parts.append(f"Quality Score: {article.metadata['quality_score']:.2f}")
        
        context_parts.append(f"Relevant Content: {matched_text}")
        
        return " | ".join(context_parts)

    def _build_context_from_results(self, search_results: List[SearchResult]) -> str:
        """Build context string from search results."""
        context_parts = []
        
        for i, result in enumerate(search_results[:3], 1):  # Use top 3 results
            context_parts.append(f"Source {i}:")
            context_parts.append(f"  {result.context}")
            context_parts.append("")
        
        return "\n".join(context_parts)

    def _classify_query(self, query: str) -> str:
        """Classify the type of query."""
        query_lower = query.lower()
        
        if any(term in query_lower for term in ['malware', 'ransomware', 'virus', 'trojan', 'backdoor']):
            return "threat_info"
        elif any(term in query_lower for term in ['how', 'what is', 'explain', 'technique', 'method']):
            return "technical"
        elif any(term in query_lower for term in ['trend', 'recent', 'latest', 'new']):
            return "trend"
        else:
            return "general"

    def _generate_threat_info_response(self, user_message: str, context: str, search_results: List[SearchResult]) -> str:
        """Generate response for threat information queries with comprehensive summaries."""
        response = "Based on the collected web content, here's what I found:\n\n"
        
        for i, result in enumerate(search_results[:3], 1):
            source_url = result.article.canonical_url or "Unknown source"
            response += f"**According to {source_url}:**\n"
            response += f"Title: {result.article.title}\n"
            if result.article.published_at:
                response += f"Published: {result.article.published_at.strftime('%Y-%m-%d')}\n"
            
            # Provide a more comprehensive summary
            if result.matched_text:
                response += f"Summary: {result.matched_text}\n"
            else:
                # Use first 300 characters of content for summary
                content_preview = result.article.content[:300] + "..." if len(result.article.content) > 300 else result.article.content
                response += f"Summary: {content_preview}\n"
            
            response += "\n"
        
        response += "This information is based on the collected web content. For more details, please refer to the original sources."
        return response

    def _generate_technical_response(self, user_message: str, context: str, search_results: List[SearchResult]) -> str:
        """Generate response for technical queries with strict content adherence."""
        response = "Based on the collected web content, here's the technical information:\n\n"
        
        for i, result in enumerate(search_results[:2], 1):
            source_url = result.article.canonical_url or "Unknown source"
            response += f"**According to {source_url}:**\n"
            response += f"\"{result.matched_text}\"\n\n"
        
        response += "This technical information is based solely on the collected web content. For implementation details, please refer to the original sources."
        return response

    def _generate_trend_response(self, user_message: str, context: str, search_results: List[SearchResult]) -> str:
        """Generate response for trend queries with strict content adherence."""
        response = "Based on the collected web content, here are the trends I found:\n\n"
        
        # Group by date to show trends
        recent_articles = [r for r in search_results if r.article.published_at and (datetime.now() - r.article.published_at).days <= 30]
        
        if recent_articles:
            response += "**Recent Activity (Last 30 Days):**\n"
            for result in recent_articles[:3]:
                source_url = result.article.canonical_url or "Unknown source"
                response += f"• According to {source_url}: {result.article.title} ({result.article.published_at.strftime('%Y-%m-%d')})\n"
        else:
            response += "**Available Trends:**\n"
            for result in search_results[:3]:
                source_url = result.article.canonical_url or "Unknown source"
                response += f"• According to {source_url}: {result.article.title}\n"
        
        response += "\nThese trends are based solely on the collected web content. For the most current information, please refer to the original sources."
        return response

    def _generate_general_response(self, user_message: str, context: str, search_results: List[SearchResult]) -> str:
        """Generate response for general queries with comprehensive summaries."""
        response = "Based on the collected web content, I found some relevant information:\n\n"
        
        for i, result in enumerate(search_results[:3], 1):
            source_url = result.article.canonical_url or "Unknown source"
            response += f"**According to {source_url}:**\n"
            response += f"Title: {result.article.title}\n"
            
            # Provide a more comprehensive summary
            if result.matched_text:
                response += f"Summary: {result.matched_text}\n"
            else:
                # Use first 400 characters of content for summary
                content_preview = result.article.content[:400] + "..." if len(result.article.content) > 400 else result.article.content
                response += f"Summary: {content_preview}\n"
            
            response += "\n"
        
        response += "This information is based on the collected web content. Would you like me to provide more specific details about any particular aspect from the available sources?"
        return response

    def _generate_no_results_response(self, user_message: str) -> str:
        """Generate response when no relevant results are found."""
        return f"I don't have information about '{user_message}' in my available content. This could be because:\n\n" \
               f"• The topic is not covered in the collected web content\n" \
               f"• The query uses terminology not found in the available sources\n" \
               f"• The information is outside the scope of the collected content\n\n" \
               f"Please try rephrasing your question or asking about topics covered in the available web content."

    def get_conversation_history(self) -> List[Dict[str, Any]]:
        """Get conversation history for display."""
        return [
            {
                "role": msg.role,
                "content": msg.content,
                "timestamp": msg.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "metadata": msg.metadata
            }
            for msg in self.conversation_history[-10:]  # Last 10 messages
        ]

    def clear_history(self):
        """Clear conversation history."""
        self.conversation_history.clear()

    async def train_on_blog_content(self) -> str:
        """Train the chatbot on blog content by fetching recent blog articles and adding them to conversation context."""
        try:
            # Search for blog articles in the database
            search_query = "blog content cybersecurity threat intelligence"
            search_results = await self._search_articles(search_query) # Changed from _search_database to _search_articles
            
            if not search_results:
                return "No blog content found in the database for training."
            
            # Get the most recent blog articles (prioritize by quality and recency)
            blog_articles = []
            for result in search_results:
                article = result.article
                # Check if it's a blog article (based on metadata or URL patterns)
                if (article.metadata and article.metadata.get('blog_name')) or \
                   any(blog_indicator in article.canonical_url.lower() for blog_indicator in ['blog', 'research', 'insights']):
                    blog_articles.append(article)
            
            if not blog_articles:
                return "No blog articles found in the search results."
            
            # Take the top 5 blog articles for training
            training_articles = blog_articles[:5]
            
            # Build comprehensive training context
            training_context = "Blog Content Training Context:\n\n"
            for i, article in enumerate(training_articles, 1):
                training_context += f"Blog Article {i}:\n"
                training_context += f"Title: {article.title}\n"
                if article.published_at:
                    training_context += f"Published: {article.published_at.strftime('%Y-%m-%d')}\n"
                if article.canonical_url:
                    training_context += f"Source: {article.canonical_url}\n"
                if article.metadata and article.metadata.get('blog_name'):
                    training_context += f"Blog: {article.metadata['blog_name']}\n"
                if article.metadata and article.metadata.get('author'):
                    training_context += f"Author: {article.metadata['author']}\n"
                
                # Include first 500 characters of content for context
                content_preview = article.content[:500] + "..." if len(article.content) > 500 else article.content
                training_context += f"Content Preview: {content_preview}\n\n"
            
            # Add training context as a system message
            training_message = ChatMessage(
                role="system",
                content=f"Training completed on {len(training_articles)} blog articles. The chatbot now has enhanced context about recent cybersecurity blog content and can provide more comprehensive summaries and insights from these sources.\n\n{training_context}",
                timestamp=datetime.now(),
                metadata={"training_type": "blog_content", "articles_count": len(training_articles)}
            )
            
            self.conversation_history.append(training_message)
            
            return f"Successfully trained on {len(training_articles)} blog articles. The chatbot now has enhanced context for providing comprehensive summaries and insights from cybersecurity blog content."
            
        except Exception as e:
            logger.error(f"Error training on blog content: {e}")
            return f"Training failed: {str(e)}"
