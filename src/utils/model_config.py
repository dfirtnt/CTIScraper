"""
Model configuration for the threat intelligence chatbot.
This allows easy switching between different LLM models.
"""

from typing import Dict, Any

# Predefined model configurations
MODEL_CONFIGS = {
    "mistral": {
        "name": "mistral",
        "url": "http://cti_ollama:11434/api/generate",
        "temperature": 0.3,
        "max_tokens": 2048,
        "top_p": 0.8,
        "top_k": 30,
        "description": "Mistral AI model - good balance of performance and memory usage"
    },
    
    "gpt-oss-20b": {
        "name": "gpt-oss:20b",
        "url": "http://cti_ollama:11434/api/generate",
        "temperature": 0.3,
        "max_tokens": 2048,
        "top_p": 0.9,
        "top_k": 40,
        "description": "GPT OSS 20B - high reasoning capabilities, requires more memory"
    },
    
    "llama2": {
        "name": "llama2",
        "url": "http://cti_ollama:11434/api/generate",
        "temperature": 0.4,
        "max_tokens": 2048,
        "top_p": 0.8,
        "top_k": 30,
        "description": "Llama2 - good general performance"
    },
    
    "openai-gpt4": {
        "name": "gpt-4",
        "url": "https://api.openai.com/v1/chat/completions",
        "temperature": 0.3,
        "max_tokens": 2048,
        "top_p": 0.8,
        "top_k": None,  # OpenAI doesn't use top_k
        "description": "OpenAI GPT-4 - high performance, requires API key"
    },
    
    "anthropic-claude": {
        "name": "claude-3-sonnet",
        "url": "https://api.anthropic.com/v1/messages",
        "temperature": 0.3,
        "max_tokens": 2048,
        "top_p": 0.8,
        "top_k": None,  # Anthropic doesn't use top_k
        "description": "Anthropic Claude - excellent reasoning capabilities"
    }
}

def get_model_config(model_name: str) -> Dict[str, Any]:
    """Get configuration for a specific model."""
    if model_name not in MODEL_CONFIGS:
        raise ValueError(f"Unknown model: {model_name}. Available models: {list(MODEL_CONFIGS.keys())}")
    return MODEL_CONFIGS[model_name].copy()

def list_available_models() -> Dict[str, str]:
    """List all available models with descriptions."""
    return {name: config["description"] for name, config in MODEL_CONFIGS.items()}

def validate_model_config(config: Dict[str, Any]) -> bool:
    """Validate a model configuration."""
    required_fields = ["name", "url", "temperature", "max_tokens"]
    return all(field in config for field in required_fields)
