#!/usr/bin/env python3
"""
Setup script for GPT OSS 20B integration with Ollama.
This script helps users install and configure GPT OSS 20B for the CTI Scraper chatbot.
"""

import os
import sys
import subprocess
import platform
import requests
import json
from pathlib import Path

def print_header():
    """Print setup header."""
    print("=" * 60)
    print("🤖 GPT OSS 20B Setup for CTI Scraper Chatbot")
    print("=" * 60)
    print()

def check_ollama_installed():
    """Check if Ollama is installed."""
    try:
        result = subprocess.run(['ollama', '--version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"✅ Ollama is installed: {result.stdout.strip()}")
            return True
        else:
            print("❌ Ollama is installed but not working properly")
            return False
    except FileNotFoundError:
        print("❌ Ollama is not installed")
        return False
    except subprocess.TimeoutExpired:
        print("❌ Ollama command timed out")
        return False

def install_ollama():
    """Install Ollama based on the operating system."""
    system = platform.system().lower()
    
    print(f"📦 Installing Ollama for {system}...")
    
    if system == "darwin":  # macOS
        print("Installing Ollama for macOS...")
        try:
            subprocess.run(['curl', '-fsSL', 'https://ollama.ai/install.sh'], 
                          check=True, capture_output=True)
            print("✅ Ollama installed successfully")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install Ollama: {e}")
            return False
    
    elif system == "linux":
        print("Installing Ollama for Linux...")
        try:
            subprocess.run(['curl', '-fsSL', 'https://ollama.ai/install.sh'], 
                          check=True, capture_output=True)
            print("✅ Ollama installed successfully")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install Ollama: {e}")
            return False
    
    elif system == "windows":
        print("For Windows, please install Ollama manually:")
        print("1. Visit https://ollama.ai/download")
        print("2. Download the Windows installer")
        print("3. Run the installer")
        print("4. Restart your terminal")
        return False
    
    else:
        print(f"❌ Unsupported operating system: {system}")
        return False

def check_ollama_service():
    """Check if Ollama service is running."""
    try:
        response = requests.get('http://localhost:11434/api/tags', timeout=5)
        if response.status_code == 200:
            print("✅ Ollama service is running")
            return True
        else:
            print("❌ Ollama service is not responding properly")
            return False
    except requests.RequestException:
        print("❌ Ollama service is not running")
        return False

def start_ollama_service():
    """Start Ollama service."""
    print("🚀 Starting Ollama service...")
    try:
        # Start Ollama in the background
        subprocess.Popen(['ollama', 'serve'], 
                        stdout=subprocess.DEVNULL, 
                        stderr=subprocess.DEVNULL)
        
        # Wait a moment for the service to start
        import time
        time.sleep(3)
        
        if check_ollama_service():
            print("✅ Ollama service started successfully")
            return True
        else:
            print("❌ Failed to start Ollama service")
            return False
    except Exception as e:
        print(f"❌ Error starting Ollama service: {e}")
        return False

def check_gpt_oss_model():
    """Check if GPT OSS 20B model is available."""
    try:
        response = requests.get('http://localhost:11434/api/tags', timeout=10)
        if response.status_code == 200:
            models = response.json().get('models', [])
                    for model in models:
            if 'gpt-oss:20b' in model.get('name', ''):
                print(f"✅ GPT OSS 20B model found: {model['name']}")
                return True
            print("❌ GPT OSS 20B model not found")
            return False
        else:
            print("❌ Failed to check models")
            return False
    except requests.RequestException as e:
        print(f"❌ Error checking models: {e}")
        return False

def download_gpt_oss_model():
    """Download GPT OSS 20B model."""
    print("📥 Downloading GPT OSS 20B model...")
    print("⚠️  This may take a while (several GB download)...")
    
    try:
        # Pull the model
        result = subprocess.run(['ollama', 'pull', 'gpt-oss:20b'], 
                              capture_output=True, text=True, timeout=3600)  # 1 hour timeout
        
        if result.returncode == 0:
            print("✅ GPT OSS 20B model downloaded successfully")
            return True
        else:
            print(f"❌ Failed to download model: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print("❌ Download timed out (took longer than 1 hour)")
        return False
    except Exception as e:
        print(f"❌ Error downloading model: {e}")
        return False

def test_gpt_oss_model():
    """Test GPT OSS 20B model with a simple query."""
    print("🧪 Testing GPT OSS 20B model...")
    
    try:
        payload = {
            "model": "gpt-oss:20b",
            "messages": [
                {"role": "user", "content": "Hello! Can you confirm you're working?"}
            ],
            "stream": False
        }
        
        response = requests.post('http://localhost:11434/api/generate', 
                               json=payload, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            if 'message' in result and 'content' in result['message']:
                print("✅ GPT OSS 20B model is working correctly")
                print(f"📝 Test response: {result['message']['content'][:100]}...")
                return True
            else:
                print("❌ Unexpected response format")
                return False
        else:
            print(f"❌ Test failed with status code: {response.status_code}")
            return False
    except requests.RequestException as e:
        print(f"❌ Error testing model: {e}")
        return False

def create_config_file():
    """Create a configuration file for the chatbot."""
    config_content = """# GPT OSS 20B Chatbot Configuration
# This file contains configuration for the CTI Scraper chatbot

# Ollama API endpoint
OLLAMA_URL = "http://localhost:11434/api/generate"

# Model configuration
MODEL_NAME = "gpt-oss:20b"
MAX_TOKENS = 2048
TEMPERATURE = 0.7

# Chatbot settings
MAX_CONVERSATION_HISTORY = 10
MIN_RELEVANCE_THRESHOLD = 0.1
MAX_SEARCH_RESULTS = 5

# Response settings
ENABLE_SOURCE_CITATION = true
ENABLE_ACTIONABLE_INSIGHTS = true
"""
    
    config_path = Path("chatbot_config.py")
    if not config_path.exists():
        with open(config_path, 'w') as f:
            f.write(config_content)
        print("✅ Created chatbot configuration file")
    else:
        print("ℹ️  Configuration file already exists")

def print_next_steps():
    """Print next steps for the user."""
    print("\n" + "=" * 60)
    print("🎉 Setup Complete! Next Steps:")
    print("=" * 60)
    print()
    print("1. 🚀 Start your CTI Scraper application:")
    print("   docker-compose up -d")
    print()
    print("2. 🌐 Access the chatbot:")
    print("   http://localhost:8000/chat")
    print()
    print("3. 🧪 Test the chatbot with questions like:")
    print("   • 'What are the latest ransomware trends?'")
    print("   • 'Tell me about recent APT activities'")
    print("   • 'How does machine learning evaluation work?'")
    print()
    print("4. 📊 Monitor the chatbot:")
    print("   • Check logs: docker logs cti_web")
    print("   • Monitor Ollama: ollama list")
    print()
    print("5. 🔧 Troubleshooting:")
    print("   • If Ollama stops: ollama serve")
    print("   • If model issues: ollama pull gpt-oss-20b")
    print("   • Check service: curl http://localhost:11434/api/tags")
    print()

def main():
    """Main setup function."""
    print_header()
    
    # Check if Ollama is installed
    if not check_ollama_installed():
        print("📦 Ollama needs to be installed...")
        if not install_ollama():
            print("❌ Failed to install Ollama. Please install manually.")
            return False
    
    # Check if Ollama service is running
    if not check_ollama_service():
        print("🚀 Ollama service needs to be started...")
        if not start_ollama_service():
            print("❌ Failed to start Ollama service.")
            return False
    
    # Check if GPT OSS 20B model is available
    if not check_gpt_oss_model():
        print("📥 GPT OSS 20B model needs to be downloaded...")
        if not download_gpt_oss_model():
            print("❌ Failed to download GPT OSS 20B model.")
            return False
    
    # Test the model
    if not test_gpt_oss_model():
        print("❌ GPT OSS 20B model test failed.")
        return False
    
    # Create configuration file
    create_config_file()
    
    # Print next steps
    print_next_steps()
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n❌ Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
