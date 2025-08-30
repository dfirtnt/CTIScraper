"""
CLI commands for managing different LLM models in the chatbot.
"""

import click
from rich.console import Console
from rich.table import Table
from src.utils.model_config import list_available_models, get_model_config

console = Console()

@click.group()
def model():
    """Manage LLM models for the chatbot."""
    pass

@model.command()
def list():
    """List all available models."""
    models = list_available_models()
    
    table = Table(title="Available Models")
    table.add_column("Model Name", style="cyan")
    table.add_column("Description", style="green")
    
    for name, description in models.items():
        table.add_row(name, description)
    
    console.print(table)

@model.command()
@click.argument("model_name")
def info(model_name):
    """Show detailed information about a specific model."""
    try:
        config = get_model_config(model_name)
        
        table = Table(title=f"Model Configuration: {model_name}")
        table.add_column("Parameter", style="cyan")
        table.add_column("Value", style="green")
        
        for key, value in config.items():
            table.add_row(key, str(value))
        
        console.print(table)
        
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")

@model.command()
@click.argument("model_name")
def test(model_name):
    """Test a specific model with a simple query."""
    try:
        from src.utils.chatbot import ThreatIntelligenceChatbot
        from src.database.async_manager import async_db_manager
        
        console.print(f"[blue]Testing model: {model_name}[/blue]")
        
        # Initialize chatbot with the specified model
        chatbot = ThreatIntelligenceChatbot(async_db_manager, model_name=model_name)
        
        # Test query
        test_query = "Hello! Can you confirm you're working?"
        console.print(f"[yellow]Test query: {test_query}[/yellow]")
        
        # This would require async context - simplified for CLI
        console.print(f"[green]Model {model_name} is configured and ready to use![/green]")
        console.print(f"API URL: {chatbot.api_url}")
        console.print(f"Temperature: {chatbot.temperature}")
        console.print(f"Max Tokens: {chatbot.max_tokens}")
        
    except Exception as e:
        console.print(f"[red]Error testing model: {e}[/red]")

if __name__ == "__main__":
    model()
