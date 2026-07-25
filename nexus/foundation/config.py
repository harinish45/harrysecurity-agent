"""
NEXUS-STRIKE Configuration
Supports: OpenAI, Anthropic, OpenRouter, Ollama, Azure, Groq, DeepSeek, Omniroute, Custom
"""
import os
from typing import Optional

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict

    class NexusConfig(BaseSettings):
        model_config = SettingsConfigDict(env_file=".env", env_ignore_empty=True, extra="ignore")

        # === LLM PROVIDERS ===
        openai_api_key: Optional[str] = None
        openai_model: str = "gpt-4-turbo"
        openai_base_url: Optional[str] = None

        anthropic_api_key: Optional[str] = None
        anthropic_model: str = "claude-3-opus-20240229"

        openrouter_api_key: Optional[str] = None
        openrouter_model: str = "openai/gpt-4-turbo"
        openrouter_base_url: str = "https://openrouter.ai/api/v1"

        ollama_base_url: str = "http://localhost:11434/v1"
        ollama_model: str = "qwen2.5-coder:latest"

        nvidia_api_key: Optional[str] = None
        nvidia_model: str = "meta/llama-3.1-8b-instruct"
        nvidia_base_url: str = "https://integrate.api.nvidia.com/v1"

        azure_openai_api_key: Optional[str] = None
        azure_openai_endpoint: Optional[str] = None
        azure_openai_model: str = "gpt-4"

        groq_api_key: Optional[str] = None
        groq_model: str = "mixtral-8x7b-32768"
        groq_base_url: str = "https://api.groq.com/openai/v1"

        deepseek_api_key: Optional[str] = None
        deepseek_model: str = "deepseek-chat"
        deepseek_base_url: str = "https://api.deepseek.com/v1"

        omniroute_api_key: Optional[str] = None
        omniroute_model: str = "gpt-4"
        omniroute_base_url: Optional[str] = None

        custom_api_key: Optional[str] = None
        custom_model: str = "custom-model"
        custom_base_url: Optional[str] = None
        custom_api_type: str = "openai"  # openai, anthropic, or custom

        # Default LLM provider to use
        llm_provider: str = "ollama"
        llm_temperature: float = 0.7
        llm_max_tokens: int = 4096

        # === EXECUTION ===
        nexus_mode: str = "guided"
        nexus_log_level: str = "INFO"
        nexus_sandbox_enabled: bool = True
        nexus_auto_approve: bool = False
        nexus_max_concurrent_tools: int = 5
        nexus_tool_timeout: int = 300

        # === GUARDRAILS ===
        nexus_allowed_targets: str = "localhost,127.0.0.1,::1"
        nexus_legal_ack: str = ""
        nexus_rate_limit_calls: int = 100
        nexus_rate_limit_window: int = 60

        # === MCP ===
        nexus_mcp_port: int = 8888

        # === DATABASE ===
        postgres_dsn: str = "postgresql://nexus:nexus@localhost:5432/nexus"
        redis_dsn: str = "redis://localhost:6379/0"

except ImportError:
    class NexusConfig:
        def __init__(self):
            # LLM Providers
            self.openai_api_key = os.getenv("OPENAI_API_KEY")
            self.openai_model = os.getenv("OPENAI_MODEL", "gpt-4-turbo")
            self.openai_base_url = os.getenv("OPENAI_BASE_URL")
            self.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
            self.anthropic_model = os.getenv("ANTHROPIC_MODEL", "claude-3-opus-20240229")
            self.openrouter_api_key = os.getenv("OPENROUTER_API_KEY")
            self.openrouter_model = os.getenv("OPENROUTER_MODEL", "openai/gpt-4-turbo")
            self.openrouter_base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
            self.ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
            self.ollama_model = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:latest")
            self.nvidia_api_key = os.getenv("NVIDIA_API_KEY")
            self.nvidia_model = os.getenv("NVIDIA_MODEL", "meta/llama-3.1-8b-instruct")
            self.nvidia_base_url = os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
            self.azure_openai_api_key = os.getenv("AZURE_OPENAI_API_KEY")
            self.azure_openai_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
            self.azure_openai_model = os.getenv("AZURE_OPENAI_MODEL", "gpt-4")
            self.groq_api_key = os.getenv("GROQ_API_KEY")
            self.groq_model = os.getenv("GROQ_MODEL", "mixtral-8x7b-32768")
            self.groq_base_url = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
            self.deepseek_api_key = os.getenv("DEEPSEEK_API_KEY")
            self.deepseek_model = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
            self.deepseek_base_url = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
            self.omniroute_api_key = os.getenv("OMNIROUTE_API_KEY")
            self.omniroute_model = os.getenv("OMNIROUTE_MODEL", "gpt-4")
            self.omniroute_base_url = os.getenv("OMNIROUTE_BASE_URL")
            self.custom_api_key = os.getenv("CUSTOM_API_KEY")
            self.custom_model = os.getenv("CUSTOM_MODEL", "custom-model")
            self.custom_base_url = os.getenv("CUSTOM_BASE_URL")
            self.custom_api_type = os.getenv("CUSTOM_API_TYPE", "openai")
            self.llm_provider = os.getenv("LLM_PROVIDER", "ollama")
            self.llm_temperature = float(os.getenv("LLM_TEMPERATURE", "0.7"))
            self.llm_max_tokens = int(os.getenv("LLM_MAX_TOKENS", "4096"))
            self.nexus_mode = os.getenv("NEXUS_MODE", "guided")
            self.nexus_log_level = os.getenv("NEXUS_LOG_LEVEL", "INFO")
            self.nexus_sandbox_enabled = os.getenv("NEXUS_SANDBOX_ENABLED", "true").lower() in ("1","true","yes")
            self.nexus_auto_approve = os.getenv("NEXUS_AUTO_APPROVE", "false").lower() in ("1","true","yes")
            self.nexus_max_concurrent_tools = int(os.getenv("NEXUS_MAX_CONCURRENT_TOOLS", "5"))
            self.nexus_tool_timeout = int(os.getenv("NEXUS_TOOL_TIMEOUT", "300"))
            self.nexus_allowed_targets = os.getenv("NEXUS_ALLOWED_TARGETS", "localhost,127.0.0.1,::1")
            self.nexus_legal_ack = os.getenv("NEXUS_LEGAL_ACK", "")
            self.nexus_rate_limit_calls = int(os.getenv("NEXUS_RATE_LIMIT_CALLS", "100"))
            self.nexus_rate_limit_window = int(os.getenv("NEXUS_RATE_LIMIT_WINDOW", "60"))
            self.nexus_mcp_port = int(os.getenv("NEXUS_MCP_PORT", "8888"))
            self.postgres_dsn = os.getenv("POSTGRES_DSN", "postgresql://nexus:nexus@localhost:5432/nexus")
            self.redis_dsn = os.getenv("REDIS_DSN", "redis://localhost:6379/0")

config = NexusConfig()
