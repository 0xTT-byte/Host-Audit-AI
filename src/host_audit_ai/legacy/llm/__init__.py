"""Optional LLM triage layer for host-audit-ai using Ollama."""

from typing import Any

__all__ = [
    "Cluster",
    "Triage",
    "triage",
    "Redactor",
    "redact_text",
    "restore_text",
    "get_provenance",
    "PROMPT_VERSION",
    "get_ollama_client",
]


def get_ollama_client(host: str | None = None, timeout: float = 600.0) -> Any:
    """Lazily import and initialize ollama.Client.
    
    Raises ImportError with explicit installation instructions if ollama is not installed.
    """
    try:
        import ollama
    except (ImportError, ModuleNotFoundError) as err:
        raise ImportError(
            "Optional LLM dependencies are not installed. "
            "Please install them with: pip install host-audit-ai[llm]"
        ) from err

    import os
    target_host = host or os.environ.get("OLLAMA_HOST") or "http://127.0.0.1:11434"
    return ollama.Client(host=target_host, timeout=timeout)


from host_audit.llm.redact import Redactor, redact_text, restore_text
from host_audit.llm.provenance import PROMPT_VERSION, get_provenance
from host_audit.llm.triage import Cluster, Triage, triage
