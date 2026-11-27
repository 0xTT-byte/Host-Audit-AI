"""LLM provenance tracking module."""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field

PROMPT_VERSION = "1.0.0"

DEFAULT_OPTIONS: dict[str, Any] = {
    "temperature": 0,
    "seed": 0,
    "num_ctx": 16384,
}


class Provenance(BaseModel):
    """Metadata detailing the model, prompt version, and runtime options."""

    model: str
    digest: str = "unknown"
    prompt_version: str = PROMPT_VERSION
    options: dict[str, Any] = Field(default_factory=lambda: dict(DEFAULT_OPTIONS))


def get_provenance(
    client: Any,
    model: str,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Capture model name, digest from client.show(model), prompt_version, and options."""
    digest = "unknown"
    if client is not None:
        try:
            info = client.show(model)
            if hasattr(info, "digest") and info.digest:
                digest = str(info.digest)
            elif isinstance(info, dict):
                digest = (
                    info.get("digest")
                    or info.get("details", {}).get("parent_model")
                    or info.get("modelinfo", {}).get("general.architecture")
                    or "unknown"
                )
        except Exception:
            # client.show may fail if model metadata is unavailable; degrade gracefully
            digest = "unknown"

    opts = dict(DEFAULT_OPTIONS)
    if options:
        opts.update(options)

    return Provenance(
        model=model,
        digest=digest,
        prompt_version=PROMPT_VERSION,
        options=opts,
    ).model_dump()
