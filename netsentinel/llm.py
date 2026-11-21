"""Optional Groq-powered explanation layer. Detection itself remains deterministic."""

from __future__ import annotations

import os
from typing import Any


def explain_with_groq(report: dict[str, Any]) -> str:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY is not set. Copy .env.example to .env and configure it.")

    try:
        from groq import Groq
    except ImportError as exc:
        raise RuntimeError("Install optional dependency with: pip install -e '.[llm]'") from exc

    model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    client = Groq(api_key=api_key)
    response = client.chat.completions.create(
        model=model,
        temperature=0.2,
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a cautious network-operations assistant. Explain the supplied "
                    "rule-based network alerts. Do not claim that an IP is malicious. "
                    "Distinguish observed evidence from hypotheses and suggest defensive "
                    "investigation steps. Never recommend offensive actions."
                ),
            },
            {
                "role": "user",
                "content": f"Explain this network analysis report:\n{report}",
            },
        ],
    )
    return response.choices[0].message.content or "No explanation returned."
