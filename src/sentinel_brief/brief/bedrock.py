"""Thin Bedrock-Claude client.

Uses the Messages API (anthropic-shape payload) via Bedrock Runtime InvokeModel.
We don't take a streaming dependency — one synth per brief, blocking is fine.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import boto3

from ..config import settings
from ..logging import get_logger

log = get_logger("brief.bedrock")


@dataclass
class ClaudeResponse:
    text: str
    input_tokens: int | None
    output_tokens: int | None
    stop_reason: str | None


def invoke_claude(
    system: str,
    user: str,
    max_tokens: int = 2000,
    temperature: float = 0.2,
) -> ClaudeResponse:
    client = boto3.client("bedrock-runtime", region_name=settings.aws_region)
    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": max_tokens,
        "temperature": temperature,
        "system": system,
        "messages": [{"role": "user", "content": user}],
    }
    resp = client.invoke_model(
        modelId=settings.bedrock_model_id,
        body=json.dumps(body),
        contentType="application/json",
        accept="application/json",
    )
    payload = json.loads(resp["body"].read())
    text_blocks = [b.get("text", "") for b in payload.get("content", []) if b.get("type") == "text"]
    text = "\n".join(t for t in text_blocks if t).strip()
    usage = payload.get("usage") or {}
    log.info(
        "claude_call",
        input_tokens=usage.get("input_tokens"),
        output_tokens=usage.get("output_tokens"),
        stop_reason=payload.get("stop_reason"),
    )
    return ClaudeResponse(
        text=text,
        input_tokens=usage.get("input_tokens"),
        output_tokens=usage.get("output_tokens"),
        stop_reason=payload.get("stop_reason"),
    )
