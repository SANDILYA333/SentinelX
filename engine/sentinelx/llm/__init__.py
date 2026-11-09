"""SentinelX LLM advisory summary layer with strict grounding verification and deterministic fallbacks."""

from sentinelx.llm.client import FakeLLMClient, GeminiClient, LLMClient
from sentinelx.llm.evidence import build_evidence_packet, redact_secrets, strip_control_characters
from sentinelx.llm.prompt import SYSTEM_INSTRUCTION, LLMClaim, LLMSummaryPayload, build_user_prompt
from sentinelx.llm.summarizer import compute_evidence_hash, summarize_incident
from sentinelx.llm.template import generate_template_summary
from sentinelx.llm.verifier import VerificationResult, verify_claim, verify_summary

__all__ = [
    "LLMClient",
    "GeminiClient",
    "FakeLLMClient",
    "build_evidence_packet",
    "strip_control_characters",
    "redact_secrets",
    "SYSTEM_INSTRUCTION",
    "LLMClaim",
    "LLMSummaryPayload",
    "build_user_prompt",
    "verify_claim",
    "verify_summary",
    "VerificationResult",
    "generate_template_summary",
    "summarize_incident",
    "compute_evidence_hash",
]

