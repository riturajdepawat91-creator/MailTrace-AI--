"""
MailTrace-AI Email Classification package.
"""

from .engine import (
    ANALYSIS_VERSION,
    MODEL_TYPE,
    CATEGORIES,
    ClassificationEvidence,
    ClassificationResult,
    classify_email,
    classify_email_to_dict,
)

from .rules import (
    RuleSignal,
    RULES,
    collect_rule_signals,
)

__all__ = [
    "ANALYSIS_VERSION",
    "MODEL_TYPE",
    "CATEGORIES",
    "ClassificationEvidence",
    "ClassificationResult",
    "classify_email",
    "classify_email_to_dict",
    "RuleSignal",
    "RULES",
    "collect_rule_signals",
]
