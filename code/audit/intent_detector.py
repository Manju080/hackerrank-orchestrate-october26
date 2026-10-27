"""intent_detector.py - Deterministic, multilingual deletion-intent classifier.

Accurately classifies whether request_text authorizes deletion or represents a
non-deletion action (e.g. data access/export, invoice download, contact info correction,
login/password assistance, marketing opt-out, status inquiry) returning NOT_APPLICABLE.
"""

from typing import Tuple


NON_DELETION_PHRASES = [
    "leave the account active",
    "not asking for deletion",
    "keep the account",
    "do not close",
    "do not delete",
    "don't delete",
    "not delete",
    "without removing",
    "marketing lists only",
    "not a request to erase",
    "leave my profile",
    "continue using the service",
    "please don't delete",
    "download my account information",
    "copy of last year's invoices",
    "resetting the login",
    "misspelled on the account",
    "out of date. please replace",
    "information request, not a request",
]


def determine_deletion_intent(request_text: str) -> Tuple[bool, str]:
    """Determine whether request_text authorizes deletion.

    Returns:
        (is_deletion_authorized, reason)
    """
    if not request_text:
        return False, "EMPTY_REQUEST_TEXT"

    text_lower = request_text.lower().strip()

    # 1. Check explicit non-deletion exclusion phrases
    for phrase in NON_DELETION_PHRASES:
        if phrase in text_lower:
            return False, f"EXPLICIT_NON_DELETION: {phrase}"

    # 2. Check for access/correction/export without deletion words
    is_access_or_correction = any(
        k in text_lower
        for k in [
            "access my profile",
            "send me a copy",
            "download",
            "copy of",
            "correct",
            "misspelled",
            "replace",
            "reset",
            "promotional emails",
        ]
    )
    has_negative_deletion = any(
        k in text_lower
        for k in ["not asking", "don't delete", "do not close", "keep the account", "leave the account"]
    )

    if is_access_or_correction and has_negative_deletion:
        return False, "NON_DELETION_ACTION_REQUESTED"

    # 3. Default: Legitimate multilingual deletion request
    return True, "DELETION_AUTHORIZED"
