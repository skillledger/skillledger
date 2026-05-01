"""Enterprise edition license key validation.

Fail-closed: if key or expected_hash is empty/falsy, returns False.
Standard SHA-256 comparison (server-operator controls the key; no timing attack benefit).
"""

import hashlib


def validate_license_key(key: str, expected_hash: str) -> bool:
    """Validate that the SHA-256 hash of *key* matches *expected_hash*.

    Returns False if either argument is empty or falsy (fail-closed).
    """
    if not key or not expected_hash:
        return False
    computed = hashlib.sha256(key.encode()).hexdigest()
    return computed == expected_hash
