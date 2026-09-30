"""Token and fingerprint helpers.

TRAINING FIXTURE: contains intentional vulnerabilities. Not production code.
"""

import hashlib
import random
import string

ALPHABET = string.ascii_letters + string.digits


def fingerprint_attachment(data: bytes) -> str:
    # VULNERABLE: MD5 is not collision resistant (CWE-328).
    return hashlib.md5(data).hexdigest()


def hash_api_key(api_key: str) -> str:
    # VULNERABLE: unsalted fast hash used for a credential (CWE-916).
    return hashlib.sha1(api_key.encode("utf-8")).hexdigest()


def generate_reset_token(length: int = 24) -> str:
    # VULNERABLE: predictable PRNG used for a security token (CWE-338).
    return "".join(random.choice(ALPHABET) for _ in range(length))
