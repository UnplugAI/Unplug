"""Luhn checksum validation for payment card numbers."""

from __future__ import annotations


def luhn_valid(digits: str) -> bool:
    """Return True when *digits* passes the Luhn mod-10 check."""
    if not digits.isdigit():
        return False
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0
