"""PW-Checker: rate the strength of a password.

The password is analysed locally. It is never printed, stored or sent anywhere.
"""

import argparse
import getpass
import math
import string
import sys
from dataclasses import dataclass, field
from pathlib import Path

COMMON_PASSWORDS_FILE = Path(__file__).with_name("common_passwords.txt")

# Entropy thresholds in bits and the label for everything below them.
RATINGS = [
    (28, "very weak"),
    (36, "weak"),
    (60, "fair"),
    (80, "strong"),
]
BEST_RATING = "very strong"

SEQUENCES = (
    string.ascii_lowercase,
    string.digits,
    "qwertzuiop",
    "asdfghjkl",
    "yxcvbnm",
    "qwertyuiop",
    "zxcvbnm",
)


@dataclass
class Result:
    entropy_bits: float
    rating: str
    is_common: bool
    tips: list = field(default_factory=list)


def load_common_passwords(path=COMMON_PASSWORDS_FILE):
    """Return the set of known weak passwords (lowercase)."""
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return set()
    return {line.strip().lower() for line in lines if line.strip()}


def pool_size(password):
    """Number of possible characters an attacker has to try per position.

    Each character class that appears in the password enlarges the search
    space: 26 lowercase, 26 uppercase, 10 digits, 32 symbols.
    """
    size = 0
    if any(c in string.ascii_lowercase for c in password):
        size += 26
    if any(c in string.ascii_uppercase for c in password):
        size += 26
    if any(c in string.digits for c in password):
        size += 10
    if any(c not in string.ascii_letters + string.digits for c in password):
        size += 32
    return size


def entropy_bits(password):
    """Estimated entropy: length * log2(pool size).

    This is an upper bound. It assumes every character is chosen at random,
    so predictable patterns are penalised separately in `analyze`.
    """
    size = pool_size(password)
    if not password or size == 0:
        return 0.0
    return len(password) * math.log2(size)


def has_repeats(password, run=3):
    """True if the same character appears `run` or more times in a row."""
    count = 1
    for previous, current in zip(password, password[1:]):
        count = count + 1 if current == previous else 1
        if count >= run:
            return True
    return False


def has_sequence(password, run=4):
    """True if the password contains `run` consecutive keys/letters/digits."""
    lowered = password.lower()
    for seq in SEQUENCES:
        for candidate in (seq, seq[::-1]):
            for start in range(len(candidate) - run + 1):
                if candidate[start:start + run] in lowered:
                    return True
    return False


def rate(bits):
    for limit, label in RATINGS:
        if bits < limit:
            return label
    return BEST_RATING


def analyze(password, common=None):
    """Analyse a password and return a `Result`."""
    if common is None:
        common = load_common_passwords()

    bits = entropy_bits(password)
    tips = []
    is_common = password.lower() in common

    if len(password) < 12:
        tips.append("Use at least 12 characters - length matters most.")
    if not any(c in string.ascii_uppercase for c in password):
        tips.append("Add uppercase letters.")
    if not any(c in string.ascii_lowercase for c in password):
        tips.append("Add lowercase letters.")
    if not any(c in string.digits for c in password):
        tips.append("Add digits.")
    if not any(c not in string.ascii_letters + string.digits for c in password):
        tips.append("Add symbols such as ! ? # %.")

    if has_repeats(password):
        bits *= 0.75
        tips.append("Avoid repeating the same character (e.g. 'aaa').")
    if has_sequence(password):
        bits *= 0.75
        tips.append("Avoid sequences like 'abcd', '1234' or 'qwertz'.")

    if is_common:
        # Attackers try known passwords first, so the guessing effort is tiny.
        bits = min(bits, 10.0)
        tips.insert(0, "This is a very common password - never use it.")

    return Result(entropy_bits=bits, rating=rate(bits), is_common=is_common, tips=tips)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Rate the strength of a password.")
    parser.add_argument(
        "password",
        nargs="?",
        help="password to check (omit it to be asked securely, without echo)",
    )
    args = parser.parse_args(argv)

    password = args.password
    if password is None:
        password = getpass.getpass("Password: ")

    result = analyze(password)
    print(f"Rating:  {result.rating}")
    print(f"Entropy: {result.entropy_bits:.1f} bits")
    for tip in result.tips:
        print(f" - {tip}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
