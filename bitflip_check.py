#!/usr/bin/env python3
"""

YOLO Vibe coding!

bitsquat_generator.py

Generate all valid 1-bit neighbors (bitsquats) for a given domain name
and show whether each candidate appears to be registered.

A "1-bit neighbor" here means:
    * We take one label (e.g. the second-level label: example.com -> 'example')
    * Choose one character in that label
    * Flip exactly one bit in that character's ASCII code
    * Keep the candidate if the resulting label is still a valid DNS label:
        - characters limited to [a-z0-9-]
        - cannot start or end with '-'
    * Re-attach the original TLD (and subdomain, if any) to form a full domain

Example:
    $ python bitsquat_generator.py --domain example.com
"""

from __future__ import annotations

import argparse
import socket
import time
import string
import requests
from dataclasses import dataclass
from typing import Iterable, List, Set


VALID_LABEL_CHARS: Set[str] = set(string.ascii_lowercase + string.digits + "-")


# For pretty printing the registration status in a column
STATUS_LABELS = {
    "registered": "REGISTERED",
    "probably_unregistered": "FREE?",
    "unknown": "UNKNOWN",
    "skipped": "SKIPPED",
}

class DomainCheckError(Exception):
    pass


@dataclass(frozen=True)
class DomainParts:
    """Simple container for a domain split into labels."""
    subdomain: str  # may be empty
    sld: str        # second-level domain (registrable part in simple cases)
    tld: str        # top-level domain (right-most label)

    @property
    def base_domain(self) -> str:
        """Return sld.tld (no subdomain)."""
        return f"{self.sld}.{self.tld}"

    def with_replaced_sld(self, new_sld: str) -> str:
        """Return full domain string but with sld replaced."""
        if self.subdomain:
            return f"{self.subdomain}.{new_sld}.{self.tld}"
        return f"{new_sld}.{self.tld}"


@dataclass(frozen=True)
class NeighborInfo:
    """Metadata about a single 1-bit neighbor."""
    domain: str           # full domain (e.g. www.conecranes.com)
    label: str            # original label that was changed (e.g. 'example')
    new_label: str        # the new label value
    char_index: int       # 0-based index within label
    original_char: str
    new_char: str
    bit_index: int        # which bit (0-7) was flipped in ASCII
    registration_status: str = "unknown"  # 'registered' / 'probably_unregistered' / 'unknown' / 'skipped'


def normalize_domain(domain: str) -> str:
    """
    Basic normalization:
        - strip whitespace
        - strip a trailing dot
        - lower-case (DNS is case-insensitive for ASCII)
    """
    return domain.strip().rstrip(".").lower()


def split_domain(domain: str) -> DomainParts:
    """
    Split a domain into (subdomain, sld, tld).

    NOTE: This is a *simple* splitter that assumes the registrable
    part is "second-level label + TLD", e.g.:

        www.example.com   -> subdomain='www',   sld='example', tld='com'
        example.com       -> subdomain='',      sld='example', tld='com'
        a.b.example.com   -> subdomain='a.b',   sld='example', tld='com'

    For complex ccTLDs like 'example.co.uk' you would need a public
    suffix list (e.g. via 'tldextract') to be perfectly accurate.
    """
    labels = domain.split(".")
    if len(labels) < 2:
        raise ValueError(f"Domain '{domain}' does not look valid (needs at least one dot).")

    tld = labels[-1]
    sld = labels[-2]
    sub_labels = labels[:-2]
    subdomain = ".".join(sub_labels) if sub_labels else ""
    return DomainParts(subdomain=subdomain, sld=sld, tld=tld)


def is_valid_label(label: str) -> bool:
    """
    Check if 'label' is a syntactically valid DNS label under the
    simplified rules we use for bitsquatting:
        * non-empty
        * only [a-z0-9-]
        * does not start or end with '-'
    """
    if not label:
        return False
    if label[0] == "-" or label[-1] == "-":
        return False
    return all(ch in VALID_LABEL_CHARS for ch in label)


def generate_one_bit_neighbors_for_label(label: str) -> List[NeighborInfo]:
    """
    Generate all valid 1-bit neighbors for a *single label* (no dots).

    Returns a list of NeighborInfo objects. The registration_status
    field is left at 'unknown' and will be filled in by the caller
    once the full domain is known (so we can resolve it).
    """
    label = label.lower()
    neighbors: List[NeighborInfo] = []
    seen_labels: Set[str] = set()

    for idx, ch in enumerate(label):
        orig_ord = ord(ch)

        # Only flip bits in the 0-7 range (standard ASCII)
        for bit_index in range(8):
            flipped_ord = orig_ord ^ (1 << bit_index)
            if not (0 <= flipped_ord <= 127):
                continue

            new_char = chr(flipped_ord)
            if new_char == ch:
                # This cannot happen with XOR of 1<<bit_index, but
                # we keep the check for clarity.
                continue

            candidate_label = label[:idx] + new_char + label[idx + 1 :]

            if candidate_label == label:
                continue
            if not is_valid_label(candidate_label):
                continue
            if candidate_label in seen_labels:
                continue

            seen_labels.add(candidate_label)

            neighbor = NeighborInfo(
                domain="",  # filled later by caller for full domain
                label=label,
                new_label=candidate_label,
                char_index=idx,
                original_char=ch,
                new_char=new_char,
                bit_index=bit_index,
            )
            neighbors.append(neighbor)

    # Sort to make output stable and "prioritize" (all are 1-bit, but we
    # put lexicographically smaller labels first, then by position/bit).
    neighbors.sort(key=lambda n: (n.new_label, n.char_index, n.bit_index))
    return neighbors




def check_registration(domain: str) -> str:
    """
    Return True if the domain looks registered, False if it's clearly not.
    Raises DomainCheckError if the RDAP server gives an unexpected error.
    """
    time.sleep(2)
    domain = domain.strip().lower()

    # Very minimal sanity check – you can make this stricter if you want
    if "." not in domain:
        raise ValueError(f"Not a valid domain: {domain!r}")

    url = f"https://rdap.org/domain/{domain}"  # RDAP proxy service

    try:
        resp = requests.get(url, timeout=5)
    except requests.RequestException as e:
        raise DomainCheckError(f"Network error while querying RDAP: {e}") from e

    if resp.status_code == 200:
        try:
            data = resp.json()
        except ValueError as e:
            raise DomainCheckError(f"Invalid JSON from RDAP: {e}") from e

        # RDAP domain objects normally have objectClassName == "domain"
        if data.get("objectClassName") == "domain":
            return True
        # If it returns 200 but not a domain object, be conservative:
        raise DomainCheckError(f"Unexpected RDAP object for {domain}: {data.get('objectClassName')}")
    elif resp.status_code in (400, 404):
        # 404 usually means "no such domain"
        return False
    elif resp.status_code in (429, 503):
        # rate limit or server issue – caller should decide what to do
        raise DomainCheckError(f"RDAP service unavailable or rate-limited (HTTP {resp.status_code})")
    else:
        raise DomainCheckError(f"Unexpected RDAP status code {resp.status_code}: {resp.text[:200]}")




def generate_bitsquat_domains(domain: str, do_reg_check: bool = True) -> List[NeighborInfo]:
    """
    Given a full domain (e.g. 'www.example.com'), generate all
    valid 1-bit neighbors of the *second-level label* and return
    them as NeighborInfo objects with 'domain' and 'registration_status' filled in.

    All results differ from the original by exactly one bit in the
    ASCII representation of one character in the SLD.
    """
    normalized = normalize_domain(domain)
    parts = split_domain(normalized)

    label_neighbors = generate_one_bit_neighbors_for_label(parts.sld)
    domain_neighbors: List[NeighborInfo] = []

    for n in label_neighbors:
        full_domain = parts.with_replaced_sld(n.new_label)

        if do_reg_check:
            try:
                is_registered = check_registration(full_domain)
            except DomainCheckError:
                reg_status = "unknown"
            else:
                # Match STATUS_LABELS keys: 'registered' / 'probably_unregistered'
                reg_status = "registered" if is_registered else "probably_unregistered"
        else:
            reg_status = "skipped"

        neighbor = NeighborInfo(
            domain=full_domain,
            label=n.label,
            new_label=n.new_label,
            char_index=n.char_index,
            original_char=n.original_char,
            new_char=n.new_char,
            bit_index=n.bit_index,
            registration_status=reg_status,
        )
        domain_neighbors.append(neighbor)

    return domain_neighbors

def format_neighbor(n: NeighborInfo) -> str:
    """
    Format a NeighborInfo into a human-readable line summarizing:
        - registration status
        - full candidate domain
        - which character changed, and at what bit
    """
    status_label = STATUS_LABELS.get(n.registration_status, n.registration_status.upper())
    return (
        f"{status_label:10s}  "
        f"{n.domain:40s}  "
        f"(label '{n.label}' -> '{n.new_label}', "
        f"pos {n.char_index}, "
        f"'{n.original_char}' -> '{n.new_char}', "
        f"bit {n.bit_index})"
    )


def main(argv: Iterable[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Generate all valid 1-bit neighbor domains (bitsquats) for the "
            "second-level label of a given domain, and show if they look "
            "registered or not based on DNS."
        )
    )
    parser.add_argument(
        "-d",
        "--domain",
        required=True,
        help="Domain to bitsquat (e.g. 'example.com', 'www.example.com').",
    )
    parser.add_argument(
        "--show-count-only",
        action="store_true",
        help="Only show how many neighbors were found, not the full list.",
    )
    parser.add_argument(
        "--no-reg-check",
        action="store_true",
        help="Skip DNS registration checks for candidates (faster).",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    neighbors = generate_bitsquat_domains(args.domain, do_reg_check=not args.no_reg_check)

    print(f"Original domain: {normalize_domain(args.domain)}")
    print(f"Number of valid 1-bit neighbors: {len(neighbors)}")

    if args.no_reg_check:
        print("Registration checks: SKIPPED")
    else:
        print("Registration checks: DNS resolution heuristic (see 'FREE?' vs 'REGISTERED').")

    if not args.show_count_only:
        print("\nCandidates (all differ by exactly 1 ASCII bit in the SLD):\n")
        for n in neighbors:
            print(format_neighbor(n))


if __name__ == "__main__":
    main()
