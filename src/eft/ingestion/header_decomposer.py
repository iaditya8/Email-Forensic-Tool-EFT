"""Header decomposition and categorization engine for Email Forensic Tool."""

from __future__ import annotations

from typing import Dict, List, Tuple, Union

from eft.models.canonical import HeaderDecomposition


class HeaderDecomposer:
    """Classifies and categorizes email headers into forensic groups."""

    @staticmethod
    def decompose(ordered_headers: List[Tuple[str, str]]) -> HeaderDecomposition:
        """Decompose an ordered list of headers into structured forensic categories.

        Args:
            ordered_headers: List of (name, value) tuples in physical transit order.

        Returns:
            HeaderDecomposition containing categorized headers.
        """
        received: List[str] = []
        auth_results: List[str] = []
        dkim_sigs: List[str] = []
        arc_headers_map: Dict[str, List[str]] = {}
        custom_x_map: Dict[str, List[str]] = {}
        standard_map: Dict[str, List[str]] = {}

        for raw_name, raw_value in ordered_headers:
            name_clean = raw_name.strip()
            name_lower = name_clean.lower()
            val_clean = raw_value.strip()

            # 1. Routing hops: Received headers
            if name_lower == "received":
                received.append(val_clean)
                continue

            # 2. Authentication & SPF results
            if name_lower in ("authentication-results", "received-spf"):
                auth_results.append(val_clean)

            # 3. DKIM Signatures
            if name_lower == "dkim-signature":
                dkim_sigs.append(val_clean)

            # 4. Authenticated Received Chain (ARC)
            if name_lower.startswith("arc-"):
                if name_lower not in arc_headers_map:
                    arc_headers_map[name_lower] = []
                arc_headers_map[name_lower].append(val_clean)
                continue

            # 5. Non-standard & Custom Vendor X-* headers
            if name_lower.startswith("x-"):
                if name_lower not in custom_x_map:
                    custom_x_map[name_lower] = []
                custom_x_map[name_lower].append(val_clean)
                continue

            # 6. Standard RFC 5322 & other headers
            if name_lower not in standard_map:
                standard_map[name_lower] = []
            standard_map[name_lower].append(val_clean)

        # Simplify 1-element lists to single strings for custom and standard dicts
        final_custom_x: Dict[str, Union[str, List[str]]] = {
            k: v[0] if len(v) == 1 else v for k, v in custom_x_map.items()
        }
        final_standard: Dict[str, Union[str, List[str]]] = {
            k: v[0] if len(v) == 1 else v for k, v in standard_map.items()
        }

        return HeaderDecomposition(
            received_headers=received,
            auth_results_headers=auth_results,
            dkim_signatures=dkim_sigs,
            arc_headers=arc_headers_map,
            custom_x_headers=final_custom_x,
            standard_headers=final_standard,
        )
