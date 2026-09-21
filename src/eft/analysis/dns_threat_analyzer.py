"""DNS Exfiltration, Tunneling, Fast-Flux, and DGA Forensics Analyzer."""

from __future__ import annotations

import math
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple, Union

import tldextract

from eft.analysis.network_intelligence import NetworkIntelligenceService
from eft.analysis.pcap_analyzer import NetworkPCAPAnalyzer
from eft.models.dns_forensics import (
    DGADomainAlert,
    DNSBeaconingAnalysis,
    DNSThreatReport,
    DNSTunnelingAlert,
    DNSTunnelingMethod,
    FastFluxAlert,
    FluxType,
    LargeTXTPayloadRecord,
    SubdomainEntropyAnalysis,
)
from eft.models.pcap import DNSPacketInfo, DNSResourceRecord, PCAPAnalysisReport


class DNSThreatAnalyzer:
    """Specialized offline forensics engine for detecting DNS covert channels, exfiltration, and botnets."""

    # Benign common domains and CDNs to prevent false positive DGA alerts
    COMMON_BENIGN_ROOTS = {
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "microsoft.com",
        "windowsupdate.com",
        "live.com",
        "office.com",
        "amazon.com",
        "amazonaws.com",
        "cloudfront.net",
        "akamai.net",
        "akamaiedge.net",
        "cloudflare.com",
        "apple.com",
        "icloud.com",
        "github.com",
        "githubusercontent.com",
        "facebook.com",
        "fbcdn.net",
        "twitter.com",
        "t.co",
        "digicert.com",
        "sectigo.com",
        "letsencrypt.org",
        "verisign.com",
    }

    def __init__(self, intel_service: Optional[NetworkIntelligenceService] = None) -> None:
        """Initialize the DNS Threat Analyzer with optional Network Intelligence."""
        self.intel_service = intel_service or NetworkIntelligenceService()
        self._tld_extractor = tldextract.TLDExtract(suffix_list_urls=())

    # -------------------------------------------------------------------------
    # Core Mathematical & Statistical Functions
    # -------------------------------------------------------------------------

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """Compute Shannon entropy in bits per symbol: H(X) = -sum(p * log2(p))."""
        if not text:
            return 0.0
        length = len(text)
        counts = Counter(text.lower())
        entropy = 0.0
        for count in counts.values():
            p = count / length
            if p > 0.0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    @staticmethod
    def detect_encoding_type(label: str) -> DNSTunnelingMethod:
        """Detect encoding mechanisms (Hex, Base32, Base64, Base64URL) within a DNS label."""
        cleaned = label.replace(".", "").replace("-", "")
        if not cleaned:
            return DNSTunnelingMethod.UNKNOWN

        # Hexadecimal check (0-9, a-f, A-F)
        if len(cleaned) >= 8 and all(c in "0123456789abcdefABCDEF" for c in cleaned):
            return DNSTunnelingMethod.HEXADECIMAL

        # Base32 check (A-Z, 2-7, =)
        if len(cleaned) >= 8 and all(
            c in "abcdefghijklmnopqrstuvwxyz234567=" for c in cleaned.lower()
        ):
            # If it has digits 2-7 and no digits 0,1,8,9, and no high non-b32 chars
            has_b32_digits = any(c in "234567" for c in cleaned)
            if has_b32_digits or len(cleaned) >= 16:
                return DNSTunnelingMethod.BASE32

        # Base64URL check (a-z, A-Z, 0-9, -, _)
        if (
            len(cleaned) >= 12
            and any(c in "-_" for c in label)
            and re.match(r"^[a-zA-Z0-9\-_]+$", label)
        ):
            return DNSTunnelingMethod.BASE64URL

        # Base64 check (mixed case + digits + optional +=/)
        has_upper = any(c.isupper() for c in label)
        has_lower = any(c.islower() for c in label)
        has_digit = any(c.isdigit() for c in label)
        if len(cleaned) >= 16 and has_upper and has_lower and (has_digit or "=" in label):
            return DNSTunnelingMethod.BASE64

        entropy = DNSThreatAnalyzer.calculate_shannon_entropy(cleaned)
        if entropy >= 4.4 and len(cleaned) >= 16:
            return DNSTunnelingMethod.BINARY_RAW

        return DNSTunnelingMethod.UNKNOWN

    def extract_domain_parts(self, fqdn: str) -> Tuple[str, str, str]:
        """Split FQDN into (subdomain, apex_domain, registered_domain)."""
        clean_fqdn = fqdn.strip().rstrip(".").lower()
        if not clean_fqdn:
            return "", "", ""
        extracted = self._tld_extractor(clean_fqdn)
        apex_domain = (
            f"{extracted.domain}.{extracted.suffix}"
            if (extracted.domain and extracted.suffix)
            else clean_fqdn
        )
        subdomain = extracted.subdomain
        return subdomain, apex_domain, clean_fqdn

    # -------------------------------------------------------------------------
    # Detection Sub-Engines
    # -------------------------------------------------------------------------

    def analyze_subdomain_entropy(self, fqdn: str) -> SubdomainEntropyAnalysis:
        """Analyze subdomain label length, Shannon entropy, and encoding anomalies."""
        subdomain, apex_domain, clean_fqdn = self.extract_domain_parts(fqdn)
        sub_len = len(subdomain)
        entropy = self.calculate_shannon_entropy(subdomain) if subdomain else 0.0
        encoding = self.detect_encoding_type(subdomain) if subdomain else DNSTunnelingMethod.UNKNOWN

        reasons: List[str] = []
        is_suspicious = False

        if sub_len > 40:
            reasons.append(f"Anomalous subdomain length ({sub_len} chars)")
            is_suspicious = True

        if entropy >= 4.5 and sub_len >= 12:
            reasons.append(f"Extremely high Shannon entropy ({entropy:.2f} bits/symbol)")
            is_suspicious = True
        elif entropy >= 3.9 and sub_len >= 24:
            reasons.append(f"Elevated Shannon entropy ({entropy:.2f} bits/symbol)")
            is_suspicious = True

        if encoding in (
            DNSTunnelingMethod.BASE32,
            DNSTunnelingMethod.BASE64,
            DNSTunnelingMethod.BASE64URL,
            DNSTunnelingMethod.HEXADECIMAL,
        ):
            if sub_len >= 16 or entropy >= 3.8:
                reasons.append(f"Covert encoding pattern identified ({encoding.value})")
                is_suspicious = True

        return SubdomainEntropyAnalysis(
            fqdn=clean_fqdn,
            apex_domain=apex_domain,
            subdomain=subdomain,
            subdomain_length=sub_len,
            entropy=entropy,
            detected_encoding=encoding,
            is_suspicious=is_suspicious,
            reasons=reasons,
        )

    def detect_dga_domain(self, domain: str) -> Optional[DGADomainAlert]:
        """Evaluate if an apex domain was algorithmically generated (DGA)."""
        subdomain, apex_domain, clean_fqdn = self.extract_domain_parts(domain)
        if not apex_domain or apex_domain in self.COMMON_BENIGN_ROOTS:
            return None

        # Extract main domain label without suffix
        parts = apex_domain.split(".")
        main_label = parts[0] if parts else ""
        label_len = len(main_label)

        if label_len < 7:
            return None

        entropy = self.calculate_shannon_entropy(main_label)

        # Count vowels, consonants, digits
        vowels = set("aeiou")
        vowel_count = sum(1 for c in main_label.lower() if c in vowels)
        consonant_count = sum(1 for c in main_label.lower() if c.isalpha() and c not in vowels)
        digit_count = sum(1 for c in main_label if c.isdigit())

        total_alpha = vowel_count + consonant_count
        vowel_ratio = (vowel_count / total_alpha) if total_alpha > 0 else 0.0

        # Max consecutive consonants
        consecutive_consonants = 0
        max_consec = 0
        for c in main_label.lower():
            if c.isalpha() and c not in vowels:
                consecutive_consonants += 1
                max_consec = max(max_consec, consecutive_consonants)
            else:
                consecutive_consonants = 0

        reasons: List[str] = []
        confidence = 0.0
        family = "High-Entropy Random"

        if entropy >= 3.7 and label_len >= 9:
            confidence += 0.40
            reasons.append(f"High label Shannon entropy ({entropy:.2f})")

        if (vowel_ratio < 0.18 or vowel_ratio > 0.65) and total_alpha >= 8:
            confidence += 0.35
            reasons.append(f"Abnormal vowel-to-consonant ratio ({vowel_ratio:.2f})")

        if max_consec >= 5:
            confidence += 0.30
            reasons.append(f"Long consonant cluster ({max_consec} consecutive consonants)")
            family = "Conficker/Mirai-like DGA"

        if digit_count >= 4 or (label_len > 0 and (digit_count / label_len) >= 0.35):
            confidence += 0.25
            reasons.append(f"High numeric density ({digit_count} digits in label)")
            family = "Hex/Alphanumeric DGA"

        # Check for hexadecimal string
        if all(c in "0123456789abcdef" for c in main_label.lower()) and label_len >= 10:
            confidence += 0.30
            reasons.append("Pure hexadecimal domain name")
            family = "Hash-based DGA"

        confidence = min(1.0, round(confidence, 2))

        if confidence >= 0.60:
            return DGADomainAlert(
                domain=clean_fqdn,
                apex_domain=apex_domain,
                entropy=entropy,
                vowel_consonant_ratio=round(vowel_ratio, 3),
                length=label_len,
                predicted_dga_family=family,
                confidence_score=confidence,
                reasons=reasons,
            )
        return None

    def detect_tunneling(
        self,
        queries_by_root: Dict[str, List[DNSResourceRecord]],
    ) -> List[DNSTunnelingAlert]:
        """Detect DNS covert channels and bulk exfiltration by analyzing query clusters per root domain."""
        alerts: List[DNSTunnelingAlert] = []

        for apex_domain, records in queries_by_root.items():
            if not apex_domain or apex_domain in self.COMMON_BENIGN_ROOTS:
                continue

            total_queries = len(records)
            if total_queries < 3:
                continue

            unique_subdomains = {r.name.lower() for r in records}
            unique_sub_count = len(unique_subdomains)

            subdomain_analyses = [self.analyze_subdomain_entropy(r.name) for r in records]
            high_entropy_count = sum(
                1 for a in subdomain_analyses if a.entropy >= 4.0 or a.is_suspicious
            )

            lengths = [a.subdomain_length for a in subdomain_analyses]
            max_len = max(lengths) if lengths else 0
            avg_len = (sum(lengths) / len(lengths)) if lengths else 0.0

            # Sum of payload bytes
            est_bytes = sum(a.subdomain_length for a in subdomain_analyses)

            detected_encodings: List[DNSTunnelingMethod] = [
                a.detected_encoding
                for a in subdomain_analyses
                if a.detected_encoding != DNSTunnelingMethod.UNKNOWN
            ]
            query_types = list({r.record_type.upper() for r in records})

            indicators: List[str] = []
            severity = "MEDIUM"

            # Check 1: High query volume with high unique subdomain ratio (C2 / Exfiltration)
            subdomain_ratio = unique_sub_count / total_queries
            if total_queries >= 10 and subdomain_ratio >= 0.75:
                indicators.append(
                    f"High unique subdomain ratio ({subdomain_ratio:.1%} over {total_queries} queries)"
                )

            # Check 2: High entropy queries
            if high_entropy_count >= 5 or (
                total_queries >= 5 and (high_entropy_count / total_queries) >= 0.5
            ):
                indicators.append(
                    f"High entropy payload labels detected ({high_entropy_count}/{total_queries} queries)"
                )
                severity = "HIGH"

            # Check 3: Maximum / average length anomaly
            if max_len >= 50 or avg_len >= 30:
                indicators.append(
                    f"Anomalous query payload sizes (Max: {max_len} chars, Avg: {avg_len:.1f} chars)"
                )
                severity = "HIGH"

            # Check 4: Specific covert query types (TXT / NULL)
            if "TXT" in query_types or "NULL" in query_types:
                indicators.append(f"Covert query type(s) utilized: {', '.join(query_types)}")

            # Check 5: Known encoding schemes detected
            if detected_encodings:
                enc_names = ", ".join(e.value for e in detected_encodings)
                indicators.append(f"Structured data encoding signatures identified: {enc_names}")
                severity = "HIGH"

            if est_bytes >= 2048:
                severity = "CRITICAL"
                indicators.append(
                    f"Significant data exfiltration volume estimated: ~{est_bytes} bytes"
                )

            if len(indicators) >= 2 or (high_entropy_count >= 4 and max_len >= 35):
                alerts.append(
                    DNSTunnelingAlert(
                        apex_domain=apex_domain,
                        total_queries=total_queries,
                        unique_subdomains_count=unique_sub_count,
                        high_entropy_queries_count=high_entropy_count,
                        max_query_length=max_len,
                        avg_query_length=round(avg_len, 1),
                        estimated_exfiltrated_bytes=est_bytes,
                        detected_encodings=list(set(detected_encodings)),
                        query_types_used=query_types,
                        threat_indicators=indicators,
                        severity=severity,
                    )
                )

        return alerts

    def detect_fast_flux(
        self,
        answers_by_domain: Dict[str, List[DNSResourceRecord]],
        ns_by_domain: Optional[Dict[str, List[DNSResourceRecord]]] = None,
    ) -> List[FastFluxAlert]:
        """Detect Fast-Flux and Double Fast-Flux bulletproof botnet hosting."""
        alerts: List[FastFluxAlert] = []
        ns_map = ns_by_domain or {}

        for domain, records in answers_by_domain.items():
            subdomain, apex_domain, clean_domain = self.extract_domain_parts(domain)
            if not apex_domain or apex_domain in self.COMMON_BENIGN_ROOTS:
                continue

            a_records = [r for r in records if r.record_type in ("A", "AAAA")]
            if not a_records:
                continue

            unique_ips = list({r.rdata for r in a_records if r.rdata})
            if len(unique_ips) < 3:
                continue

            ttls = [r.ttl for r in a_records if r.ttl >= 0]
            avg_ttl = (sum(ttls) / len(ttls)) if ttls else 0.0
            min_ttl = min(ttls) if ttls else 0

            # Collect NS records for double flux check
            ns_records = ns_map.get(domain, []) + [r for r in records if r.record_type == "NS"]
            unique_ns = list({r.rdata for r in ns_records if r.rdata})

            # Check network diversity of resolved IPs
            distinct_subnets = {ip.rsplit(".", 1)[0] for ip in unique_ips if "." in ip}
            asns: set[str] = set()
            countries: set[str] = set()

            for ip in unique_ips:
                try:
                    intel = self.intel_service.lookup_ip(ip)
                    if intel and intel.asn:
                        asns.add(str(intel.asn))
                    if intel and intel.country_code:
                        countries.add(intel.country_code)
                except Exception:
                    pass

            indicators: List[str] = []
            flux_type = FluxType.NONE

            # Fast flux heuristic: >=3 distinct IPs with low TTL (<300s) spanning multiple subnets
            if (min_ttl <= 300 or avg_ttl <= 300) and (
                len(unique_ips) >= 4 or len(distinct_subnets) >= 3
            ):
                flux_type = FluxType.SINGLE_FLUX
                indicators.append(
                    f"Rapidly rotating A records ({len(unique_ips)} distinct IPs) with low TTL (Min: {min_ttl}s, Avg: {avg_ttl:.1f}s)"
                )

                if len(distinct_subnets) >= 3:
                    indicators.append(
                        f"Resolved IPs span {len(distinct_subnets)} distinct /24 network subnets"
                    )

                if len(asns) >= 2:
                    indicators.append(
                        f"Resolved IPs span {len(asns)} distinct Autonomous Systems (ASNs)"
                    )

                if len(countries) >= 2:
                    indicators.append(
                        f"Geographically dispersed endpoints across {len(countries)} countries"
                    )

                # Double Fast-Flux check
                if len(unique_ns) >= 3:
                    flux_type = FluxType.DOUBLE_FLUX
                    indicators.append(
                        f"Double Fast-Flux detected: Rapidly rotating Name Servers ({len(unique_ns)} distinct NS)"
                    )

            if flux_type != FluxType.NONE and indicators:
                severity = "CRITICAL" if flux_type == FluxType.DOUBLE_FLUX else "HIGH"
                alerts.append(
                    FastFluxAlert(
                        domain=clean_domain,
                        flux_type=flux_type,
                        unique_a_ips_count=len(unique_ips),
                        unique_ns_count=len(unique_ns),
                        unique_asns_count=len(asns),
                        unique_countries_count=len(countries),
                        avg_ttl=round(avg_ttl, 1),
                        min_ttl=min_ttl,
                        resolved_ips=unique_ips[:15],
                        nameservers=unique_ns[:10],
                        threat_indicators=indicators,
                        severity=severity,
                    )
                )

        return alerts

    def detect_beaconing(
        self,
        queries_with_timestamps: Sequence[Tuple[datetime, str]],
    ) -> List[DNSBeaconingAnalysis]:
        """Detect automated periodic DNS C2 beaconing using inter-arrival jitter statistics."""
        analyses: List[DNSBeaconingAnalysis] = []
        domain_times: Dict[str, List[datetime]] = defaultdict(list)

        for ts, domain in queries_with_timestamps:
            if not ts or not domain:
                continue
            subdomain, apex_domain, _ = self.extract_domain_parts(domain)
            if apex_domain and apex_domain not in self.COMMON_BENIGN_ROOTS:
                domain_times[apex_domain].append(ts)

        for apex_domain, timestamps in domain_times.items():
            if len(timestamps) < 4:
                continue

            sorted_ts = sorted(timestamps)
            intervals = [
                (sorted_ts[i + 1] - sorted_ts[i]).total_seconds() for i in range(len(sorted_ts) - 1)
            ]

            # Filter out simultaneous / zero-delta queries
            valid_intervals = [dt for dt in intervals if dt > 0.05]
            if len(valid_intervals) < 3:
                continue

            mean_int = sum(valid_intervals) / len(valid_intervals)
            sorted_ints = sorted(valid_intervals)
            mid = len(sorted_ints) // 2
            median_int = (
                (sorted_ints[mid - 1] + sorted_ints[mid]) / 2.0
                if len(sorted_ints) % 2 == 0
                else sorted_ints[mid]
            )

            # Standard deviation (jitter)
            variance = sum((x - mean_int) ** 2 for x in valid_intervals) / len(valid_intervals)
            std_dev = math.sqrt(variance)

            # Regularity score (coefficient of variation CV = std_dev / mean_int)
            cv = (std_dev / mean_int) if mean_int > 0 else 1.0
            regularity = max(0.0, min(1.0, 1.0 - cv))

            is_beacon = False
            severity = "LOW"

            if regularity >= 0.70 and mean_int >= 1.0 and len(valid_intervals) >= 4:
                is_beacon = True
                severity = "CRITICAL" if regularity >= 0.88 else "HIGH"

            if is_beacon or len(valid_intervals) >= 8:
                analyses.append(
                    DNSBeaconingAnalysis(
                        apex_domain=apex_domain,
                        query_count=len(timestamps),
                        mean_interval_seconds=round(mean_int, 2),
                        median_interval_seconds=round(median_int, 2),
                        interval_std_dev=round(std_dev, 2),
                        regularity_score=round(regularity, 3),
                        is_periodic_beacon=is_beacon,
                        severity=severity,
                    )
                )

        return analyses

    def detect_large_txt_payloads(
        self,
        answers: Sequence[DNSResourceRecord],
    ) -> List[LargeTXTPayloadRecord]:
        """Detect unusually large TXT or NULL records used for downstream payload smuggling."""
        records: List[LargeTXTPayloadRecord] = []

        for rr in answers:
            if rr.record_type in ("TXT", "NULL", "CNAME") and rr.rdata:
                payload = rr.rdata
                payload_len = len(payload.encode("utf-8", errors="ignore"))
                entropy = self.calculate_shannon_entropy(payload)
                encoding = self.detect_encoding_type(payload)

                is_suspicious = False
                if payload_len >= 120 or (payload_len >= 64 and entropy >= 4.5):
                    is_suspicious = True

                if is_suspicious:
                    records.append(
                        LargeTXTPayloadRecord(
                            domain=rr.name,
                            record_type=rr.record_type,
                            payload_length_bytes=payload_len,
                            payload_snippet=payload[:80] + ("..." if len(payload) > 80 else ""),
                            entropy=entropy,
                            detected_encoding=encoding,
                            is_suspicious=is_suspicious,
                        )
                    )

        return records

    # -------------------------------------------------------------------------
    # Master Forensic Report Generation
    # -------------------------------------------------------------------------

    def analyze_dns_packets(
        self,
        dns_packets: Sequence[DNSPacketInfo],
        packet_timestamps: Optional[Sequence[datetime]] = None,
        source_hashes: Optional[Dict[str, str]] = None,
        file_path: Optional[str] = None,
        filename: Optional[str] = None,
    ) -> DNSThreatReport:
        """Synthesize all DNS packets into a canonical DNSThreatReport."""
        total_packets = len(dns_packets)
        total_queries = sum(1 for p in dns_packets if not p.is_response)
        total_responses = sum(1 for p in dns_packets if p.is_response)

        query_type_dist: Counter[str] = Counter()
        rcode_dist: Counter[str] = Counter()
        total_nxdomains = 0

        queries_by_root: Dict[str, List[DNSResourceRecord]] = defaultdict(list)
        answers_by_domain: Dict[str, List[DNSResourceRecord]] = defaultdict(list)
        ns_by_domain: Dict[str, List[DNSResourceRecord]] = defaultdict(list)
        all_answers: List[DNSResourceRecord] = []
        queries_with_ts: List[Tuple[datetime, str]] = []
        all_fqdns: set[str] = set()

        for idx, packet in enumerate(dns_packets):
            ts = (
                packet_timestamps[idx]
                if (packet_timestamps and idx < len(packet_timestamps))
                else datetime.now(timezone.utc)
            )

            # RCODE distribution
            if packet.is_response:
                rcode_name = packet.rcode_name or "NOERROR"
                rcode_dist[rcode_name] += 1
                if packet.rcode == 3 or rcode_name == "NXDOMAIN":
                    total_nxdomains += 1

            # Questions
            for q in packet.questions:
                query_type_dist[q.record_type.upper()] += 1
                all_fqdns.add(q.name)
                sub, apex, clean_fqdn = self.extract_domain_parts(q.name)
                if apex:
                    queries_by_root[apex].append(q)
                queries_with_ts.append((ts, q.name))

            # Answers
            for ans in packet.answers:
                all_answers.append(ans)
                all_fqdns.add(ans.name)
                answers_by_domain[ans.name.lower()].append(ans)

            # Authorities (NS)
            for auth in packet.authorities:
                if auth.record_type == "NS":
                    ns_by_domain[auth.name.lower()].append(auth)

        # 1. Subdomain Entropy Analysis
        subdomain_analyses: List[SubdomainEntropyAnalysis] = []
        for fqdn in all_fqdns:
            analysis = self.analyze_subdomain_entropy(fqdn)
            if analysis.is_suspicious:
                subdomain_analyses.append(analysis)

        # 2. DGA Detection
        dga_alerts: List[DGADomainAlert] = []
        for fqdn in all_fqdns:
            dga_alert = self.detect_dga_domain(fqdn)
            if dga_alert:
                dga_alerts.append(dga_alert)

        # 3. Tunneling & Exfiltration Detection
        tunneling_alerts = self.detect_tunneling(queries_by_root)

        # 4. Fast-Flux Detection
        fast_flux_alerts = self.detect_fast_flux(answers_by_domain, ns_by_domain)

        # 5. Periodic Beaconing Detection
        beaconing_analyses = self.detect_beaconing(queries_with_ts)

        # 6. Large TXT Payloads
        large_txt_payloads = self.detect_large_txt_payloads(all_answers)

        # Threat Scoring & IoCs
        threat_score = 0.0
        iocs: set[str] = set()

        if tunneling_alerts:
            threat_score += 40.0
            for t in tunneling_alerts:
                iocs.add(t.apex_domain)

        if fast_flux_alerts:
            threat_score += 35.0
            for ff in fast_flux_alerts:
                iocs.add(ff.domain)
                iocs.update(ff.resolved_ips)

        if dga_alerts:
            threat_score += 25.0
            for dga in dga_alerts:
                iocs.add(dga.apex_domain)

        if any(b.is_periodic_beacon for b in beaconing_analyses):
            threat_score += 20.0
            for b in beaconing_analyses:
                if b.is_periodic_beacon:
                    iocs.add(b.apex_domain)

        if large_txt_payloads:
            threat_score += 15.0

        # NXDOMAIN rate anomaly
        nxdomain_rate = (total_nxdomains / total_responses) if total_responses > 0 else 0.0
        if total_nxdomains >= 10 and nxdomain_rate >= 0.40:
            threat_score += 15.0

        threat_score = min(100.0, threat_score)

        # Verdict
        if threat_score >= 60.0:
            verdict = "MALICIOUS"
        elif threat_score >= 25.0:
            verdict = "SUSPICIOUS"
        else:
            verdict = "BENIGN"

        # Executive Summary & Remediation
        summary_parts = []
        if tunneling_alerts:
            summary_parts.append(
                f"Detected {len(tunneling_alerts)} DNS covert tunneling / exfiltration channel(s)."
            )
        if fast_flux_alerts:
            summary_parts.append(
                f"Identified {len(fast_flux_alerts)} Fast-Flux bulletproof botnet domain(s)."
            )
        if dga_alerts:
            summary_parts.append(
                f"Flagged {len(dga_alerts)} algorithmically generated domain(s) (DGA)."
            )
        if any(b.is_periodic_beacon for b in beaconing_analyses):
            summary_parts.append("Identified periodic C2 DNS beaconing behavior.")

        if not summary_parts:
            exec_summary = (
                "No malicious DNS tunneling, fast-flux botnets, or covert channels detected."
            )
        else:
            exec_summary = " ".join(summary_parts)

        remediation: List[str] = []
        if verdict in ("MALICIOUS", "SUSPICIOUS"):
            remediation.append(
                "Block all identified malicious apex domains and resolved IPs at the perimeter DNS/firewall."
            )
            remediation.append(
                "Isolate internal hosts generating high-entropy DNS queries for forensic imaging."
            )
            remediation.append(
                "Inspect perimeter DNS logs for historical query records matching extracted IoCs."
            )
            remediation.append(
                "Enable DNS Response Policy Zones (RPZ) and strict query rate-limiting."
            )

        unique_roots = len(queries_by_root)

        return DNSThreatReport(
            file_path=file_path,
            filename=filename or (os.path.basename(file_path) if file_path else "memory_buffer"),
            hashes=source_hashes or {},
            total_dns_packets=total_packets,
            total_queries=total_queries,
            total_responses=total_responses,
            total_nxdomains=total_nxdomains,
            nxdomain_rate=round(nxdomain_rate, 4),
            unique_apex_domains_count=unique_roots,
            unique_fqdns_count=len(all_fqdns),
            query_type_distribution=dict(query_type_dist),
            response_code_distribution=dict(rcode_dist),
            high_entropy_subdomains=subdomain_analyses,
            tunneling_alerts=tunneling_alerts,
            fast_flux_alerts=fast_flux_alerts,
            dga_alerts=dga_alerts,
            beaconing_analyses=beaconing_analyses,
            large_txt_payloads=large_txt_payloads,
            threat_score=threat_score,
            verdict=verdict,
            extracted_iocs=sorted(list(iocs)),
            executive_summary=exec_summary,
            remediation_guidance=remediation,
        )

    def analyze_pcap(self, pcap_source: Union[str, Path, bytes]) -> DNSThreatReport:
        """Ingest a PCAP or PCAPNG capture and run full DNS threat analytics."""
        pcap_analyzer = NetworkPCAPAnalyzer(net_intel=self.intel_service)
        pcap_report: PCAPAnalysisReport = pcap_analyzer.analyze(pcap_source)

        # Extract all DNS packets and timestamps from parsed packet list
        dns_packets: List[DNSPacketInfo] = []
        timestamps: List[datetime] = []

        for pkt in pcap_analyzer.last_parsed_packets:
            if pkt.dns_info:
                dns_packets.append(pkt.dns_info)
                timestamps.append(pkt.timestamp)

        hashes = pcap_report.hashes
        filename = pcap_report.filename
        file_path = pcap_report.file_path

        return self.analyze_dns_packets(
            dns_packets=dns_packets,
            packet_timestamps=timestamps,
            source_hashes=hashes,
            file_path=file_path,
            filename=filename,
        )

    def analyze_domain_list(self, domains: Sequence[str]) -> DNSThreatReport:
        """Inspect a list of raw domain names or FQDNs without network capture."""
        synthetic_packets: List[DNSPacketInfo] = []
        for idx, dom in enumerate(domains):
            synthetic_packets.append(
                DNSPacketInfo(
                    transaction_id=1000 + idx,
                    is_response=False,
                    questions=[DNSResourceRecord(name=dom, record_type="A")],
                )
            )
        return self.analyze_dns_packets(synthetic_packets)
