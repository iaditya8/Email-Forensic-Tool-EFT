"""Forensic IP Geolocation, ASN, and Network Intelligence enrichment service."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    import maxminddb
except ImportError:
    maxminddb = None  # type: ignore[assignment]

from eft.models.canonical import (
    CanonicalEmail,
    IPNetworkIntelligence,
    RelayHop,
    TransitRoute,
)

# Known major cloud providers and their primary ASNs and organization keywords
KNOWN_CLOUD_PROVIDERS: Dict[str, Tuple[List[int], List[str]]] = {
    "AWS": ([16509, 14618, 7224, 38895, 19349], ["amazon", "aws"]),
    "Microsoft Azure": ([8075, 8068, 8069], ["microsoft", "azure"]),
    "Google Cloud": ([15169, 396982, 16591, 19527], ["google", "gcp"]),
    "Cloudflare": ([13335, 209242, 394536], ["cloudflare"]),
    "DigitalOcean": ([14061, 202053, 202109], ["digitalocean"]),
    "Hetzner": ([24940, 213230], ["hetzner"]),
    "OVH": ([16276, 35540], ["ovh"]),
    "Oracle Cloud": ([31898, 20473], ["oracle"]),
    "Linode / Akamai": ([63949, 20940, 16625], ["linode", "akamai"]),
    "Alibaba Cloud": ([37963, 45102], ["alibaba", "alicloud"]),
    "Vultr": ([20473, 64512], ["vultr", "choopa", "constant company"]),
}

# Known VPN and proxy hosting ASNs frequently used for anonymized relay
KNOWN_VPN_PROXY_ASNS: Dict[int, str] = {
    9009: "M247 Ltd (Common VPN/Proxy Hosting)",
    212238: "Datacamp Limited (Common VPN/Proxy Hosting)",
    8100: "QuadraNet Enterprises LLC (Hosting/Proxy)",
    47583: "Hostinger International Limited",
    51167: "Contabo GmbH (Hosting/Proxy)",
    62240: "Clouvider Global (Hosting/VPN)",
}

# Known Tor Exit Node subnets
KNOWN_TOR_SUBNETS: List[str] = [
    "185.220.101.0/24",
    "185.220.100.0/24",
    "185.220.102.0/24",
    "171.25.193.0/24",
    "109.70.100.0/24",
    "195.176.3.0/24",
]

# Offline fallback database for deterministic, air-gapped forensic operations
OFFLINE_IP_DATABASE: Dict[str, Dict[str, object]] = {
    "8.8.8.8": {
        "country": "United States",
        "country_code": "US",
        "city": "Mountain View",
        "region": "California",
        "latitude": 37.4223,
        "longitude": -122.0848,
        "asn": 15169,
        "as_org": "Google LLC",
        "isp": "Google Public DNS",
    },
    "8.8.4.4": {
        "country": "United States",
        "country_code": "US",
        "city": "Mountain View",
        "region": "California",
        "latitude": 37.4223,
        "longitude": -122.0848,
        "asn": 15169,
        "as_org": "Google LLC",
        "isp": "Google Public DNS",
    },
    "1.1.1.1": {
        "country": "Australia",
        "country_code": "AU",
        "city": "Sydney",
        "region": "New South Wales",
        "latitude": -33.8688,
        "longitude": 151.2093,
        "asn": 13335,
        "as_org": "Cloudflare, Inc.",
        "isp": "Cloudflare Public DNS",
    },
    "209.85.208.177": {
        "country": "United States",
        "country_code": "US",
        "city": "Mountain View",
        "region": "California",
        "latitude": 37.4223,
        "longitude": -122.0848,
        "asn": 15169,
        "as_org": "Google LLC",
        "isp": "Google Workspace / Gmail Relay",
    },
    "209.85.208.1": {
        "country": "United States",
        "country_code": "US",
        "city": "Mountain View",
        "region": "California",
        "latitude": 37.4223,
        "longitude": -122.0848,
        "asn": 15169,
        "as_org": "Google LLC",
        "isp": "Google Relay",
    },
    "52.96.0.1": {
        "country": "United States",
        "country_code": "US",
        "city": "Redmond",
        "region": "Washington",
        "latitude": 47.6740,
        "longitude": -122.1215,
        "asn": 8075,
        "as_org": "Microsoft Corporation",
        "isp": "Microsoft 365 Exchange Online",
    },
    "54.240.0.1": {
        "country": "United States",
        "country_code": "US",
        "city": "Seattle",
        "region": "Washington",
        "latitude": 47.6062,
        "longitude": -122.3321,
        "asn": 16509,
        "as_org": "Amazon.com, Inc.",
        "isp": "Amazon SES / AWS",
    },
    "185.220.101.5": {
        "country": "Germany",
        "country_code": "DE",
        "city": "Frankfurt am Main",
        "region": "Hesse",
        "latitude": 50.1109,
        "longitude": 8.6821,
        "asn": 208294,
        "as_org": "Zwiebelfreunde e.V.",
        "isp": "Tor Exit Relay",
    },
    "198.185.159.25": {
        "country": "United States",
        "country_code": "US",
        "city": "New York",
        "region": "New York",
        "latitude": 40.7128,
        "longitude": -74.0060,
        "asn": 26615,
        "as_org": "Squarespace, Inc.",
        "isp": "Squarespace Mail / Edge",
    },
    "198.185.159.10": {
        "country": "United States",
        "country_code": "US",
        "city": "New York",
        "region": "New York",
        "latitude": 40.7128,
        "longitude": -74.0060,
        "asn": 26615,
        "as_org": "Squarespace, Inc.",
        "isp": "Squarespace Mail / Edge",
    },
}


class NetworkIntelligenceService:
    """Forensic network intelligence provider for IP geolocation, ASN, and cloud/threat tagging."""

    def __init__(
        self,
        custom_provider: Optional[Callable[[str], Optional[IPNetworkIntelligence]]] = None,
        city_db_path: Optional[str | Path] = None,
        asn_db_path: Optional[str | Path] = None,
    ) -> None:
        """Initialize NetworkIntelligenceService with cache, MMDB readers, and optional live provider.

        Args:
            custom_provider: Optional callable for external or dynamic GeoIP lookup queries.
            city_db_path: Optional path to GeoLite2-City.mmdb file.
            asn_db_path: Optional path to GeoLite2-ASN.mmdb file.
        """
        self._cache: Dict[str, IPNetworkIntelligence] = {}
        self._custom_provider = custom_provider
        self._city_reader = None
        self._asn_reader = None

        # Resolve City MMDB path
        resolved_city_path = (
            city_db_path or os.environ.get("GEOIP_CITY_DB") or "data/geoip/GeoLite2-City.mmdb"
        )
        if resolved_city_path and maxminddb is not None:
            c_p = Path(resolved_city_path)
            if c_p.is_file():
                try:
                    self._city_reader = maxminddb.open_database(str(c_p))
                except Exception:
                    self._city_reader = None

        # Resolve ASN MMDB path
        resolved_asn_path = (
            asn_db_path or os.environ.get("GEOIP_ASN_DB") or "data/geoip/GeoLite2-ASN.mmdb"
        )
        if resolved_asn_path and maxminddb is not None:
            a_p = Path(resolved_asn_path)
            if a_p.is_file():
                try:
                    self._asn_reader = maxminddb.open_database(str(a_p))
                except Exception:
                    self._asn_reader = None

    def register_provider(
        self,
        provider: Callable[[str], Optional[IPNetworkIntelligence]],
    ) -> None:
        """Register a dynamic lookup provider (e.g. MaxMind GeoIP2, IPinfo, VirusTotal)."""
        self._custom_provider = provider

    def lookup_ip(self, ip_str: Optional[str]) -> Optional[IPNetworkIntelligence]:
        """Perform comprehensive forensic network intelligence lookup for an IP address.

        Features:
        1. Fast in-memory session cache.
        2. RFC 1918 / Loopback private network isolation.
        3. Local MaxMind GeoLite2 City & ASN MMDB offline queries (if present).
        4. Embedded offline fallback database (for air-gapped forensic environments).
        5. Cloud provider classification (AWS, Azure, GCP, Cloudflare, etc.).
        6. Threat & anonymizer flagging (Tor Exit Node, Commercial VPN/Proxy).

        Args:
            ip_str: Target IPv4 or IPv6 address string.

        Returns:
            Populated IPNetworkIntelligence model, or None if IP string is invalid/empty.
        """
        if not ip_str or not ip_str.strip():
            return None

        clean_ip = ip_str.strip().strip("[]")

        # Check in-memory session cache
        if clean_ip in self._cache:
            return self._cache[clean_ip]

        # Validate IP format and check for private / local subnet
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
        except ValueError:
            return None

        # 1. Handle Private / Intranet IP Addresses
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
            intel = IPNetworkIntelligence(
                ip=clean_ip,
                country="Private Network",
                country_code="LOCAL",
                city="Local Subnet",
                region="Intranet",
                asn=0,
                as_org="Internal / Private RFC 1918",
                isp="Local Network Infrastructure",
                is_private=True,
                threat_tags=["PRIVATE_NETWORK", "LOCAL_INTRANET"],
            )
            self._cache[clean_ip] = intel
            return intel

        # 2. Check Custom Dynamic Provider (if registered)
        if self._custom_provider:
            try:
                custom_result = self._custom_provider(clean_ip)
                if custom_result:
                    self._apply_threat_heuristics(custom_result, ip_obj)
                    self._cache[clean_ip] = custom_result
                    return custom_result
            except Exception:
                pass

        # 3. Check Local MaxMind GeoLite2 MMDB Databases (Air-Gapped)
        if self._city_reader or self._asn_reader:
            try:
                country_name: Optional[str] = None
                country_iso: Optional[str] = None
                city_name: Optional[str] = None
                region_name: Optional[str] = None
                lat_val: Optional[float] = None
                lon_val: Optional[float] = None
                asn_num: Optional[int] = None
                as_org_name: Optional[str] = None

                if self._city_reader:
                    raw_city: Any = self._city_reader.get(clean_ip)
                    if isinstance(raw_city, dict):
                        country_dict = raw_city.get("country")
                        if isinstance(country_dict, dict):
                            names_dict = country_dict.get("names")
                            if isinstance(names_dict, dict):
                                c_name = names_dict.get("en")
                                if c_name is not None:
                                    country_name = str(c_name)
                            c_iso = country_dict.get("iso_code")
                            if c_iso is not None:
                                country_iso = str(c_iso)

                        city_dict = raw_city.get("city")
                        if isinstance(city_dict, dict):
                            names_dict = city_dict.get("names")
                            if isinstance(names_dict, dict):
                                ct_name = names_dict.get("en")
                                if ct_name is not None:
                                    city_name = str(ct_name)

                        subdivs = raw_city.get("subdivisions")
                        if (
                            isinstance(subdivs, list)
                            and len(subdivs) > 0
                            and isinstance(subdivs[0], dict)
                        ):
                            s_names = subdivs[0].get("names")
                            if isinstance(s_names, dict):
                                s_en = s_names.get("en")
                                if s_en is not None:
                                    region_name = str(s_en)

                        loc = raw_city.get("location")
                        if isinstance(loc, dict):
                            lt = loc.get("latitude")
                            ln = loc.get("longitude")
                            if lt is not None:
                                lat_val = float(str(lt))
                            if ln is not None:
                                lon_val = float(str(ln))

                if self._asn_reader:
                    raw_asn: Any = self._asn_reader.get(clean_ip)
                    if isinstance(raw_asn, dict):
                        asn_val = raw_asn.get("autonomous_system_number")
                        if asn_val is not None:
                            asn_num = int(str(asn_val))
                        as_org_val = raw_asn.get("autonomous_system_organization")
                        if as_org_val is not None:
                            as_org_name = str(as_org_val)

                if country_name or city_name or asn_num:
                    intel = IPNetworkIntelligence(
                        ip=clean_ip,
                        country=country_name or "Unknown Country",
                        country_code=country_iso or "XX",
                        city=city_name,
                        region=region_name,
                        latitude=lat_val,
                        longitude=lon_val,
                        asn=asn_num,
                        as_org=as_org_name,
                        isp=as_org_name,
                        is_private=False,
                    )
                    self._apply_threat_heuristics(intel, ip_obj)
                    self._cache[clean_ip] = intel
                    return intel
            except Exception:
                pass

        # 4. Check Embedded Offline Forensic Database
        if clean_ip in OFFLINE_IP_DATABASE:
            entry = OFFLINE_IP_DATABASE[clean_ip]
            offline_lat = entry.get("latitude")
            offline_lon = entry.get("longitude")
            offline_asn = entry.get("asn")
            intel = IPNetworkIntelligence(
                ip=clean_ip,
                country=str(entry.get("country")) if entry.get("country") else None,
                country_code=str(entry.get("country_code")) if entry.get("country_code") else None,
                city=str(entry.get("city")) if entry.get("city") else None,
                region=str(entry.get("region")) if entry.get("region") else None,
                latitude=float(str(offline_lat)) if offline_lat is not None else None,
                longitude=float(str(offline_lon)) if offline_lon is not None else None,
                asn=int(str(offline_asn)) if offline_asn is not None else None,
                as_org=str(entry.get("as_org")) if entry.get("as_org") else None,
                isp=str(entry.get("isp")) if entry.get("isp") else None,
                is_private=False,
            )
        else:
            # Fallback generic public IP record
            intel = IPNetworkIntelligence(
                ip=clean_ip,
                country="Public Internet",
                country_code="GLOBAL",
                is_private=False,
                threat_tags=["PUBLIC_ROUTABLE"],
            )

        # 4. Apply Cloud Provider & Anonymizer Threat Heuristics
        self._apply_threat_heuristics(intel, ip_obj)

        self._cache[clean_ip] = intel
        return intel

    def _apply_threat_heuristics(
        self,
        intel: IPNetworkIntelligence,
        ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> None:
        """Evaluate cloud hyperscalers, Tor exit nodes, and VPN threat categories."""
        # 1. Cloud Provider Matching
        for provider_name, (asn_list, keywords) in KNOWN_CLOUD_PROVIDERS.items():
            is_match = False
            if intel.asn and intel.asn in asn_list:
                is_match = True
            elif intel.as_org:
                org_lower = intel.as_org.lower()
                if any(kw in org_lower for kw in keywords):
                    is_match = True

            if is_match:
                intel.is_cloud_provider = True
                intel.cloud_provider_name = provider_name
                tag = f"CLOUD_PROVIDER_{provider_name.upper().replace(' ', '_').replace('/', '_')}"
                if tag not in intel.threat_tags:
                    intel.threat_tags.append(tag)
                break

        # 2. Tor Exit Node Matching
        for tor_subnet in KNOWN_TOR_SUBNETS:
            try:
                if ip_obj in ipaddress.ip_network(tor_subnet):
                    intel.is_tor_exit_node = True
                    if "TOR_EXIT_NODE" not in intel.threat_tags:
                        intel.threat_tags.append("TOR_EXIT_NODE")
                    break
            except Exception:
                continue

        # 3. Known VPN / Proxy Hosting ASN Matching
        if intel.asn and intel.asn in KNOWN_VPN_PROXY_ASNS:
            intel.is_vpn = True
            intel.is_proxy = True
            tag = "COMMERCIAL_VPN_HOSTING"
            if tag not in intel.threat_tags:
                intel.threat_tags.append(tag)

    def enrich_hop(self, hop: RelayHop) -> RelayHop:
        """Enrich a RelayHop instance with network intelligence for its from_ip.

        Args:
            hop: Target RelayHop model.

        Returns:
            Enriched RelayHop instance with populated network_intelligence.
        """
        if hop.from_ip:
            hop.network_intelligence = self.lookup_ip(hop.from_ip)
        return hop

    def enrich_route(self, route: TransitRoute) -> TransitRoute:
        """Enrich all hops and originating IP in a TransitRoute model.

        Args:
            route: Target TransitRoute model.

        Returns:
            Enriched TransitRoute model with network intelligence.
        """
        for hop in route.hops:
            self.enrich_hop(hop)

        if route.originating_ip:
            route.originating_ip_intelligence = self.lookup_ip(route.originating_ip)

        return route

    def enrich_email(self, email: CanonicalEmail) -> CanonicalEmail:
        """Enrich transit route and relay hops within a CanonicalEmail instance.

        Args:
            email: Target CanonicalEmail model.

        Returns:
            Enriched CanonicalEmail instance.
        """
        if email.transit_route:
            self.enrich_route(email.transit_route)
        return email
