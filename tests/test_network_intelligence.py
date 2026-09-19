"""Unit tests for IP Geolocation, ASN, and Network Intelligence service."""

from eft.analysis.network_intelligence import NetworkIntelligenceService
from eft.models.canonical import (
    CanonicalEmail,
    IPNetworkIntelligence,
    RelayHop,
    TransitRoute,
)


def test_lookup_private_ips():
    """Test classification of RFC 1918 private, loopback, and local subnet IPs."""
    service = NetworkIntelligenceService()

    private_ips = ["10.0.0.1", "192.168.1.100", "172.16.5.1", "127.0.0.1", "::1"]
    for ip in private_ips:
        intel = service.lookup_ip(ip)
        assert intel is not None
        assert intel.is_private is True
        assert intel.country == "Private Network"
        assert intel.country_code == "LOCAL"
        assert "PRIVATE_NETWORK" in intel.threat_tags


def test_lookup_google_cloud():
    """Test GeoIP and ASN resolution for Google infrastructure."""
    service = NetworkIntelligenceService()

    intel = service.lookup_ip("8.8.8.8")
    assert intel is not None
    assert intel.asn == 15169
    assert intel.as_org == "Google LLC"
    assert intel.country == "United States"
    assert intel.city == "Mountain View"
    assert intel.is_cloud_provider is True
    assert intel.cloud_provider_name == "Google Cloud"
    assert "CLOUD_PROVIDER_GOOGLE_CLOUD" in intel.threat_tags


def test_lookup_aws_and_azure():
    """Test cloud provider detection for AWS and Azure IPs."""
    service = NetworkIntelligenceService()

    # AWS
    aws_intel = service.lookup_ip("54.240.0.1")
    assert aws_intel is not None
    assert aws_intel.asn == 16509
    assert aws_intel.is_cloud_provider is True
    assert aws_intel.cloud_provider_name == "AWS"
    assert "CLOUD_PROVIDER_AWS" in aws_intel.threat_tags

    # Azure
    azure_intel = service.lookup_ip("52.96.0.1")
    assert azure_intel is not None
    assert azure_intel.asn == 8075
    assert azure_intel.is_cloud_provider is True
    assert azure_intel.cloud_provider_name == "Microsoft Azure"
    assert "CLOUD_PROVIDER_MICROSOFT_AZURE" in azure_intel.threat_tags


def test_lookup_cloudflare():
    """Test Cloudflare 1.1.1.1 DNS resolution and tagging."""
    service = NetworkIntelligenceService()

    intel = service.lookup_ip("1.1.1.1")
    assert intel is not None
    assert intel.asn == 13335
    assert intel.country == "Australia"
    assert intel.is_cloud_provider is True
    assert intel.cloud_provider_name == "Cloudflare"


def test_lookup_tor_exit_node():
    """Test detection of Tor exit node subnet IP."""
    service = NetworkIntelligenceService()

    intel = service.lookup_ip("185.220.101.5")
    assert intel is not None
    assert intel.country == "Germany"
    assert intel.is_tor_exit_node is True
    assert "TOR_EXIT_NODE" in intel.threat_tags


def test_vpn_proxy_asn_tagging():
    """Test threat tagging for hosting providers commonly used as commercial VPNs/proxies."""
    service = NetworkIntelligenceService()

    # Register custom provider returning M247 Ltd (ASN 9009)
    def vpn_provider(ip: str):
        return IPNetworkIntelligence(
            ip=ip,
            asn=9009,
            as_org="M247 Ltd",
            isp="M247 Infrastructure",
            country="United Kingdom",
        )

    service.register_provider(vpn_provider)

    intel = service.lookup_ip("185.200.116.1")
    assert intel is not None
    assert intel.is_vpn is True
    assert intel.is_proxy is True
    assert "COMMERCIAL_VPN_HOSTING" in intel.threat_tags


def test_session_caching():
    """Test in-memory caching to eliminate redundant lookups."""
    service = NetworkIntelligenceService()

    intel1 = service.lookup_ip("8.8.4.4")
    intel2 = service.lookup_ip("8.8.4.4")

    assert intel1 is not None
    assert intel2 is not None
    assert intel1 is intel2  # Identical cached object instance


def test_enrich_hop_and_route():
    """Test enriching RelayHop and TransitRoute structures with intelligence."""
    service = NetworkIntelligenceService()

    hop1 = RelayHop(hop_number=1, from_ip="192.168.1.50", from_host="laptop")
    hop2 = RelayHop(hop_number=2, from_ip="209.85.208.177", from_host="mail.google.com")

    service.enrich_hop(hop1)
    service.enrich_hop(hop2)

    assert hop1.network_intelligence is not None
    assert hop1.network_intelligence.is_private is True

    assert hop2.network_intelligence is not None
    assert hop2.network_intelligence.is_cloud_provider is True
    assert hop2.network_intelligence.cloud_provider_name == "Google Cloud"

    route = TransitRoute(
        total_hops=2,
        originating_ip="209.85.208.177",
        hops=[hop1, hop2],
    )
    service.enrich_route(route)

    assert route.originating_ip_intelligence is not None
    assert route.originating_ip_intelligence.asn == 15169


def test_enrich_canonical_email():
    """Test end-to-end CanonicalEmail enrichment."""
    service = NetworkIntelligenceService()

    hop = RelayHop(hop_number=1, from_ip="54.240.0.1")
    route = TransitRoute(total_hops=1, originating_ip="54.240.0.1", hops=[hop])
    email = CanonicalEmail(
        message_id="<test-intel@domain.com>",
        transit_route=route,
    )

    service.enrich_email(email)

    assert email.transit_route is not None
    assert email.transit_route.originating_ip_intelligence is not None
    assert email.transit_route.originating_ip_intelligence.cloud_provider_name == "AWS"


def test_invalid_and_empty_inputs():
    """Test graceful handling of invalid IP inputs."""
    service = NetworkIntelligenceService()

    assert service.lookup_ip(None) is None
    assert service.lookup_ip("") is None
    assert service.lookup_ip("   ") is None
    assert service.lookup_ip("invalid.not.an.ip") is None
    assert service.lookup_ip("999.999.999.999") is None
