"""Performance, Latency, and Scalability Benchmark Suite for Email Forensic Tool."""

import time
from pathlib import Path

from eft.analysis.threat_scorer import ThreatScorer
from eft.ingestion.engine import EmailIngester
from eft.reporting.exporter import ForensicReportExporter
from tests.test_corpus_integration import CORPUS_DIR, run_full_forensic_pipeline


def test_benchmark_ingestion_latency() -> None:
    """Benchmark raw email ingestion and MIME parsing throughput."""
    sample_path = CORPUS_DIR / "01_benign_corporate.eml"
    assert sample_path.is_file()

    ingester = EmailIngester()
    iterations = 20
    start = time.perf_counter()
    for _ in range(iterations):
        res = ingester.ingest_file(sample_path)
        assert res.success is True
    elapsed = time.perf_counter() - start
    avg_latency_ms = (elapsed / iterations) * 1000.0

    # Ingestion should take < 100ms per typical email (even in virtualized CI runners)
    assert avg_latency_ms < 100.0, f"Ingestion latency too high: {avg_latency_ms:.2f}ms"


def test_benchmark_full_forensic_analysis_latency(tmp_path: Path) -> None:
    """Benchmark full multi-vector forensic analysis pipeline latency."""
    sample_path = CORPUS_DIR / "02_phishing_homoglyph.eml"
    ingester = EmailIngester()
    result = ingester.ingest_file(sample_path)
    email = result.messages[0]

    iterations = 10
    start = time.perf_counter()
    for i in range(iterations):
        analyzed = run_full_forensic_pipeline(email, tmp_path / f"bench_{i}")
        risk = ThreatScorer.calculate_composite_risk(analyzed)
        assert risk.overall_score >= 0.0
    elapsed = time.perf_counter() - start
    avg_latency_ms = (elapsed / iterations) * 1000.0

    # Full forensic analysis should take < 400ms per email in CI runners
    assert avg_latency_ms < 400.0, f"Analysis latency too high: {avg_latency_ms:.2f}ms"


def test_benchmark_report_export_latency(tmp_path: Path) -> None:
    """Benchmark multi-format report exporter throughput (PDF, JSON, CSV, STIX 2.1)."""
    sample_path = CORPUS_DIR / "01_benign_corporate.eml"
    ingester = EmailIngester()
    result = ingester.ingest_file(sample_path)
    email = run_full_forensic_pipeline(result.messages[0], tmp_path / "exp_bench_init")

    iterations = 5
    start = time.perf_counter()
    for i in range(iterations):
        out_dir = tmp_path / f"bench_export_{i}"
        exports = ForensicReportExporter.export_all(email, out_dir)
        assert len(exports) == 4
    elapsed = time.perf_counter() - start
    avg_latency_ms = (elapsed / iterations) * 1000.0

    # Full bundle report generation should take < 800ms per batch in CI runners
    assert avg_latency_ms < 800.0, f"Report generation latency too high: {avg_latency_ms:.2f}ms"


def test_benchmark_batch_scalability(tmp_path: Path) -> None:
    """Benchmark high-throughput batch processing across 30 sequential emails."""
    sample_paths = list(CORPUS_DIR.glob("*.eml"))
    assert len(sample_paths) >= 5

    ingester = EmailIngester()
    batch_size = 30
    start = time.perf_counter()
    processed_count = 0

    for i in range(batch_size):
        path = sample_paths[i % len(sample_paths)]
        res = ingester.ingest_file(path)
        for msg in res.messages:
            analyzed = run_full_forensic_pipeline(msg, tmp_path / f"batch_{i}_{processed_count}")
            _ = ThreatScorer.calculate_composite_risk(analyzed)
            processed_count += 1

    elapsed = time.perf_counter() - start
    throughput_per_sec = processed_count / elapsed

    # Batch throughput should exceed 4 emails per second in CI runners
    assert throughput_per_sec > 4.0, (
        f"Batch throughput too low: {throughput_per_sec:.2f} emails/sec"
    )
