"""Run the offline evaluation lab: ``python -m scamshield.evaluation``."""

from __future__ import annotations

import platform
import sys
import traceback
from importlib import metadata as importlib_metadata
from pathlib import Path


def _bootstrap() -> Path:
    # <root>/src/scamshield/evaluation/__main__.py -> parents[3] is <root>.
    root = Path(__file__).resolve().parents[3]
    sys.path.insert(0, str(root / "src"))
    return root


def _package_versions() -> dict:
    versions: dict[str, str] = {}
    for dist in ("fastapi", "opencv-python-headless", "numpy", "httpx",
                 "qrcode", "pillow", "pytest"):
        try:
            versions[dist] = importlib_metadata.version(dist)
        except Exception:  # noqa: BLE001 - metadata is best-effort
            continue
    return versions


def _run_network_blocked(cases) -> list[dict]:
    """Re-run with outbound network APIs disabled; restores them after."""
    import http.client
    import socket

    import httpx

    from scamshield.evaluation import run_all

    saved = {
        "create_connection": socket.create_connection,
        "getaddrinfo": socket.getaddrinfo,
        "gethostbyname": socket.gethostbyname,
        "http_request": http.client.HTTPConnection.request,
        "httpx_post": httpx.post,
    }

    def blocked(*args, **kwargs):
        raise AssertionError("network access attempted during evaluation")

    socket.create_connection = blocked  # type: ignore[method-assign]
    socket.getaddrinfo = blocked  # type: ignore[assignment]
    socket.gethostbyname = blocked  # type: ignore[assignment]
    http.client.HTTPConnection.request = blocked  # type: ignore[method-assign]
    httpx.post = blocked  # type: ignore[method-assign]
    try:
        return run_all(cases)
    finally:
        socket.create_connection = saved["create_connection"]
        socket.getaddrinfo = saved["getaddrinfo"]
        socket.gethostbyname = saved["gethostbyname"]
        http.client.HTTPConnection.request = saved["http_request"]
        httpx.post = saved["httpx_post"]


def main() -> int:
    root = _bootstrap()
    try:
        from scamshield import __version__
        from scamshield.evaluation import (
            EVALUATOR_VERSION,
            evaluate,
            generate_reports,
            load_cases,
            run_all,
        )

        cases = load_cases()
        results = run_all(cases)
        deterministic = run_all(cases) == results
        network_ok = _run_network_blocked(cases) == results
        metadata = {
            "evaluator_version": EVALUATOR_VERSION,
            "deterministic_runs": deterministic,
            "network_disabled_runs": network_ok,
            "python_version": platform.python_version(),
            "packages": _package_versions(),
        }
        metrics = evaluate(results)
        paths = generate_reports(results, metrics, __version__, root / "evaluation", metadata)
    except Exception:  # noqa: BLE001 - evaluator failure must be visible
        traceback.print_exc()
        return 1
    failed = [r for r in results if not r["passed"]]
    print(f"Cases:   {metrics['total']}")
    print(f"Passed:  {metrics['passed']}")
    print(f"Failed:  {metrics['failed']}")
    print(f"Detection rate: {metrics['detection_rate'] * 100:.1f}%")
    print(f"False-positive rate: {metrics['false_positive_rate'] * 100:.1f}%")
    print(f"Precision: {metrics['precision'] * 100:.1f}%  "
          f"Recall: {metrics['recall'] * 100:.1f}%")
    print(f"Unexplained threat predictions: {metrics['unexplained']}")
    print(f"Deterministic repeat runs: {deterministic}")
    print(f"Network-disabled run matches: {network_ok}")
    if failed:
        print("Failed: " + ", ".join(r["id"] for r in failed))
    print(f"Wrote {paths['results_json']}")
    print(f"Wrote {paths['report_md']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
