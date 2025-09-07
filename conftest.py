# tests/conftest.py
import pytest
from datetime import datetime
from pathlib import Path


@pytest.hookimpl(trylast=True)

def pytest_terminal_summary(terminalreporter, config):
    stats = terminalreporter.stats  # dict: outcome -> [reports]
    lines = []
    for outcome in ("passed", "failed", "error", "skipped", "xpassed", "xfailed"):
        for rep in stats.get(outcome, []):
            lines.append(f"{outcome.upper()}: {rep.nodeid}")

    total = getattr(terminalreporter, "_numcollected", 0)
    passed = len(stats.get("passed", []))
    failed = len(stats.get("failed", [])) + len(stats.get("error", []))
    skipped = len(stats.get("skipped", []))
    lines += [
        "",
        f"TOTAL: {total}  PASSED: {passed}  FAILED: {failed}  SKIPPED: {skipped}",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    ]

    outdir = Path(".pytest_artifacts")
    outdir.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = outdir / f"test_results_{stamp}.txt"
    content = "\n".join(lines) + "\n"

    try:
        path.write_text(content, encoding="utf-8")
    except PermissionError:
        # If something locked the path, fall back to a differently named file
        alt = outdir / f"test_results_{stamp}_alt.txt"
        alt.write_text(content, encoding="utf-8")
