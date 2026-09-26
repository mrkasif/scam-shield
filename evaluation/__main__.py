"""Evaluator command: ``python -m evaluation`` from the project root.

Delegates to the packaged lab; regenerates evaluation/results.json and
evaluation/report.md; exits non-zero only if the evaluator itself fails
(failed cases are findings, not tool failures).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

if __name__ == "__main__":
    from scamshield.evaluation.__main__ import main

    raise SystemExit(main())
