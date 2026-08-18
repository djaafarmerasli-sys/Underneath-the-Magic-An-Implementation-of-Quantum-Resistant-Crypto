"""Pytest configuration shared by the whole test suite.

The `pqcrypto` package lives under `src/` (a "src layout") and the project is
not pip-installed yet, so Python wouldn't find it on a bare `import pqcrypto`.
We prepend `src/` to sys.path here, which pytest imports before collecting any
tests -- letting the suite run straight from the project root with no install
step:

    pytest

Once the project is installed (``pip install -e .``), this shim becomes a
harmless no-op.
"""

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
