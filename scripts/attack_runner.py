#!/usr/bin/env python3
"""CLI wrapper to run attack scenarios."""

import sys
from pathlib import Path

# Add engine to sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "engine"))

from sentinelx.attack.runner import main  # noqa: E402

if __name__ == "__main__":
    main()
