#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from darkweb_collector.self_update import run_installed_self_update, run_self_update


def main() -> None:
    parser = argparse.ArgumentParser(description="Install a verified release package and restart services")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--job-id")
    mode.add_argument("--installed-root", type=Path)
    # Accepted for one transition release so an already queued legacy command
    # does not fail argument parsing after the source files are updated.
    parser.add_argument("--branch", default="")
    parser.add_argument("--remote", default="")
    args = parser.parse_args()
    if args.installed_root is not None:
        run_installed_self_update(args.installed_root)
    else:
        run_self_update(args.job_id)


if __name__ == "__main__":
    main()
