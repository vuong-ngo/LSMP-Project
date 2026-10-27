#!/usr/bin/env python3
# ============================================================================
# file: scripts/prepare_loghub.py
# Description: Standalone script to clean, extract features, and split Loghub dataset.
# ============================================================================

import sys
import argparse
from pathlib import Path

# Add project root and src to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR / "src") not in sys.path:
    sys.path.insert(0, str(BASE_DIR / "src"))

from lsmp_ai.data_preparation.loghub import LoghubPreparer


def main():
    parser = argparse.ArgumentParser(description="Prepare Loghub Syslog & OpenSSH Dataset")
    parser.add_argument(
        "--raw-dir", "-r", type=str, default=None,
        help="Path to raw Loghub directory containing *.log files (default: data/raw/)"
    )
    parser.add_argument(
        "--output-dir", "-o", type=str, default=None,
        help="Path to output directory (default: data/processed/loghub/)"
    )
    parser.add_argument(
        "--max-samples", "-m", type=int, default=None,
        help="Maximum sample count limit (default: None - full dataset)"
    )

    args = parser.parse_args()

    preparer = LoghubPreparer(raw_dir=args.raw_dir, output_dir=args.output_dir)
    output_path = preparer.prepare(max_samples=args.max_samples)
    print(f"✅ Loghub dataset prepared successfully: {output_path}")


if __name__ == "__main__":
    main()
