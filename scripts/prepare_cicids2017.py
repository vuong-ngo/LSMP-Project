#!/usr/bin/env python3
# ============================================================================
# file: scripts/prepare_cicids2017.py
# Description: Standalone script to clean, map, and split CICIDS2017 dataset.
# ============================================================================

import sys
import argparse
from pathlib import Path

# Add project root and src to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR / "src") not in sys.path:
    sys.path.insert(0, str(BASE_DIR / "src"))

from lsmp_ai.data_preparation.cicids2017 import CICIDS2017Preparer


def main():
    parser = argparse.ArgumentParser(description="Prepare CICIDS2017 Network Flow Dataset")
    parser.add_argument(
        "--raw-dir", "-r", type=str, default=None,
        help="Path to raw CICIDS2017 CSV directory (default: data/raw/ or dataset/MachineLearningCVE)"
    )
    parser.add_argument(
        "--output-dir", "-o", type=str, default=None,
        help="Path to output directory (default: data/processed/cicids2017/)"
    )
    parser.add_argument(
        "--max-samples", "-m", type=int, default=None,
        help="Maximum sample count limit (default: None - full dataset)"
    )
    parser.add_argument(
        "--split-strategy", "-s", type=str, default="day", choices=["day", "ratio"],
        help="Splitting strategy: 'day' (Monday=Train, Tuesday=Val, Thursday=Test) or 'ratio' (60/20/20 temporal split)"
    )

    args = parser.parse_args()

    preparer = CICIDS2017Preparer(raw_dir=args.raw_dir, output_dir=args.output_dir)
    output_path = preparer.prepare(max_samples=args.max_samples, split_strategy=args.split_strategy)
    print(f"✅ CICIDS2017 dataset prepared successfully: {output_path}")


if __name__ == "__main__":
    main()
