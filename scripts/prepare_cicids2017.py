# ============================================================================
# file: scripts/prepare_cicids2017.py
# Description: Wrapper for backward compatibility redirecting to prepare_data.py
# ============================================================================

from prepare_data import prepare_dataset, prepare_full_cicids2017_dataset, main

if __name__ == "__main__":
    main()
