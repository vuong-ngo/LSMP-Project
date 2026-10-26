# 📁 LSMP Audited Unlabeled Data Repository

This directory contains feature vectors and log records that lack verified ground-truth labels (e.g., missing labels, NaN, or marked as 'unknown').

### Purpose & Policy (User Policy A2)
1. **Zero-Contamination Principle**: Unlabeled samples are isolated here and NEVER used in unsupervised training or supervised benchmarking to preserve statistical rigor.
2. **SOC Active Learning**: Security analysts review `unlabeled_samples.csv` to confirm ground-truth labels, which can then be promoted to verified training datasets.
