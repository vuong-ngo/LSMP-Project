# 📁 LSMP DATASET DOCUMENTATION & SOURCES GUIDE

Due to file size constraints (> 2.5 GB), raw benchmark datasets (`.csv` files) are excluded from version control via `.gitignore`. This document provides the official reference links, explanations, and instructions for obtaining the datasets used by the **LSMP AI Security Engine**.

---

## 🌐 1. CICIDS2017 BENCHMARK DATASET

### 📌 Overview & Explanation

- **Dataset Name**: CICIDS2017 (Canadian Institute for Cybersecurity Intrusion Detection Dataset 2017)
- **Publisher**: Canadian Institute for Cybersecurity (CIC), University of New Brunswick (UNB)
- **Description**: The CICIDS2017 dataset contains benign network traffic and 8 contemporary multi-stage cyberattack scenarios (FTP/SSH Brute Force, DoS/DDoS, Heartbleed, Web Attacks, Botnet, and PortScan).
- **Primary Portal Link**: [https://cicresearch.ca/CICDataset/CIC-IDS-2017/](https://cicresearch.ca/CICDataset/CIC-IDS-2017/)
- **Alternative Portal Link**: [https://www.unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html)

### 📥 Direct Download URLs

- **Machine Learning CSV Set (`MachineLearningCSV.zip` - Recommended)**:
  `http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/MachineLearningCSV.zip`
- **HuggingFace Public Mirror**:
  `https://huggingface.co/datasets/cic/CICIDS2017/resolve/main/MachineLearningCSV.zip`

---

## 📜 2. LOGHUB OPENSSH REAL-WORLD SYSLOG DATASET

### 📌 Overview & Explanation

- **Dataset Name**: OpenSSH_2k.log (Loghub Benchmark Repository)
- **Publisher**: LogPAI (Log Intelligence Research Group)
- **Repository URL**: [https://github.com/logpai/loghub](https://github.com/logpai/loghub)
- **Description**: **Loghub** is a globally recognized benchmark suite of real-world system logs collected from production supercomputers, enterprise Linux servers, and web applications. The `OpenSSH_2k.log` dataset contains **2,000 real-world Linux OpenSSH syslog lines**, including authentic SSH brute force attacks, invalid user login attempts, break-in alerts, and normal user connections.
- **LSMP Purpose**: Used to perform **Cross-Dataset Generalization & Real-World Domain Transfer Audits** (testing whether the AI model trained on network flows can detect real-world Linux server login attacks).

---

## 📂 3. DATASET DIRECTORY STRUCTURE

```text
data/
├── README.md                 <-- (Dataset Source & Link Documentation)
├── raw/                      <-- (Raw Dataset Directory)
│   ├── *.log        		  <-- (Real-world OpenSSH syslog file)
│   └── *.csv                 <-- (Extracted CICIDS2017 CSV files)
├── processed/                <-- (LSMP Feature-Engineered Dataset)
│   └── dataset.csv           <-- (Processed 200,000 clean benchmark samples)
└── interim/                  <-- (Offline Predictions Backup - predictions_fallback.csv)
```

---

## ⚙️ 4. DATASET PREPROCESSING & FEATURE EXTRACTION

After placing raw CSV files into `data/raw/`, run the preprocessing pipeline to map network flows to the 14 LSMP Feature Vectors:

```bash
python scripts/prepare_cicids2017.py
```
