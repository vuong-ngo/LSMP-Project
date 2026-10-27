# ============================================================================
# file: src/lsmp_ai/data_preparation/loghub.py
# Description: Dedicated data preparer for Loghub real-world Syslog & OpenSSH datasets.
# ============================================================================

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import numpy as np
import pandas as pd

from lsmp_ai.common.constants import FEATURE_COLUMNS, LABEL_NORMAL, LABEL_ANOMALY
from lsmp_ai.common.logger import setup_logger
from lsmp_ai.data_preparation.base import BaseDataPreparer
from lsmp_ai.feature_engineering.feature_pipeline import extract_features_from_logs

logger = setup_logger(__name__)

# OpenSSH Syslog Regular Expression patterns
SSH_LOG_RE = re.compile(
    r"^(?P<ts>[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<message>.*)$"
)
FAILED_PASS_RE = re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
ACCEPTED_PASS_RE = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
BREAK_IN_RE = re.compile(r"POSSIBLE BREAK-IN ATTEMPT.*\[(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\]")
GENERIC_IP_RE = re.compile(r"\b(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b")


class LoghubPreparer(BaseDataPreparer):
    """Dedicated data preparation pipeline for Loghub real-world Syslog and OpenSSH log datasets.

    Parses raw syslog event streams, detects authentication attack patterns,
    and calculates 14 standardized LSMP feature vectors across sliding time windows.
    """

    def __init__(
        self,
        raw_dir: Optional[Union[str, Path]] = None,
        output_dir: Optional[Union[str, Path]] = None,
    ):
        super().__init__(raw_dir=raw_dir, output_dir=output_dir)
        self.output_dir = Path(output_dir) if output_dir else (self.project_root / "data" / "processed" / "loghub")

    def discover_raw_files(self) -> List[Path]:
        """Locates all raw Loghub log files (*.log) in raw_dir and parent directories."""
        candidates = []
        if self.raw_dir.exists():
            candidates.extend(self.raw_dir.glob("*.log"))

        parent_data = self.project_root.parent / "dataset"
        if parent_data.exists():
            candidates.extend(parent_data.glob("**/*.log"))

        seen = set()
        unique_files = []
        for f in candidates:
            if f.name not in seen:
                seen.add(f.name)
                unique_files.append(f)

        return sorted(unique_files)

    def parse_log_line(self, line: str) -> Dict[str, Optional[str]]:
        """Extracts structured fields (timestamp, host, PID, event_type, user, ip) from a single log line."""
        line = line.strip()
        record: Dict[str, Optional[str]] = {
            "raw_log": line,
            "timestamp": None,
            "host": None,
            "pid": None,
            "event_type": "other",
            "username": None,
            "src_ip": None,
        }

        m = SSH_LOG_RE.match(line)
        if m:
            record["timestamp"] = m.group("ts")
            record["host"] = m.group("host")
            record["pid"] = m.group("pid")
            msg = m.group("message")
        else:
            msg = line

        # 1. Check for Failed Password
        m_fail = FAILED_PASS_RE.search(msg)
        if m_fail:
            record["event_type"] = "failed_password"
            record["username"] = m_fail.group("user")
            record["src_ip"] = m_fail.group("ip")
            return record

        # 2. Check for Invalid User
        m_inv = INVALID_USER_RE.search(msg)
        if m_inv:
            record["event_type"] = "invalid_user"
            record["username"] = m_inv.group("user")
            record["src_ip"] = m_inv.group("ip")
            return record

        # 3. Check for Accepted Login
        m_acc = ACCEPTED_PASS_RE.search(msg)
        if m_acc:
            record["event_type"] = "accepted"
            record["username"] = m_acc.group("user")
            record["src_ip"] = m_acc.group("ip")
            return record

        # 4. Check for Break-in Attempt
        m_brk = BREAK_IN_RE.search(msg)
        if m_brk:
            record["event_type"] = "break_in_attempt"
            record["src_ip"] = m_brk.group("ip")
            return record

        # 5. Fallback IP extraction
        m_ip = GENERIC_IP_RE.search(msg)
        if m_ip:
            record["src_ip"] = m_ip.group("ip")

        return record

    def clean_and_transform(
        self, file_path: Path, max_rows: Optional[int] = None
    ) -> Tuple[pd.DataFrame, Dict]:
        """Parses a Loghub syslog file, aggregates events into real time windows, and extracts 14 features."""
        logger.info(f"[Loghub] Processing syslog file: {file_path.name}...")
        lines = []
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                if max_rows is not None and i >= max_rows:
                    break
                s_line = line.strip()
                if s_line:
                    lines.append(s_line)
        initial_lines = len(lines)

        if not lines:
            return pd.DataFrame(), {"file_name": file_path.name, "rows": 0}

        # 1. Parse individual log events with structured fields and timestamps
        parsed_events = []
        inferred_year = 2017
        previous_month_day = None
        invalid_timestamp_lines = 0
        for idx, line in enumerate(lines):
            rec = self.parse_log_line(line)
            ip_val = rec.get("src_ip")
            if not ip_val:
                continue

            ts_raw = rec.get("timestamp")
            if ts_raw:
                parsed_month_day = pd.to_datetime(
                    f"2000 {ts_raw}",
                    format="%Y %b %d %H:%M:%S",
                    errors="coerce",
                    utc=True,
                )
                if pd.notna(parsed_month_day):
                    month_day = (parsed_month_day.month, parsed_month_day.day)
                    if (
                        previous_month_day is not None
                        and month_day[0] < previous_month_day[0]
                    ):
                        inferred_year += 1
                    previous_month_day = month_day
                    dt = parsed_month_day.replace(year=inferred_year)
                else:
                    dt = pd.NaT
            else:
                dt = pd.NaT

            if pd.isna(dt):
                invalid_timestamp_lines += 1
                continue

            evt = rec.get("event_type", "other")
            user = (rec.get("username") or "").lower()
            is_fail = evt in ("failed_password", "invalid_user", "break_in_attempt") or bool(
                re.search(r"failed\s+password|invalid\s+user|authentication\s+failure", line, re.I)
            )
            is_ok = evt == "accepted" or bool(re.search(r"accepted\s+password|accepted\s+publickey", line, re.I))
            is_breakin = evt == "break_in_attempt" or bool(
                re.search(r"possible\s+break-in\s+attempt|break-in", line, re.I)
            )

            parsed_events.append({
                "ts": dt,
                "src_ip": ip_val,
                "username": user,
                "is_fail": is_fail,
                "is_ok": is_ok,
                "is_breakin": is_breakin,
                "raw_log": line,
            })

        if not parsed_events:
            return pd.DataFrame(), {"file_name": file_path.name, "rows": 0}

        df_ev = pd.DataFrame(parsed_events).sort_values("ts").reset_index(drop=True)

        # 2. Check for external ground-truth attacks label file if present
        attack_ips = set()
        labels_candidates = [
            self.raw_dir / "attacks.csv",
            self.raw_dir.parent / "labels" / "attacks.csv",
            self.project_root / "data" / "labels" / "attacks.csv",
        ]
        labels_file = next((p for p in labels_candidates if p.exists()), None)
        if labels_file:
            try:
                df_lab = pd.read_csv(labels_file)
                if "attacker_ip" in df_lab.columns:
                    attack_ips.update(df_lab["attacker_ip"].dropna().astype(str).unique())
                elif "ip" in df_lab.columns:
                    attack_ips.update(df_lab["ip"].dropna().astype(str).unique())
            except Exception as e:
                logger.warning(f"Could not load external labels file {labels_file}: {e}")

        # 3. Dynamic temporal windowing
        span_sec = (df_ev["ts"].max() - df_ev["ts"].min()).total_seconds()
        win_freq = "1min" if span_sec < 3600 else "5min"
        win_duration = pd.Timedelta(win_freq)
        df_ev["window_start"] = df_ev["ts"].dt.floor(win_freq)

        # Compute global active IPs per window
        active_per_window = df_ev.groupby("window_start")["src_ip"].nunique().to_dict()
        mean_events_per_ip = max(float(len(df_ev) / max(df_ev["src_ip"].nunique(), 1)), 1.0)

        # 4. Aggregate 14 standardized features per (window, src_ip)
        feature_rows = []
        for (w_start, ip), grp in df_ev.groupby(["window_start", "src_ip"]):
            n_fail = int(grp["is_fail"].sum())
            n_ok = int(grp["is_ok"].sum())
            n_tot = n_fail + n_ok
            fail_ratio = float(n_fail / n_tot) if n_tot > 0 else 0.0
            distinct_user = float(grp[grp["is_fail"]]["username"].nunique()) if n_fail > 0 else 0.0

            # Interarrival statistics
            fail_times = grp[grp["is_fail"]]["ts"].sort_values()
            if len(fail_times) >= 2:
                diffs = fail_times.diff().dropna().dt.total_seconds().values
                ia_mean = float(diffs.mean())
                ia_std = float(diffs.std()) if len(diffs) > 1 else 0.0
            else:
                ia_mean, ia_std = 0.0, 0.0

            global_active = float(active_per_window.get(w_start, 1.0))
            burst = float(len(grp) / mean_events_per_ip)

            # Scientifically grounded labeling (MITRE ATT&CK T1110)
            has_breakin = bool(grp["is_breakin"].any())
            is_known_attacker = bool(ip in attack_ips)
            is_brute_force = bool(
                (n_fail >= 5) or (n_fail >= 3 and fail_ratio >= 0.75) or (burst >= 2.0 and n_fail >= 3)
            )
            is_spraying = bool(distinct_user >= 3 and n_fail >= 3)
            is_attack = is_known_attacker or has_breakin or is_brute_force or is_spraying

            if has_breakin:
                attack_cat = "SSH-BreakInAttempt"
                label_src = "explicit_sshd_breakin_alert"
            elif is_spraying:
                attack_cat = "SSH-PasswordSpraying"
                label_src = "mitre_t1110_spraying_rule"
            elif is_brute_force:
                attack_cat = "SSH-BruteForce"
                label_src = "mitre_t1110_bruteforce_rule"
            elif is_known_attacker:
                attack_cat = "SSH-KnownAttacker"
                label_src = "external_ground_truth_ip"
            else:
                attack_cat = "BENIGN"
                label_src = "benign_background_traffic"

            feature_rows.append({
                "window_start": w_start,
                "timestamp": w_start + win_duration,
                "src_ip": ip,
                "entity_id": ip,
                "auth_fail_count": float(n_fail),
                "auth_success_count": float(n_ok),
                "auth_fail_ratio": fail_ratio,
                "distinct_username": distinct_user,
                "fail_interarrival_mean": ia_mean,
                "fail_interarrival_std": ia_std,
                "http_req_rate": 0.0,
                "http_4xx_ratio": 0.0,
                "http_5xx_ratio": 0.0,
                "http_post_ratio": 0.0,
                "distinct_user_agent": 0.0,
                "bytes_sent_mean": 0.0,
                "global_active_ips": global_active,
                "burst_rate": burst,
                "label": LABEL_ANOMALY if is_attack else LABEL_NORMAL,
                "attack_category": attack_cat,
                "timestamp_source": "original_syslog_timestamp_year_inferred",
                "label_source": label_src,
            })

        df_features = pd.DataFrame(feature_rows)
        df_features = self.sanitize_dataframe(df_features, fill_missing=False)
        df_features["source_file"] = file_path.name

        stats = {
            "file_name": file_path.name,
            "initial_log_lines": initial_lines,
            "extracted_feature_rows": len(df_features),
            "normal_count": int((df_features["label"] == LABEL_NORMAL).sum()),
            "anomaly_count": int((df_features["label"] == LABEL_ANOMALY).sum()),
            "invalid_timestamp_lines": invalid_timestamp_lines,
            "timestamp_source": "original_syslog_timestamp_year_inferred",
        }
        return df_features, stats

    def prepare(
        self,
        max_samples: Optional[int] = None,
        split_ratio: Tuple[float, float, float] = (0.6, 0.2, 0.2),
    ) -> Path:
        """Executes full Loghub dataset preparation, feature extraction, and temporal splitting."""
        log_files = self.discover_raw_files()
        if not log_files:
            raise FileNotFoundError(f"No raw Loghub log files found in {self.raw_dir}.")

        logger.info(f"=== PREPARING LOGHUB DATASET ({len(log_files)} log files discovered) ===")
        all_dfs = []
        file_stats = []
        max_log_lines = (max_samples * 100) if max_samples is not None else None
        for f in log_files:
            df_feat, stats = self.clean_and_transform(f, max_rows=max_log_lines)
            if not df_feat.empty:
                all_dfs.append(df_feat)
                file_stats.append(stats)

        if not all_dfs:
            raise RuntimeError(f"Could not extract any feature vectors from Loghub files in {self.raw_dir}.")

        df_combined = pd.concat(all_dfs, ignore_index=True)
        df_combined["dataset_source"] = "loghub"

        # Global deduplication across all windows to eliminate train/test vector leakage
        initial_combined = len(df_combined)
        df_combined = df_combined.drop_duplicates(
            subset=["source_file", "timestamp", *FEATURE_COLUMNS],
            keep="first",
        ).reset_index(drop=True)
        logger.info(f"Loghub global deduplication removed {initial_combined - len(df_combined):,} duplicate feature vectors.")

        if max_samples is not None and max_samples > 0 and len(df_combined) > max_samples:
            logger.info(f"Subsampling Loghub dataset to {max_samples:,} rows preserving temporal sequence...")
            indices = np.linspace(0, len(df_combined) - 1, max_samples, dtype=int)
            df_combined = df_combined.iloc[indices].reset_index(drop=True)

        self.output_dir.mkdir(parents=True, exist_ok=True)
        dataset_path = self.output_dir / "loghub_dataset.csv"
        df_combined.to_csv(dataset_path, index=False)

        # Temporal split (60/20/20) with entity disjoint guarantee
        train_df, val_df, test_df = self.temporal_split(
            df_combined, frac=split_ratio, entity_disjoint=True
        )
        self.save_splits(
            train_df,
            val_df,
            test_df,
            self.output_dir,
            metadata={
                "dataset_source": "loghub",
                "input_files": file_stats,
                "sampling": (
                    "full_dataset"
                    if max_samples is None
                    else f"debug_limit_{max_samples * 100}_log_lines"
                ),
            },
        )

        logger.info(f"Loghub preparation complete. Output saved to {dataset_path}")
        return dataset_path
