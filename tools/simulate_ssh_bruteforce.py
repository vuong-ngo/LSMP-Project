#!/usr/bin/env python3
# ============================================================================
# file: scripts/simulate_ssh_bruteforce.py
# Description: Security Simulation Tool for testing Wazuh SIEM & LSMP AI Detection.
#              Simulates synthetic SSH brute-force login attempts against a target
#              host to trigger Wazuh alert rules (5710, 5716, 5720) and evaluate
#              the LSMP AI Risk Scoring engine.
# ============================================================================

import os
import sys
import time
import socket
import argparse
from datetime import datetime

try:
    import paramiko
except ImportError:
    print("📦 Installing required 'paramiko' library for SSH simulation...")
    os.system("pip install paramiko")
    import paramiko

# Default test wordlists for simulation
COMMON_USERNAMES = [
    "root", "admin", "user", "postgres", "ubuntu", "test",
    "webmaster", "operator", "sysadmin", "guest", "deploy"
]

COMMON_PASSWORDS = [
    "123456", "password", "admin123", "root123", "letmein",
    "P@ssw0rd", "welcome", "shadow", "123456789", "master"
]


def test_ssh_connection(ip: str, port: int, timeout: float = 3.0) -> bool:
    """Verifies if the SSH port on the target host is reachable."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def simulate_ssh_attempt(target_ip: str, port: int, username: str, password: str, timeout: float = 3.0) -> dict:
    """Attempts a single SSH login to trigger authentication failure logs on target."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    start_time = time.time()
    success = False
    error_msg = ""

    try:
        client.connect(
            hostname=target_ip,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            auth_timeout=timeout,
            banner_timeout=timeout,
            allow_agent=False,
            look_for_keys=False
        )
        success = True
    except paramiko.AuthenticationException:
        error_msg = "Authentication Failed (Expected)"
    except paramiko.SSHException as e:
        error_msg = f"SSH Protocol Error: {e}"
    except (socket.timeout, TimeoutError):
        error_msg = "Connection Timeout"
    except Exception as e:
        error_msg = f"Connection Refused / Error: {e}"
    finally:
        client.close()

    elapsed = round(time.time() - start_time, 3)

    return {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "target": f"{target_ip}:{port}",
        "user": username,
        "password": password,
        "success": success,
        "error": error_msg,
        "latency_sec": elapsed
    }


def main():
    parser = argparse.ArgumentParser(
        description="🛡️ LSMP Security Test: SSH Brute-Force Simulation Tool for SIEM & AI Benchmark."
    )
    parser.add_argument("-t", "--target", type=str, required=True, help="Target Host IP address (e.g. 192.168.1.15)")
    parser.add_argument("-p", "--port", type=int, default=22, help="SSH Port (default: 22)")
    parser.add_argument("-c", "--count", type=int, default=20, help="Total login attempts to simulate (default: 20)")
    parser.add_argument("-d", "--delay", type=float, default=0.3, help="Delay between attempts in seconds (default: 0.3)")
    parser.add_argument("-u", "--username", type=str, default=None, help="Target specific username (optional)")

    args = parser.parse_args()

    print("=" * 70)
    print("🛡️ LSMP SECURITY TESTING - SSH BRUTE FORCE SIMULATION")
    print(f"🎯 Target Host IP : {args.target}:{args.port}")
    print(f"🔢 Total Attempts  : {args.count}")
    print(f"⏱️ Delay Between   : {args.delay} sec")
    print("=" * 70)

    print("\n🔍 Checking SSH Port Reachability...")
    if not test_ssh_connection(args.target, args.port):
        print(f"❌ Error: Cannot connect to SSH port {args.port} on {args.target}.")
        print("💡 Hint: Ensure SSH service (sshd) is running on the target and firewall permits traffic.")
        sys.exit(1)
    
    print("✅ SSH Port is reachable. Starting synthetic brute-force simulation...\n")

    failed_count = 0
    success_count = 0

    for i in range(1, args.count + 1):
        user = args.username if args.username else COMMON_USERNAMES[(i - 1) % len(COMMON_USERNAMES)]
        passwd = COMMON_PASSWORDS[(i - 1) % len(COMMON_PASSWORDS)]

        result = simulate_ssh_attempt(args.target, args.port, user, passwd)

        if result["success"]:
            success_count += 1
            print(f"[{result['timestamp']}] #{i:03d} | USER: {user:10s} | PASS: {passwd:12s} | 🟢 LOGIN SUCCESSFUL")
        else:
            failed_count += 1
            print(f"[{result['timestamp']}] #{i:03d} | USER: {user:10s} | PASS: {passwd:12s} | 🔴 FAILED ({result['error']})")

        time.sleep(args.delay)

    print("\n" + "=" * 70)
    print("📊 SIMULATION SUMMARY")
    print(f"🔴 Total Failed Attempts  : {failed_count} (Triggers Wazuh Rule 5716/5720)")
    print(f"🟢 Total Successful Logins : {success_count}")
    print("=" * 70)
    print("💡 Next Step: Check Wazuh Dashboard or Grafana 'lsmp_db' risk_score table to verify AI detection!")


if __name__ == "__main__":
    main()
