#!/usr/bin/env python3
import os
import sys
import signal
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# paths of attack scripts
ARP_SCRIPT = ROOT / "arp" / "arp_spoofer.py"
DNS_SCRIPT = ROOT / "dns" / "dns_spoofer.py"
SSL_SCRIPT = ROOT / "ssl" / "ssl_stripper.py"

# venv python (linux/mac vs windows)
SSL_VENV_PY_LINUX = Path("/home/attacker-mallory/mitm-env/bin/python3")

def ssl_python():
    return str(SSL_VENV_PY_LINUX)

    # fallback: run with current python, but warn
    print("[!] Warning: SSL venv python not found, falling back to current interpreter.")
    return sys.executable

MODES = {
    "1": ("ARP only", [("arp", sys.executable, ARP_SCRIPT)]),
    "2": ("ARP + DNS", [
        ("arp", sys.executable, ARP_SCRIPT),
        ("dns", sys.executable, DNS_SCRIPT),
    ]),
    "3": ("ARP + SSLStrip", [
        ("arp", sys.executable, ARP_SCRIPT),
        ("sslstrip", ssl_python(), SSL_SCRIPT),
    ]),
}

def check_files():
    missing = []
    for _, (_, progs) in MODES.items():
        for name, py, script in progs:
            if not Path(script).exists():
                missing.append(f"{name}: {script}")
    if missing:
        print("Missing scripts:")
        for m in missing:
            print("  -", m)
        sys.exit(1)

def start_process(python_exec: str, script_path: Path):
    cmd = [python_exec, str(script_path)]
    return subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        preexec_fn=os.setsid if os.name != "nt" else None,  # separate process group (posix)
    )

def stop_all(procs):
    print("\nStopping processes...")
    for p in procs:
        if p.poll() is None:
            try:
                if os.name != "nt":
                    os.killpg(os.getpgid(p.pid), signal.SIGTERM)
                else:
                    p.terminate()
            except Exception as e:
                print(f"[!] Could not terminate PID={p.pid}: {e}")

    # hard kill if needed
    for p in procs:
        try:
            p.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                if os.name != "nt":
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                else:
                    p.kill()
            except Exception:
                pass
    print("Done.")

def menu():
    print("=== Attack Launcher ===")
    for k, (label, progs) in MODES.items():
        print(f"{k}) {label}")
    print("q) quit")
    while True:
        c = input("Choose a mode: ").strip().lower()
        if c in MODES or c == "q":
            return c
        print("Invalid choice.")

def main():
    check_files()
    choice = menu()
    if choice == "q":
        return

    label, program_list = MODES[choice]
    print(f"\nSelected: {label}")

    procs = []
    try:
        for name, py, script in program_list:
            p = start_process(py, script)
            procs.append(p)
            print(f"Started {name:8} PID={p.pid}  ({py})")

        print("\nPress Ctrl+C to stop everything.\n")
        while True:
            # if any child exits, stop everything
            for p in procs:
                rc = p.poll()
                if rc is not None:
                    print(f"\nProcess PID={p.pid} exited with code {rc}. Stopping all.")
                    raise KeyboardInterrupt
            signal.pause()
    except KeyboardInterrupt:
        stop_all(procs)

if __name__ == "__main__":
    if os.name == "nt":
        import time
        signal.pause = lambda: time.sleep(1)
    main()

