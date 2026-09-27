"""
safe_attack_demo.py
A SAFE demonstration script for the Professional NIDS.

WHAT THIS DOES
--------------
It generates harmless traffic FROM your machine TO your own machine only,
so you can watch the NIDS detect it in real time. It never contacts any
other computer, never exploits anything, and never sends malicious
payloads - it just opens ordinary TCP connection attempts (the same kind
your web browser makes constantly) at a rate high enough to cross the
detection thresholds in config.json.

HOW TO USE
----------
1. Start the Professional NIDS (python main.py) and click Start Monitoring.
2. In a SEPARATE terminal, run this script:
       python safe_attack_demo.py
3. Watch the Alerts page in the NIDS - you should see alerts appear within
   a few seconds.
4. Stop the script any time with Ctrl+C. It cleans up after itself and
   leaves nothing running or installed on your system.

WHY THIS IS SAFE
----------------
- A hard-coded safety check (see `_assert_target_is_local`) refuses to run
  against anything except 127.0.0.1 or an IP address that belongs to this
  same machine. It is not possible to point this script at another
  computer without deliberately rewriting the safety check.
- It only uses Python's standard `socket` module to open and close plain
  TCP connections, and the standard OS `ping` command for ICMP. No raw
  packet crafting, no payloads, no privilege escalation, no persistence.
- Everything it does is indistinguishable from a slightly-too-fast burst
  of ordinary network activity - the same kind of traffic your own
  computer generates every day.
"""

import socket
import subprocess
import sys
import time
import platform

TARGET = "127.0.0.1"  # Change to your own machine's LAN IP if 127.0.0.1
                       # traffic doesn't show up in the NIDS (loopback
                       # capture support varies by Windows/Npcap version).


def _assert_target_is_local(target):
    """Refuse to run unless the target is this machine. This is the
    safety guard that keeps this script from ever being pointed at
    someone else's computer."""
    local_ips = {"127.0.0.1", "localhost", "::1"}
    try:
        hostname = socket.gethostname()
        local_ips.add(socket.gethostbyname(hostname))
        for info in socket.getaddrinfo(hostname, None):
            local_ips.add(info[4][0])
    except Exception:
        pass

    if target not in local_ips:
        print(f"REFUSING TO RUN: '{target}' does not appear to be this machine.")
        print("This script only ever targets your own computer. Exiting.")
        sys.exit(1)


def demo_port_scan(target, start_port=8000, num_ports=25, delay=0.02):
    """
    Rapidly attempts TCP connections to many different ports on the
    target. Almost all will simply be refused (nothing is listening) -
    that's expected and harmless. This is enough for the NIDS's Port Scan
    rule to see many distinct destination ports from one source and alert.
    """
    print(f"\n[1] Simulating a port scan against {target} "
          f"(ports {start_port}-{start_port + num_ports})...")
    for port in range(start_port, start_port + num_ports):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        try:
            s.connect_ex((target, port))  # connect_ex never raises on refusal
        except Exception:
            pass
        finally:
            s.close()
        time.sleep(delay)
    print("    Done. Check the NIDS Alerts page for 'Port Scan'.")


def demo_repeated_connections(target, port=8080, count=60, delay=0.02):
    """
    Rapidly opens and closes many TCP connections to the SAME port. Each
    attempt sends one ordinary SYN packet - the same first step every web
    request makes. This exercises the NIDS's TCP SYN Flood and Repeated
    Connection Attempts rules.
    """
    print(f"\n[2] Simulating rapid repeated connections to {target}:{port} "
          f"({count} attempts)...")
    for _ in range(count):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        try:
            s.connect_ex((target, port))
        except Exception:
            pass
        finally:
            s.close()
        time.sleep(delay)
    print("    Done. Check the NIDS Alerts page for 'TCP SYN Flood' / "
          "'Repeated Connection Attempts'.")


def demo_suspicious_port(target, port=3389):
    """A single connection attempt to a commonly-abused port (RDP by
    default). One attempt is enough - the NIDS flags this immediately."""
    print(f"\n[3] Simulating a single connection attempt to suspicious port "
          f"{target}:{port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)
    try:
        s.connect_ex((target, port))
    except Exception:
        pass
    finally:
        s.close()
    print("    Done. Check the NIDS Alerts page for 'Suspicious Port Access'.")


def demo_icmp_flood(target, count=60):
    """
    Uses the operating system's own `ping` command to send a burst of
    ICMP echo requests to the target. This relies on the OS's built-in,
    already-privileged ping implementation rather than crafting raw
    packets ourselves.
    """
    print(f"\n[4] Simulating an ICMP flood ({count} pings) against {target}...")
    if platform.system() == "Windows":
        cmd = ["ping", "-n", str(count), "-w", "200", target]
    else:
        cmd = ["ping", "-c", str(count), "-i", "0.05", target]
    try:
        subprocess.run(cmd, capture_output=True, timeout=count * 0.5 + 10)
    except Exception as e:
        print(f"    Could not run ping ({e}). Skipping this step.")
        return
    print("    Done. Check the NIDS Alerts page for 'ICMP Flood'.")


def main():
    _assert_target_is_local(TARGET)

    print("=" * 60)
    print(" Professional NIDS - SAFE Attack Simulation Demo")
    print(f" Target: {TARGET}  (verified to be this machine only)")
    print("=" * 60)
    print("Make sure the NIDS is running and 'Start Monitoring' is active,")
    print("then watch the Alerts page while this script runs.\n")

    try:
        demo_port_scan(TARGET)
        demo_repeated_connections(TARGET)
        demo_suspicious_port(TARGET)
        demo_icmp_flood(TARGET)
    except KeyboardInterrupt:
        print("\nStopped by user. No changes were made to your system.")
        return

    print("\nAll demo steps complete. Nothing was installed, modified, or")
    print("left running on your system - this script only opened and")
    print("closed ordinary network connections to your own machine.")


if __name__ == "__main__":
    main()
