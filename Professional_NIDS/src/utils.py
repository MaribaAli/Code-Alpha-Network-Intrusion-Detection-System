"""
utils.py
Small helper functions shared across the NIDS project:
 - timestamp formatting
 - listing network interfaces (Windows-friendly)
 - a SAFE, opt-in Windows Firewall blocking helper (defensive-only)
 - severity -> color mapping for the GUI
"""

import time
import platform
import subprocess

# Accent color presets used by the GUI's theme switcher.
ACCENT_PRESETS = {
    "Teal": "#00d4aa",
    "Blue": "#3b82f6",
    "Purple": "#8b5cf6",
    "Amber": "#f59e0b",
    "Rose": "#f43f5e",
}


def beep_alert():
    """
    Best-effort audible alert for Critical severity detections.
    Uses the built-in winsound module on Windows; silently does nothing on
    other platforms or if anything goes wrong, so this is always safe to call.
    """
    try:
        if platform.system() == "Windows":
            import winsound
            winsound.Beep(1200, 180)
            winsound.Beep(1500, 180)
        else:
            print("\a", end="", flush=True)  # terminal bell fallback
    except Exception:
        pass


def format_timestamp(ts):
    """Convert an epoch timestamp into a readable local date/time string."""
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except Exception:
        return str(ts)


def get_friendly_interfaces():
    """
    Return a list of (display_name, iface_id) tuples describing the network
    interfaces available for packet capture. Falls back gracefully if the
    Windows-specific interface list is unavailable (e.g. non-Windows OS or
    Npcap not installed).
    """
    interfaces = []

    if platform.system() == "Windows":
        try:
            from scapy.arch.windows import get_windows_if_list
            for iface in get_windows_if_list():
                name = iface.get("name") or iface.get("guid") or "Unknown"
                description = iface.get("description", name)
                display = f"{description} [{name}]"
                interfaces.append((display, name))
            if interfaces:
                return interfaces
        except Exception:
            pass

    # Generic fallback (works on Windows/Linux/macOS if scapy is importable)
    try:
        from scapy.all import get_if_list
        for iface in get_if_list():
            interfaces.append((iface, iface))
    except Exception:
        pass

    return interfaces


def severity_color(severity):
    """Map a severity label to a hex color used throughout the GUI."""
    colors = {
        "Low": "#2ecc71",
        "Medium": "#f1c40f",
        "High": "#e67e22",
        "Critical": "#e74c3c",
    }
    return colors.get(severity, "#95a5a6")


def block_ip_windows(ip_address):
    """
    DEFENSIVE-ONLY helper.

    Adds Windows Firewall rules that block inbound AND outbound traffic
    to/from the given IP address on the LOCAL machine only. This does not
    send any packets to the target, scan it, or perform any action against
    a remote system - it only changes the local firewall configuration.

    This function is never called automatically. It is only reachable from
    the GUI's "Block Source" action, which is disabled by default and must
    be explicitly enabled by the user in Settings, plus a manual
    confirmation dialog before every use.

    Requires the application to be run as Administrator on Windows.
    Returns (success: bool, message: str).
    """
    if platform.system() != "Windows":
        return False, "Local firewall blocking is only implemented for Windows in this build."

    rule_in = f"NIDS_Block_{ip_address}_IN"
    rule_out = f"NIDS_Block_{ip_address}_OUT"

    try:
        cmd_in = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_in}", "dir=in", "action=block",
            f"remoteip={ip_address}",
        ]
        cmd_out = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_out}", "dir=out", "action=block",
            f"remoteip={ip_address}",
        ]
        subprocess.run(cmd_in, check=True, capture_output=True, timeout=10)
        subprocess.run(cmd_out, check=True, capture_output=True, timeout=10)
        return True, f"Added local firewall rules blocking {ip_address} ({rule_in}, {rule_out})."
    except FileNotFoundError:
        return False, "'netsh' was not found. This feature requires Windows."
    except subprocess.CalledProcessError as e:
        return False, (
            "Failed to add the firewall rule. Make sure the application is "
            f"running as Administrator. Details: {e}"
        )
    except Exception as e:
        return False, f"Unexpected error while adding firewall rule: {e}"


def get_firewall_state():
    """
    DEFENSIVE-ONLY helper.

    Reads the CURRENT on/off state of the local machine's own Windows
    Firewall (all profiles: Domain / Private / Public) by calling
    'netsh advfirewall show allprofiles state'. This is read-only - it
    never changes anything.

    Returns one of "ON", "OFF", "MIXED" (profiles disagree), or "UNKNOWN"
    (non-Windows OS, or netsh output could not be parsed / command failed).
    """
    if platform.system() != "Windows":
        return "UNKNOWN"

    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles", "state"],
            check=True, capture_output=True, timeout=10, text=True,
        )
        states = set()
        for line in result.stdout.splitlines():
            line = line.strip().lower()
            if line.startswith("state"):
                if "on" in line:
                    states.add("ON")
                elif "off" in line:
                    states.add("OFF")
        if not states:
            return "UNKNOWN"
        if len(states) == 1:
            return next(iter(states))
        return "MIXED"
    except Exception:
        return "UNKNOWN"


def set_firewall_state(enable):
    """
    DEFENSIVE-ONLY helper.

    Directly turns the LOCAL machine's own Windows Firewall ON or OFF for
    all profiles (Domain / Private / Public) via
    'netsh advfirewall set allprofiles state on|off'.

    This only ever touches the firewall configuration of the machine the
    NIDS app is running on - it never contacts, scans, or sends any
    traffic to another host. It is only reachable from an explicit,
    user-clicked GUI action that requires confirmation every time, and is
    never called automatically by the detector or simulator.

    Requires the application to be run as Administrator on Windows.
    Returns (success: bool, message: str).
    """
    if platform.system() != "Windows":
        return False, "Direct firewall on/off control is only implemented for Windows in this build."

    state = "on" if enable else "off"
    try:
        subprocess.run(
            ["netsh", "advfirewall", "set", "allprofiles", "state", state],
            check=True, capture_output=True, timeout=10,
        )
        return True, f"Windows Firewall turned {state.upper()} for this machine (all profiles)."
    except FileNotFoundError:
        return False, "'netsh' was not found. This feature requires Windows."
    except subprocess.CalledProcessError as e:
        return False, (
            "Failed to change the firewall state. Make sure the application is "
            f"running as Administrator. Details: {e}"
        )
    except Exception as e:
        return False, f"Unexpected error while changing firewall state: {e}"
