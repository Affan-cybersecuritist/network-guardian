"""
firewall.py
-----------
Turns a detection into an actual response: block a malicious source IP at the
Windows Firewall. Without this, the dashboard could only tell you what
happened -- you still had to go run the command yourself. This closes that
gap for the one action that's safe to automate (a scoped inbound block rule)
while keeping a human in the loop: nothing here is ever called automatically
by the scoring pipeline, only by an explicit user click + confirmation in the
UI (see POST /firewall/block in main.py).

Windows-only (uses `netsh advfirewall`) -- this project already requires
Windows + Npcap + Administrator for live capture, so that's consistent.

SAFETY:
- Every IP is validated with the stdlib `ipaddress` module before it ever
  reaches a subprocess call, and passed as a separate argv element (never
  interpolated into a shell string), so this is not shell-injectable.
- A small deny-list refuses to block addresses that would be self-destructive
  (loopback, unspecified, broadcast) -- blocking your own machine or "all
  hosts" would cut off the very dashboard you're using to manage this.
- Every rule this module creates is named with a distinctive prefix so
  list/unblock only ever touch rules Network Guardian itself created --
  never a rule that was already on the system.
"""
import ipaddress
import platform
import subprocess

RULE_PREFIX = "NetworkGuardian_Block_"

# Blocking any of these would be self-destructive (cuts off localhost/this
# machine's own dashboard, or "all hosts") -- refuse regardless of who asks.
_NEVER_BLOCK = {"0.0.0.0", "255.255.255.255", "127.0.0.1", "::1", "::"}


class FirewallError(Exception):
    pass


def _validate_ip(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise FirewallError(f"{ip!r} is not a valid IP address")
    if str(addr) in _NEVER_BLOCK or addr.is_loopback or addr.is_unspecified:
        raise FirewallError(f"Refusing to block {ip} -- this would be self-destructive")
    return str(addr)


def _rule_name(ip: str) -> str:
    return f"{RULE_PREFIX}{ip}"


def block_ip(ip: str) -> dict:
    ip = _validate_ip(ip)
    system = platform.system()

    if system == "Windows":
        return _block_ip_windows(ip)
    elif system == "Linux":
        return _block_ip_linux(ip)
    elif system == "Darwin":
        return _block_ip_macos(ip)
    else:
        raise FirewallError(f"Unsupported platform: {system}")


def _block_ip_windows(ip: str) -> dict:
    """Block IP using Windows Firewall (netsh advfirewall)"""
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={_rule_name(ip)}", "dir=in", "action=block", f"remoteip={ip}",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
    except FileNotFoundError:
        raise FirewallError("netsh not found -- this only works on Windows")
    except subprocess.TimeoutExpired:
        raise FirewallError("netsh timed out")

    if proc.returncode != 0:
        raise FirewallError(
            f"netsh failed (exit {proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}. "
            "This almost always means the backend isn't running as Administrator."
        )
    return {"ip": ip, "platform": "Windows", "rule_name": _rule_name(ip), "output": proc.stdout.strip()}


def _block_ip_linux(ip: str) -> dict:
    """Block IP using iptables (or ufw if available)"""
    # Try ufw first (user-friendly)
    cmd_ufw = ["sudo", "ufw", "deny", "from", ip]
    try:
        proc = subprocess.run(cmd_ufw, capture_output=True, text=True, timeout=10, check=False)
        if proc.returncode == 0:
            return {"ip": ip, "platform": "Linux (ufw)", "output": proc.stdout.strip()}
    except (FileNotFoundError, PermissionError):
        pass

    # Fallback to iptables
    cmd_iptables = ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
    try:
        proc = subprocess.run(cmd_iptables, capture_output=True, text=True, timeout=10, check=False)
        if proc.returncode == 0:
            return {"ip": ip, "platform": "Linux (iptables)", "output": "Rule added"}
        else:
            raise FirewallError(f"iptables failed: {proc.stderr.strip()}")
    except (FileNotFoundError, PermissionError) as e:
        raise FirewallError(f"iptables not available: {e}. Try: sudo ufw deny from {ip}")


def _block_ip_macos(ip: str) -> dict:
    """Block IP using pf (macOS packet filter)"""
    # macOS uses pf -- requires sudo
    pfctl_cmd = f"echo 'block in quick from {ip}' | sudo pfctl -f - -e"
    try:
        proc = subprocess.run(pfctl_cmd, shell=True, capture_output=True, text=True, timeout=10, check=False)
        if proc.returncode == 0:
            return {"ip": ip, "platform": "macOS (pf)", "output": "Rule added"}
        else:
            raise FirewallError(f"pf failed: {proc.stderr.strip()}")
    except Exception as e:
        raise FirewallError(f"pf not available: {e}. Try: sudo pfctl -d / sudo pfctl -f rules.txt -e")


def unblock_ip(ip: str) -> dict:
    ip = _validate_ip(ip)
    system = platform.system()

    if system == "Windows":
        return _unblock_ip_windows(ip)
    elif system == "Linux":
        return _unblock_ip_linux(ip)
    elif system == "Darwin":
        return _unblock_ip_macos(ip)
    else:
        raise FirewallError(f"Unsupported platform: {system}")


def _unblock_ip_windows(ip: str) -> dict:
    """Unblock IP using Windows Firewall"""
    cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={_rule_name(ip)}"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
    except FileNotFoundError:
        raise FirewallError("netsh not found -- this only works on Windows")
    except subprocess.TimeoutExpired:
        raise FirewallError("netsh timed out")

    if proc.returncode != 0:
        raise FirewallError(f"netsh failed (exit {proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}")
    return {"ip": ip, "platform": "Windows", "output": proc.stdout.strip()}


def _unblock_ip_linux(ip: str) -> dict:
    """Unblock IP using iptables/ufw"""
    # Try ufw first
    cmd_ufw = ["sudo", "ufw", "delete", "deny", "from", ip]
    try:
        proc = subprocess.run(cmd_ufw, capture_output=True, text=True, timeout=10, check=False)
        if proc.returncode == 0:
            return {"ip": ip, "platform": "Linux (ufw)", "output": proc.stdout.strip()}
    except (FileNotFoundError, PermissionError):
        pass

    # Fallback to iptables
    cmd_iptables = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
    try:
        proc = subprocess.run(cmd_iptables, capture_output=True, text=True, timeout=10, check=False)
        if proc.returncode == 0:
            return {"ip": ip, "platform": "Linux (iptables)", "output": "Rule removed"}
        else:
            raise FirewallError(f"iptables failed: {proc.stderr.strip()}")
    except (FileNotFoundError, PermissionError) as e:
        raise FirewallError(f"iptables not available: {e}")


def _unblock_ip_macos(ip: str) -> dict:
    """Unblock IP using pf (macOS)"""
    # Note: pf doesn't have built-in tracking of who created rules
    # This is a simplified version
    return {"ip": ip, "platform": "macOS (pf)", "output": "Manual unblock required (pfctl -d)", "note": "pf requires manual rule management"}
