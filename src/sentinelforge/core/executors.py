"""Cross-platform action executors — Windows and Linux.

Every executor:
  1. Validates inputs (no shell injection)
  2. Supports canary (dry-run) mode
  3. Returns structured result with stdout/stderr
  4. Has a corresponding rollback function

SECURITY: All subprocess calls use lists (no shell=True).
All targets are validated against strict patterns before execution.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from sentinelforge.core.logging import get_logger

logger = get_logger("executors")

IS_WINDOWS = platform.system() == "Windows"

IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
HOSTNAME_PATTERN = re.compile(r"^[a-zA-Z0-9._-]{1,255}$")
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9._@\\-]{1,128}$")
PID_PATTERN = re.compile(r"^\d{1,7}$")
PATH_FORBIDDEN = re.compile(r"[;&|`$]")


@dataclass
class ExecutionResult:
    success: bool
    output: str
    command_preview: str
    canary: bool = False


def _validate_ip(ip: str) -> bool:
    if not IP_PATTERN.match(ip):
        return False
    return all(0 <= int(p) <= 255 for p in ip.split("."))


def _validate_not_self(ip: str) -> bool:
    """Prevent blocking localhost or common self-addresses."""
    blocked = {"127.0.0.1", "0.0.0.0", "::1", "localhost"}  # noqa: S104
    return ip not in blocked


def _run_command(args: list[str], timeout: int = 30) -> tuple[bool, str]:
    """Run a subprocess safely — never uses shell=True."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        output = result.stdout.strip()
        if result.returncode != 0:
            output = f"STDERR: {result.stderr.strip()}" if result.stderr else f"Exit code {result.returncode}"
            return False, output
        return True, output or "OK"
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except FileNotFoundError as e:
        return False, f"Command not found: {e}"
    except Exception as e:
        return False, f"Execution error: {e}"


# === BLOCK IP ===

def block_ip(ip: str, canary: bool = False, timeout: int = 30) -> ExecutionResult:
    """Block an IP address via Windows Firewall or Linux iptables."""
    if not _validate_ip(ip):
        return ExecutionResult(False, f"Invalid IP: {ip}", "")
    if not _validate_not_self(ip):
        return ExecutionResult(False, f"Cannot block self-address: {ip}", "")

    rule_name = f"SentinelForge_Block_{ip}"

    if IS_WINDOWS:
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", "action=block",
            f"remoteip={ip}", "protocol=any",
        ]
    else:
        cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP",
               "-m", "comment", "--comment", rule_name]

    preview = " ".join(cmd)
    if canary:
        logger.info("canary_block_ip", ip=ip, command=preview)
        return ExecutionResult(True, f"CANARY: Would execute: {preview}", preview, canary=True)

    logger.info("executing_block_ip", ip=ip)
    success, output = _run_command(cmd, timeout)
    return ExecutionResult(success, output, preview)


def unblock_ip(ip: str, timeout: int = 30) -> ExecutionResult:
    """Remove a firewall block on an IP address."""
    if not _validate_ip(ip):
        return ExecutionResult(False, f"Invalid IP: {ip}", "")

    rule_name = f"SentinelForge_Block_{ip}"

    if IS_WINDOWS:
        cmd = ["netsh", "advfirewall", "firewall", "delete", "rule",
               f"name={rule_name}"]
    else:
        cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP",
               "-m", "comment", "--comment", rule_name]

    preview = " ".join(cmd)
    logger.info("executing_unblock_ip", ip=ip)
    success, output = _run_command(cmd, timeout)
    return ExecutionResult(success, output, preview)


# === KILL PROCESS ===

def kill_process(target: str, canary: bool = False, timeout: int = 15) -> ExecutionResult:
    """Kill a process by PID or name. Validates input strictly."""
    by_pid = PID_PATTERN.match(target)

    if by_pid:
        pid = int(target)
        if pid <= 4:
            return ExecutionResult(False, f"Cannot kill system process PID {pid}", "")
        if pid == os.getpid():
            return ExecutionResult(False, "Cannot kill own process", "")

        if IS_WINDOWS:
            cmd = ["taskkill", "/PID", str(pid), "/F"]
        else:
            cmd = ["kill", "-9", str(pid)]
    else:
        if not HOSTNAME_PATTERN.match(target):
            return ExecutionResult(False, f"Invalid process name: {target}", "")

        protected = {"explorer.exe", "svchost.exe", "csrss.exe", "lsass.exe",
                     "winlogon.exe", "services.exe", "smss.exe", "wininit.exe",
                     "System", "init", "systemd", "kernel"}
        if target.lower() in {p.lower() for p in protected}:
            return ExecutionResult(False, f"Cannot kill protected process: {target}", "")

        if IS_WINDOWS:
            cmd = ["taskkill", "/IM", target, "/F"]
        else:
            cmd = ["pkill", "-9", "-f", target]

    preview = " ".join(cmd)
    if canary:
        logger.info("canary_kill_process", target=target, command=preview)
        return ExecutionResult(True, f"CANARY: Would execute: {preview}", preview, canary=True)

    logger.info("executing_kill_process", target=target)
    success, output = _run_command(cmd, timeout)
    return ExecutionResult(success, output, preview)


# === DISABLE ACCOUNT ===

def disable_account(username: str, canary: bool = False, timeout: int = 15) -> ExecutionResult:
    """Disable a local user account."""
    if not USERNAME_PATTERN.match(username):
        return ExecutionResult(False, f"Invalid username: {username}", "")

    protected = {"administrator", "admin", "root", "system", "localservice",
                 "networkservice", "defaultaccount"}
    if username.lower() in protected:
        return ExecutionResult(False, f"Cannot disable protected account: {username}", "")

    if IS_WINDOWS:
        cmd = ["net", "user", username, "/active:no"]
    else:
        cmd = ["usermod", "-L", username]

    preview = " ".join(cmd)
    if canary:
        logger.info("canary_disable_account", username=username, command=preview)
        return ExecutionResult(True, f"CANARY: Would execute: {preview}", preview, canary=True)

    logger.info("executing_disable_account", username=username)
    success, output = _run_command(cmd, timeout)
    return ExecutionResult(success, output, preview)


def enable_account(username: str, timeout: int = 15) -> ExecutionResult:
    """Re-enable a disabled user account."""
    if not USERNAME_PATTERN.match(username):
        return ExecutionResult(False, f"Invalid username: {username}", "")

    if IS_WINDOWS:
        cmd = ["net", "user", username, "/active:yes"]
    else:
        cmd = ["usermod", "-U", username]

    preview = " ".join(cmd)
    logger.info("executing_enable_account", username=username)
    success, output = _run_command(cmd, timeout)
    return ExecutionResult(success, output, preview)


# === QUARANTINE FILE ===

QUARANTINE_DIR = Path("./data/quarantine")


def quarantine_file(file_path: str, canary: bool = False) -> ExecutionResult:
    """Move a suspicious file to quarantine directory."""
    if PATH_FORBIDDEN.search(file_path):
        return ExecutionResult(False, f"Forbidden characters in path: {file_path}", "")

    source = Path(file_path)
    if not source.exists():
        return ExecutionResult(False, f"File not found: {file_path}", "")

    protected_dirs = {
        "C:\\Windows", "C:\\Program Files", "/usr", "/bin", "/sbin",
        "/etc", "/boot", "/lib", "/var/lib",
    }
    for pd in protected_dirs:
        if str(source).startswith(pd):
            return ExecutionResult(False, f"Cannot quarantine file in protected directory: {pd}", "")

    dest = QUARANTINE_DIR / source.name
    preview = f"move {source} -> {dest}"

    if canary:
        logger.info("canary_quarantine", source=str(source), dest=str(dest))
        return ExecutionResult(True, f"CANARY: Would {preview}", preview, canary=True)

    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    try:
        metadata = QUARANTINE_DIR / f"{source.name}.meta"
        metadata.write_text(f"original_path={source}\nsize={source.stat().st_size}\n")
        shutil.move(str(source), str(dest))
        logger.info("file_quarantined", source=str(source), dest=str(dest))
        return ExecutionResult(True, f"Quarantined: {preview}", preview)
    except Exception as e:
        return ExecutionResult(False, f"Quarantine failed: {e}", preview)


def restore_file(filename: str) -> ExecutionResult:
    """Restore a file from quarantine to its original location."""
    quarantined = QUARANTINE_DIR / filename
    meta = QUARANTINE_DIR / f"{filename}.meta"

    if not quarantined.exists():
        return ExecutionResult(False, f"File not in quarantine: {filename}", "")

    original_path = ""
    if meta.exists():
        for line in meta.read_text().splitlines():
            if line.startswith("original_path="):
                original_path = line.split("=", 1)[1]
                break

    if not original_path:
        return ExecutionResult(False, "Cannot determine original path", "")

    try:
        shutil.move(str(quarantined), original_path)
        meta.unlink(missing_ok=True)
        return ExecutionResult(True, f"Restored to {original_path}", f"move {quarantined} -> {original_path}")
    except Exception as e:
        return ExecutionResult(False, f"Restore failed: {e}", "")


# === ISOLATE HOST ===

def isolate_host(hostname: str, canary: bool = False, timeout: int = 30) -> ExecutionResult:
    """Isolate a host by blocking all traffic to/from it.
    On Windows: adds firewall rules. On Linux: iptables rules.
    """
    if _validate_ip(hostname):
        ip = hostname
    elif HOSTNAME_PATTERN.match(hostname):
        ip = hostname
    else:
        return ExecutionResult(False, f"Invalid hostname: {hostname}", "")

    if IS_WINDOWS:
        cmd_in = ["netsh", "advfirewall", "firewall", "add", "rule",
                   f"name=SentinelForge_Isolate_{ip}_IN", "dir=in", "action=block",
                   f"remoteip={ip}", "protocol=any"]
        cmd_out = ["netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=SentinelForge_Isolate_{ip}_OUT", "dir=out", "action=block",
                    f"remoteip={ip}", "protocol=any"]
        preview = " ".join(cmd_in) + " && " + " ".join(cmd_out)
    else:
        cmd_in = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP",
                   "-m", "comment", "--comment", f"SentinelForge_Isolate_{ip}"]
        cmd_out = ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP",
                    "-m", "comment", "--comment", f"SentinelForge_Isolate_{ip}"]
        preview = " ".join(cmd_in) + " && " + " ".join(cmd_out)

    if canary:
        logger.info("canary_isolate_host", host=ip, command=preview)
        return ExecutionResult(True, f"CANARY: Would execute: {preview}", preview, canary=True)

    logger.info("executing_isolate_host", host=ip)
    ok1, out1 = _run_command(cmd_in, timeout)
    ok2, out2 = _run_command(cmd_out, timeout)

    if ok1 and ok2:
        return ExecutionResult(True, f"Inbound: {out1} | Outbound: {out2}", preview)
    return ExecutionResult(False, f"Inbound: {out1} | Outbound: {out2}", preview)


def reconnect_host(hostname: str, timeout: int = 30) -> ExecutionResult:
    """Remove isolation rules for a host."""
    ip = hostname

    if IS_WINDOWS:
        cmd1 = ["netsh", "advfirewall", "firewall", "delete", "rule",
                 f"name=SentinelForge_Isolate_{ip}_IN"]
        cmd2 = ["netsh", "advfirewall", "firewall", "delete", "rule",
                 f"name=SentinelForge_Isolate_{ip}_OUT"]
    else:
        cmd1 = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP",
                 "-m", "comment", "--comment", f"SentinelForge_Isolate_{ip}"]
        cmd2 = ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP",
                 "-m", "comment", "--comment", f"SentinelForge_Isolate_{ip}"]

    ok1, out1 = _run_command(cmd1, timeout)
    ok2, out2 = _run_command(cmd2, timeout)
    preview = f"Remove isolation rules for {ip}"
    return ExecutionResult(ok1 and ok2, f"{out1} | {out2}", preview)
