"""
Curated admin task library.

Only NAMED tasks are allowed — no arbitrary commands, ever.
Each task has a fixed argv and a human-readable description.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class AdminTask:
    name: str
    argv: tuple[str, ...]
    description: str


_TASKS: dict[str, AdminTask] = {}


def _register(task: AdminTask):
    _TASKS[task.name] = task


# --- Network ---
_register(AdminTask(
    name="flush_dns",
    argv=("ipconfig", "/flushdns"),
    description="Flush the DNS resolver cache.",
))
_register(AdminTask(
    name="release_ip",
    argv=("ipconfig", "/release"),
    description="Release the current DHCP IP address.",
))
_register(AdminTask(
    name="renew_ip",
    argv=("ipconfig", "/renew"),
    description="Renew the DHCP IP address.",
))
_register(AdminTask(
    name="reset_winsock",
    argv=("netsh", "winsock", "reset"),
    description="Reset the Winsock catalog (fixes many network errors).",
))
_register(AdminTask(
    name="reset_tcpip",
    argv=("netsh", "int", "ip", "reset"),
    description="Reset the TCP/IP stack.",
))
_register(AdminTask(
    name="show_network_adapters",
    argv=("netsh", "interface", "show", "interface"),
    description="List all network adapters and their states.",
))

# --- System health ---
_register(AdminTask(
    name="sfc_scan",
    argv=("sfc", "/scannow"),
    description="Scan system files for corruption (takes several minutes).",
))
_register(AdminTask(
    name="dism_check_health",
    argv=("dism", "/online", "/cleanup-image", "/checkhealth"),
    description="Check Windows component store health.",
))
_register(AdminTask(
    name="chkdsk_scan",
    argv=("chkdsk", "/scan"),
    description="Read-only disk integrity scan (no repairs).",
))

# --- Diagnostics ---
_register(AdminTask(
    name="battery_report",
    argv=("powercfg", "/batteryreport"),
    description="Generate an HTML battery report to %USERPROFILE%.",
))
_register(AdminTask(
    name="energy_report",
    argv=("powercfg", "/energy"),
    description="Generate a 60-second energy efficiency report.",
))
_register(AdminTask(
    name="view_firewall_status",
    argv=("netsh", "advfirewall", "show", "allprofiles"),
    description="Show firewall status for all profiles (read-only).",
))
_register(AdminTask(
    name="list_services",
    argv=("sc", "query", "type=", "service", "state=", "all"),
    description="List all Windows services and their states (read-only).",
))
_register(AdminTask(
    name="list_startup",
    argv=("wmic", "startup", "get", "Caption,Command,User"),
    description="List startup entries (read-only).",
))


# --- Services (restart only — never disable) ---
SERVICE_RESTART_ALLOWLIST = {
    "spooler",                  # Print spooler
    "wuauserv",                 # Windows Update
    "bits",                     # Background transfer
    "dhcp",                     # DHCP Client
    "dnscache",                 # DNS Client
    "audiosrv",                 # Windows Audio
    "audioendpointbuilder",
    "themes",                   # Themes
    "wsearch",                  # Windows Search
}


def get_task(name: str) -> AdminTask | None:
    return _TASKS.get(name)


def all_task_names() -> list[str]:
    return sorted(_TASKS.keys())


def all_tasks() -> list[AdminTask]:
    return [t for _, t in sorted(_TASKS.items())]


def build_service_stop_argv(service_name: str) -> tuple[str, ...] | None:
    s = (service_name or "").lower().strip()
    if s not in SERVICE_RESTART_ALLOWLIST:
        return None
    return ("sc", "stop", s)


def build_service_start_argv(service_name: str) -> tuple[str, ...] | None:
    s = (service_name or "").lower().strip()
    if s not in SERVICE_RESTART_ALLOWLIST:
        return None
    return ("sc", "start", s)