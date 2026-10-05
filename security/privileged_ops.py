"""
Allowlist dispatcher for the privileged helper.

Only operations that appear in tools/admin_tasks.py may be resolved.
The `restart_service:<svc>` pattern is honoured only when <svc> is in
tools.admin_tasks.SERVICE_RESTART_ALLOWLIST.

No executable path, argv, service name, or task definition is ever
accepted from the request. Every argv is constructed here from the
curated allowlist.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from tools import admin_tasks

logger = logging.getLogger(__name__)

HARD_MAX_TIMEOUT_SECONDS = 3600
MIN_TIMEOUT_SECONDS = 5
_DEFAULT_OP_TIMEOUT = 60

_OP_TIMEOUTS = {
    "flush_dns": 30,
    "release_ip": 30,
    "renew_ip": 60,
    "reset_winsock": 60,
    "reset_tcpip": 60,
    "show_network_adapters": 30,
    "sfc_scan": 3600,
    "dism_check_health": 600,
    "chkdsk_scan": 3600,
    "battery_report": 120,
    "energy_report": 180,
    "view_firewall_status": 30,
    "list_services": 60,
    "list_startup": 60,
    "restart_service": 60,  # applies to restart_service:<svc>
}


@dataclass(frozen=True)
class ResolvedOperation:
    task_name: str
    steps: tuple  # tuple of (argv: tuple, delay_before_seconds: float)
    max_timeout_seconds: int


def _build_steps_for_task(task_name: str):
    task = admin_tasks.get_task(task_name)
    if task is not None:
        return [(tuple(task.argv), 0.0)]

    if task_name.startswith("restart_service:"):
        svc = task_name.split(":", 1)[1].strip().lower()
        if svc not in admin_tasks.SERVICE_RESTART_ALLOWLIST:
            return None
        stop_argv = admin_tasks.build_service_stop_argv(svc)
        start_argv = admin_tasks.build_service_start_argv(svc)
        if not stop_argv or not start_argv:
            return None
        # Two separate subprocesses. No cmd.exe. No shell.
        return [
            (tuple(stop_argv), 0.0),
            (tuple(start_argv), 2.0),
        ]

    return None


def resolve(task_name: str) -> Optional[ResolvedOperation]:
    if not isinstance(task_name, str) or not task_name.strip():
        return None
    task_name = task_name.strip()
    steps = _build_steps_for_task(task_name)
    if steps is None:
        return None
    key = "restart_service" if task_name.startswith("restart_service:") \
        else task_name
    max_timeout = min(
        _OP_TIMEOUTS.get(key, _DEFAULT_OP_TIMEOUT),
        HARD_MAX_TIMEOUT_SECONDS,
    )
    return ResolvedOperation(
        task_name=task_name,
        steps=tuple(steps),
        max_timeout_seconds=max_timeout,
    )


def allowed_task_names() -> list:
    names = list(admin_tasks.all_task_names())
    names.append(
        "restart_service:<name>  where <name> is one of: "
        + ", ".join(sorted(admin_tasks.SERVICE_RESTART_ALLOWLIST))
    )
    return names


def clamp_timeout(requested, op_max: int) -> int:
    try:
        t = int(requested)
    except (TypeError, ValueError):
        t = op_max
    if t < MIN_TIMEOUT_SECONDS:
        t = MIN_TIMEOUT_SECONDS
    if t > op_max:
        t = op_max
    if t > HARD_MAX_TIMEOUT_SECONDS:
        t = HARD_MAX_TIMEOUT_SECONDS
    return t