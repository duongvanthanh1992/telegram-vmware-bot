from __future__ import annotations
import logging
from html import escape
from typing import Dict, List, Optional, Union, Any

logger = logging.getLogger(__name__)

# Power state emoji mapping
POWER_STATE_EMOJIS = {
    "poweredOn": "🟢",
    "poweredOff": "🔴",
    "suspended": "🟡",
    "unknown": "⚪",
}

# Connection state emoji mapping
CONNECTION_STATE_EMOJIS = {
    "connected": "🟢",
    "disconnected": "🔴",
    "notResponding": "🟠",
    "unknown": "⚪",
}

# Status indicators (available for callers)
STATUS_ICONS = {
    "connected": "🔗",
    "disconnected": "🔌",
    "warning": "⚠️",
    "error": "❌",
    "success": "✅",
    "info": "ℹ️",
    "loading": "⏳",
}

# ---------- HTML helpers (safe) ----------


def c(v) -> str:
    """Wrap value in <code>…</code> with HTML-escaped content."""
    return f"<code>{escape(str(v))}</code>"


def b(v) -> str:
    """Wrap value in <b>…</b> with HTML-escaped content."""
    return f"<b>{escape(str(v))}</b>"


def ihtml(v) -> str:
    """Wrap value in <i>…</i> with HTML-escaped content (preserve newlines as plain newlines)."""
    if v is None:
        return ""
    text = escape(str(v))
    return f"<i>{text}</i>"


def code_join(items: List[Any], sep: str = ", ") -> str:
    """Join a list of items safely inside one <code>…</code> block."""
    return f"<code>{sep.join(escape(str(x)) for x in items)}</code>"


# ---------- Basic formatters ----------


def format_power_state(state: Optional[str]) -> str:
    """Format power state with emojis (case tolerant)."""
    if not state:
        return "⚪ Unknown"
    key = str(state).strip()
    emoji = POWER_STATE_EMOJIS.get(key, POWER_STATE_EMOJIS.get(key.lower(), "⚪"))
    # Show original text safely
    return f"{emoji} {escape(key)}"


def format_bytes_to_gb(bytes_value: Union[int, float, None]) -> str:
    """Convert bytes to GB with proper formatting."""
    if bytes_value is None:
        return "N/A"
    try:
        gb = float(bytes_value) / (1024**3)
        return f"{gb:.2f} GB"
    except (ValueError, TypeError):
        return "N/A"


def format_mb_to_gb(mb_value: Union[int, float, None]) -> str:
    """Convert MB to GB with proper formatting."""
    if mb_value is None:
        return "N/A"
    try:
        gb = float(mb_value) / 1024
        return f"{gb:.2f} GB"
    except (ValueError, TypeError):
        return "N/A"


def format_uptime(uptime_seconds: Union[int, None]) -> str:
    """Format uptime seconds into human readable format."""
    if uptime_seconds is None:
        return "N/A"
    try:
        seconds = int(uptime_seconds)
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        minutes = (seconds % 3600) // 60
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"
    except (ValueError, TypeError):
        return "N/A"


# ---------- VM formatting ----------


def format_vm_basic(vm_info: Dict[str, Any]) -> str:
    """Format basic VM info display (safe HTML)."""
    if not vm_info:
        return "❌ No VM information available"

    source = vm_info.get("_source", "redis" if vm_info.get("updated_at") else "vcenter")

    cpu_ram_text = (
        f"{vm_info.get('cpu_cores', '?')} vCPU / {vm_info.get('ram_size_gb', '?')} GB"
    )

    lines = [
        b(vm_info.get("name", "(no name)")),
        f"{format_power_state(vm_info.get('power_state', 'unknown'))}",
        f"IP: {c(vm_info.get('ip') or vm_info.get('ip_address') or 'N/A')}",
        f"DNS: {c(vm_info.get('dns') or vm_info.get('dns_name') or 'N/A')}",
        f"OS: {c(vm_info.get('guest_os', 'Unknown'))}",
        f"CPU/RAM: {c(cpu_ram_text)}",
        f"ESXi Host: {c(vm_info.get('host_name', 'Unknown'))}",
    ]
    return "\n".join(lines)


def format_vm_list(
    vm_list: List[str], title: str = "Virtual Machines", max_items: int = 50
) -> str:
    """Format list of VM names (safe HTML)."""
    if not vm_list:
        return f"{escape(title)}\n\nNo VMs found."

    lines = [
        f"<b>{escape(title)}</b> ({len(vm_list)} found)",
        "",
    ]

    display_items = vm_list[:max_items]
    for i, vm_name in enumerate(display_items, 1):
        lines.append(f"{i:2d}. {c(vm_name)}")

    if len(vm_list) > max_items:
        lines.extend(
            [
                "",
                f"... and <b>{len(vm_list) - max_items}</b> more VMs",
            ]
        )

    return "\n".join(lines)


def format_vm_events(events_data: Dict) -> str:
    """Format VM events display with improved formatting."""
    if "error" in events_data:
        return f"❌ Error retrieving events: {escape(str(events_data['error']))}"

    events = events_data.get("events", [])
    vm_name = events_data.get("vm_name", "Unknown")
    total_found = events_data.get("total_found", len(events))
    total_returned = events_data.get("total_returned", len(events))
    limit_applied = events_data.get("limit_applied", False)
    newest_first = events_data.get("newest_first", True)

    if not events:
        message = events_data.get("message", "No events found")
        lines = [
            f"<b>Events for {escape(vm_name)}</b>",
            "",
            escape(str(message))
        ]
        return "\n".join(lines)

    # Create header with updated information
    header = f"<b>Events for {escape(vm_name)}</b>"
    if limit_applied:
        subheader = f"Showing latest {total_returned} of {total_found} total events"
    else:
        subheader = f"Found {total_found} event{'s' if total_found != 1 else ''}"
    
    lines = [
        header,
        subheader,
    ]

    for i, event in enumerate(events, 1):
        timestamp = event.get("timestamp", "N/A")
        event_type = event.get("event_type", "Unknown")
        message = event.get("message", "N/A")
        user = event.get("user", "")
        severity = event.get("severity", "info")
        
        # Add severity emoji
        severity_emoji = {
            "error": "🔴",
            "warning": "🟡", 
            "info": "ℹ️"
        }.get(severity.lower(), "")
        
        # Format event type for better readability
        display_type = event_type
        if event_type.endswith("Event"):
            display_type = event_type[:-5]  # Remove "Event" suffix
        
        # Color code common event types
        type_emoji = ""
        if "PoweredOn" in event_type:
            type_emoji = "🟢"
        elif "PoweredOff" in event_type:
            type_emoji = "🔴"
        elif "Suspended" in event_type:
            type_emoji = "🟡"
        elif "Reset" in event_type:
            type_emoji = "🔄"
        elif "AcquiredTicket" in event_type:
            type_emoji = "🎫"
        elif "AlarmStatusChanged" in event_type:
            type_emoji = "⚠️"
        elif "Reconfigured" in event_type:
            type_emoji = "⚙️"
        elif "Migrated" in event_type:
            type_emoji = "🔄"
        
        # Build the event entry
        lines.append(f"<b>{i}. {timestamp}</b>")
        lines.append(f"   {type_emoji} {escape(display_type)} {severity_emoji}")
        lines.append(f"   {escape(message)}")
        
        if user:
            lines.append(f"   👤 {escape(user)}")
            
        lines.append("")  # Empty line between events

    # Add info about newest first ordering
    if newest_first:
        lines.append("<i>Events shown newest first</i>")
    
    return "\n".join(lines)


def format_network_info(nic_data: List[Dict]) -> str:
    """Format network interface details (safe HTML)."""
    if not nic_data:
        return "Network: No network interfaces found"

    lines = [
        "<b>Network Interfaces</b>",
        "",
        "",
    ]

    for i, nic in enumerate(nic_data, 1):
        status_icon = "🔗" if nic.get("connected") else "🔌"
        label = b(nic.get("label", f"NIC {i}"))
        mac = c(nic.get("mac", "N/A"))
        network = c(nic.get("network", "N/A"))
        nic_type = c(nic.get("nic_type", "Unknown"))
        lines.extend(
            [
                f"{label} {status_icon}",
                f"   MAC: {mac}",
                f"   Type: {nic_type}",
            ]
        )
        ips = nic.get("ipv4_addresses", [])
        lines.append(f"   IPs: {code_join(ips) if ips else c('None')}")
        lines.append("")

    return "\n".join(lines)


def format_resource_usage(vm_info: Dict[str, Any]) -> str:
    """Format CPU/Memory usage display (safe HTML)."""
    if not vm_info:
        return "Resource usage: No data available"

    lines = [
        "<b>Resource Usage</b>",
        "",
        "",
    ]

    # CPU
    cpu_cores = vm_info.get("cpu_cores")
    cpu_usage = vm_info.get("cpu_mhz")
    cpu_text = f"{cpu_cores} vCPU" if cpu_cores is not None else "N/A"
    lines.append(f"CPU: {c(cpu_text)}")
    if cpu_usage:
        lines.append(f"   Usage: {c(cpu_usage)} MHz")
    lines.append("")

    # Memory
    ram_total = vm_info.get("ram_size_gb")
    mem_usage_mb = vm_info.get("mem_mb")
    mem_guest_mb = vm_info.get("mem_guest_mb")
    mem_host_mb = vm_info.get("mem_host_mb")

    lines.append(
        f"Memory: {c(ram_total if ram_total is not None else 'N/A')} GB"
    )

    def _safe_gb(x):
        try:
            return float(x) / 1024.0
        except (TypeError, ValueError):
            return None

    if ram_total:
        try:
            ram_total_f = float(ram_total)
        except (TypeError, ValueError):
            ram_total_f = None

        if mem_usage_mb is not None and ram_total_f:
            try:
                usage_gb = float(mem_usage_mb) / 1024.0
                usage_percent = (
                    (usage_gb / ram_total_f * 100.0) if ram_total_f else None
                )
                if usage_percent is not None:
                    lines.append(
                        f"   Usage: {c(f'{usage_gb:.2f} GB ({usage_percent:.1f}%)')}"
                    )
            except (TypeError, ValueError, ZeroDivisionError):
                pass
        elif mem_guest_mb is not None:
            usage_gb = _safe_gb(mem_guest_mb)
            if usage_gb is not None:
                lines.append(f"   Guest Usage: {c(f'{usage_gb:.2f} GB')}")
        elif mem_host_mb is not None:
            usage_gb = _safe_gb(mem_host_mb)
            if usage_gb is not None:
                lines.append(f"   Host Usage: {c(f'{usage_gb:.2f} GB')}")
    lines.append("")

    # Uptime
    uptime = vm_info.get("uptime_s")
    lines.append(f"Uptime: {c(format_uptime(uptime)) if uptime else c('N/A')}")

    return "\n".join(lines)


def format_vm_detailed(vm_info: Dict[str, Any]) -> str:
    """Format detailed VM information (safe HTML)."""
    if not vm_info:
        return "❌ No VM information available"

    lines = [
        f"{b(vm_info.get('name', '(no name)'))}",
        "",
    ]

    # Basic info
    lines.extend(
        [
            "<b>Basic Information</b>",
            f"• {format_power_state(vm_info.get('power_state', 'unknown'))}",
            f"• MOID: {c(vm_info.get('moid', 'N/A'))}",
            f"• DNS: {c(vm_info.get('dns') or vm_info.get('dns_name') or 'N/A')}",
            f"• OS: {c(vm_info.get('guest_os', 'Unknown'))}",
            f"• ESXi Host: {c(vm_info.get('host_name', 'Unknown'))}",
            "",
        ]
    )

    # Resources (allocations)
    cpu_text = f"{vm_info.get('cpu_cores', 'N/A')} vCPU"
    ram_text = f"{vm_info.get('ram_size_gb', 'N/A')} GB"
    lines.extend(
        [
            "<b>Resources</b>",
            f"• CPU: {c(cpu_text)}",
            f"• RAM: {c(ram_text)}",
        ]
    )

    # Resource usage if available
    uptime = vm_info.get("uptime_s")
    if uptime:
        lines.append(f"• Uptime: {c(format_uptime(uptime))}")

    cpu_usage = vm_info.get("cpu_mhz")
    if cpu_usage:
        lines.append(f"• 🔥 CPU Usage: {c(cpu_usage)} MHz")

    mem_usage = vm_info.get("mem_mb")
    if mem_usage:
        lines.append(f"• 🔥 Memory Usage: {c(format_mb_to_gb(mem_usage))}")

    lines.append("")

    # Network
    ip_list = vm_info.get("ipv4_addresses", [])
    if ip_list:
        lines.extend(
            [
                "<b>Network</b>",
                f"• Primary IP: {c(ip_list[0])}",
            ]
        )
        if len(ip_list) > 1:
            lines.append(f"• Additional IPs: {code_join(ip_list[1:])}")
    else:
        lines.extend(
            [
                "<b>Network</b>",
                f"• IP: {c(vm_info.get('ip') or vm_info.get('ip_address') or 'N/A')}",
            ]
        )

    # NICs
    nics = vm_info.get("nics", [])
    if nics:
        lines.append("• NICs:")
        for i, nic in enumerate(nics[:3]):
            status = "🔗" if nic.get("connected") else "🔌"
            label = b(nic.get("label", f"NIC {i+1}"))
            mac = c(nic.get("mac", "N/A"))
            nic_type = c(nic.get("nic_type", "Unknown"))
            lines.append(f"  {i+1}. {status} {label} ({mac})")
            lines.append(f"     Type: {nic_type}")
            ips = nic.get("ipv4_addresses", [])
            lines.append(f"     IPs: {code_join(ips) if ips else c('None')}")
        if len(nics) > 3:
            lines.append(f"  ... and {len(nics) - 3} more")
    lines.append("")

    # Storage
    disks = vm_info.get("disks", [])
    if disks:
        lines.append("<b>Storage</b>")
        total_storage = 0.0
        for i, disk in enumerate(disks[:5]):
            try:
                size_gb = float(disk.get("size_gb", 0) or 0)
            except (ValueError, TypeError):
                size_gb = 0.0
            total_storage += size_gb
            name = escape(disk.get("name", f"Disk {i+1}"))
            ds = c(disk.get("datastore", "N/A"))
            lines.append(f"• {name}: {c(f'{size_gb:.2f} GB')} [{ds}]")
        if len(disks) > 5:
            lines.append(f"• ... and {len(disks) - 5} more disks")
        lines.append(f"• Total: {c(f'{total_storage:.2f} GB')}")
        lines.append("")

    # UUIDs
    vm_uuid = vm_info.get("vm_uuid")
    instance_uuid = vm_info.get("instance_uuid")
    if vm_uuid or instance_uuid:
        lines.append("<b>Identifiers</b>")
        if vm_uuid:
            lines.append(f"• BIOS UUID: {c(vm_uuid)}")
        if instance_uuid:
            lines.append(f"• Instance UUID: {c(instance_uuid)}")
        lines.append("")

    # Tools
    tools_status = vm_info.get("vmware_tools_status")
    if tools_status:
        lines.extend(
            [
                "<b>VMware Tools</b>",
                f"• Status: {c(tools_status)}",
            ]
        )

    # Annotation
    annotation = vm_info.get("annotation")
    if annotation and annotation.strip():
        lines.extend(
            [   
                "",
                "<b>Notes</b>",
                ihtml(annotation.strip()),
            ]
        )

    return "\n".join(lines)


# ---------- Host formatting ----------


def format_connection_state(state: Optional[str]) -> str:
    """Format connection state with emojis (case tolerant)."""
    if not state:
        return "⚪ Unknown"
    key = str(state).strip()
    emoji = CONNECTION_STATE_EMOJIS.get(
        key, CONNECTION_STATE_EMOJIS.get(key.lower(), "⚪")
    )
    return f"{escape(key)} {emoji}"


def format_maintenance_mode(in_maintenance: Optional[bool]) -> str:
    """Format maintenance mode status."""
    if in_maintenance is None:
        return "⚪ Unknown"
    return "Maintenance Mode : ✅ " if in_maintenance else "Maintenance Mode : ❌"


def format_boot_time(boot_time) -> str:
    """Format boot time from various formats."""
    if not boot_time:
        return "N/A"

    try:
        if isinstance(boot_time, (int, float)):
            # Unix timestamp
            import datetime

            dt = datetime.datetime.fromtimestamp(boot_time)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        elif hasattr(boot_time, "strftime"):
            # DateTime object
            return boot_time.strftime("%Y-%m-%d %H:%M:%S")
        else:
            return str(boot_time)
    except Exception:
        return "N/A"


def format_host_basic(host_info: Dict[str, Any]) -> str:
    """Format basic ESXi host info display (safe HTML)."""
    if not host_info:
        return "❌ No host information available"

    source = "Redis Cache" if host_info.get("updated_at") else "vCenter Direct"
    
    # CPU and Memory summary
    cpu_text = f"{host_info.get('cpu_cores', '?')} cores"
    if host_info.get("cpu_threads"):
        cpu_text += f" / {host_info.get('cpu_threads')} threads"

    memory_gb = host_info.get("memory_size_gb", 0)
    memory_text = f"{memory_gb} GB" if memory_gb else "Unknown"

    # Resource usage
    cpu_usage_text = "N/A"
    if host_info.get("cpu_usage_percent"):
        cpu_usage_text = f"{host_info.get('cpu_usage_percent')}%"
    elif host_info.get("cpu_usage_mhz"):
        cpu_usage_text = f"{host_info.get('cpu_usage_mhz')}"

    memory_usage_text = "N/A"
    if host_info.get("memory_usage_percent"):
        memory_usage_text = f"{host_info.get('memory_usage_percent')}%"
    elif host_info.get("memory_usage_mb"):
        memory_usage_text = f"{format_mb_to_gb(host_info.get('memory_usage_mb'))}"

    lines = [
        f"ESXi Host : {b(host_info.get('name', '(no name)'))}",
        f"{format_connection_state(host_info.get('connection_state', 'unknown'))}",
        f"{format_maintenance_mode(host_info.get('in_maintenance_mode'))}",
        f"Vendor: {c(host_info.get('vendor', 'Unknown'))}",
        f"Model: {c(host_info.get('model', 'Unknown'))}",
        f"CPU: {c(cpu_text)}",
        f"Memory: {c(memory_text)}",
        f"🔥 CPU Usage: {c(cpu_usage_text)}",
        f"🔥 Memory Usage: {c(memory_usage_text)}",
    ]

    # VM counts
    vm_total = host_info.get("vm_count_total")
    vm_on = host_info.get("vm_count_powered_on")
    if vm_total is not None:
        vm_text = f"{vm_on or 0}/{vm_total} VMs powered on"
        lines.append(f"{c(vm_text)}")

    return "\n".join(lines)


def format_host_detailed(host_info: Dict[str, Any]) -> str:
    """Format detailed ESXi host information (safe HTML) – CPU in MHz/GHz only, no percentages."""
    if not host_info:
        return "⚠  No host information available"

    def _fmt_mhz(mhz: Optional[float]) -> str:
        if mhz is None:
            return "N/A"
        try:
            mhz = float(mhz)
        except Exception:
            return "N/A"
        return f"{mhz / 1000:.2f} GHz" if mhz >= 1000 else f"{mhz:.0f} MHz"

    lines = [
        f"{b(host_info.get('name', '(no name)'))}",
        "",
    ]

    # Basic information
    lines.extend(
        [
            "<b>Basic Information</b>",
            f"• {format_connection_state(host_info.get('connection_state', 'unknown'))}",
            f"• {format_maintenance_mode(host_info.get('in_maintenance_mode'))}",
            f"• Vendor: {c(host_info.get('vendor', 'Unknown'))}",
            f"• Model: {c(host_info.get('model', 'Unknown'))}",

        ]
    )

    boot_time = format_boot_time(host_info.get("boot_time"))
    if boot_time != "N/A":
        lines.append(f"• Uptime: {c(boot_time)}")

    lines.append("")

    # Hardware resources
    cpu_model = host_info.get("cpu_model", "Unknown")
    cpu_cores = host_info.get("cpu_cores", 0)
    cpu_threads = host_info.get("cpu_threads", 0)
    cpu_mhz = host_info.get("cpu_mhz_per_core", 0)
    cpu_total_mhz = host_info.get("cpu_total_mhz", 0)
    memory_gb = host_info.get("memory_size_gb", 0)

    lines.extend(
        [
            "<b>Hardware Resources</b>",
            f"• CPU Model: {c(cpu_model)}",
            f"• CPU Cores: {c(cpu_cores)}",
            f"• CPU Threads: {c(cpu_threads)}",
            f"• CPU Speed: {c(cpu_mhz)} MHz per core"
            if cpu_mhz
            else f"• CPU Speed: {c('N/A')}",
            f"• Total CPU Capacity: {c(f'{cpu_total_mhz:,} GHz' if cpu_total_mhz else 'N/A')}",
            f"• Memory: {c(f'{memory_gb} GB' if memory_gb else 'N/A')}",
            "",
        ]
    )

    # Current usage
    lines.append("<b>Current Usage</b>")

    # CPU usage (MHz only)
    cpu_usage_mhz = host_info.get("cpu_usage_mhz")
    if cpu_usage_mhz is not None:
        lines.append(f"• 🔥 CPU: {c(_fmt_mhz(cpu_usage_mhz))} used of {c(f'{cpu_total_mhz:,} GHz')}")
    else:
        # Try to derive from percent only if per-core MHz is known
        cpu_usage_percent = host_info.get("cpu_usage_percent")
        if cpu_usage_percent is not None and cpu_total_mhz:
            # If total MHz is available, percent of total capacity is a reasonable derivation
            try:
                derived = float(cpu_usage_percent) * float(cpu_total_mhz) / 100.0
                lines.append(f"• 🔥 CPU: {c(_fmt_mhz(derived))} used of {c(f'{cpu_total_mhz:,} GHz')}")
            except Exception:
                lines.append(f"• 🔥 CPU: {c('N/A')}")
        else:
            lines.append(f"• 🔥 CPU: {c('N/A')}")

    # Memory usage (no percentages – show used, optionally "of total")
    memory_usage_mb = host_info.get("memory_usage_mb")
    if memory_usage_mb is not None:
        used_text = format_mb_to_gb(memory_usage_mb)  # e.g., "12.34 GB"
        if memory_gb:
            lines.append(f"• 🔥 Memory: {c(used_text)} used of {c(f'{memory_gb} GB')}")
        else:
            lines.append(f"• 🔥 Memory: {c(used_text)} used")
    else:
        lines.append(f"• 🔥 Memory: {c('N/A')}")

    # Active memory if available
    active_memory_mb = host_info.get("host_active_memory_mb")
    if active_memory_mb is not None:
        lines.append(f"• Active Memory: {c(format_mb_to_gb(active_memory_mb))}")

    lines.append("")

    # VM information
    vm_total = host_info.get("vm_count_total", 0)
    vm_on = host_info.get("vm_count_powered_on", 0)
    vm_off = (
        vm_total - vm_on
        if (isinstance(vm_total, int) and isinstance(vm_on, int))
        else "N/A"
    )

    lines.extend(
        [
            "<b>Virtual Machines</b>",
            f"• Total VMs: {c(vm_total)}",
            f"• Powered On: {c(vm_on)}",
            f"• Powered Off: {c(vm_off)}",
            "",
        ]
    )

    # Top VMs by CPU usage – MHz/GHz only
    # Accept either `top_vms_cpu` with `cpu_usage_mhz`, or legacy `top_vms_cpu_percent`
    top_cpu_mhz_list = host_info.get(
        "top_vms_cpu", []
    )  # expected objects with cpu_usage_mhz
    top_cpu_pct_list = host_info.get(
        "top_vms_cpu_percent", []
    )  # legacy objects with cpu_usage_percent

    def _append_vm_cpu_line(
        idx: int, vm_name: str, cpu_mhz_val: Optional[float], vcpus: Any
    ):
        if cpu_mhz_val is not None:
            lines.append(
                f"{idx}. {escape(vm_name)}: {c(_fmt_mhz(cpu_mhz_val))} ({c(vcpus)} vCPU)"
            )
        else:
            lines.append(f"{idx}. {escape(vm_name)}: {c('N/A')} ({c(vcpus)} vCPU)")

    if top_cpu_mhz_list or top_cpu_pct_list:
        lines.append("<b>🔥 Top VMs by CPU Usage</b>")

        # Prefer MHz list if available
        if top_cpu_mhz_list:
            for i, vm in enumerate(top_cpu_mhz_list[:5], 1):
                vm_name = vm.get("name", f"VM {i}")
                cpu_mhz_val = vm.get("cpu_usage_mhz")
                cpu_cores_vm = vm.get("cpu_cores", "?")
                _append_vm_cpu_line(i, vm_name, cpu_mhz_val, cpu_cores_vm)
        else:
            # Fallback: derive from percent if we can (need per-core MHz OR total capacity per VM)
            host_mhz_per_core = host_info.get("cpu_mhz_per_core")
            for i, vm in enumerate(top_cpu_pct_list[:5], 1):
                vm_name = vm.get("name", f"VM {i}")
                cpu_pct = vm.get("cpu_usage_percent")
                cpu_cores_vm = vm.get("cpu_cores", 1)

                derived_mhz = None
                if cpu_pct is not None and host_mhz_per_core:
                    try:
                        derived_mhz = (
                            float(cpu_pct)
                            / 100.0
                            * float(cpu_cores_vm)
                            * float(host_mhz_per_core)
                        )
                    except Exception:
                        derived_mhz = None

                _append_vm_cpu_line(i, vm_name, derived_mhz, cpu_cores_vm)

        lines.append("")

    # Top VMs by Active Memory usage (unchanged logic, no %)
    top_mem = host_info.get("top_vms_active_memory_mb", [])
    if top_mem:
        lines.append("<b>🔥 Top VMs by Active Memory Usage</b>")
        for i, vm in enumerate(top_mem[:5], 1):
            vm_name = escape(vm.get("name", f"VM {i}"))
            active_mem_mb = vm.get("active_memory_mb") or vm.get("memory_usage_mb", 0)

            if active_mem_mb and active_mem_mb >= 1024:
                mem_text = f"{active_mem_mb / 1024:.2f} GB"
            elif active_mem_mb:
                mem_text = f"{active_mem_mb:.0f} MB"
            else:
                mem_text = "N/A"

            mem_allocated_mb = vm.get("memory_mb", 0)
            allocated_text = (
                f"{mem_allocated_mb / 1024:.0f} GB" if mem_allocated_mb else "?"
            )
            lines.append(
                f"{i}. {vm_name}: {c(mem_text)} / {c(allocated_text)}"
            )
        lines.append("")

    return "\n".join(lines)


# ---------- Message structure helpers ----------


def format_error_message(error: Union[str, Exception]) -> str:
    """Standardized error messages (safe HTML)."""
    error_msg = str(error) if not isinstance(error, Exception) else str(error)
    return f"❌ <b>Error</b>\n{escape(error_msg)}"


def format_success_message(message: str) -> str:
    """Success message formatting (safe HTML)."""
    return f"✅ <b>Success</b>\n{escape(message)}"


def format_warning_message(message: str) -> str:
    """Warning message formatting (safe HTML)."""
    return f"⚠️ <b>Warning</b>\n{escape(message)}"


def format_info_message(message: str) -> str:
    """Info message formatting (safe HTML)."""
    return f"ℹ️ <b>Info</b>\n{escape(message)}"


def format_search_results(
    results: List[str], search_term: str, result_type: str = "VMs"
) -> str:
    """Format search results display (safe HTML)."""
    if not results:
        return f"<b>Search Results</b>\nNo {result_type.lower()} found matching {c(search_term)}"
    return format_vm_list(results, f"Search Results for '{search_term}'")


def format_help_message(
    commands: List[str], user_role: str = None) -> str:
    """Format help message showing available commands (safe for HTML parse_mode)."""
    lines = [
        "<b>Available Commands</b>",
    ]

    if user_role:
        lines.append(f"Your role: {c(user_role)}")
        lines.append("")

    # Group commands by category
    basic_commands = [cmd for cmd in commands if cmd in ["/start", "/help"]]
    user_commands = [cmd for cmd in commands if cmd in ["/find", "/vm_name", "/vm_ip", "/vm_events", "/host_name"]]
    admin_commands = [cmd for cmd in commands if cmd in ["/flush", "/ai_linux_basic", "/ai_linux_sec"]]

    if basic_commands:
        lines.append("<b>Basic Commands</b>")
        for cmd in basic_commands:
            if cmd == "/start":
                lines.append("• <code>/start</code> - Show welcome message")
            elif cmd == "/help":
                lines.append("• <code>/help</code> - Show this help message")
        lines.append("")

    if user_commands:
        lines.append("<b>VM Operations</b>")
        for cmd in user_commands:
            if cmd == "/find":
                lines.append("• <code>/find</code> [<code>VM Keyword</code>] - Search VMs by keyword")
            elif cmd == "/vm_name":
                lines.append("• <code>/vm_name</code> [<code>VM Name</code>] - Get VM info by VM name")
            elif cmd == "/vm_ip":
                lines.append("• <code>/vm_ip</code> [<code>IPv4</code>] - Get VM info by IPv4 address")
            elif cmd == "/vm_events":
                if str(user_role).lower() == "admin":
                    lines.append("• <code>/vm_events</code> [<code>VM Name</code>] [<code>Number</code>] - Get xx VM events (default 5, max 50)")
                else:
                    lines.append("• <code>/vm_events</code> [<code>VM Name</code>] - Get 5 VM events ")
            elif cmd == "/host_name":
                lines.append("• <code>/host_name</code> [<code>ESXi Host Name</code>] - Get ESXi host info by name")
        lines.append("")

    if admin_commands:
        lines.append("<b>Admin Commands</b>")
        for cmd in admin_commands:
            if cmd == "/flush":
                lines.append("• <code>/flush</code> - Clear all cached VM data on Redis")
            elif cmd == "/ai_linux_basic":
                lines.append("• <code>/ai_linux_basic</code> [<code>IPv4</code>] - Get basic Linux VM info using AI")
            elif cmd == "/ai_linux_sec":
                lines.append("• <code>/ai_linux_sec</code> [<code>IPv4</code>] - Get security Linux VM info using AI")
        lines.append("")

    if not commands or len(commands) <= 2:
        lines.extend([
            "No additional commands available for your role.",
            "Contact an administrator for access.",
        ])

    return "\n".join(lines)


def format_start_message(
    user_name: Optional[str] = None,
    user_id: Optional[int] = None,
    user_role: Optional[str] = None,
) -> str:
    """Format the welcome/start message (safe HTML)."""
    greeting = f"Hello, {escape(user_name)}!" if user_name else "Hello!"
    role_text = escape(user_role or "unknown")
    uid_text = escape(str(user_id)) if user_id is not None else "N/A"
    uname_text = f"@{user_name}" if user_name else "N/A"

    return (
        f"🤖 Telegram VMware Bot 🤖\n"
        f"User: <code>{escape(uname_text)}</code>\n"
        f"User ID: <code>{uid_text}</code>\n"
        f"Your role: <b>{role_text}</b>\n"
        "Use /help to see available commands for your role."
    )
