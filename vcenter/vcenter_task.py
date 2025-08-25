from __future__ import annotations

import ssl
import ipaddress
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional

import logging
from pytz import UTC
from pyVmomi import vim
from pyVim.connect import SmartConnect, Disconnect


logger = logging.getLogger(__name__)


class VCenterClient:
    """Thin wrapper to manage and reuse a vCenter connection."""

    def __init__(self, host: str, user: str, password: str) -> None:
        self.host = host
        self.user = user
        self.password = password
        self.service_instance = None

    def connect(self) -> None:
        """Establish connection to vCenter (idempotent)."""
        if not self.service_instance:
            try:
                ssl_context = ssl._create_unverified_context()
                self.service_instance = SmartConnect(
                    host=self.host,
                    user=self.user,
                    pwd=self.password,
                    sslContext=ssl_context,
                )
                logger.info("Successfully connected to vCenter")
            except Exception as e:
                logger.error(f"Failed to connect to vCenter: {e}")
                raise

    def disconnect(self) -> None:
        """Disconnect from vCenter (safe to call multiple times)."""
        if self.service_instance:
            try:
                Disconnect(self.service_instance)
                self.service_instance = None
                logger.info("Disconnected from vCenter")
            except Exception as e:
                logger.error(f"Error disconnecting from vCenter: {e}")

    def get_instance(self):
        """Get service instance, connecting if necessary."""
        self.connect()
        return self.service_instance

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()


class VMwareTask:
    """Collection of static operations on vCenter objects."""

    @staticmethod
    def _split_ip(ip_str: str) -> str:
        """Strip CIDR if present: '192.168.1.10/24' -> '192.168.1.10'."""
        return ip_str.split("/", 1)[0].strip() if isinstance(ip_str, str) else ip_str

    @staticmethod
    def _is_ipv4(ip_str: str) -> bool:
        """Return True if ip_str is a valid IPv4 address."""
        try:
            return ipaddress.ip_address(ip_str).version == 4
        except Exception:
            return False

    @staticmethod
    def _collect_ipv4s_and_nics(vm) -> Tuple[List[str], List[Dict]]:
        """
        Collect all IPv4 addresses and NIC details of a VM.

        Returns:
            ipv4s: list[str] of unique IPv4s across all NICs
            nics: list[dict] each with keys:
                  label, mac, network, connected, nic_type, ipv4_addresses
        """
        ipv4s = set()
        nics: List[Dict] = []

        # Map MAC -> IPv4 list from guest.net
        guest_mac_to_ips: Dict[str, List[str]] = {}
        guest = getattr(vm, "guest", None)

        if guest and getattr(guest, "net", None):
            for net in guest.net:
                mac = getattr(net, "macAddress", None)
                ips: List[str] = []
                if getattr(net, "ipAddress", None):
                    for raw in net.ipAddress:
                        ip = VMwareTask._split_ip(raw)
                        if VMwareTask._is_ipv4(ip):
                            ips.append(ip)
                            ipv4s.add(ip)
                if mac:
                    guest_mac_to_ips[mac.lower()] = ips

        # Iterate config.hardware to pull NIC metadata by device
        config = getattr(vm, "config", None)
        hardware = getattr(config, "hardware", None)

        if hardware and getattr(hardware, "device", None):
            for dev in hardware.device:
                # Only care about ethernet cards
                if isinstance(dev, vim.vm.device.VirtualEthernetCard):
                    label = getattr(dev.deviceInfo, "label", None)
                    mac = getattr(dev, "macAddress", None)
                    nic_type = dev.__class__.__name__

                    # Connection state
                    connected = False
                    try:
                        if getattr(dev, "connectable", None):
                            connected = bool(
                                getattr(dev.connectable, "connected", False)
                            )
                    except Exception:
                        pass

                    # Network/Portgroup name
                    network = None
                    try:
                        if getattr(dev, "backing", None):
                            network = getattr(dev.backing, "deviceName", None)
                            if not network and getattr(dev.backing, "network", None):
                                network = getattr(dev.backing.network, "name", None)
                    except Exception:
                        pass

                    ips = guest_mac_to_ips.get(mac.lower(), []) if mac else []
                    nics.append(
                        {
                            "label": label,
                            "mac": mac,
                            "network": network,
                            "connected": connected,
                            "nic_type": nic_type,
                            "ipv4_addresses": sorted(set(ips)),
                        }
                    )

        # Fallback: guest.ipAddress if it's an IPv4 and not already included
        if guest and getattr(guest, "ipAddress", None):
            p = VMwareTask._split_ip(guest.ipAddress)
            if VMwareTask._is_ipv4(p):
                ipv4s.add(p)

        return sorted(ipv4s), nics

    @staticmethod
    def vcenter_list_all_vm(service_instance) -> List[str]:
        """List all VM names in vCenter."""
        try:
            content = service_instance.RetrieveContent()
            container_view = content.viewManager.CreateContainerView(
                content.rootFolder, [vim.VirtualMachine], True
            )
            vms = [vm.name for vm in container_view.view if vm.name]
            container_view.Destroy()
            return sorted(vms)
        except Exception as e:
            logger.error(f"Error listing VMs: {e}")
            return []

    @staticmethod
    def check_vm_info(service_instance, vm_name: str) -> Dict:
        """Check if VM exists and return basic info (IPv4 primary only)."""
        try:
            content = service_instance.RetrieveContent()
            container_view = content.viewManager.CreateContainerView(
                content.rootFolder, [vim.VirtualMachine], True
            )

            for vm in container_view.view:
                if vm_name.lower() == vm.name.lower():
                    ipv4_list, _ = VMwareTask._collect_ipv4s_and_nics(vm)
                    container_view.Destroy()
                    return {
                        "exists": True,
                        "moid": getattr(vm, "_moId", None),
                        "name": vm.name,
                        "power_state": vm.summary.runtime.powerState,
                        "ip_address": ipv4_list[0] if ipv4_list else "N/A",
                    }

            container_view.Destroy()
            return {"exists": False, "message": f"VM '{vm_name}' not found"}

        except Exception as e:
            logger.error(f"Error checking VM info: {e}")
            return {"exists": False, "error": str(e)}

    @staticmethod
    def get_vm_info(service_instance, vm_name: str) -> Optional[Dict]:
        """Get detailed VM information by name (IPv4 only, with NIC MACs and UUIDs)."""
        try:
            content = service_instance.RetrieveContent()
            container_view = content.viewManager.CreateContainerView(
                content.rootFolder, [vim.VirtualMachine], True
            )

            for vm in container_view.view:
                if vm_name.lower() == vm.name.lower():
                    summary = vm.summary
                    runtime = summary.runtime
                    config = summary.config
                    guest = getattr(vm, "guest", None)
                    qs = getattr(summary, "quickStats", None)

                    status: Dict = {
                        "moid": getattr(vm, "_moId", None),
                        "name": vm.name,
                        "power_state": runtime.powerState,
                        "ram_size_gb": round((config.memorySizeMB or 0) / 1024, 2)
                        if config
                        else 0,
                        "cpu_cores": getattr(config, "numCpu", None)
                        if config
                        else None,
                        "host_name": vm.runtime.host.name if vm.runtime.host else "N/A",
                        "dns_name": getattr(guest, "hostName", None)
                        or "N/A (VMware Tools not installed)",
                        "guest_os": getattr(config, "guestFullName", None) or "Unknown",
                        "vmware_tools_status": getattr(guest, "toolsStatus", None)
                        or "Unknown",
                        "annotation": getattr(config, "annotation", None) or "",
                        "uptime_s": getattr(qs, "uptimeSeconds", None) if qs else None,
                        "cpu_mhz": getattr(qs, "overallCpuUsage", None) if qs else None,
                        "mem_guest_mb": getattr(qs, "guestMemoryUsage", None)
                        if qs
                        else None,
                        "mem_host_mb": getattr(qs, "hostMemoryUsage", None)
                        if qs
                        else None,
                        "disks": [],
                    }

                    status["mem_mb"] = (
                        status["mem_guest_mb"]
                        if status["mem_guest_mb"] is not None
                        else status["mem_host_mb"]
                    )

                    # Disks
                    if getattr(vm, "config", None) and getattr(
                        vm.config, "hardware", None
                    ):
                        for device in vm.config.hardware.device:
                            if isinstance(device, vim.vm.device.VirtualDisk):
                                disk_size_gb = device.capacityInBytes / (1024**3)
                                datastore = "Unknown"
                                try:
                                    if hasattr(device.backing, "fileName"):
                                        # Example: "[datastore1] vmFolder/vm.vmdk"
                                        datastore = device.backing.fileName.split(
                                            "[", 1
                                        )[1].split("]", 1)[0]
                                except Exception:
                                    pass
                                status["disks"].append(
                                    {
                                        "name": getattr(
                                            device.deviceInfo, "label", None
                                        ),
                                        "size_gb": round(disk_size_gb, 2),
                                        "datastore": datastore,
                                    }
                                )

                    # IPv4 + NICs + UUIDs
                    ipv4_list, nic_list = VMwareTask._collect_ipv4s_and_nics(vm)
                    status.update(
                        {
                            "ip_address": ipv4_list[0] if ipv4_list else "N/A",
                            "ipv4_addresses": ipv4_list,
                            "nics": nic_list,
                            "vm_uuid": getattr(vm.config, "uuid", None)
                            or "Unknown",  # BIOS UUID
                            "instance_uuid": getattr(vm.config, "instanceUuid", None)
                            or "Unknown",  # vCenter Instance UUID
                        }
                    )

                    container_view.Destroy()
                    return status

            container_view.Destroy()
            return None

        except Exception as e:
            logger.error(f"Error getting VM info: {e}")
            return None

    @staticmethod
    def get_ipv4_info(service_instance, ipv4_address: str) -> Optional[Dict]:
        """Get VM information by an IPv4 address (supports multiple NICs/IPs)."""
        try:
            content = service_instance.RetrieveContent()
            container_view = content.viewManager.CreateContainerView(
                content.rootFolder, [vim.VirtualMachine], True
            )

            target = VMwareTask._split_ip(ipv4_address)
            if not VMwareTask._is_ipv4(target):
                container_view.Destroy()
                logger.error(f"Invalid IPv4 address provided: {ipv4_address}")
                return None

            for vm in container_view.view:
                ipv4_list, _ = VMwareTask._collect_ipv4s_and_nics(vm)
                if target in ipv4_list:
                    vm_info = VMwareTask.get_vm_info(service_instance, vm.name)
                    container_view.Destroy()
                    return vm_info

            container_view.Destroy()
            return None

        except Exception as e:
            logger.error(f"Error finding VM by IP {ipv4_address}: {e}")
            return None

    @staticmethod
    def find_vm_by_keyword(service_instance, keyword: str) -> List[str]:
        """Find VM names containing the keyword (case-insensitive)."""
        try:
            content = service_instance.RetrieveContent()
            container_view = content.viewManager.CreateContainerView(
                content.rootFolder, [vim.VirtualMachine], True
            )

            matching_vms: List[str] = []
            keyword_lower = keyword.lower()

            for vm in container_view.view:
                if vm.name and keyword_lower in vm.name.lower():
                    matching_vms.append(vm.name)

            container_view.Destroy()
            return sorted(matching_vms)

        except Exception as e:
            logger.error(f"Error finding VMs by keyword '{keyword}': {e}")
            return []

    @staticmethod
    def get_vm_events(service_instance, vm_name: str, limit: int = 10) -> Dict:
        """Get latest events for a specific VM (newest N events)."""
        try:
            content = service_instance.RetrieveContent()
            container_view = content.viewManager.CreateContainerView(
                content.rootFolder, [vim.VirtualMachine], True
            )

            vm_obj = None
            for vm in container_view.view:
                if vm.name.lower() == vm_name.lower():
                    vm_obj = vm
                    break

            container_view.Destroy()

            if not vm_obj:
                return {"error": f"VM '{vm_name}' not found"}

            # Event manager
            event_manager = content.eventManager

            logger.info(f"Querying latest {limit} events for VM {vm_name}")

            # Create event filter specification - NO TIME FILTER, just VM-specific
            filter_spec = vim.event.EventFilterSpec(
                entity=vim.event.EventFilterSpec.ByEntity(
                    entity=vm_obj, recursion="self"  # Only events for this specific VM
                )
                # No time filter - we want all events, then we'll sort and limit
            )

            # Query events
            try:
                # Get a larger batch first, then sort and limit
                # This ensures we get the actual newest events
                events = event_manager.QueryEvents(filter_spec)
                logger.info(
                    f"Found {len(events) if events else 0} total events for VM {vm_name}"
                )
            except Exception as query_error:
                logger.error(f"Failed to query events: {query_error}")
                return {
                    "error": f"Failed to query events: {str(query_error)}",
                    "vm_name": vm_name,
                }

            if not events:
                return {
                    "events": [],
                    "message": f"No events found for VM '{vm_name}'",
                    "vm_name": vm_name,
                    "total_found": 0,
                    "total_returned": 0,
                }

            # Sort events by creation time (newest first) and limit
            events.sort(key=lambda x: x.createdTime, reverse=True)
            limited_events = events[:limit]

            # Format events
            formatted_events = []
            for event in limited_events:
                try:
                    # Handle timezone for event time
                    event_time = event.createdTime
                    if event_time.tzinfo is None:
                        # Assume vCenter returns UTC if no timezone info
                        event_time_utc = event_time.replace(tzinfo=UTC)
                    else:
                        event_time_utc = event_time.astimezone(UTC)

                    # Format for display
                    timestamp_str = event_time_utc.strftime("%Y-%m-%d %H:%M:%S UTC")

                    # Better event type display
                    event_type = event.__class__.__name__
                    if event_type.startswith("vim.event."):
                        event_type = event_type.replace("vim.event.", "")

                    # Better message extraction with priority order
                    message = "N/A"
                    user_info = ""

                    # Try different message fields in priority order
                    if (
                        hasattr(event, "fullFormattedMessage")
                        and event.fullFormattedMessage
                    ):
                        message = event.fullFormattedMessage.strip()
                    elif hasattr(event, "description") and event.description:
                        if hasattr(event.description, "message"):
                            message = event.description.message.strip()
                        else:
                            message = str(event.description).strip()
                    elif hasattr(event, "message") and event.message:
                        message = event.message.strip()
                    else:
                        # Generate a meaningful message based on event type
                        if "PoweredOn" in event_type:
                            message = f"VM '{vm_name}' was powered on"
                        elif "PoweredOff" in event_type:
                            message = f"VM '{vm_name}' was powered off"
                        elif "Suspended" in event_type:
                            message = f"VM '{vm_name}' was suspended"
                        elif "Reset" in event_type:
                            message = f"VM '{vm_name}' was reset"
                        elif "Reconfigured" in event_type:
                            message = f"VM '{vm_name}' configuration was changed"
                        elif "AcquiredTicket" in event_type:
                            message = f"Console/remote access ticket acquired for VM '{vm_name}'"
                        elif "AlarmStatusChanged" in event_type:
                            message = f"Alarm status changed for VM '{vm_name}'"
                        else:
                            message = f"Event: {event_type}"

                    # Extract user information
                    if hasattr(event, "userName") and event.userName:
                        user_info = event.userName.strip()
                        # Clean up domain info if present
                        if "\\" in user_info:
                            user_info = user_info.split("\\")[-1]
                    elif hasattr(event, "createdBy") and event.createdBy:
                        user_info = str(event.createdBy).strip()

                    # Remove duplicate user info in message
                    if user_info and f"(by {user_info})" in message:
                        message = message.replace(f" (by {user_info})", "")
                        message = message.replace(f"(by {user_info})", "")

                    # Truncate long messages
                    if len(message) > 150:
                        message = message[:147] + "..."

                    formatted_event = {
                        "timestamp": timestamp_str,
                        "event_type": event_type,
                        "message": message,
                        "user": user_info if user_info else "",
                        "severity": getattr(event, "severity", "info"),
                        "raw_event_time": event_time_utc.isoformat(),
                    }

                    formatted_events.append(formatted_event)

                except Exception as format_error:
                    logger.warning(
                        f"Could not format event {event.__class__.__name__}: {format_error}"
                    )
                    # Add a basic entry so we don't lose the event completely
                    formatted_events.append(
                        {
                            "timestamp": "Unknown",
                            "event_type": event.__class__.__name__,
                            "message": "Error formatting event details",
                            "user": "",
                            "severity": "info",
                            "raw_event_time": "",
                        }
                    )
                    continue

            result = {
                "events": formatted_events,
                "total_found": len(events),  # Total available events
                "total_returned": len(formatted_events),  # Total returned (after limit)
                "vm_name": vm_name,
                "limit_applied": len(events) > limit,
                "newest_first": True,
            }

            logger.info(
                f"Successfully retrieved {len(formatted_events)} latest events for VM {vm_name}"
            )
            return result

        except Exception as e:
            logger.error(f"Error retrieving VM events for {vm_name}: {e}")
            return {"error": str(e), "vm_name": vm_name}

    @staticmethod
    def _build_perf_counter_map(perf_manager):
        """Build performance counter mapping for efficient lookups."""
        try:
            counter_map = {}
            for counter in perf_manager.perfCounter:
                group_info = counter.groupInfo.key
                name_info = counter.nameInfo.key
                rollup_type = counter.rollupType
                key = (group_info, name_info, rollup_type)
                counter_map[key] = counter.key
            return counter_map
        except Exception as e:
            logger.warning(f"Failed to build performance counter map: {e}")
            return {}

    @staticmethod
    def _query_realtime_perf(perf_manager, entity, metric_ids, max_sample=1):
        """Query real-time performance metrics for an entity."""
        try:
            if not metric_ids:
                return {}

            query_spec = vim.PerformanceManager.QuerySpec(
                entity=entity,
                metricId=[
                    vim.PerformanceManager.MetricId(counterId=mid, instance="")
                    for mid in metric_ids
                ],
                maxSample=max_sample,
                intervalId=20,  # Real-time interval (20 seconds)
            )

            result = perf_manager.QueryPerf([query_spec])
            if not result or not result[0].value:
                return {}

            values = {}
            for metric in result[0].value:
                if metric.value:
                    values[metric.id.counterId] = metric.value[0]

            return values
        except Exception as e:
            logger.warning(f"Performance query failed: {e}")
            return {}

    @staticmethod
    def get_host_basic_info(service_instance, host_name: str) -> Optional[Dict]:
        """Get basic ESXi host information (fast, using quickStats only)."""
        try:
            content = service_instance.RetrieveContent()
            view = content.viewManager.CreateContainerView(
                content.rootFolder, [vim.HostSystem], True
            )

            host_obj = None
            for host in view.view:
                if host.name and host.name.lower() == host_name.lower():
                    host_obj = host
                    break
            view.Destroy()

            if not host_obj:
                return None

            # Basic host information
            summary = host_obj.summary
            hw = summary.hardware
            runtime = summary.runtime
            hqs = summary.quickStats

            # Count VMs
            vm_count = len(getattr(host_obj, "vm", []) or [])
            powered_on_vms = 0
            if host_obj.vm:
                for vm in host_obj.vm:
                    try:
                        if vm.summary.runtime.powerState == "poweredOn":
                            powered_on_vms += 1
                    except Exception:
                        continue

            host_info = {
                "name": host_obj.name,
                "vendor": getattr(hw, "vendor", None) or "Unknown",
                "model": getattr(hw, "model", None) or "Unknown",
                "cpu_cores": getattr(hw, "numCpuCores", None) or 0,
                "cpu_threads": getattr(hw, "numCpuThreads", None) or 0,
                "cpu_mhz_per_core": getattr(hw, "cpuMhz", None) or 0,
                "memory_size_gb": round(
                    (getattr(hw, "memorySize", 0)) / (1024**3), 2
                ),
                "connection_state": getattr(runtime, "connectionState", None)
                or "unknown",
                "in_maintenance_mode": getattr(runtime, "inMaintenanceMode", False),
                "boot_time": getattr(runtime, "bootTime", None),
                "vm_count_total": vm_count,
                "vm_count_powered_on": powered_on_vms,
            }

            # Add resource usage from quickStats if available
            if hqs:
                host_info.update(
                    {
                        "cpu_usage_mhz": getattr(hqs, "overallCpuUsage", None),
                        "memory_usage_mb": getattr(hqs, "overallMemoryUsage", None),
                    }
                )

            # Calculate total CPU capacity
            cpu_total_mhz = host_info["cpu_cores"] * host_info["cpu_mhz_per_core"]
            host_info["cpu_total_mhz"] = cpu_total_mhz

            # Calculate usage percentages if data available
            if host_info["cpu_usage_mhz"] and cpu_total_mhz > 0:
                host_info["cpu_usage_percent"] = round(
                    (host_info["cpu_usage_mhz"] / cpu_total_mhz) * 100, 1
                )

            if host_info["memory_usage_mb"] and host_info["memory_size_gb"] > 0:
                memory_total_mb = host_info["memory_size_gb"] * 1024
                host_info["memory_usage_percent"] = round(
                    (host_info["memory_usage_mb"] / memory_total_mb) * 100, 1
                )

            return host_info

        except Exception as e:
            logger.error(f"Error getting basic host info for {host_name}: {e}")
            return None

    @staticmethod
    def get_host_detailed_info(
        service_instance, host_name: str, top_n: int = 5
    ) -> Optional[Dict]:
        """Get detailed ESXi host information with CORRECT CPU/Memory metrics."""
        try:
            # Start with basic info
            host_info = VMwareTask.get_host_basic_info(service_instance, host_name)
            if not host_info:
                return None

            # Get host object again for detailed queries
            content = service_instance.RetrieveContent()
            view = content.viewManager.CreateContainerView(
                content.rootFolder, [vim.HostSystem], True
            )

            host_obj = None
            for host in view.view:
                if host.name and host.name.lower() == host_name.lower():
                    host_obj = host
                    break
            view.Destroy()

            if not host_obj:
                return host_info

            # Setup performance manager and counters
            perf_manager = content.perfManager
            counter_map = VMwareTask._build_perf_counter_map(perf_manager)

            # Key performance counters we need
            cpu_usage_counter = counter_map.get(
                ("cpu", "usage", "average")
            )  # CPU usage %
            mem_active_counter = counter_map.get(
                ("mem", "active", "average")
            )  # Active memory KB
            mem_consumed_counter = counter_map.get(
                ("mem", "consumed", "average")
            )  # Consumed memory KB

            # Collect detailed VM stats
            vm_objs = getattr(host_obj, "vm", []) or []
            vm_stats = []

            for vm in vm_objs:
                try:
                    s = vm.summary
                    qs = s.quickStats
                    config = s.config

                    if not qs or s.runtime.powerState != "poweredOn":
                        continue  # Skip powered off VMs

                    # Get basic VM info
                    vm_stat = {
                        "name": getattr(config, "name", vm.name),
                        "power_state": getattr(s.runtime, "powerState", None),
                        "cpu_cores": getattr(config, "numCpu", None),
                        "memory_mb": getattr(config, "memorySizeMB", None),
                    }

                    # Try to get accurate performance data from performance counters
                    cpu_usage_percent = None
                    active_memory_kb = None
                    consumed_memory_kb = None

                    try:
                        if (
                            cpu_usage_counter
                            or mem_active_counter
                            or mem_consumed_counter
                        ):
                            metric_ids = []
                            if cpu_usage_counter:
                                metric_ids.append(cpu_usage_counter)
                            if mem_active_counter:
                                metric_ids.append(mem_active_counter)
                            if mem_consumed_counter:
                                metric_ids.append(mem_consumed_counter)

                            perf_vals = VMwareTask._query_realtime_perf(
                                perf_manager, vm, metric_ids
                            )

                            if cpu_usage_counter in perf_vals:
                                # CPU usage is returned as percentage * 100 (e.g., 150 = 1.5%)
                                cpu_usage_percent = round(
                                    perf_vals[cpu_usage_counter] / 100.0, 1
                                )

                            if mem_active_counter in perf_vals:
                                active_memory_kb = perf_vals[mem_active_counter]

                            if mem_consumed_counter in perf_vals:
                                consumed_memory_kb = perf_vals[mem_consumed_counter]

                    except Exception as e:
                        logger.debug(f"Performance query failed for VM {vm.name}: {e}")

                    # Fallback to quickStats if performance counters fail
                    if cpu_usage_percent is None:
                        # Calculate CPU percentage from quickStats
                        cpu_mhz = getattr(qs, "overallCpuUsage", None)
                        if cpu_mhz and vm_stat["cpu_cores"]:
                            # Estimate CPU percentage (very rough approximation)
                            # This assumes host CPU frequency, which isn't perfect
                            host_cpu_mhz = host_info.get(
                                "cpu_mhz_per_core", 2400
                            )  # Default fallback
                            max_vm_mhz = vm_stat["cpu_cores"] * host_cpu_mhz
                            if max_vm_mhz > 0:
                                cpu_usage_percent = round(
                                    (cpu_mhz / max_vm_mhz) * 100, 1
                                )

                    # Use active memory if available, otherwise fall back to consumed or host memory
                    memory_usage_kb = None
                    if active_memory_kb is not None:
                        memory_usage_kb = active_memory_kb
                    elif consumed_memory_kb is not None:
                        memory_usage_kb = consumed_memory_kb
                    else:
                        # Fallback to quickStats
                        mem_host_mb = getattr(qs, "hostMemoryUsage", None)
                        mem_guest_mb = getattr(qs, "guestMemoryUsage", None)
                        mem_mb = (
                            mem_host_mb if mem_host_mb is not None else mem_guest_mb
                        )
                        if mem_mb is not None:
                            memory_usage_kb = mem_mb * 1024

                    vm_stat.update(
                        {
                            "cpu_usage_percent": cpu_usage_percent,
                            "memory_usage_kb": memory_usage_kb,
                            "memory_usage_mb": round(memory_usage_kb / 1024, 1)
                            if memory_usage_kb
                            else None,
                            "active_memory_mb": round(active_memory_kb / 1024, 1)
                            if active_memory_kb
                            else None,
                        }
                    )

                    # Only add VMs with meaningful data
                    if cpu_usage_percent is not None or memory_usage_kb is not None:
                        vm_stats.append(vm_stat)

                except Exception as e:
                    logger.warning(f"Error collecting VM stats for {vm.name}: {e}")
                    continue

            # Sort and get top VMs
            # Top VMs by CPU Usage (percentage)
            vms_with_cpu = [
                v for v in vm_stats if v.get("cpu_usage_percent") is not None
            ]
            top_cpu = sorted(
                vms_with_cpu, key=lambda x: x["cpu_usage_percent"], reverse=True
            )[:top_n]

            # Top VMs by Active Memory (MB)
            vms_with_memory = [
                v for v in vm_stats if v.get("memory_usage_mb") is not None
            ]
            top_memory = sorted(
                vms_with_memory, key=lambda x: x["memory_usage_mb"], reverse=True
            )[:top_n]

            # Add to host info
            host_info.update(
                {
                    "top_vms_cpu_percent": top_cpu,
                    "top_vms_active_memory_mb": top_memory,  # Changed from top_vms_memory_mb
                    "detailed": True,
                    "performance_data_source": "performance_counters"
                    if counter_map
                    else "quickstats_fallback",
                }
            )

            logger.info(
                f"Retrieved detailed host info for {host_name} with {len(vm_stats)} VMs analyzed"
            )
            return host_info

        except Exception as e:
            logger.error(f"Error getting detailed host info for {host_name}: {e}")
            return None


# -----------------------------------------------------------------------------
# Convenience wrapper functions
# -----------------------------------------------------------------------------


def get_vm_info_by_name(vcenter_client: VCenterClient, vm_name: str) -> Optional[Dict]:
    """Wrapper to get VM info by name."""
    try:
        service_instance = vcenter_client.get_instance()
        return VMwareTask.get_vm_info(service_instance, vm_name)
    except Exception as e:
        logger.error(f"Error in get_vm_info_by_name: {e}")
        return None


def get_vm_info_by_ipv4(
    vcenter_client: VCenterClient, ipv4_address: str
) -> Optional[Dict]:
    """Wrapper to get VM info by IPv4."""
    try:
        service_instance = vcenter_client.get_instance()
        return VMwareTask.get_ipv4_info(service_instance, ipv4_address)
    except Exception as e:
        logger.error(f"Error in get_vm_info_by_ipv4: {e}")
        return None


def get_vm_events_by_name(
    vcenter_client: VCenterClient, vm_name: str, limit: int = 10
) -> Dict:
    """Wrapper to get VM events by name."""
    try:
        service_instance = vcenter_client.get_instance()
        return VMwareTask.get_vm_events(service_instance, vm_name, limit)
    except Exception as e:
        logger.error(f"Error in get_vm_events wrapper for '{vm_name}': {e}")
        return {"error": str(e), "vm_name": vm_name}


def find_vms_by_keyword(vcenter_client: VCenterClient, keyword: str) -> List[str]:
    """Wrapper to find VM names by keyword."""
    try:
        service_instance = vcenter_client.get_instance()
        return VMwareTask.find_vm_by_keyword(service_instance, keyword)
    except Exception as e:
        logger.error(f"Error in find_vms_by_keyword: {e}")
        return []


def get_host_info_by_name(
    vcenter_client: VCenterClient, host_name: str, detailed: bool = False
) -> Optional[Dict]:
    """Wrapper to get host info by name."""
    try:
        service_instance = vcenter_client.get_instance()
        if detailed:
            return VMwareTask.get_host_detailed_info(service_instance, host_name)
        else:
            return VMwareTask.get_host_basic_info(service_instance, host_name)
    except Exception as e:
        logger.error(f"Error in get_host_info_by_name: {e}")
        return None
