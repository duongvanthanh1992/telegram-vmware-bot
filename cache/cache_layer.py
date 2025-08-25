from __future__ import annotations

import json
import time
import asyncio
from typing import Optional, List, Dict, Any
from redis.exceptions import LockError
from cache.redis_index import (
    search_by_exact_name,
    search_by_ip,
    search_by_keyword,
    upsert_vm_doc,
    ensure_vm_index,
)
from vcenter.vcenter_task import VMwareTask

import logging

logger = logging.getLogger(__name__)

LOCK_KEY = lambda host, k: f"lock:{host}:{k}"


def _prepare_vm_doc_for_cache(
        vm_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prepare VM info for caching by ensuring all fields are serializable
    and adding required metadata.
    """
    if not vm_info:
        return {}

    # Create a copy to avoid modifying original data
    doc = dict(vm_info)

    # Ensure required fields exist
    doc.setdefault("moid", vm_info.get("name", "").lower())
    doc.setdefault("name", "")
    doc.setdefault("updated_at", int(time.time()))

    # Ensure searchable fields are present
    doc["name_lc"] = doc["name"].lower()
    doc.setdefault("ip", vm_info.get("ip_address"))  # For compatibility
    doc.setdefault("vm_uuid", "")
    doc.setdefault("instance_uuid", "")
    doc.setdefault("annotation", "")

    # Convert complex objects to serializable format
    if "power_state" in doc and doc["power_state"]:
        doc["power_state"] = str(doc["power_state"])

    # Ensure numeric fields are properly typed
    numeric_fields = [
        "cpu_cores",
        "ram_size_gb",
        "uptime_s",
        "cpu_mhz",
        "mem_guest_mb",
        "mem_mb",
    ]
    for field in numeric_fields:
        if field in doc and doc[field] is not None:
            try:
                doc[field] = float(doc[field])
            except (ValueError, TypeError):
                doc[field] = None

    # Ensure lists are properly formatted
    list_fields = ["ipv4_addresses", "nics", "disks"]
    for field in list_fields:
        if field not in doc:
            doc[field] = []
        elif not isinstance(doc[field], list):
            doc[field] = []

    return doc


async def get_vm_info_by_name_cached_async(
    r, vcenter_client, name: str, ttl: int = 180
) -> Optional[Dict[str, Any]]:
    """
    Caches FULL VM data, not just basic fields.
    """
    host = vcenter_client.host
    ensure_vm_index(r, host)

    # Try cache first
    cached = search_by_exact_name(r, host, name)
    if cached:
        logger.debug(f"Cache HIT for VM: {name}")
        return cached

    logger.debug(f"Cache MISS for VM: {name}")

    # Prevent thundering herd with distributed lock
    lock_key = LOCK_KEY(host, f"name:{name.lower()}")
    have_lock = r.set(lock_key, "1", nx=True, px=10_000)  # 10 second lock

    try:
        if have_lock:
            logger.debug(f"Acquired lock for VM: {name}")

            # Fetch FULL data from vCenter
            info = await asyncio.to_thread(
                VMwareTask.get_vm_info, vcenter_client.get_instance(), name
            )

            if info:
                # Prepare full document for caching
                doc = _prepare_vm_doc_for_cache(info)

                # Cache the COMPLETE VM data
                upsert_vm_doc(r, host, doc, ttl=ttl)

                logger.info(f"Cached full VM data for: {name}")
                return info
            else:
                logger.warning(f"VM not found in vCenter: {name}")
                return None
        else:
            # Wait briefly and retry (another process is fetching)
            logger.debug(f"Lock busy for VM: {name}, waiting...")
            await asyncio.sleep(0.2)
            return await get_vm_info_by_name_cached_async(r, vcenter_client, name, ttl)

    except Exception as e:
        logger.error(f"Error in get_vm_info_by_name_cached_async for {name}: {e}")
        # Fallback to direct vCenter call
        try:
            info = await asyncio.to_thread(
                VMwareTask.get_vm_info, vcenter_client.get_instance(), name
            )
            return info
        except Exception as fallback_e:
            logger.error(f"Fallback also failed for {name}: {fallback_e}")
            return None
    finally:
        if have_lock:
            try:
                r.delete(lock_key)
                logger.debug(f"Released lock for VM: {name}")
            except Exception as e:
                logger.warning(f"Failed to release lock for {name}: {e}")


async def get_vm_info_by_ip_cached_async(
    r, vcenter_client, ip: str, ttl: int = 180
) -> Optional[Dict[str, Any]]:
    """
    IP search with full data caching.
    """
    host = vcenter_client.host
    ensure_vm_index(r, host)

    # Search in cache first
    found = search_by_ip(r, host, ip, limit=1)
    if found:
        logger.debug(f"Cache HIT for IP: {ip}")
        return found[0]

    logger.debug(f"Cache MISS for IP: {ip}")

    lock_key = LOCK_KEY(host, f"ip:{ip}")
    have_lock = r.set(lock_key, "1", nx=True, px=10_000)

    try:
        if have_lock:
            logger.debug(f"Acquired lock for IP: {ip}")

            # Use vCenter search index for IP lookup
            si = vcenter_client.get_instance()
            vm = await asyncio.to_thread(
                si.content.searchIndex.FindByIp, None, ip, True
            )

            if not vm:
                logger.warning(f"No VM found for IP: {ip}")
                return None

            # Get FULL VM info
            info = await asyncio.to_thread(VMwareTask.get_vm_info, si, vm.name)

            if info:
                # Cache complete data
                doc = _prepare_vm_doc_for_cache(info)
                upsert_vm_doc(r, host, doc, ttl=ttl)

                logger.info(f"Cached full VM data for IP {ip} -> {vm.name}")
                return info
            else:
                logger.error(f"Failed to get full info for VM found by IP {ip}")
                return None
        else:
            # Wait and retry
            await asyncio.sleep(0.2)
            return await get_vm_info_by_ip_cached_async(r, vcenter_client, ip, ttl)

    except Exception as e:
        logger.error(f"Error in get_vm_info_by_ip_cached_async for {ip}: {e}")
        # Fallback to direct vCenter call
        try:
            info = await asyncio.to_thread(
                VMwareTask.get_ipv4_info, vcenter_client.get_instance(), ip
            )
            return info
        except Exception as fallback_e:
            logger.error(f"Fallback failed for IP {ip}: {fallback_e}")
            return None
    finally:
        if have_lock:
            try:
                r.delete(lock_key)
                logger.debug(f"Released lock for IP: {ip}")
            except Exception as e:
                logger.warning(f"Failed to release lock for IP {ip}: {e}")


async def find_vms_by_keyword_cached_async(
    r, vcenter_client, kw: str, limit: int = 60
) -> List[str]:
    """
    Find VMs by keyword. This returns just names, so caching strategy is different.
    We cache the search results temporarily but still rely on individual VM caching.
    """
    host = vcenter_client.host
    ensure_vm_index(r, host)

    # Search in indexed cache first
    docs = search_by_keyword(r, host, kw, limit=limit)
    if docs:
        names = [d.get("name") for d in docs if d and d.get("name")]
        if names:
            logger.debug(f"Cache HIT for keyword search: {kw} ({len(names)} results)")
            return names

    logger.debug(f"Cache MISS for keyword search: {kw}")

    # Fallback to vCenter direct search
    try:
        names = await asyncio.to_thread(
            VMwareTask.find_vm_by_keyword, vcenter_client.get_instance(), kw
        )
        logger.info(f"Found {len(names)} VMs for keyword '{kw}' from vCenter")
        return names[:limit]
    except Exception as e:
        logger.error(f"Error in keyword search for '{kw}': {e}")
        return []


def get_vm_from_cache_only(
        r, host: str, vm_name: str) -> Optional[Dict[str, Any]]:
    """
    Get VM data from cache only (no vCenter fallback).
    Useful for read-only operations or when you want to avoid vCenter calls.
    """
    try:
        ensure_vm_index(r, host)
        return search_by_exact_name(r, host, vm_name)
    except Exception as e:
        logger.error(f"Error reading from cache for {vm_name}: {e}")
        return None


def cache_vm_data_async(
        r, host: str, vm_info: Dict[str, Any], ttl: int = 180) -> bool:
    """
    Manually cache VM data (useful for bulk operations).
    """
    try:
        if not vm_info or not vm_info.get("name"):
            return False

        doc = _prepare_vm_doc_for_cache(vm_info)
        upsert_vm_doc(r, host, doc, ttl=ttl)
        logger.debug(f"Manually cached VM: {vm_info['name']}")
        return True
    except Exception as e:
        logger.error(f"Error manually caching VM data: {e}")
        return False


def _prepare_host_doc_for_cache(
        host_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prepare host info for caching by ensuring all fields are serializable
    and adding required metadata.
    """
    if not host_info:
        return {}

    # Create a copy to avoid modifying original data
    doc = dict(host_info)

    # Ensure required fields exist
    doc.setdefault("updated_at", int(time.time()))
    doc.setdefault("name", "")

    # Ensure numeric fields are properly typed
    numeric_fields = [
        "cpu_cores",
        "cpu_threads",
        "cpu_mhz_per_core",
        "memory_size_gb",
        "cpu_usage_mhz",
        "memory_usage_mb",
        "cpu_total_mhz",
        "cpu_usage_percent",
        "memory_usage_percent",
        "vm_count_total",
        "vm_count_powered_on",
    ]
    for field in numeric_fields:
        if field in doc and doc[field] is not None:
            try:
                doc[field] = (
                    float(doc[field]) if "." in str(doc[field]) else int(doc[field])
                )
            except (ValueError, TypeError):
                doc[field] = None

    # Ensure boolean fields
    boolean_fields = ["in_maintenance_mode"]
    for field in boolean_fields:
        if field in doc:
            doc[field] = bool(doc[field])

    # Ensure string fields
    string_fields = ["vendor", "model", "connection_state"]
    for field in string_fields:
        if field in doc and doc[field] is not None:
            doc[field] = str(doc[field])

    # Handle datetime fields (boot_time)
    if "boot_time" in doc and doc["boot_time"]:
        # Convert datetime to timestamp if needed
        if hasattr(doc["boot_time"], "timestamp"):
            doc["boot_time"] = int(doc["boot_time"].timestamp())

    # Ensure lists are properly formatted
    list_fields = ["top_vms_cpu_percent", "top_vms_active_memory_mb"]
    for field in list_fields:
        if field not in doc:
            doc[field] = []
        elif not isinstance(doc[field], list):
            doc[field] = []

    return doc


async def get_host_info_cached_async(
    r, vcenter_client, host_name: str, detailed: bool = False, ttl: int = 180
) -> Optional[Dict[str, Any]]:
    """
    Get host info with caching - similar to get_vm_info_by_name_cached_async.
    """
    vcenter_host = vcenter_client.host
    cache_key_suffix = f"{host_name.lower()}:{'detailed' if detailed else 'basic'}"

    # Try cache first
    cached = get_host_from_cache_only(r, vcenter_host, cache_key_suffix)
    if cached:
        logger.debug(f"Cache HIT for host: {host_name} (detailed={detailed})")
        return cached

    logger.debug(f"Cache MISS for host: {host_name} (detailed={detailed})")

    # Prevent thundering herd with distributed lock
    lock_key = LOCK_KEY(vcenter_host, f"host:{host_name.lower()}:{detailed}")
    have_lock = r.set(
        lock_key, "1", nx=True, px=15_000
    )  
    # 15 second lock (hosts take longer)

    try:
        if have_lock:
            logger.debug(f"Acquired lock for host: {host_name}")

            # Fetch data from vCenter based on detail level
            if detailed:
                info = await asyncio.to_thread(
                    VMwareTask.get_host_detailed_info,
                    vcenter_client.get_instance(),
                    host_name,
                )
            else:
                info = await asyncio.to_thread(
                    VMwareTask.get_host_basic_info,
                    vcenter_client.get_instance(),
                    host_name,
                )

            if info:
                # Prepare and cache the host data
                doc = _prepare_host_doc_for_cache(info)

                # Use different cache keys for basic vs detailed
                cache_key = f"vc:{vcenter_host}:host:{host_name.lower()}:{'detailed' if detailed else 'basic'}"
                r.setex(cache_key, ttl, json.dumps(doc))

                logger.info(f"Cached host data for: {host_name} (detailed={detailed})")
                return info
            else:
                logger.warning(f"Host not found in vCenter: {host_name}")
                return None
        else:
            # Wait briefly and retry (another process is fetching)
            logger.debug(f"Lock busy for host: {host_name}, waiting...")
            await asyncio.sleep(0.3)
            return await get_host_info_cached_async(
                r, vcenter_client, host_name, detailed, ttl
            )

    except Exception as e:
        logger.error(f"Error in get_host_info_cached_async for {host_name}: {e}")
        # Fallback to direct vCenter call
        try:
            if detailed:
                info = await asyncio.to_thread(
                    VMwareTask.get_host_detailed_info,
                    vcenter_client.get_instance(),
                    host_name,
                )
            else:
                info = await asyncio.to_thread(
                    VMwareTask.get_host_basic_info,
                    vcenter_client.get_instance(),
                    host_name,
                )
            return info
        except Exception as fallback_e:
            logger.error(f"Fallback also failed for host {host_name}: {fallback_e}")
            return None
    finally:
        if have_lock:
            try:
                r.delete(lock_key)
                logger.debug(f"Released lock for host: {host_name}")
            except Exception as e:
                logger.warning(f"Failed to release lock for host {host_name}: {e}")


def get_host_from_cache_only(
    r, host_vcenter: str, host_name: str
) -> Optional[Dict[str, Any]]:
    """
    Get host data from cache only (no vCenter fallback).
    Uses simple key-value storage for hosts since we don't need complex search.
    """
    try:
        cache_key = f"vc:{host_vcenter}:host:{host_name.lower()}"
        cached_data = r.get(cache_key)
        if cached_data:
            return json.loads(cached_data)
        return None
    except Exception as e:
        logger.error(f"Error reading host from cache for {host_name}: {e}")
        return None


def cache_host_data(
    r, host_vcenter: str, host_info: Dict[str, Any], ttl: int = 180
) -> bool:
    """
    Cache host data with TTL (3 minutes default since host data changes less frequently).
    """
    try:
        if not host_info or not host_info.get("name"):
            return False

        doc = _prepare_host_doc_for_cache(host_info)
        cache_key = f"vc:{host_vcenter}:host:{host_info['name'].lower()}"

        r.setex(cache_key, ttl, json.dumps(doc))
        logger.debug(f"Cached host data for: {host_info['name']}")
        return True
    except Exception as e:
        logger.error(f"Error caching host data: {e}")
        return False
