from __future__ import annotations

import time
import redis
import logging
from typing import Dict, Any, List, Optional, Union
from redis.commands.search.field import TextField, TagField, NumericField
from redis.commands.search.index_definition import IndexDefinition, IndexType
from redis.commands.search.query import Query
from redis.commands.json.path import Path

logger = logging.getLogger(__name__)

# Key patterns
KEY_DOC = lambda host, moid: f"vc:{host}:vm:{moid}"
KEY_STATS = lambda host: f"vc:{host}:stats"
INDEX_NAME = lambda host: f"idx:vc:{host}:vm"

# Index field definitions
INDEX_FIELDS = [
    TextField("$.name_lc", as_name="name"),
    TextField("$.dns", as_name="dns"),
    TagField("$.ip", as_name="ip"),
    TagField("$.moid", as_name="moid"),
    TagField("$.vm_uuid", as_name="vm_uuid"),
    TagField("$.instance_uuid", as_name="instance_uuid"),
    TextField("$.guest_os", as_name="guest_os"),
    TextField("$.host_name", as_name="host_name"),
    TagField("$.power_state", as_name="power_state"),
    NumericField("$.cpu_cores", as_name="cpu_cores"),
    NumericField("$.ram_size_gb", as_name="ram_size_gb"),
    NumericField("$.updated_at", as_name="updated_at"),
    NumericField("$.uptime_s", as_name="uptime_s"),
    TextField("$.annotation", as_name="annotation"),
]


def connect(
    url: Optional[str] = None,
    host: str = "localhost",
    port: int = 6379,
    db: int = 0,
    decode_responses: bool = True,
) -> redis.Redis:
    """Create Redis connection."""
    try:
        if url:
            client = redis.from_url(url, decode_responses=decode_responses)
        else:
            client = redis.Redis(
                host=host, port=port, db=db, decode_responses=decode_responses
            )

        # Test connection
        client.ping()
        logger.info("Redis connection established")
        return client
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}")
        raise


def create_vm_index(r: redis.Redis, host: str) -> bool:
    """Create enhanced index with MOID, UUID fields and other improvements."""
    idx_name = INDEX_NAME(host)

    try:
        # Check if index already exists
        try:
            info = r.ft(idx_name).info()
            logger.info(f"Index {idx_name} already exists")
            return True
        except Exception:
            pass

        # Create new index
        r.ft(idx_name).create_index(
            fields=INDEX_FIELDS,
            definition=IndexDefinition(
                prefix=[f"vc:{host}:vm:"], index_type=IndexType.JSON
            ),
        )

        logger.info(f"Created enhanced VM index: {idx_name}")
        return True

    except Exception as e:
        logger.error(f"Error creating enhanced VM index: {e}")
        return False


def ensure_vm_index(r: redis.Redis, host: str) -> None:
    """Ensure VM index exists (backward compatible with original function)."""
    create_vm_index(r, host)


def search_by_moid(r: redis.Redis, host: str, moid: str) -> Optional[Dict[str, Any]]:
    """Search by MOID (Managed Object ID)."""
    try:
        q = Query(f"@moid:{{{moid}}}").paging(0, 1)
        res = r.ft(INDEX_NAME(host)).search(q)

        if res.total > 0:
            return r.json().get(res.docs[0].id)
        return None

    except Exception as e:
        logger.error(f"Error searching by MOID {moid}: {e}")
        return None


def search_by_uuid(
    r: redis.Redis, host: str, uuid: str, uuid_type: str = "any"
) -> List[Dict[str, Any]]:
    """
    Search by UUID (VM UUID or Instance UUID).
    """
    try:
        if uuid_type == "vm":
            query_str = f"@vm_uuid:{{{uuid}}}"
        elif uuid_type == "instance":
            query_str = f"@instance_uuid:{{{uuid}}}"
        else:  # any
            query_str = f"(@vm_uuid:{{{uuid}}} | @instance_uuid:{{{uuid}}})"

        q = Query(query_str).paging(0, 10)
        res = r.ft(INDEX_NAME(host)).search(q)

        return [r.json().get(doc.id) for doc in res.docs]

    except Exception as e:
        logger.error(f"Error searching by UUID {uuid}: {e}")
        return []


def search_by_power_state(
    r: redis.Redis, host: str, power_state: str, limit: int = 50
) -> List[Dict[str, Any]]:
    """Search VMs by power state."""
    try:
        q = Query(f"@power_state:{{{power_state}}}").paging(0, limit)
        res = r.ft(INDEX_NAME(host)).search(q)

        return [r.json().get(doc.id) for doc in res.docs]

    except Exception as e:
        logger.error(f"Error searching by power state {power_state}: {e}")
        return []


def search_by_host(
    r: redis.Redis, host: str, esxi_host: str, limit: int = 50
) -> List[Dict[str, Any]]:
    """Search VMs by ESXi host."""
    try:
        q = Query(f'@host_name:"{esxi_host}"').paging(0, limit)
        res = r.ft(INDEX_NAME(host)).search(q)

        return [r.json().get(doc.id) for doc in res.docs]

    except Exception as e:
        logger.error(f"Error searching by host {esxi_host}: {e}")
        return []


def search_by_resource_range(
    r: redis.Redis,
    host: str,
    min_cpu: Optional[int] = None,
    max_cpu: Optional[int] = None,
    min_ram: Optional[float] = None,
    max_ram: Optional[float] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Search VMs by resource ranges (CPU cores, RAM GB)."""
    try:
        conditions = []

        if min_cpu is not None:
            conditions.append(f"@cpu_cores:[{min_cpu} +inf]")
        if max_cpu is not None:
            conditions.append(f"@cpu_cores:[-inf {max_cpu}]")
        if min_ram is not None:
            conditions.append(f"@ram_size_gb:[{min_ram} +inf]")
        if max_ram is not None:
            conditions.append(f"@ram_size_gb:[-inf {max_ram}]")

        if not conditions:
            return []

        query_str = " ".join(conditions)
        q = Query(query_str).paging(0, limit)
        res = r.ft(INDEX_NAME(host)).search(q)

        return [r.json().get(doc.id) for doc in res.docs]

    except Exception as e:
        logger.error(f"Error searching by resource range: {e}")
        return []


def advanced_search(
    r: redis.Redis,
    host: str,
    name_pattern: Optional[str] = None,
    ip_address: Optional[str] = None,
    power_state: Optional[str] = None,
    guest_os_pattern: Optional[str] = None,
    esxi_host: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Advanced search with multiple criteria."""
    try:
        conditions = []

        if name_pattern:
            conditions.append(f"@name:*{name_pattern.lower()}*")
        if ip_address:
            conditions.append(f"@ip:{{{ip_address}}}")
        if power_state:
            conditions.append(f"@power_state:{{{power_state}}}")
        if guest_os_pattern:
            conditions.append(f'@guest_os:"{guest_os_pattern}"')
        if esxi_host:
            conditions.append(f'@host_name:"{esxi_host}"')

        if not conditions:
            return []

        query_str = " ".join(conditions)
        q = Query(query_str).paging(0, limit)
        res = r.ft(INDEX_NAME(host)).search(q)

        return [r.json().get(doc.id) for doc in res.docs]

    except Exception as e:
        logger.error(f"Error in advanced search: {e}")
        return []


def rebuild_vm_index(r: redis.Redis, host: str) -> bool:
    """Rebuild entire index (useful after schema changes)."""
    idx_name = INDEX_NAME(host)

    try:
        # Drop existing index
        try:
            r.ft(idx_name).dropindex(delete_documents=False)
            logger.info(f"Dropped existing index: {idx_name}")
        except Exception as e:
            logger.debug(f"Index {idx_name} didn't exist or couldn't be dropped: {e}")

        # Recreate with enhanced schema
        success = create_vm_index(r, host)

        if success:
            logger.info(f"Successfully rebuilt index: {idx_name}")
        else:
            logger.error(f"Failed to rebuild index: {idx_name}")

        return success

    except Exception as e:
        logger.error(f"Error rebuilding index: {e}")
        return False


def update_index_schema(r: redis.Redis, host: str) -> bool:
    """Update index with new fields (tries to preserve existing data)."""
    idx_name = INDEX_NAME(host)

    try:
        # Check current index info
        try:
            current_info = r.ft(idx_name).info()
            current_fields = [field[1] for field in current_info["attributes"]]
            logger.info(f"Current index has {len(current_fields)} fields")
        except Exception:
            logger.info("Index doesn't exist, creating new one")
            return create_vm_index(r, host)

        # For now, we rebuild the index since Redis Search doesn't support
        # adding fields to existing indexes easily
        return rebuild_vm_index(r, host)

    except Exception as e:
        logger.error(f"Error updating index schema: {e}")
        return False


def upsert_vm_doc(
    r: redis.Redis, host: str, doc: Dict[str, Any], ttl: Optional[int] = None
) -> str:
    """Enhanced upsert with additional fields."""
    if not doc.get("moid"):
        raise ValueError("doc must contain 'moid'")
    if not doc.get("name"):
        raise ValueError("doc must contain 'name'")

    # Prepare document
    doc = dict(doc)
    doc.setdefault("updated_at", int(time.time()))
    doc["name_lc"] = doc["name"].lower()

    # Ensure we have UUIDs (even if empty)
    doc.setdefault("vm_uuid", "")
    doc.setdefault("instance_uuid", "")
    doc.setdefault("annotation", "")

    key = KEY_DOC(host, doc["moid"])

    try:
        r.json().set(key, Path.root_path(), doc)

        if ttl:
            r.expire(key, ttl)

        # Update stats
        _update_cache_stats(r, host, "upsert")

        return key

    except Exception as e:
        logger.error(f"Error upserting VM doc: {e}")
        raise


def get_doc(r: redis.Redis, host: str, moid: str) -> Optional[Dict[str, Any]]:
    """Get document by MOID."""
    try:
        doc = r.json().get(KEY_DOC(host, moid))
        if doc:
            _update_cache_stats(r, host, "hit")
        else:
            _update_cache_stats(r, host, "miss")
        return doc
    except Exception as e:
        logger.error(f"Error getting doc {moid}: {e}")
        _update_cache_stats(r, host, "miss")
        return None


def search_by_ip(
    r: redis.Redis, host: str, ip: str, limit: int = 5
) -> List[Dict[str, Any]]:
    """Search by IP address."""
    try:
        q = Query(f"@ip:{{{ip}}}").paging(0, limit)
        res = r.ft(INDEX_NAME(host)).search(q)

        results = [r.json().get(doc.id) for doc in res.docs]
        _update_cache_stats(r, host, "hit" if results else "miss")
        return results

    except Exception as e:
        logger.error(f"Error searching by IP {ip}: {e}")
        _update_cache_stats(r, host, "miss")
        return []


def search_by_exact_name(
    r: redis.Redis, host: str, name: str
) -> Optional[Dict[str, Any]]:
    """Search by exact VM name."""
    try:
        q = Query(f'@name:"{name.lower()}"').paging(0, 1)
        res = r.ft(INDEX_NAME(host)).search(q)

        if res.total > 0:
            result = r.json().get(res.docs[0].id)
            _update_cache_stats(r, host, "hit")
            return result

        _update_cache_stats(r, host, "miss")
        return None

    except Exception as e:
        logger.error(f"Error searching by exact name {name}: {e}")
        _update_cache_stats(r, host, "miss")
        return None


def search_by_keyword(
    r: redis.Redis, host: str, kw: str, limit: int = 50
) -> List[Dict[str, Any]]:
    """Search by keyword in VM name."""
    try:
        q = Query(f"@name:*{kw.lower()}*").paging(0, limit)
        res = r.ft(INDEX_NAME(host)).search(q)

        results = [r.json().get(doc.id) for doc in res.docs]
        _update_cache_stats(r, host, "hit" if results else "miss")
        return results

    except Exception as e:
        logger.error(f"Error searching by keyword {kw}: {e}")
        _update_cache_stats(r, host, "miss")
        return []


def _update_cache_stats(r: redis.Redis, host: str, operation: str) -> None:
    """Update cache statistics."""
    try:
        stats_key = KEY_STATS(host)
        current_time = int(time.time())

        # Use pipeline for atomic updates
        pipe = r.pipeline()
        pipe.hincrby(stats_key, f"total_{operation}", 1)
        pipe.hset(stats_key, "last_access", current_time)
        pipe.expire(stats_key, 86400)  # Expire stats after 24h
        pipe.execute()

    except Exception as e:
        logger.debug(f"Error updating cache stats: {e}")


def get_index_info(r: redis.Redis, host: str) -> Optional[Dict[str, Any]]:
    """Get Redis Search index information."""
    try:
        idx_name = INDEX_NAME(host)
        info = r.ft(idx_name).info()

        return {
            "index_name": idx_name,
            "num_docs": info.get("num_docs", 0),
            "num_terms": info.get("num_terms", 0),
            "num_records": info.get("num_records", 0),
            "inverted_sz_mb": info.get("inverted_sz_mb", 0),
            "vector_index_sz_mb": info.get("vector_index_sz_mb", 0),
            "total_inverted_index_blocks": info.get("total_inverted_index_blocks", 0),
            "offset_vectors_sz_mb": info.get("offset_vectors_sz_mb", 0),
            "doc_table_size_mb": info.get("doc_table_size_mb", 0),
            "key_table_size_mb": info.get("key_table_size_mb", 0),
        }

    except Exception as e:
        logger.error(f"Error getting index info: {e}")
        return None


def _to_float(v, default=0.0):
    try:
        if v is None:
            return default
        return float(v)
    except Exception:
        return default


def get_cache_statistics(r: redis.Redis, host: str) -> Dict[str, Any]:
    try:
        stats_key = KEY_STATS(host)
        index_info = get_index_info(r, host)

        stats = r.hgetall(stats_key)

        pattern = f"vc:{host}:vm:*"

        total_keys = sum(1 for _ in r.scan_iter(pattern))

        total_hits = int(stats.get("total_hit", 0))
        total_misses = int(stats.get("total_miss", 0))
        total_requests = total_hits + total_misses
        hit_rate = (total_hits / total_requests * 100) if total_requests > 0 else 0.0

        result = {
            "total_keys": total_keys,
            "total_hits": total_hits,
            "total_misses": total_misses,
            "hit_rate": f"{hit_rate:.1f}",
            "total_upserts": int(stats.get("total_upsert", 0)),
            "last_access": stats.get("last_access", "Never"),
        }

        if index_info:
            inv = _to_float(index_info.get("inverted_sz_mb"))
            doc = _to_float(index_info.get("doc_table_size_mb"))
            key = _to_float(index_info.get("key_table_size_mb"))
            result.update(
                {
                    "index_docs": int(_to_float(index_info.get("num_docs"), 0)),
                    "index_size_mb": round(inv + doc + key, 2),
                }
            )

        return result
    except Exception as e:
        logger.error(f"Error getting cache statistics: {e}")
        return {"error": str(e)}
