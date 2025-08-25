from __future__ import annotations

import time
import redis
import logging
from typing import Dict, Any, List, Optional

from cache.redis_index import KEY_DOC, KEY_STATS, INDEX_NAME, get_cache_statistics

logger = logging.getLogger(__name__)

def flush_all_cache(r: redis.Redis, host: str) -> Dict[str, Any]:
    """
    Clear ALL VM cache for a host.
    """
    try:
        start_time = time.time()
        
        # Get current stats before flush
        pre_stats = get_basic_cache_stats(r, host)
        
        # Pattern for VM documents
        vm_pattern = f"vc:{host}:vm:*"
        vm_keys = r.keys(vm_pattern)
        
        # Pattern for stats
        stats_pattern = f"vc:{host}:stats"
        
        deleted_count = 0
        
        # Delete VM documents in batches
        if vm_keys:
            batch_size = 1000
            for i in range(0, len(vm_keys), batch_size):
                batch = vm_keys[i:i + batch_size]
                deleted_count += r.delete(*batch)
        
        # Delete stats
        stats_deleted = r.delete(stats_pattern)
        
        # Rebuild index to clear it
        try:
            from cache.redis_index import rebuild_vm_index
            rebuild_vm_index(r, host)
        except Exception as e:
            logger.warning(f"Could not rebuild index after flush: {e}")
        
        elapsed_time = time.time() - start_time
        
        result = {
            "success": True,
            "vm_documents_deleted": deleted_count,
            "stats_deleted": stats_deleted,
            "total_keys_before": pre_stats.get("total_keys", 0),
            "elapsed_seconds": round(elapsed_time, 2),
            "message": f"Cleared {deleted_count} VM documents for host {host}"
        }
        
        logger.info(f"Cache flush completed for {host}: {deleted_count} documents deleted in {elapsed_time:.2f}s")
        return result
        
    except Exception as e:
        logger.error(f"Error flushing cache for host {host}: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Failed to flush cache: {e}"
        }

def get_cache_stats(r: redis.Redis, host: str) -> Dict[str, Any]:
    """
    Get basic cache statistics for a host.
    """
    try:
        # Use enhanced stats if available
        try:
            return get_cache_statistics(r, host)
        except ImportError:
            return get_basic_cache_stats(r, host)
            
    except Exception as e:
        logger.error(f"Error getting cache stats for host {host}: {e}")
        return {
            "error": str(e),
            "host": host,
            "timestamp": int(time.time())
        }

def get_basic_cache_stats(r: redis.Redis, host: str) -> Dict[str, Any]:
    """Get basic cache statistics without enhanced features."""
    try:
        # Count VM documents
        vm_pattern = f"vc:{host}:vm:*"
        vm_keys = r.keys(vm_pattern)
        total_keys = len(vm_keys)
        
        # Get basic stats from hash if it exists
        stats_key = KEY_STATS(host)
        stats = r.hgetall(stats_key)
        
        # Memory usage estimation (rough)
        memory_usage = "N/A"
        if vm_keys:
            try:
                # Sample a few keys to estimate memory usage
                sample_size = min(10, len(vm_keys))
                total_memory = 0
                
                for key in vm_keys[:sample_size]:
                    memory_info = r.memory_usage(key)
                    if memory_info:
                        total_memory += memory_info
                
                # Extrapolate to all keys
                if total_memory > 0:
                    avg_memory = total_memory / sample_size
                    estimated_total = (avg_memory * total_keys) / (1024 * 1024)  # MB
                    memory_usage = f"{estimated_total:.2f} MB"
                    
            except Exception as e:
                logger.debug(f"Could not estimate memory usage: {e}")
        
        # Get oldest and newest entries
        oldest_entry = None
        newest_entry = None
        
        if vm_keys:
            try:
                timestamps = []
                for key in vm_keys[:20]:  # Sample first 20 keys
                    doc = r.json().get(key)
                    if doc and doc.get("updated_at"):
                        timestamps.append((doc["updated_at"], doc.get("name", key)))
                
                if timestamps:
                    timestamps.sort(key=lambda x: x[0])
                    oldest_time, oldest_name = timestamps[0]
                    newest_time, newest_name = timestamps[-1]
                    
                    oldest_entry = f"{oldest_name} ({time.strftime('%Y-%m-%d %H:%M', time.localtime(oldest_time))})"
                    newest_entry = f"{newest_name} ({time.strftime('%Y-%m-%d %H:%M', time.localtime(newest_time))})"
                    
            except Exception as e:
                logger.debug(f"Could not determine oldest/newest entries: {e}")
        
        # Calculate hit rate
        total_hits = int(stats.get("total_hit", 0))
        total_misses = int(stats.get("total_miss", 0))
        total_requests = total_hits + total_misses
        hit_rate = f"{(total_hits / total_requests * 100):.1f}" if total_requests > 0 else "0.0"
        
        return {
            "host": host,
            "total_keys": total_keys,
            "memory_usage": memory_usage,
            "hit_rate": hit_rate,
            "total_hits": total_hits,
            "total_misses": total_misses,
            "total_upserts": int(stats.get("total_upsert", 0)),
            "last_access": stats.get("last_access", "Never"),
            "oldest_entry": oldest_entry or "N/A",
            "newest_entry": newest_entry or "N/A",
            "timestamp": int(time.time())
        }
        
    except Exception as e:
        logger.error(f"Error getting basic cache stats: {e}")
        return {
            "error": str(e),
            "host": host,
            "timestamp": int(time.time())
        }

def cleanup_expired_entries(r: redis.Redis, host: str, max_age_hours: int = 24) -> Dict[str, Any]:
    """
    Clean up expired cache entries older than specified hours.
    """
    try:
        start_time = time.time()
        cutoff_timestamp = int(time.time() - (max_age_hours * 3600))
        
        vm_pattern = f"vc:{host}:vm:*"
        vm_keys = r.keys(vm_pattern)
        
        expired_keys = []
        checked_count = 0
        
        # Check each key for expiration
        for key in vm_keys:
            try:
                doc = r.json().get(key)
                if doc and doc.get("updated_at", 0) < cutoff_timestamp:
                    expired_keys.append(key)
                checked_count += 1
            except Exception as e:
                logger.debug(f"Error checking key {key}: {e}")
        
        # Delete expired keys in batches
        deleted_count = 0
        if expired_keys:
            batch_size = 100
            for i in range(0, len(expired_keys), batch_size):
                batch = expired_keys[i:i + batch_size]
                deleted_count += r.delete(*batch)
        
        elapsed_time = time.time() - start_time
        
        result = {
            "success": True,
            "checked_keys": checked_count,
            "expired_keys_found": len(expired_keys),
            "deleted_keys": deleted_count,
            "max_age_hours": max_age_hours,
            "elapsed_seconds": round(elapsed_time, 2),
            "message": f"Cleaned up {deleted_count} expired entries (older than {max_age_hours}h)"
        }
        
        logger.info(f"Cache cleanup for {host}: {deleted_count}/{len(expired_keys)} expired keys deleted")
        return result
        
    except Exception as e:
        logger.error(f"Error during cache cleanup for host {host}: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Cleanup failed: {e}"
        }

def get_cache_health(r: redis.Redis, host: str) -> Dict[str, Any]:
    """
    Get cache health information including key distribution and potential issues.
    """
    try:
        stats = get_cache_stats(r, host)
        
        vm_pattern = f"vc:{host}:vm:*"
        vm_keys = r.keys(vm_pattern)
        
        health_score = 100
        issues = []
        recommendations = []
        
        # Check total key count
        total_keys = len(vm_keys)
        if total_keys > 10000:
            health_score -= 10
            issues.append("High key count may impact performance")
            recommendations.append("Consider implementing periodic cleanup")
        
        # Check hit rate
        hit_rate = float(stats.get("hit_rate", 0))
        if hit_rate < 50:
            health_score -= 20
            issues.append("Low cache hit rate")
            recommendations.append("Review cache TTL settings or query patterns")
        elif hit_rate > 95:
            recommendations.append("Excellent hit rate - cache is working well")
        
        # Check for very old entries
        current_time = int(time.time())
        old_entries = 0
        
        if total_keys > 0:
            sample_size = min(50, total_keys)
            for key in vm_keys[:sample_size]:
                try:
                    doc = r.json().get(key)
                    if doc and doc.get("updated_at", current_time) < (current_time - 86400):  # 24h old
                        old_entries += 1
                except Exception:
                    pass
            
            old_percentage = (old_entries / sample_size) * 100
            if old_percentage > 30:
                health_score -= 15
                issues.append(f"{old_percentage:.1f}% of sampled entries are over 24h old")
                recommendations.append("Run cleanup_expired_entries() to remove stale data")
        
        # Memory usage check (if available)
        memory_usage = stats.get("memory_usage", "N/A")
        if isinstance(memory_usage, str) and "MB" in memory_usage:
            try:
                mem_mb = float(memory_usage.replace(" MB", ""))
                if mem_mb > 500:  # 500MB threshold
                    health_score -= 10
                    issues.append("High memory usage")
                    recommendations.append("Consider reducing cache TTL or running cleanup")
            except ValueError:
                pass
        
        # Determine health status
        if health_score >= 90:
            status = "Excellent"
        elif health_score >= 80:
            status = "Good"
        elif health_score >= 70:
            status = "Fair"
        elif health_score >= 60:
            status = "Poor"
        else:
            status = "Critical"
        
        return {
            "host": host,
            "health_score": max(0, health_score),
            "status": status,
            "total_keys": total_keys,
            "hit_rate": hit_rate,
            "issues": issues,
            "recommendations": recommendations,
            "timestamp": current_time,
            "memory_usage": memory_usage,
        }
        
    except Exception as e:
        logger.error(f"Error getting cache health for host {host}: {e}")
        return {
            "host": host,
            "health_score": 0,
            "status": "Error",
            "error": str(e),
            "timestamp": int(time.time())
        }
