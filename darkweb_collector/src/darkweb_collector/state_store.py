from __future__ import annotations

import os
import time
from typing import Protocol


class StateStore(Protocol):
    def claim_seed_slot(self, site_name: str, ttl_seconds: int) -> bool:
        ...

    def claim_detail(self, site_name: str, target_url: str, ttl_seconds: int) -> bool:
        ...

    def acquire_detail_slot(
        self,
        site_name: str,
        owner: str,
        max_concurrent: int,
        ttl_seconds: int,
    ) -> bool:
        ...

    def release_detail_slot(self, site_name: str, owner: str) -> None:
        ...


class InMemoryStateStore:
    def __init__(self) -> None:
        self._claims: dict[str, float] = {}
        self._detail_slots: dict[str, dict[str, float]] = {}

    def _claim(self, key: str, ttl_seconds: int) -> bool:
        now = time.monotonic()
        expires_at = self._claims.get(key, 0.0)
        if expires_at > now:
            return False
        self._claims[key] = now + max(ttl_seconds, 1)
        return True

    def claim_seed_slot(self, site_name: str, ttl_seconds: int) -> bool:
        return self._claim(f"seed:{site_name}", ttl_seconds)

    def claim_detail(self, site_name: str, target_url: str, ttl_seconds: int) -> bool:
        return self._claim(f"detail:{site_name}:{target_url}", ttl_seconds)

    def acquire_detail_slot(
        self,
        site_name: str,
        owner: str,
        max_concurrent: int,
        ttl_seconds: int,
    ) -> bool:
        now = time.monotonic()
        owners = self._detail_slots.setdefault(site_name, {})
        expired = [key for key, expires_at in owners.items() if expires_at <= now]
        for key in expired:
            owners.pop(key, None)
        if owner in owners:
            owners[owner] = now + max(ttl_seconds, 1)
            return True
        if len(owners) >= max(max_concurrent, 1):
            return False
        owners[owner] = now + max(ttl_seconds, 1)
        return True

    def release_detail_slot(self, site_name: str, owner: str) -> None:
        owners = self._detail_slots.get(site_name)
        if owners is None:
            return
        owners.pop(owner, None)
        if not owners:
            self._detail_slots.pop(site_name, None)


class RedisStateStore:
    def __init__(self, redis_url: str | None = None) -> None:
        self._redis_url = redis_url or os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")
        try:
            import redis
        except ImportError as exc:
            raise RuntimeError("redis package is required for Redis-backed queue state") from exc
        self._client = redis.Redis.from_url(
            self._redis_url,
            decode_responses=True,
            socket_connect_timeout=3,
            socket_timeout=5,
            retry_on_timeout=False,
        )

    def _claim(self, key: str, ttl_seconds: int) -> bool:
        return bool(self._client.set(key, "1", nx=True, ex=max(ttl_seconds, 1)))

    def claim_seed_slot(self, site_name: str, ttl_seconds: int) -> bool:
        return self._claim(f"darkweb:seed:{site_name}", ttl_seconds)

    def claim_detail(self, site_name: str, target_url: str, ttl_seconds: int) -> bool:
        return self._claim(f"darkweb:detail:{site_name}:{target_url}", ttl_seconds)

    @staticmethod
    def _detail_slot_key(site_name: str) -> str:
        return f"darkweb:detail-slot:{site_name}"

    def acquire_detail_slot(
        self,
        site_name: str,
        owner: str,
        max_concurrent: int,
        ttl_seconds: int,
    ) -> bool:
        from redis.exceptions import ConnectionError, TimeoutError, WatchError

        key = self._detail_slot_key(site_name)
        ttl = max(ttl_seconds, 1)
        while True:
            now = time.time()
            expires_at = now + ttl
            with self._client.pipeline() as pipeline:
                try:
                    pipeline.watch(key)
                    rows = pipeline.zrange(key, 0, -1, withscores=True)
                    active_owners = {str(member) for member, score in rows if float(score) > now}
                    expired_owners = [str(member) for member, score in rows if float(score) <= now]
                    if owner not in active_owners and len(active_owners) >= max(max_concurrent, 1):
                        pipeline.unwatch()
                        return False
                    pipeline.multi()
                    if expired_owners:
                        pipeline.zrem(key, *expired_owners)
                    pipeline.zadd(key, {owner: expires_at})
                    pipeline.expire(key, ttl * 2)
                    pipeline.execute()
                    return True
                except WatchError as exc:
                    if isinstance(exc.__cause__ or exc.__context__, (ConnectionError, TimeoutError)):
                        raise
                    continue

    def release_detail_slot(self, site_name: str, owner: str) -> None:
        self._client.zrem(self._detail_slot_key(site_name), owner)


def get_state_store(prefer_redis: bool) -> StateStore:
    if prefer_redis:
        return RedisStateStore()
    return InMemoryStateStore()
