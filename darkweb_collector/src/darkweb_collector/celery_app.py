from __future__ import annotations

import os

from celery import Celery
from celery.signals import worker_ready

from darkweb_collector.worker_supervisor import mark_worker_ready


def _broker_url() -> str:
    return os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")


app = Celery(
    "darkweb_collector",
    broker=_broker_url(),
    backend=_broker_url(),
)

app.conf.update(
    broker_connection_timeout=3,
    broker_transport_options={
        "socket_connect_timeout": 3,
        "socket_timeout": 5,
        "retry_on_timeout": False,
        "max_retries": 1,
    },
    redis_socket_connect_timeout=3,
    redis_socket_timeout=5,
    redis_retry_on_timeout=False,
    result_backend_transport_options={"retry_policy": {"max_retries": 1, "interval_start": 0.2}},
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_default_queue="seed_http",
)

app.autodiscover_tasks(["darkweb_collector"])
worker_ready.connect(mark_worker_ready, weak=False)
