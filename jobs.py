"""Async analysis jobs: in-memory or Redis state, Kafka command publication."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from typing import Literal

from pydantic import BaseModel, Field
from redis import Redis
from redis.exceptions import RedisError

logger = logging.getLogger("nukesandbox")

COMMAND_TOPIC = "nukesandbox.analyze.commands"
JOB_TTL_SECONDS = 3600
JobStatus = Literal["queued", "running", "succeeded", "failed"]


class JobRecord(BaseModel):
    job_id: str
    status: JobStatus
    stage: str
    target_url: str
    identity: str
    created_at: float
    result: dict | None = None
    error: str | None = None


class AnalyzeAccepted(BaseModel):
    job_id: str
    status: Literal["queued"] = "queued"
    poll_url: str


class AnalyzeCommand(BaseModel):
    event_type: Literal["AnalyzeRequested"] = "AnalyzeRequested"
    job_id: str
    target_url: str
    requested_by: str
    request_id: str
    created_at: float = Field(default_factory=time.time)


def kafka_enabled() -> bool:
    return bool(os.getenv("KAFKA_BOOTSTRAP_SERVERS"))


def build_analyze_command(target_url: str, identity: str, request_id: str) -> AnalyzeCommand:
    return AnalyzeCommand(
        job_id=str(uuid.uuid4()),
        target_url=target_url,
        requested_by=identity,
        request_id=request_id,
    )


class JobStore:
    """Process-local store used when Redis is not configured."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, JobRecord] = {}

    def create(self, record: JobRecord) -> JobRecord:
        with self._lock:
            self._jobs[record.job_id] = record
            return record

    def get(self, job_id: str) -> JobRecord | None:
        with self._lock:
            return self._jobs.get(job_id)

    def update(self, job_id: str, **changes: object) -> JobRecord | None:
        with self._lock:
            current = self._jobs.get(job_id)
            if current is None:
                return None
            updated = current.model_copy(update=changes)
            self._jobs[job_id] = updated
            return updated


class RedisJobStore:
    """Shared store so API replicas can all see Pekko worker completions."""

    def __init__(self, client: Redis) -> None:
        self._client = client

    def _key(self, job_id: str) -> str:
        return f"nukesandbox:job:{job_id}"

    def create(self, record: JobRecord) -> JobRecord:
        self._client.setex(self._key(record.job_id), JOB_TTL_SECONDS, record.model_dump_json())
        return record

    def get(self, job_id: str) -> JobRecord | None:
        raw = self._client.get(self._key(job_id))
        if not raw:
            return None
        return JobRecord.model_validate_json(raw)

    def update(self, job_id: str, **changes: object) -> JobRecord | None:
        current = self.get(job_id)
        if current is None:
            return None
        updated = current.model_copy(update=changes)
        self._client.setex(self._key(job_id), JOB_TTL_SECONDS, updated.model_dump_json())
        return updated


_store: JobStore | RedisJobStore | None = None
_producer = None


def get_job_store() -> JobStore | RedisJobStore:
    global _store
    if _store is None:
        redis_url = os.getenv("REDIS_URL")
        if redis_url:
            try:
                _store = RedisJobStore(Redis.from_url(redis_url, decode_responses=True, socket_connect_timeout=1))
            except RedisError:
                logger.warning("job_store_redis_unavailable_using_memory")
                _store = JobStore()
        else:
            _store = JobStore()
    return _store


def publish_analyze_command(command: AnalyzeCommand) -> None:
    """Publish with the job_id as the Kafka key so retries stay on one partition."""
    global _producer
    bootstrap = os.getenv("KAFKA_BOOTSTRAP_SERVERS")
    if not bootstrap:
        raise RuntimeError("KAFKA_BOOTSTRAP_SERVERS is not set.")
    if _producer is None:
        from kafka import KafkaProducer

        _producer = KafkaProducer(
            bootstrap_servers=[item.strip() for item in bootstrap.split(",") if item.strip()],
            key_serializer=lambda key: key.encode(),
            value_serializer=lambda value: json.dumps(value).encode(),
            acks="all",
            retries=3,
        )
    future = _producer.send(COMMAND_TOPIC, key=command.job_id, value=command.model_dump())
    future.get(timeout=10)
