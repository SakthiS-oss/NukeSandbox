# Distributed analysis path

The default API is still synchronous: `POST /api/analyze` waits for the sandbox and Gemini. That is the right mode for Azure scale-to-zero, where a Kafka cluster would add cost.

Set `KAFKA_BOOTSTRAP_SERVERS` to switch to an event-driven path. This is for local and interview demos of backpressure, at-least-once delivery, and a Scala worker.

```text
Client ── POST /api/analyze ──> FastAPI
                 │                 │
                 │                 ├── validate + SSRF preflight
                 │                 ├── write JobRecord (memory or Redis)
                 │                 └── Kafka key=job_id  topic=nukesandbox.analyze.commands
                 │
                 └── 202 { job_id, poll_url }

Pekko / Akka Streams worker
  consume (max-in-flight = 2)
       │
       ├── POST /internal/jobs/{id}/events  status=running
       ├── POST /internal/execute           sandbox + Gemini
       └── POST /internal/jobs/{id}/events  succeeded | failed
            commit Kafka offset

Client ── GET /api/jobs/{id} ──> queued | running | succeeded | failed
```

## Why these pieces

| Piece | Role |
|---|---|
| Kafka | Durable command log. The job id is the record key, so retries for one analysis stay on one partition. |
| Pekko Streams | The open-source Akka model: `mapAsync(N)` is the backpressure valve so workers do not start unbounded sandboxes. |
| Scala worker | Consumes commands, calls the Python executor, reports job events. Sandbox/Azure/Gemini stay in Python. |
| Internal token | `/internal/*` is not a public API. The worker sends `X-Internal-Token`. |
| Idempotent events | Kafka is at-least-once. A second `succeeded`/`failed` event does not overwrite a terminal job. |

Pekko is used instead of commercial Akka so the repo stays Apache-2.0. The actor/stream/Kafka APIs are the same ones people mean by "Akka + Kafka".

## Run it locally

```bash
docker compose up -d kafka
export KAFKA_BOOTSTRAP_SERVERS=localhost:9094
export INTERNAL_API_TOKEN=dev-internal-token
python3 main.py

# other terminal, after sbt is installed
cd worker
INTERNAL_API_TOKEN=dev-internal-token NUKESANDBOX_API_BASE_URL=http://127.0.0.1:8000 sbt run
```

`POST /api/analyze` then returns `202` and the dashboard polls `/api/jobs/{id}`. Leave `KAFKA_BOOTSTRAP_SERVERS` unset to keep the original synchronous API.
