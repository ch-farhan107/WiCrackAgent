# REST API

Machine-readable automation surface; the web console itself consumes these
endpoints. Spec: [`src/wicrack/web/static/openapi.yaml`](https://github.com/ch-farhan107/WiCrackAgent/blob/main/src/wicrack/web/static/openapi.yaml)
(vendored at `/static/openapi.yaml` when running). Auth: console session
cookie (log in once via `POST /login`).

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/status` | live snapshot (stage, speed, queue, counters) |
| GET | `/api/v1/jobs` | snapshot + last 25 runs |
| POST | `/api/v1/jobs` | `{"action": "start"\|"stop"}` control the queue |
| GET | `/api/v1/results` | all recovered credentials |
| GET | `/api/v1/results.csv` | CSV export as JSON payload |

## Examples

```bash
# login (cookie jar)
curl -c jar -d 'password=…' http://localhost:5000/login

# live status
curl -b jar http://localhost:5000/api/v1/status | jq

# start processing every uploaded capture
curl -b jar -H 'Content-Type: application/json' \
     -d '{"action":"start"}' http://localhost:5000/api/v1/jobs

# poll results
curl -b jar http://localhost:5000/api/v1/results | jq '.results[].essid'
```
