# MailTrace — Regional SOC Routing v1

This package adds the first production-oriented SOC routing layer without replacing the existing case claim/lease system.

## What it adds

- Tenant-scoped SOC queues with a configured `region_key`.
- Employee-to-region configuration based on organizational identity, **not IP geolocation**.
- Automatic routing when an employee report creates/updates a case.
- Central SOC fallback when no active regional mapping/queue exists.
- Capacity-aware analyst selection using `max_open_cases` and current open case load.
- Persistent routing records and routing audit events.
- Admin endpoints for queue, employee-region and analyst configuration.
- SOC endpoint to inspect a case's routing record.
- Existing `/api/cases/{case_id}/claim` and 20-minute analyst claim lease remain intact.

## Files in this feature package

- `backend/database/database.py` — new routing tables and routing functions.
- `backend/main.py` — initializes routing, registers the router, and routes employee-report cases.
- `backend/services/case_routing.py` — service wrapper.
- `backend/routes/soc_routing.py` — configuration and routing APIs.
- `backend/tests/test_soc_routing.py` — isolated SQLite routing/fallback test.

## PowerShell install

From the MailTrace project root, back up the two modified files first:

```powershell
Copy-Item .\backend\main.py .\backend\main.py.before-soc-routing-v1 -Force
Copy-Item .\backend\database\database.py .\backend\database\database.py.before-soc-routing-v1 -Force
```

Then copy the package files into the project, preserving the `backend\` paths.

## Configuration flow

1. Create a regional queue with `POST /api/soc/routing/queues`.
2. Map an employee `subject_id` to that region with `POST /api/soc/routing/employee-region`.
3. Register available analysts for that region with `POST /api/soc/routing/analysts`.
4. Employee submits a report.
5. The existing employee-report/case flow calls the routing service.
6. The case is assigned to the regional queue and, if capacity is available, to the least-loaded eligible analyst.
7. If regional mapping/queue is unavailable, the case goes to the tenant's `CENTRAL` queue.
8. Existing analyst claim/lease remains the final working lock for investigation work.

## Important boundary

This version does **not** claim SSO, full multi-tenant case isolation, employee-facing routing UI, SLA/escalation, or gateway enforcement. Those are separate milestones.

## Verification performed before delivery

- Python syntax compilation for all changed Python files: PASS.
- Backend `main` module import: PASS.
- Isolated SQLite regional routing test: PASS.
- Isolated SQLite central fallback test: PASS.
