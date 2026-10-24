# 0007. One process and SQLite, with the way out written down

## Situation

The tool is used by one organisation's compliance team: a handful of people, reviews that take minutes, tens of reviews a day
at most. It has to be easy to run and to back up. A job queue, a separate worker fleet and a database server would be more to
operate than the whole application.

## Decision

- The web server, the background work and the database are one process and one SQLite file in write-ahead mode.
- A review runs as an `asyncio` task. Two limits bound the work: how many reviews run at once and how many controls one review
  assesses at once. Uploads are refused with `429` when 20 reviews are waiting or running.
- A review interrupted by a restart is marked `failed` at the next start. Nothing is resumed silently.
- `Repository` is the only code that talks to SQLite, and `AuditService` is the only code that talks to `Repository`.

## Why

- No other service to deploy, secure or keep alive. The container has one volume.
- A review's cost is dominated by model calls, not by the database. A single writer is nowhere near the limit.
- Marking an interrupted review failed is honest, and "run again" is cheap because answers are cached.

## Consequences

- No horizontal scaling: two processes on one database file would each run reviews and each mark the other's as interrupted.
  Run one instance.
- A restart loses the review in progress, though not the findings already saved.
- Backups are a copy of the database taken with SQLite's backup mechanism, not a file copy of a live write-ahead database.
- It is not multi-tenant.

## When to leave this behind

If this needs more than one instance or hundreds of reviews a day: swap `Repository` for a server database (the interface is
small and the SQL is plain), move `AuditService.run` behind a queue with separate workers, and replace the in-process
semaphores with a shared rate limit on model calls. The pieces are already separated along those lines.

## Considered

- PostgreSQL and a queue from the start. Right at a larger scale, wrong for this one.
- Running reviews synchronously inside the request. A review takes minutes, which is long for a request and too long for a proxy.
