# Navigation performance — 21 October 2026

## Production baseline

Read-only audit: Actions run 39677909807. Database: 4,131,934,208 bytes.
Provider counts scanned the observation payload table in 70,816.98 ms. During
that workload, the local vendor-status HTTP request took 18,801 ms; an actor
profile took 307 ms. These are distinct workloads, not a like-for-like before
and after comparison of the actor listing. The machine has two CPU cores and
approximately 954 MiB RAM.

## Changes

- Move inventory, entity and provider-evidence reads off the Express event loop.
  Inventory reads use a separate worker so their counts do not queue actor reads.
  Bound pending requests, worker memory and cached results. Cache identity includes
  account scope. Multi-query reads use one read transaction.
- Add a covering observation index in an isolated worker, with bounded SQLite
  cache and disk-backed temporary sorting. Keep HTTP listening during preparation;
  queue scheduled ingestion until preparation ends. This changes no evidence.
- Use primary-key probes for actor and malware relationships, instead of scanning
  every observation belonging to an account.
- Register repeated entity names once per ingest chunk. Adapt transaction sizes
  toward 30 ms and yield between chunks. This is a target, not a hard deadline.
- Show the base actor catalog without waiting for account evidence aggregation.
  Load profile/model code when opened; retain loading/retry feedback for extras.
- Compute news filters/grouping in a browser worker, reuse organization annotations,
  and group once for both category counts and cards. Paginate cards at 20 items.
- Reuse complete account/preference-scoped news snapshots and conditional ETags.
  Stop the previous once-per-second feed rerender. IOC inventory navigation does
  not trigger another full-news request.

## Validation before deployment

- 892 server tests pass, including authenticated conditional responses, reader
  parity, scope isolation, ingestion barriers and additive-index query parity.
- 267 frontend unit tests pass, including complete IOC retention and equivalent
  grouping/filtering before and after worker extraction.
- Typecheck and production build pass. Tracked source lint has no errors; existing
  warnings remain. Untracked unrelated QA bundles/mobile project are excluded
  from the local lint invocation, and are not part of the commit.
- Browser against local synthetic fixtures: 10,000 news stories, table/card
  paging, page 2, search for story 9999; 1,200 actors, listing search for Mirai.
  These are functional checks, not production response-time measurements.

## Operational verification

The UI-only audit mode uses authenticated GET requests for an existing account,
emits only timings/status/byte counts and keeps its short-lived signature in
memory. It checks the covering index and saved Axur checkpoint without full
table counts. Run after deployment and retain the result with this audit.

Cold inventory aggregation and the first full-news transfer still depend on
data volume and VPS resources. The index, short-lived caches and worker isolation
reduce that cost and prevent it from monopolizing the HTTP event loop; this does
not replace a future paginated news endpoint or materialized inventory summary.


## Follow-up after the first production verification

The index completed successfully. The base actor catalog returned HTTP 200 in
1,453 ms and a profile in 498 ms, but account aggregation, news and inventory
still exceeded the 20-second probe deadline. Authentication itself took 16,209 ms
during one aggregation. These results do not establish that navigation is fixed.

Read-only process inspection confirmed disk waits and substantial paging:
approximately 384 MB RSS and 384 MB swapped for the application at 21:59 UTC.
The inherited service memory limits were unlimited; the host itself has ~1 GB.
The news archive contained 10,141 publications. The import checkpoint retained
3,000,000 Axur records read; it was not reset or advanced before batch completion.

The follow-up isolates provider batch writes too, sharing the exact observation
and entity-registration SQL with news revisions. Main-thread news revisions and
provider writes remain serialized by the existing ingestion queue. Actor activity
receives only fields needed for its counts instead of full publication/story
payloads. Idle IOC/CVE readers terminate after ten seconds; the write worker
terminates after five idle seconds, releasing its SQLite and JavaScript memory.
Low-memory hosts default to two concurrent feed requests and one article IOC
extraction; configured concurrency overrides remain respected.
