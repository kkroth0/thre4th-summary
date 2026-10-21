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
