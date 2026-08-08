# Shodan Batch Import and Credit Visibility

Date: 2026-08-08
Repository: `/home/mandrade/Dev/thre4th-summary`

## Goal

Let an analyst upload a TXT or JSON file containing any number of supported
Shodan targets, run every imported target, and see the combined findings in one
Attack Surface result. Show the remaining Shodan query credits in the interface.

There is no application-defined target or result ceiling. Shodan still returns
search results in pages of 100 and the Membership plan has a provider-defined
monthly credit budget.

## Supported input

The existing import parser remains the single parser for TXT and JSON. It
continues to accept IP, CIDR, domain, ASN, and `shodan:` / `query:` entries,
while deduplicating them in their source order.

- URLs are reduced to their hostname before classification.
- Hashes and unrecognised values are not sent to Shodan; the UI reports them in
  the ignored count.
- The import preview shows the full count and is not truncated to ten entries.

## User flow

1. The user imports a TXT or JSON file.
2. The page shows the count of accepted and ignored entries, plus available
   query credits.
3. Selecting search processes every accepted entry sequentially and accumulates
   deduplicated findings.
4. Search requests use Shodan's 100-result pages internally and continue until
   the target has no further results.
5. The page reports progress (`target X of N`, current page, findings total).
6. If Shodan rejects a request for exhausted credits or rate limiting, the page
   retains completed results and identifies the unprocessed target; it does not
   silently drop it.

IP lookups keep using Shodan's host endpoint. Search targets (CIDR, domain,
ASN, organization, and advanced query) use the search endpoint and pagination.
Active TCP validation remains opt-in and applies only to the returned,
provider-observed public IP/port pairs.

## Credit visibility

Add a backend helper that calls Shodan's `/api-info` endpoint with the server's
API key. It returns a small, key-free response containing `query_credits` and
the plan name. The browser polls it before a batch and after each completed
target, then displays the remaining query credits next to the import control.

The UI must state that credits are controlled by Shodan, not claim unlimited
retrieval. It must not expose the API key or other account data.

## Design choices

The batch is driven sequentially in the existing page rather than adding a
queue, database, worker, or new dependency. This keeps the current endpoint
and rate limiter effective, makes progress visible, and avoids a new persistence
system. A future background job is warranted only if users need processing to
continue after leaving the page.

The current numeric `limit` control is removed from the batch path. The value
of 100 remains only an internal Shodan page size; it is not a user-facing cap.

## Error handling

- Invalid individual entries are reported by the parser and do not start a
  network request.
- A failed target adds a warning and the batch continues when safe.
- Credit exhaustion or rate limiting stops further paid search pages, retains
  existing findings, and tells the user where processing stopped.
- Missing Shodan configuration keeps the existing public 503-style error.

## Testing

Add focused tests for:

- imports with more than 100 accepted entries and URL hostname extraction;
- query pagination and accumulated finding deduplication;
- host results not being truncated by the former 100-result limit;
- sanitized Shodan credit response and credit-exhaustion warnings.

Run the affected frontend unit tests, server tests, typecheck, lint, and a
production build before completion.
