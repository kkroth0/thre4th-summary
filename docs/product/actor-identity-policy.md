# Actor identities and evidence

Actor catalog display, text extraction and structured provider imports share one identity policy in `server/actorIdentity.js`.

- A unique MITRE name or accepted alias can absorb a source catalog entry with the same primary name. Separate MITRE group IDs never merge through a shared label.
- Source-only entities can resolve to a unique trusted catalog name or alias. Ambiguous labels remain source associations in `relatedNames`; they cannot independently identify an actor.
- Accepted aliases exclude normalized duplicates and the actor's own primary name. Historical IDs remain in `redirectIds`; source provenance remains in `identitySources`.
- Profiles, organization profiles, archived publications, provider publications and activity calculations resolve historical IDs to their canonical identity. Scoped observations stay scoped to their original account.
- Provider matching refreshes its catalog revision before use, including aliases loaded from the saved CTI.fyi cache at startup.

Actor reads use the narrow `actor_observations` projection after its background backfill completes. It includes only observations with an actual actor entity link, maintains itself with SQLite triggers, and leaves the source observations untouched. Until the backfill finishes, publication reads use the existing query. Activity streams individual observations so unrelated IOCs in a shared publication do not inherit another observation's actor.

Publication URL deduplication strips tracking parameters and ordinary fragments. CTI.fyi `#claim-*` fragments remain distinct. A publication's co-occurring indicators remain evidence of mention, not proof that the actor owns that infrastructure.

## Validation on 2026-10-24

On the captured production base catalog: 1,401 entries become 1,374 identities; all 1,401 original IDs remain resolvable, all 176 MITRE groups remain separate, and no accepted AKA repeats its primary name or another accepted AKA. This is catalog validation, not confirmation of a production migration.

Regression coverage includes Daggerfly/Evasive Panda, APT29/UNC2452, Lazarus/APT38 separation, ambiguous aliases, Noberus, Chaya_004, historical IDs, account isolation, projection updates and a payload-heavy migration fixture. All 936 server tests pass. Type checking, frontend build and lint of changed files pass. Local browser QA uses synthetic evidence attributed to the former Evasive Panda ID and confirms it appears in Daggerfly's publication and IOC tabs.
