# News toolbar and filters — 2026-10-19

## Change
- Removed the monitored-vendors settings shortcut from the news action bar. Existing account monitoring preferences and collection behavior remain in use.
- Export and refresh use 36px icon controls with accessible names and hover titles. The export dialog still exposes period, content, and Excel/CSV/JSON formats.
- Filter popover uses four aligned labeled selects (severity, period, source and sorting), a KEV switch, a collapsible organization-context section, and clear/done actions.
- Feed views have their own row. Leading categories stay on a single scrollable row; remaining categories open in a menu. A selected category stays visible even when outside the leading group.

## Local verification
- TypeScript passed. Full frontend unit/brand bundle: 264 tests passed. Lint and production build passed, with existing warnings only.
- Temporary local preview used synthetic account and feed fixtures, isolated from production; preview code is not part of the application changes.
- Combined High severity, KEV, and a source filter returned the expected single fixture publication. Clearing filters restored all 20 results. Selecting OT/ICS through More categories returned its two publications and kept the selected category visible.
- Export icon measured 36px and opened the original period/content/format dialog. No monitored-vendor action link remained on the toolbar.
- Context fields expand and the context-only switch is disabled without a context model. Publicações and Cards switches retain the category selection.
- Narrow-layout browser observation: no horizontal page overflow; filter controls remained within the viewport. Temporary viewport override reset after QA.

## Production
- Functional release `6645ef5eee0bfdbaf0f572be45f7154732cf23e8` verified exactly in VPS deployment logs. CI 39269863390 succeeded (825 backend tests, 257 frontend unit tests, 7 brand tests). VPS 39270240997 and Cloudflare Pages 39270241110 succeeded.
- Authenticated production feed loaded 6,221 stories. Export trigger measured 167px before and 36px after deployment. The monitored-vendor shortcut is absent.
- Main filter fields each measured 187px at the tested desktop viewport. Selecting Critical + KEV produced the two expected active chips and all visible rows contained KEV evidence; clearing restored the default feed.
- The compact export trigger opens the original Export news and IOCs dialog. View navigation and category row are distinct. No horizontal page overflow was observed.
- Screenshots saved locally under the temporary `news-layout-2026-10-19` directory, not committed. Both agent-created browser tabs closed and the temporary fixture server stopped.
- Repository lint passed with the unrelated untracked `transforma-mobile/` project excluded from the local invocation. That project and all other unrelated files were preserved.
- The separate dependency security scan retains the existing dependency findings; this UI change does not modify dependencies.
