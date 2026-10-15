import { createNewsArchiveStore } from './newsArchiveStore.js';
import { createStoryStore } from './newsStoryStore.js';

// One process owns news writes. Async publications are serialized; SQLite's
// generation guard also rejects updates computed before a synchronous migration.
export function createSqliteNewsStores({ persistence, archive, stories, writeBackup = () => {}, onBackupError = () => {} }) {
  if (!persistence.activate({ archive: archive.all(), stories: stories.all() })) return { archive, stories };
  let snapshot, archiveView, storyView, pending = Promise.resolve();
  function backup() {
    let failure;
    try { writeBackup(snapshot); } catch (error) { failure = error; }
    try { persistence.recordBackup(failure); } catch (error) { failure ||= error; }
    // Never report an already committed publication as failed because recovery
    // copy bookkeeping or a diagnostic callback could not be written.
    if (failure) { try { onBackupError(failure); } catch { /* diagnostic only */ } }
  }
  function install(next) {
    snapshot = next;
    archiveView = createNewsArchiveStore({ initialRows: snapshot.archive, writeJsonAtomic: (_, next) => commit({ ...snapshot, archive: next }) });
    storyView = createStoryStore({ initialRows: snapshot.stories, writeJsonAtomic: (_, next) => commit({ ...snapshot, stories: next }) });
  }
  function refresh() {
    if (snapshot?.generation === persistence.generation()) return;
    install(persistence.readSnapshot());
  }
  function commit(next) {
    // Detach drafts exactly as persisted JSON before advancing the database.
    // The transaction verifies payloads and relationships; a second full read
    // after that successful commit provided no additional integrity guarantee.
    const detached = JSON.parse(JSON.stringify(next));
    const result = persistence.commit(detached, detached.generation);
    install({ ...detached, generation: result.generation });
    backup();
  }
  refresh();
  // Restarts repair a stale/missing JSON copy from verified SQLite, never the
  // reverse. A failed backup does not roll back an already committed database.
  backup();
  const facade = (methods, view) => Object.fromEntries(methods.map(method => [method, (...args) => { refresh(); return view()[method](...args); }]));
  const result = {
    archive: facade(['all', 'size', 'add', 'list', 'reclassifyPhishing', 'restorePhishingEvidence', 'restorePhishingMembership'], () => archiveView),
    stories: facade(['all', 'get', 'save', 'list'], () => storyView),
  };
  result.archive.publishSnapshot = (operation, suppliedStories) => {
    if (suppliedStories !== result.stories) throw Error('News stores must share one SQLite transaction');
    const run = pending.then(async () => {
      refresh();
      const base = snapshot;
      const draftArchive = createNewsArchiveStore({ initialRows: base.archive, writeJsonAtomic: () => {} });
      const draftStories = createStoryStore({ initialRows: base.stories, writeJsonAtomic: () => {} });
      const correlation = await operation({ archive: draftArchive, stories: draftStories });
      commit({ archive: draftArchive.all(), stories: draftStories.all(), generation: base.generation });
      return correlation;
    });
    pending = run.catch(() => {});
    return run;
  };
  return result;
}
