// A narrow projection of observations that actually have actor links. Reads of
// actor profiles must not fetch multi-KB provider payloads from millions of IOCs.
const projection = `SELECT o.id,o.scope,o.provider,o.external_id,o.published,
  COALESCE(json_extract(o.details,'$.link'),''),COALESCE(json_extract(o.details,'$.title'),o.provider),
  COALESCE(json_extract(o.details,'$.source'),o.provider),i.type,i.value
  FROM observations o JOIN indicators i ON i.id=o.indicator WHERE o.id=?
  AND EXISTS(SELECT 1 FROM entity_links e WHERE e.observation=o.id AND e.kind='actor')`;
const update=` ON CONFLICT(observation) DO UPDATE SET scope=excluded.scope,provider=excluded.provider,external_id=excluded.external_id,
  published=excluded.published,link=excluded.link,title=excluded.title,source=excluded.source,type=excluded.type,value=excluded.value`;
export function ensureActorObservationIndex(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS actor_observations(
    observation TEXT PRIMARY KEY,scope TEXT NOT NULL,provider TEXT NOT NULL,external_id TEXT NOT NULL,published TEXT NOT NULL,
    link TEXT NOT NULL,title TEXT NOT NULL,source TEXT NOT NULL,type TEXT NOT NULL,value TEXT NOT NULL);
    CREATE TRIGGER IF NOT EXISTS actor_observation_insert AFTER INSERT ON entity_links WHEN NEW.kind='actor' BEGIN
      INSERT INTO actor_observations ${projection.replace('o.id=?','o.id=NEW.observation')}${update}; END;
    CREATE TRIGGER IF NOT EXISTS actor_observation_delete AFTER DELETE ON entity_links WHEN OLD.kind='actor' BEGIN
      DELETE FROM actor_observations WHERE observation=OLD.observation AND NOT EXISTS(
        SELECT 1 FROM entity_links WHERE observation=OLD.observation AND kind='actor'); END;
    CREATE TRIGGER IF NOT EXISTS actor_observation_update AFTER UPDATE ON observations BEGIN
      INSERT INTO actor_observations ${projection.replace('o.id=?','o.id=NEW.id')}${update}; END;
    CREATE TRIGGER IF NOT EXISTS actor_observation_remove AFTER DELETE ON observations BEGIN
      DELETE FROM actor_observations WHERE observation=OLD.id; END;`);
  if (!db.prepare('SELECT 1 FROM observations LIMIT 1').get()) {
    db.prepare('INSERT OR IGNORE INTO intelligence_state VALUES(?,?)').run('actor-observations-v1', JSON.stringify({ ready: true, rows: 0 }));
  }
}
export function backfillActorObservationIndex(db) {
  ensureActorObservationIndex(db);
  if (db.prepare("SELECT 1 FROM intelligence_state WHERE id='actor-observations-v1'").get()) return;
  const ids=db.prepare("SELECT DISTINCT observation FROM entity_links WHERE kind='actor'").all();
  const put=db.prepare('INSERT OR REPLACE INTO actor_observations '+projection);
  const write=db.transaction(rows=>{for(const row of rows)put.run(row.observation);});
  for(let offset=0;offset<ids.length;offset+=200)write(ids.slice(offset,offset+200));
  db.prepare('INSERT OR REPLACE INTO intelligence_state VALUES(?,?)').run('actor-observations-v1',JSON.stringify({ready:true,rows:ids.length}));
}
