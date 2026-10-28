import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';
import {gzipSync,gunzipSync} from 'node:zlib';

/** Append-only private response history; memory eviction never deletes these snapshots. */
export function createLookupSnapshots(filePath) {
    if (filePath !== ':memory:') fs.mkdirSync(path.dirname(filePath),{recursive:true});
    const db=new Database(filePath);db.pragma('journal_mode=WAL');db.pragma('busy_timeout=5000');db.pragma('cache_size=-4000');
    db.exec(`CREATE TABLE IF NOT EXISTS lookup_snapshots(id INTEGER PRIMARY KEY,cache_key TEXT NOT NULL,owner TEXT NOT NULL,provider TEXT NOT NULL,query TEXT NOT NULL,collected TEXT NOT NULL,value BLOB NOT NULL);
      CREATE INDEX IF NOT EXISTS lookup_latest ON lookup_snapshots(cache_key,id DESC);`);
    const latest=db.prepare('SELECT collected,value FROM lookup_snapshots WHERE cache_key=? ORDER BY id DESC LIMIT 1');
    const put=db.prepare('INSERT INTO lookup_snapshots(cache_key,owner,provider,query,collected,value) VALUES(?,?,?,?,?,?)');
    const count=db.prepare('SELECT COUNT(*) n FROM lookup_snapshots');
    return {
        get(key){const row=latest.get(key);return row?{collectedAt:row.collected,value:JSON.parse(gunzipSync(row.value,{maxOutputLength:64*1024*1024}).toString())}:null;},
        save(key,request,snapshot){put.run(key,String(request.owner||''),request.provider,request.query,snapshot.collectedAt,gzipSync(Buffer.from(JSON.stringify(snapshot.value)),{level:3}));},
        count:()=>count.get().n,close:()=>db.close(),
    };
}
