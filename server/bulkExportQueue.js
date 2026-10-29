// A full workbook is only released after every item has complete coverage.
export function releaseCompletedBulkExports(store, at = Date.now()) {
  return store.prepare(`UPDATE bulk_exports SET state='pending',updated=?,revision=(SELECT revision FROM bulk_jobs WHERE id=bulk_exports.job)
    WHERE state='awaiting_completion'
      AND EXISTS(SELECT 1 FROM bulk_jobs WHERE id=bulk_exports.job AND state='complete')
      AND NOT EXISTS(SELECT 1 FROM bulk_items WHERE job=bulk_exports.job AND state NOT IN ('complete','unsupported'))`).run(at).changes;
}
