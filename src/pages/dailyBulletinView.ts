export const canOpenReport = (job: { status: string; json?: unknown; hasReport?: boolean }) =>
  job.status === "done" && Boolean(job.json || job.hasReport);

export function buildHuntLink(report: { id: string; title?: string; techniques?: string[]; cves?: string[] }) {
  const params = new URLSearchParams({ new: "1", sourceReportId: report.id });
  if (report.title) params.set("title", report.title);
  if (report.techniques?.length) params.set("techniques", report.techniques.join(","));
  if (report.cves?.length) params.set("cves", report.cves.join(","));
  return `/hunting?${params}`;
}
