import { createNewsProjector, type ProjectionItem, type NewsProjectionOptions } from '../utils/newsProjection';

let items: ProjectionItem[] = [];
const project = createNewsProjector<ProjectionItem>();
const channel = self as unknown as { onmessage: (message: MessageEvent) => void; postMessage(value: unknown): void };
channel.onmessage = ({ data }) => {
  if (data.type === 'snapshot') { items = data.items; return; }
  if (data.type !== 'project') return;
  try { channel.postMessage({ id: data.id, data: project(items, data.options as NewsProjectionOptions) }); }
  catch { channel.postMessage({ id: data.id, error: true }); }
};
