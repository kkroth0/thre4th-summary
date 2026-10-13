// Coordinates follow the original 1942 × 809 illustration. Shared by SVG and GIF.
export const PIPELINE_CYCLE = 8;
export const PIPELINE_PACKET_OFFSETS = [0, 0.12, 0.24];
type Point = [number, number];
type Curve = [Point, Point, Point, Point];
export type PipelineFlow = { id: string; curves: Curve[]; start: number; duration: number };
const line = (from: Point, to: Point): Curve => [from, from, to, to];

export const pipelineFlows: PipelineFlow[] = [
  ...[201, 291, 382, 475, 566, 658].map((y, i) => {
    const end = 400 + i * 10;
    return {
      id: `source-${i}`, start: 0.2 + i * 0.09, duration: 1.6,
      curves: [
        [[289, y], [304, y], [308, y], [322, y]],
        [[322, y], [388, y], [316, end], [418, end]],
      ] as Curve[],
    };
  }),
  { id: 'extraction', curves: [line([732, 426], [901, 426])], start: 2.35, duration: 0.85 },
  { id: 'cve', curves: [line([1079, 364], [1079, 282])], start: 3.5, duration: 0.65 },
  { id: 'ioc', curves: [line([1020, 369], [960, 330])], start: 3.6, duration: 0.65 },
  { id: 'actor', curves: [line([1137, 369], [1198, 330])], start: 3.7, duration: 0.65 },
  { id: 'malware', curves: [line([1020, 478], [958, 519])], start: 3.8, duration: 0.65 },
  { id: 'ttp', curves: [line([1139, 478], [1201, 519])], start: 3.9, duration: 0.65 },
  { id: 'reference', curves: [line([1079, 483], [1079, 562])], start: 4, duration: 0.65 },
  { id: 'investigation', curves: [line([1247, 426], [1485, 426])], start: 5.1, duration: 1.1 },
  ...[227, 330, 436, 545, 652].map((y, i) => ({
    id: `delivery-${i}`, start: 6.1 + i * 0.12, duration: 0.55,
    curves: [[[1485, 426], [1506, 426], [1497, y], [1525, y]]] as Curve[],
  })),
];

export const pipelinePulses = [
  ...[168, 258, 346, 438, 531, 621].map((y, i) => ({
    id: `source-${i}`, x: 81, y, width: 204, height: 70, start: 0.07 + i * 0.09, duration: 1,
  })),
  { id: 'extraction', x: 423, y: 378, width: 307, height: 96, start: 1.8, duration: 1.2 },
  { id: 'event', x: 977, y: 369, width: 207, height: 109, start: 3.1, duration: 1.6 },
  ...[
    [1001, 182, 157, 95], [815, 258, 140, 100], [1202, 259, 142, 100],
    [811, 492, 143, 100], [1206, 491, 143, 100], [989, 568, 184, 106],
  ].map(([x, y, width, height], i) => ({
    id: `entity-${i}`, x, y, width, height, start: 4 + i * 0.1, duration: 0.85,
  })),
  ...[182, 285, 391, 500, 607].map((y, i) => ({
    id: `tool-${i}`, x: 1525, y, width: 341, height: 90, start: 6.65 + i * 0.12, duration: 0.75,
  })),
];

export function pipelineSvgPath(curves: Curve[]) {
  return `M${curves[0][0].join(',')} ${curves.map(c => `C${c.slice(1).map(p => p.join(',')).join(' ')}`).join(' ')}`;
}

// Approximate arc length so the exported particles travel at constant speed,
// matching SVG animateMotion's paced interpolation.
export function pipelinePathPoints(curves: Curve[]) {
  const points = curves.flatMap((c, index) => Array.from({ length: 81 }, (_, step) => {
    const t = step / 80, u = 1 - t;
    return [0, 1].map(axis => u ** 3 * c[0][axis] + 3 * u ** 2 * t * c[1][axis] + 3 * u * t ** 2 * c[2][axis] + t ** 3 * c[3][axis]) as Point;
  }).slice(index ? 1 : 0));
  let length = 0;
  return points.map((point, i) => {
    if (i) length += Math.hypot(point[0] - points[i - 1][0], point[1] - points[i - 1][1]);
    return { point, length };
  });
}

export function pipelinePosition(points: ReturnType<typeof pipelinePathPoints>, progress: number): Point {
  const target = Math.max(0, Math.min(1, progress)) * points[points.length - 1].length;
  const next = points.findIndex(p => p.length >= target);
  if (next <= 0) return points[0].point;
  const previous = points[next - 1], current = points[next];
  const ratio = (target - previous.length) / (current.length - previous.length);
  return [previous.point[0] + (current.point[0] - previous.point[0]) * ratio, previous.point[1] + (current.point[1] - previous.point[1]) * ratio];
}
