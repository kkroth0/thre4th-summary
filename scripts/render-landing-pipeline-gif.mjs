// Offline export only. Requires Node 24 and @napi-rs/canvas + gifenc installed
// in the directory passed as the first argument; no frontend dependency.
import { createRequire } from 'node:module';
import { writeFile, mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PIPELINE_CYCLE, pipelineFlows, pipelinePulses, pipelinePathPoints, pipelinePosition } from '../src/lib/landingPipelineMotion.ts';

if (!process.argv[2]) throw new Error('Usage: node scripts/render-landing-pipeline-gif.mjs <authoring-package-directory> [proof-directory]');
const require = createRequire(resolve(process.argv[2], 'package.json'));
const { createCanvas, loadImage } = require('@napi-rs/canvas');
const { GIFEncoder, quantize, applyPalette } = require('gifenc');
const root = fileURLToPath(new URL('../', import.meta.url));
const width = 1440, height = 600, fps = 20, frames = PIPELINE_CYCLE * fps;
const flows = pipelineFlows.map(flow => ({ ...flow, points: pipelinePathPoints(flow.curves) }));

for (const lang of ['pt', 'en']) {
  const background = await loadImage(resolve(root, `public/images/etl-pipeline-${lang}-v1.png`));
  const canvas = createCanvas(width, height), ctx = canvas.getContext('2d');
  const gif = GIFEncoder();
  const draw = time => {
    ctx.drawImage(background, 0, 0, width, height);
    ctx.save();
    ctx.scale(width / 1942, height / 809);
    for (const flow of flows) {
      const progress = (time - flow.start) / flow.duration;
      if (progress <= 0 || progress >= 1) continue;
      const [x, y] = pipelinePosition(flow.points, progress);
      const opacity = Math.min(1, (time - flow.start) / 0.06, (flow.start + flow.duration - time) / 0.06);
      ctx.globalAlpha = opacity * 0.18;
      ctx.fillStyle = '#f97316';
      ctx.beginPath(); ctx.arc(x, y, 13, 0, Math.PI * 2); ctx.fill();
      ctx.globalAlpha = opacity;
      ctx.fillStyle = '#ffcf99';
      ctx.beginPath(); ctx.arc(x, y, 5, 0, Math.PI * 2); ctx.fill();
    }
    for (const pulse of pipelinePulses) {
      const progress = (time - pulse.start) / pulse.duration;
      if (progress <= 0 || progress >= 1) continue;
      ctx.globalAlpha = 0.7 * (1 - Math.abs(2 * progress - 1));
      ctx.strokeStyle = '#fb923c'; ctx.lineWidth = 3;
      ctx.beginPath(); ctx.roundRect(pulse.x, pulse.y, pulse.width, pulse.height, 10); ctx.stroke();
    }
    ctx.restore();
    return ctx.getImageData(0, 0, width, height).data;
  };
  // One palette keeps the charcoal backdrop and text stable throughout the loop.
  const staticFrame = draw(0);
  const palette = quantize(staticFrame, 253);
  palette.push([255, 207, 153], [251, 146, 60]);
  while (palette.length < 255) palette.push([13, 17, 23]);
  palette.push([255, 0, 255]);
  let previous;
  if (process.argv[3]) await mkdir(resolve(process.argv[3]), { recursive: true });
  for (let frame = 0; frame < frames; frame++) {
    const data = draw(frame / fps);
    const indexed = applyPalette(data, palette);
    const delta = indexed.slice();
    if (previous) for (let pixel = 0; pixel < indexed.length; pixel++) {
      if (indexed[pixel] === previous[pixel]) delta[pixel] = 255;
    }
    gif.writeFrame(delta, width, height, {
      palette: frame === 0 ? palette : undefined,
      delay: 1000 / fps, repeat: 0, dispose: 1,
      transparent: frame !== 0, transparentIndex: 255,
    });
    previous = indexed;
    if (process.argv[3] && lang === 'pt' && [0, 22, 77, 132, 159].includes(frame)) {
      await writeFile(resolve(process.argv[3], `pipeline-frame-${frame}.png`), canvas.toBuffer('image/png'));
    }
  }
  gif.finish();
  const output = resolve(root, `public/images/etl-pipeline-${lang}-animated-v2.gif`);
  await writeFile(output, gif.bytes());
  console.log(JSON.stringify({ lang, width, height, frames, seconds: PIPELINE_CYCLE, bytes: gif.bytesView().length, output }));
}
