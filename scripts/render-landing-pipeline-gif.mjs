// Offline export only. Requires Node 24 and @napi-rs/canvas + gifenc installed
// in the directory passed as the first argument; no frontend dependency.
import { createRequire } from 'node:module';
import { writeFile, mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PIPELINE_CYCLE, PIPELINE_PACKET_OFFSETS, pipelineFlows, pipelinePulses, pipelinePathPoints, pipelinePosition } from '../src/lib/landingPipelineMotion.ts';

if (!process.argv[2]) throw new Error('Usage: node scripts/render-landing-pipeline-gif.mjs <authoring-package-directory> [proof-directory]');
const require = createRequire(resolve(process.argv[2], 'package.json'));
const { createCanvas, loadImage } = require('@napi-rs/canvas');
const { GIFEncoder, quantize, applyPalette } = require('gifenc');
const root = fileURLToPath(new URL('../', import.meta.url));
const width = 1440, height = 600, fps = 25, frames = PIPELINE_CYCLE * fps;
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
      if (progress > 0 && progress < 1) {
        const opacity = Math.min(1, (time - flow.start) / 0.06, (flow.start + flow.duration - time) / 0.06);
        ctx.beginPath();
        for (let segment = 0; segment <= 16; segment++) {
          const [x, y] = pipelinePosition(flow.points, Math.max(0, progress - 0.15) + Math.min(progress, 0.15) * segment / 16);
          if (segment) ctx.lineTo(x, y); else ctx.moveTo(x, y);
        }
        ctx.strokeStyle = '#fb923c'; ctx.lineCap = 'round';
        ctx.globalAlpha = opacity * 0.18; ctx.lineWidth = 9; ctx.stroke();
        ctx.globalAlpha = opacity; ctx.lineWidth = 3.5; ctx.stroke();
      }
      PIPELINE_PACKET_OFFSETS.forEach((offset, packet) => {
        const elapsed = time - flow.start - offset, phase = elapsed / flow.duration;
        if (phase <= 0 || phase >= 1) return;
        const [x, y] = pipelinePosition(flow.points, phase);
        const opacity = Math.min(1, elapsed / 0.06, (flow.duration - elapsed) / 0.06);
        ctx.globalAlpha = opacity * (packet ? 0.13 : 0.18); ctx.fillStyle = '#f97316';
        ctx.beginPath(); ctx.arc(x, y, packet ? 9 : 16, 0, Math.PI * 2); ctx.fill();
        ctx.globalAlpha = opacity; ctx.fillStyle = packet ? '#fb923c' : '#ffe4bf';
        ctx.beginPath(); ctx.arc(x, y, packet ? 3 : 5.5, 0, Math.PI * 2); ctx.fill();
      });
    }
    for (const pulse of pipelinePulses) {
      const progress = (time - pulse.start) / pulse.duration;
      if (progress <= 0 || progress >= 1) continue;
      const opacity = 1 - Math.abs(2 * progress - 1);
      ctx.beginPath(); ctx.roundRect(pulse.x, pulse.y, pulse.width, pulse.height, 10);
      ctx.globalAlpha = opacity * 0.055; ctx.fillStyle = '#f97316'; ctx.fill();
      ctx.globalAlpha = opacity * 0.9; ctx.strokeStyle = '#fb923c'; ctx.lineWidth = 2.5;
      ctx.shadowColor = '#fb923c'; ctx.shadowBlur = 2; ctx.stroke(); ctx.shadowBlur = 0;
      ctx.save(); ctx.clip(); ctx.globalAlpha = opacity * 0.06; ctx.fillStyle = '#ffcf99';
      ctx.fillRect(pulse.x - 50 + (pulse.width + 100) * progress, pulse.y, 45, pulse.height); ctx.restore();
    }
    const orbit = time >= 1.8 && time < 3.6 ? (time <= 2.4 ? (time - 1.8) / 0.6 : (3.6 - time) / 1.2) * 0.72 : 0;
    if (orbit > 0) {
      ctx.save(); ctx.translate(470, 426); ctx.rotate(Math.PI * time);
      ctx.globalAlpha = orbit; ctx.strokeStyle = '#fb923c'; ctx.lineWidth = 2; ctx.setLineDash([28, 79]);
      ctx.beginPath(); ctx.arc(0, 0, 34, 0, Math.PI * 2); ctx.stroke(); ctx.restore();
    }
    ctx.restore();
    return ctx.getImageData(0, 0, width, height).data;
  };
  // One palette keeps the charcoal backdrop and text stable throughout the loop.
  const samples = [0, 1.1, 2.2, 4.4, 7].map(draw);
  const paletteInput = new Uint8Array(samples[0].length * samples.length);
  samples.forEach((sample, i) => paletteInput.set(sample, i * sample.length));
  const palette = quantize(paletteInput, 252);
  palette.push([255, 228, 191], [251, 146, 60], [249, 115, 22]);
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
    if (process.argv[3] && lang === 'pt' && [0, 28, 55, 110, 175, 199].includes(frame)) {
      await writeFile(resolve(process.argv[3], `pipeline-frame-${frame}.png`), canvas.toBuffer('image/png'));
    }
  }
  gif.finish();
  const output = resolve(root, `public/images/etl-pipeline-${lang}-animated-v3.gif`);
  await writeFile(output, gif.bytes());
  console.log(JSON.stringify({ lang, width, height, frames, seconds: PIPELINE_CYCLE, bytes: gif.bytesView().length, output }));
}
