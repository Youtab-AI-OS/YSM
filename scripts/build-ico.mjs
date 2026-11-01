#!/usr/bin/env node
/**
 * Build a multi-resolution .ico from the Youtab PNG.
 *
 * Inno Setup and Windows Explorer want a real .ico containing several sizes;
 * a renamed PNG shows as a generic icon. This writes a proper ICO container with
 * PNG-compressed entries (supported since Windows Vista), which keeps the file
 * small and avoids needing an image library.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PNG } from 'pngjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const source = join(root, 'icon_d8b', 'app-icon-256.png');
const out = join(root, 'assets', 'ysm.ico');

if (!existsSync(source)) {
  throw new Error(`source icon not found: ${source}`);
}

/**
 * Resize RGBA with box filtering. Nearest-neighbour makes a small icon look
 * aliased, and bicubic is overkill for a logo whose edges are few.
 */
function resize(png, size) {
  const dst = new PNG({ width: size, height: size });
  const xRatio = png.width / size;
  const yRatio = png.height / size;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const x0 = Math.floor(x * xRatio);
      const x1 = Math.min(png.width, Math.ceil((x + 1) * xRatio));
      const y0 = Math.floor(y * yRatio);
      const y1 = Math.min(png.height, Math.ceil((y + 1) * yRatio));
      let r = 0;
      let g = 0;
      let b = 0;
      let a = 0;
      let n = 0;
      for (let sy = y0; sy < y1; sy++) {
        for (let sx = x0; sx < x1; sx++) {
          const i = (png.width * sy + sx) << 2;
          const alpha = png.data[i + 3];
          // Weight colour by alpha so transparent pixels do not darken edges.
          r += png.data[i] * alpha;
          g += png.data[i + 1] * alpha;
          b += png.data[i + 2] * alpha;
          a += alpha;
          n++;
        }
      }
      const di = (size * y + x) << 2;
      if (a === 0 || n === 0) {
        dst.data[di] = 0;
        dst.data[di + 1] = 0;
        dst.data[di + 2] = 0;
        dst.data[di + 3] = 0;
      } else {
        dst.data[di] = Math.round(r / a);
        dst.data[di + 1] = Math.round(g / a);
        dst.data[di + 2] = Math.round(b / a);
        dst.data[di + 3] = Math.round(a / n);
      }
    }
  }
  return dst;
}

const src = PNG.sync.read(readFileSync(source));
const sizes = [16, 24, 32, 48, 64, 128, 256];
const images = sizes.map((size) => ({
  size,
  data: PNG.sync.write(size === src.width ? src : resize(src, size)),
}));

// ICO layout: 6-byte header, 16-byte directory entry per image, then the data.
const header = Buffer.alloc(6);
header.writeUInt16LE(0, 0); // reserved
header.writeUInt16LE(1, 2); // type: icon
header.writeUInt16LE(images.length, 4);

const entries = [];
let offset = 6 + images.length * 16;

for (const image of images) {
  const entry = Buffer.alloc(16);
  entry.writeUInt8(image.size >= 256 ? 0 : image.size, 0); // width (0 means 256)
  entry.writeUInt8(image.size >= 256 ? 0 : image.size, 1); // height
  entry.writeUInt8(0, 2); // palette size
  entry.writeUInt8(0, 3); // reserved
  entry.writeUInt16LE(1, 4); // colour planes
  entry.writeUInt16LE(32, 6); // bits per pixel
  entry.writeUInt32LE(image.data.length, 8);
  entry.writeUInt32LE(offset, 12);
  entries.push(entry);
  offset += image.data.length;
}

writeFileSync(out, Buffer.concat([header, ...entries, ...images.map((i) => i.data)]));
console.log(`wrote ${out} with sizes ${sizes.join(', ')}`);
