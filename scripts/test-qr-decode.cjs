/**
 * Verify the QR pipeline end to end with a real decoder.
 *
 * The renderer only paints a matrix, so what matters is:
 *   1. the main process produces a correct matrix (verified by decoding it here)
 *   2. the renderer's painting routine reproduces those modules faithfully
 *      (verified by rendering with the same algorithm and decoding that)
 *
 * This is the check that the earlier hand-rolled encoder failed, so it stays.
 */
const { encodeQrMatrix } = require('../electron/qr.cjs');
const jsQR = require('jsqr');

let pass = 0;
let fail = 0;
const check = (name, cond, extra = '') => {
  if (cond) {
    pass++;
    console.log(`  PASS ${name}`);
  } else {
    fail++;
    console.log(`  FAIL ${name} ${extra}`);
  }
};

/**
 * Paint a matrix exactly as renderer/app.js does, then return the RGBA buffer.
 * Keeping this in sync with the renderer is the point: same quiet zone, same
 * scale, same rounding.
 */
function paint(matrix, scale = 8, quiet = 4) {
  const { size, modules } = matrix;
  const full = (size + quiet * 2) * scale;
  const data = new Uint8ClampedArray(full * full * 4).fill(255);
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (!modules[r][c]) continue;
      for (let dy = 0; dy < scale; dy++) {
        for (let dx = 0; dx < scale; dx++) {
          const y = (r + quiet) * scale + dy;
          const x = (c + quiet) * scale + dx;
          const i = (y * full + x) * 4;
          data[i] = 0;
          data[i + 1] = 0;
          data[i + 2] = 0;
          data[i + 3] = 255;
        }
      }
    }
  }
  return { data, width: full, height: full };
}

const cases = [
  'otpauth://totp/YSM:alice?secret=JBSWY3DPEHPK3PXP&issuer=YSM&algorithm=SHA1&digits=6&period=30',
  'otpauth://totp/YSM:Bob%20Smith?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=YSM&algorithm=SHA1&digits=6&period=30',
  'otpauth://totp/YSM:%D8%A7%D9%84%DB%8C%D8%B3?secret=JBSWY3DPEHPK3PXP&issuer=YSM',
  'hello',
  'YSM',
  'A'.repeat(80),
];

for (const text of cases) {
  const matrix = encodeQrMatrix(text);
  check(
    `matrix is square and a valid QR size (${matrix.size})`,
    matrix.modules.length === matrix.size && (matrix.size - 17) % 4 === 0 && matrix.size >= 21,
  );

  const { data, width, height } = paint(matrix);
  const result = jsQR(data, width, height);
  const decoded = result === null ? null : result.data;
  const label = text.length > 40 ? `${text.slice(0, 40)}…` : text;
  check(`decodes with jsQR: ${JSON.stringify(label)}`, decoded === text, decoded === null ? 'jsQR returned null' : `got ${JSON.stringify(String(decoded).slice(0, 50))}`);
}

console.log('=== refusals ===');
check('empty text refused', (() => { try { encodeQrMatrix(''); return false; } catch { return true; } })());
check('over-long text refused', (() => { try { encodeQrMatrix('x'.repeat(3000)); return false; } catch { return true; } })());
check('non-string refused', (() => { try { encodeQrMatrix(null); return false; } catch { return true; } })());

console.log('=== determinism ===');
const a = encodeQrMatrix('otpauth://totp/x?secret=ABC');
const b = encodeQrMatrix('otpauth://totp/x?secret=ABC');
check('same input gives same matrix', JSON.stringify(a.modules) === JSON.stringify(b.modules));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
