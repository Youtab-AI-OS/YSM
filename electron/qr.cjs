/**
 * QR generation, main-process side.
 *
 * Rationale: the renderer runs sandboxed with `connect-src 'none'` and no Node
 * integration, so it cannot load a CommonJS QR library and cannot be bundled
 * without adding a build step. Rather than hand-roll or transpile a QR encoder
 * into the renderer — which is not security-critical code but IS correctness-
 * critical, since an unreadable QR locks a user out of 2FA enrolment — we use the
 * audited `qrcode` package here and send the renderer a plain boolean matrix.
 *
 * The renderer only paints rectangles. It never parses QR data, so there is no
 * attack surface from the encoding step.
 */

const QRCode = require('qrcode');

/**
 * Encode `text` into a module matrix.
 *
 * @param {string} text
 * @returns {{ size: number, modules: boolean[][] }}
 */
function encodeQrMatrix(text) {
  if (typeof text !== 'string' || text.length === 0) {
    throw new Error('QR text must be a non-empty string');
  }
  if (text.length > 2000) {
    // An otpauth URI is well under this; refuse rather than emit a dense code
    // that cameras struggle with.
    throw new Error('QR text is too long');
  }
  const qr = QRCode.create(text, { errorCorrectionLevel: 'M' });
  const size = qr.modules.size;
  const modules = [];
  for (let r = 0; r < size; r++) {
    const row = [];
    for (let c = 0; c < size; c++) row.push(qr.modules.get(r, c) === 1);
    modules.push(row);
  }
  return { size, modules };
}

module.exports = { encodeQrMatrix };
