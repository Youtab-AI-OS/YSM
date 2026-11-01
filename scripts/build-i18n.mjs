#!/usr/bin/env node
/**
 * Emit renderer/i18n.js from src/ysm/i18n/strings.ts.
 *
 * One source of truth for translations: the TypeScript module is used by the
 * main process and tests, and this script produces the ES module the sandboxed
 * renderer loads. If they could drift, a missing translation would ship.
 *
 * Integration happens by stripping the TypeScript-only syntax and rewriting the
 * three dict declarations into a plain-JS export. The parser is deliberately
 * simple because the input is our own file: if the shape changes, this script
 * fails loudly rather than emitting something wrong.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const src = readFileSync(join(root, 'src', 'ysm', 'i18n', 'strings.ts'), 'utf8');

// Pull out the three dictionary literals and the locale metadata.
function extractDict(name) {
  const start = src.indexOf(`const ${name}: Dict = {`);
  if (start === -1) throw new Error(`could not find dict ${name}`);
  const open = src.indexOf('{', start);
  let depth = 0;
  let end = -1;
  for (let i = open; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}') {
      depth--;
      if (depth === 0) {
        end = i;
        break;
      }
    }
  }
  if (end === -1) throw new Error(`unterminated dict ${name}`);
  return src.slice(open, end + 1);
}

const en = extractDict('en');
const fa = extractDict('fa');
const nl = extractDict('nl');

const out = `/**
 * Translations for the renderer.
 *
 * GENERATED FILE — do not edit. Source: src/ysm/i18n/strings.ts
 * Regenerate with: node scripts/build-i18n.mjs
 *
 * Farsi is RTL: callers must set document.dir based on RTL_LOCALES.
 */

export const LOCALES = ['en', 'fa', 'nl'];
export const RTL_LOCALES = new Set(['fa']);
export const LOCALE_NAMES = { en: 'English', fa: 'فارسی', nl: 'Nederlands' };

const DICTS = {
  en: ${en},
  fa: ${fa},
  nl: ${nl},
};

/**
 * Translate a key and substitute {placeholders}.
 *
 * Falls back to English, then to the key itself. A missing translation is caught
 * by the test suite, so the fallback should never be visible to a user.
 */
export function translate(locale, key, vars) {
  const dict = DICTS[locale] || DICTS.en;
  let template = dict[key];
  if (template === undefined) template = DICTS.en[key] !== undefined ? DICTS.en[key] : key;
  if (!vars) return template;
  return template.replace(/\\{(\\w+)\\}/g, (match, name) => {
    const value = vars[name];
    return value === undefined ? match : String(value);
  });
}

export function isRtl(locale) {
  return RTL_LOCALES.has(locale);
}

export { DICTS };
`;

writeFileSync(join(root, 'renderer', 'i18n.js'), out);

// Sanity: every locale must have the same key count as English.
const count = (s) => (s.match(/^\s*'[^']+':/gm) ?? []).length;
const [cEn, cFa, cNl] = [count(en), count(fa), count(nl)];
if (cEn === 0) throw new Error('no keys parsed from English dict');
if (cEn !== cFa || cEn !== cNl) {
  throw new Error(`key count mismatch: en=${cEn} fa=${cFa} nl=${cNl}`);
}

console.log(`renderer/i18n.js written — ${cEn} keys x 3 locales`);
