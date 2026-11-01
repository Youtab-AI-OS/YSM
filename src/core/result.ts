/**
 * Tagged result algebra.
 *
 * Every operation that can fail for an *expected* reason returns a Result
 * instead of throwing. Failures carry a machine-readable code so the CLI and
 * any future adapter can react without string matching.
 */

export type ErrorCode =
  | 'INVALID_BASE64'
  | 'INVALID_HEX'
  | 'INVALID_ENVELOPE'
  | 'UNSUPPORTED_VERSION'
  | 'UNSUPPORTED_FLAGS'
  | 'UNSUPPORTED_ALGORITHM'
  | 'UNSUPPORTED_KDF'
  | 'UNSUPPORTED_CIPHER'
  | 'MALFORMED_PARAMETER'
  | 'BAD_KEY_LENGTH'
  | 'BAD_PASSWORD'
  | 'WEAK_PASSWORD'
  | 'INTEGRITY_FAILURE'
  | 'PADDING_FAILURE'
  | 'UNKNOWN_RECIPIENT'
  | 'RECIPIENT_EXPIRED';

export interface Failure {
  readonly ok: false;
  readonly code: ErrorCode;
  readonly message: string;
  readonly cause?: unknown;
}

export type Result<T> = { readonly ok: true; readonly value: T } | Failure;

/** Wrap a success value. */
export function ok<T>(value: T): Result<T> {
  return { ok: true, value };
}

/** Build a failure. */
export function fail(code: ErrorCode, message: string, cause?: unknown): Failure {
  return cause === undefined ? { ok: false, code, message } : { ok: false, code, message, cause };
}

/** Map over a success, passing failures through unchanged. */
export function mapResult<T, U>(r: Result<T>, f: (v: T) => U): Result<U> {
  return r.ok ? ok(f(r.value)) : r;
}

/** Narrow, throwing Error wrapper used at API edges that prefer exceptions. */
export class CryptoMessageError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string, cause?: unknown) {
    super(message);
    this.name = 'CryptoMessageError';
    this.code = code;
    if (cause !== undefined) this.cause = cause;
  }

  static from(f: Failure): CryptoMessageError {
    return new CryptoMessageError(f.code, f.message, f.cause);
  }
}

/** Unwrap a Result or throw a CryptoMessageError. */
export function unwrap<T>(r: Result<T>): T {
  if (r.ok) return r.value;
  throw CryptoMessageError.from(r);
}
