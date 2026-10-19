// Type definitions for the Game Digital Wallet (GDW) framework.
//
// SPDX-License-Identifier: CC-BY-4.0

export type ErrorCode =
  | 'ERR_MALFORMED'
  | 'ERR_SIGNATURE_INVALID'
  | 'ERR_ISSUER_UNKNOWN'
  | 'ERR_VCT_NOT_ALLOWED'
  | 'ERR_EXPIRED'
  | 'ERR_NOT_YET_VALID'
  | 'ERR_DISCLOSURE_UNKNOWN'
  | 'ERR_CLAIM_MISSING'
  | 'ERR_DUPLICATE_CLAIM'
  | 'ERR_KB_MISSING'
  | 'ERR_KB_INVALID'
  | 'ERR_AUD_MISMATCH'
  | 'ERR_NONCE_MISMATCH'
  | 'ERR_SD_HASH_MISMATCH'
  | 'ERR_REPLAY';

export class GdwError extends Error {
  constructor(code: ErrorCode | string);
  code: ErrorCode | string;
}

/** Any JSON value the framework can carry. Numbers must be integers. */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

/** Tagged empty array so it round-trips as `[]` rather than `{}`. */
export class JsonArray {
  constructor(items?: JsonValue[]);
  items: JsonValue[];
}

export interface GdwKeyInit {
  alg?: string;
  k?: string | null;
  crv?: string | null;
  x?: string | null;
  y?: string | null;
  d?: string | null;
}

export class GdwKey {
  constructor(init?: GdwKeyInit);
  alg: string;
  k: string | null;
  crv: string | null;
  x: string | null;
  y: string | null;
  d: string | null;
  static hs256(rawSecret: string): GdwKey;
  static hs256FromBytes(raw: Uint8Array): GdwKey;
  static fromJson(value: unknown): GdwKey;
  toJson(): Record<string, string>;
  sameSecret(other: GdwKey): boolean;
}

export interface Signer {
  alg: string;
  sign(signingInput: string): string;
  verify(signingInput: string, signature: string): boolean;
}

export class Hs256Signer implements Signer {
  constructor(key: GdwKey);
  alg: 'HS256';
  sign(signingInput: string): string;
  verify(signingInput: string, signature: string): boolean;
}

export class EcdsaP256Signer implements Signer {
  constructor(key: GdwKey);
  alg: 'ES256';
  sign(signingInput: string): string;
  verify(signingInput: string, signature: string): boolean;
  static generate(): [GdwKey, GdwKey];
}

export function signerFor(key: GdwKey): Signer;
export function haveEs256(): boolean;

export interface DecodedToken {
  header: Record<string, JsonValue>;
  payload: Record<string, JsonValue>;
  signingInput: string;
  signature: string;
  headerSegment: string;
}

export interface ParsedCredential {
  token: DecodedToken;
  disclosures: string[];
}

export function decodeToken(token: string): DecodedToken;
export function parseCredential(credential: string): ParsedCredential;

export interface IssueOptions {
  vct?: string;
  claims?: Record<string, JsonValue>;
  disclosable?: string[];
  iat?: number;
  exp?: number;
  sub?: string;
  holderKey?: GdwKey;
  salts?: string[];
  extraPayload?: Record<string, JsonValue>;
}

export class Issuer {
  constructor(iss: string, issuerKey: GdwKey);
  readonly id: string;
  issue(options: IssueOptions): string;
}

export class Wallet {
  constructor(holderKey: GdwKey);
  readonly credentials: string[];
  store(credential: string): void;
  claimsOf(credential: string): string[];
  present(
    credential: string,
    requestedClaims: string[],
    aud: string,
    nonce: string,
    issuedAt: number,
  ): string;
}

export interface VerificationRequest {
  aud: string;
  nonce: string;
  vct: string[];
  claims: string[];
  iat: number;
  expires_at: number;
}

export interface VerifyResult {
  ok: boolean;
  claims: Record<string, JsonValue>;
  errors: ErrorCode[];
}

export class Verifier {
  constructor(aud: string);
  setClockSkew(skew: number): void;
  trust(issuer: string, key: GdwKey): void;
  markNonceUsed(iss: string, nonce: string): void;
  createRequest(vct: string[], claims: string[], ttlSeconds: number): VerificationRequest;
  verify(
    request: VerificationRequest,
    presentation: string,
    currentTime: number,
  ): VerifyResult;
}

export function now(): number;

// ---- primitives -----------------------------------------------------------

export function b64urlEncode(data: Uint8Array): string;
export function b64urlDecode(text: string): Uint8Array;
export function b64urlUtf8(text: string): string;
export function jsonSegment(value: JsonValue): string;
export function parseSegment(segment: string): JsonValue;
export function isValidClaimName(name: string): boolean;
export function isReserved(name: string): boolean;
export function makeDisclosure(saltB64: string, name: string, value: JsonValue): string;
export interface ParsedDisclosure {
  salt: string;
  name: string;
  value: JsonValue;
}
export function parseDisclosure(segment: string): ParsedDisclosure;
export function disclosureDigest(segment: string): string;
export function sdHash(baseText: string): string;
export function randomBase64url(numBytes: number): string;

export namespace json {
  function canonical(value: JsonValue): string;
  function parse(text: string): JsonValue;
  function isObject(value: unknown): boolean;
  function isArray(value: unknown): boolean;
  function get(value: unknown, key: string): JsonValue | undefined;
  function has(value: unknown, key: string): boolean;
  function asStr(value: unknown): string | null;
  function asInt(value: unknown): number | null;
}
