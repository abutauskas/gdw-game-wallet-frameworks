// Deterministic JSON value with canonical (JCS-style) encoding.
//
// Objects serialise with keys sorted ascending by Unicode code point, numbers
// are integers only (SPEC.md §2.2). Parsing is a hand-written strict parser so
// that floats, exponents, "-0", leading zeros and integers outside +/-(2^53-1)
// are rejected — matching the C++/Rust/C#/Python/GDScript frameworks.
//
// SPDX-License-Identifier: CC-BY-4.0

'use strict';

const { ERR_MALFORMED, GdwError } = require('./errors');

const MAX_SAFE_INT = Number.MAX_SAFE_INTEGER; // 2^53 - 1

const OBJ = 'object';
const ARR = 'array';

function isObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v) && !(v instanceof JsonArray);
}
function isArray(v) {
  return Array.isArray(v) || v instanceof JsonArray;
}

// A marker wrapper so an explicitly-tagged empty array survives parsing.
class JsonArray {
  constructor(items) {
    this.items = items || [];
  }
}

function get(value, key) {
  return isObject(value) ? value[key] : undefined;
}
function has(value, key) {
  return isObject(value) && Object.prototype.hasOwnProperty.call(value, key);
}
function asStr(value) {
  return typeof value === 'string' ? value : null;
}
function asInt(value) {
  return typeof value === 'number' && Number.isInteger(value) ? value : null;
}
function entries(value) {
  if (!isObject(value)) return [];
  return Object.keys(value)
    .sort()
    .map((key) => [key, value[key]]);
}

// ---- canonical encoding ---------------------------------------------------

function writeString(out, value) {
  out.push('"');
  for (const ch of value) {
    const code = ch.codePointAt(0);
    if (ch === '"') out.push('\\"');
    else if (ch === '\\') out.push('\\\\');
    else if (ch === '\b') out.push('\\b');
    else if (ch === '\t') out.push('\\t');
    else if (ch === '\n') out.push('\\n');
    else if (ch === '\f') out.push('\\f');
    else if (ch === '\r') out.push('\\r');
    else if (code < 0x20) out.push('\\u' + code.toString(16).padStart(4, '0'));
    else out.push(ch);
  }
  out.push('"');
}

function write(out, value) {
  if (value === null) out.push('null');
  else if (value === true) out.push('true');
  else if (value === false) out.push('false');
  else if (typeof value === 'number') {
    if (!Number.isInteger(value)) throw new GdwError(ERR_MALFORMED);
    if (value < -MAX_SAFE_INT || value > MAX_SAFE_INT) throw new GdwError(ERR_MALFORMED);
    out.push(String(value));
  } else if (typeof value === 'string') writeString(out, value);
  else if (isArray(value)) {
    const items = value instanceof JsonArray ? value.items : value;
    out.push('[');
    items.forEach((item, i) => {
      if (i > 0) out.push(',');
      write(out, item);
    });
    out.push(']');
  } else if (isObject(value)) {
    out.push('{');
    Object.keys(value)
      .sort()
      .forEach((key, i) => {
        if (i > 0) out.push(',');
        writeString(out, key);
        out.push(':');
        write(out, value[key]);
      });
    out.push('}');
  } else {
    throw new GdwError(ERR_MALFORMED);
  }
}

function canonical(value) {
  const out = [];
  write(out, value);
  return out.join('');
}

// ---- strict parsing -------------------------------------------------------

class Parser {
  constructor(text) {
    this.text = text;
    this.pos = 0;
  }

  fail() {
    throw new GdwError(ERR_MALFORMED);
  }

  peek() {
    return this.pos < this.text.length ? this.text[this.pos] : '';
  }

  skipWs() {
    while (this.pos < this.text.length) {
      const c = this.text[this.pos];
      if (c === ' ' || c === '\t' || c === '\n' || c === '\r') this.pos += 1;
      else break;
    }
  }

  parseDocument() {
    const value = this.parseValue();
    this.skipWs();
    if (this.pos !== this.text.length) this.fail();
    return value;
  }

  parseValue() {
    this.skipWs();
    const c = this.peek();
    if (c === '{') return this.parseObject();
    if (c === '[') return this.parseArray();
    if (c === '"') return this.parseString();
    if (c === 't') return this.parseLiteral('true', true);
    if (c === 'f') return this.parseLiteral('false', false);
    if (c === 'n') return this.parseLiteral('null', null);
    if (c === '-' || (c >= '0' && c <= '9')) return this.parseNumber();
    return this.fail();
  }

  parseLiteral(word, value) {
    if (this.text.substr(this.pos, word.length) !== word) this.fail();
    this.pos += word.length;
    return value;
  }

  parseObject() {
    this.pos += 1; // {
    const obj = {};
    this.skipWs();
    if (this.peek() === '}') {
      this.pos += 1;
      return obj;
    }
    for (;;) {
      this.skipWs();
      if (this.peek() !== '"') this.fail();
      const key = this.parseString();
      this.skipWs();
      if (this.peek() !== ':') this.fail();
      this.pos += 1;
      obj[key] = this.parseValue();
      this.skipWs();
      const c = this.peek();
      if (c === ',') {
        this.pos += 1;
        continue;
      }
      if (c === '}') {
        this.pos += 1;
        return obj;
      }
      this.fail();
    }
  }

  parseArray() {
    this.pos += 1; // [
    const arr = [];
    this.skipWs();
    if (this.peek() === ']') {
      this.pos += 1;
      return new JsonArray(arr);
    }
    for (;;) {
      arr.push(this.parseValue());
      this.skipWs();
      const c = this.peek();
      if (c === ',') {
        this.pos += 1;
        continue;
      }
      if (c === ']') {
        this.pos += 1;
        return new JsonArray(arr);
      }
      this.fail();
    }
  }

  parseString() {
    this.pos += 1; // opening quote
    let out = '';
    for (;;) {
      if (this.pos >= this.text.length) this.fail();
      const c = this.text[this.pos];
      this.pos += 1;
      if (c === '"') return out;
      if (c === '\\') {
        if (this.pos >= this.text.length) this.fail();
        const e = this.text[this.pos];
        this.pos += 1;
        switch (e) {
          case '"': out += '"'; break;
          case '\\': out += '\\'; break;
          case '/': out += '/'; break;
          case 'b': out += '\b'; break;
          case 'f': out += '\f'; break;
          case 'n': out += '\n'; break;
          case 'r': out += '\r'; break;
          case 't': out += '\t'; break;
          case 'u': {
            let cp = this.parseHex4();
            if (
              cp >= 0xd800 && cp <= 0xdbff &&
              this.pos + 1 < this.text.length &&
              this.text[this.pos] === '\\' && this.text[this.pos + 1] === 'u'
            ) {
              this.pos += 2;
              const low = this.parseHex4();
              if (low >= 0xdc00 && low <= 0xdfff) {
                cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
              }
            }
            out += String.fromCodePoint(cp);
            break;
          }
          default: this.fail();
        }
      } else {
        out += c;
      }
    }
  }

  parseHex4() {
    if (this.pos + 4 > this.text.length) this.fail();
    let value = 0;
    for (let i = 0; i < 4; i += 1) {
      const c = this.text[this.pos];
      this.pos += 1;
      value <<= 4;
      const code = c.charCodeAt(0);
      if (code >= 0x30 && code <= 0x39) value |= code - 0x30;
      else if (code >= 0x61 && code <= 0x66) value |= code - 0x61 + 10;
      else if (code >= 0x41 && code <= 0x46) value |= code - 0x41 + 10;
      else this.fail();
    }
    return value;
  }

  parseNumber() {
    const start = this.pos;
    if (this.peek() === '-') this.pos += 1;
    const digitStart = this.pos;
    while (this.pos < this.text.length && this.text[this.pos] >= '0' && this.text[this.pos] <= '9') {
      this.pos += 1;
    }
    if (this.pos === digitStart) this.fail();
    const c = this.peek();
    if (c === '.' || c === 'e' || c === 'E') this.fail();
    const digits = this.text.substring(start, this.pos);
    const body = digits[0] === '-' ? digits.substring(1) : digits;
    if (digits === '-0' || (body.length > 1 && body[0] === '0')) this.fail();
    const value = Number(digits);
    if (!Number.isSafeInteger(value) || value < -MAX_SAFE_INT || value > MAX_SAFE_INT) this.fail();
    return value;
  }
}

function parse(text) {
  if (typeof text !== 'string') throw new GdwError(ERR_MALFORMED);
  return new Parser(text).parseDocument();
}

module.exports = {
  MAX_SAFE_INT,
  JsonArray,
  isObject,
  isArray,
  get,
  has,
  asStr,
  asInt,
  entries,
  canonical,
  parse,
};
