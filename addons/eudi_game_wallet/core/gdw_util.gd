## GDW primitives: base64url, SHA-256, HMAC-SHA256, canonical JSON, disclosures.
##
## Part of the EudiGameWallet GDScript addon. Mirrors the C++ and C# frameworks;
## see frameworks/SPEC.md for the normative rules.
##
## SPDX-License-Identifier: CC-BY-4.0
class_name GdwUtil
extends RefCounted

const CLAIM_NAME_REGEX := "^[A-Za-z0-9_-]{1,64}$"
const RESERVED := ["_sd", "_sd_alg", "cnf", "iss", "sub", "iat", "exp", "vct"]


static func is_valid_claim_name(name: String) -> bool:
	if name.is_empty() or name.length() > 64:
		return false
	if name.begins_with("_"):
		return false
	var regex := RegEx.new()
	regex.compile(CLAIM_NAME_REGEX)
	return regex.search(name) != null


static func is_reserved(name: String) -> bool:
	return RESERVED.has(name)


# ---- strict typed accessors (mirror Python's isinstance/as_int/as_str) ------
#
# GDScript's ``JSON.parse_string`` returns floats for every number, so an
# integer claim arrives as TYPE_FLOAT with an integral value. These helpers
# accept only integral floats (and native ints) for ``_as_int`` and return
# ``null`` for everything else, so verifier comparisons never hit GDScript's
# cross-type operator errors (which would abort the function and, before this
# fix, silently pass verification).

static func json_get(value: Variant, key: String) -> Variant:
	if typeof(value) == TYPE_DICTIONARY and value.has(key):
		return value[key]
	return null


static func json_as_str(value: Variant) -> Variant:
	return value if typeof(value) == TYPE_STRING else null


static func json_as_int(value: Variant) -> Variant:
	# Parsers must hand back native ints for JSON integers (see parse_segment);
	# anything else (float/bool/string/null) is not a valid integer.
	return value if typeof(value) == TYPE_INT else null


static func json_is_dict(value: Variant) -> bool:
	return typeof(value) == TYPE_DICTIONARY


static func json_is_array(value: Variant) -> bool:
	return typeof(value) == TYPE_ARRAY


# ---- base64url -------------------------------------------------------------

static func base64url_encode(data: PackedByteArray) -> String:
	return Marshalls.raw_to_base64(data).rstrip("=").replace("+", "-").replace("/", "_")


## Decode base64url. Invalid input (leftover length 1 mod 4, or characters
## outside the base64url alphabet) yields an empty PackedByteArray, which
## callers treat as a malformed segment.
static func base64url_decode(text: String) -> PackedByteArray:
	for i in text.length():
		var c := text[i]
		var valid := (c >= "A" and c <= "Z") or (c >= "a" and c <= "z") or (c >= "0" and c <= "9") or c == "-" or c == "_"
		if not valid:
			return PackedByteArray()
	if text.length() % 4 == 1:
		return PackedByteArray()
	var s := text.replace("-", "+").replace("_", "/")
	match s.length() % 4:
		2:
			s += "=="
		3:
			s += "="
	return Marshalls.base64_to_raw(s)


static func base64url_utf8(text: String) -> String:
	return base64url_encode(text.to_utf8_buffer())


# ---- hashing ---------------------------------------------------------------

static func sha256(data: PackedByteArray) -> PackedByteArray:
	var ctx := HashingContext.new()
	ctx.start(HashingContext.HASH_SHA256)
	ctx.update(data)
	return ctx.finish()


static func sha256_base64url(data: PackedByteArray) -> String:
	return base64url_encode(sha256(data))


static func hmac_sha256(key: PackedByteArray, message: PackedByteArray) -> PackedByteArray:
	return Crypto.new().hmac_digest(HashingContext.HASH_SHA256, key, message)


# ---- canonical JSON --------------------------------------------------------

## Recursively encode a parsed JSON value in canonical form.
static func canonical(value: Variant) -> String:
	match typeof(value):
		TYPE_NIL:
			return "null"
		TYPE_BOOL:
			return "true" if value else "false"
		TYPE_INT:
			if value < -MAX_SAFE_INT or value > MAX_SAFE_INT:
				push_error("GDW canonical JSON forbids integers outside +/-2^53-1: %s" % value)
				return ""
			return str(value)
		TYPE_FLOAT:
			return _canonical_number(value)
		TYPE_STRING, TYPE_STRING_NAME:
			return encode_string(String(value))
		TYPE_ARRAY, TYPE_PACKED_STRING_ARRAY, TYPE_PACKED_INT32_ARRAY, TYPE_PACKED_INT64_ARRAY:
			var parts := PackedStringArray()
			for i in value.size():
				parts.append(canonical(value[i]))
			return "[" + ",".join(parts) + "]"
		TYPE_DICTIONARY:
			var keys: Array = value.keys()
			keys.sort_custom(func(a, b): return String(a) < String(b))
			var members := PackedStringArray()
			for k in keys:
				members.append(encode_string(String(k)) + ":" + canonical(value[k]))
			return "{" + ",".join(members) + "}"
		_:
			return "null"


static func _canonical_number(value: float) -> String:
	# GDScript's JSON parser yields floats for every number, so an integral
	# float here is a legitimate integer. Anything non-integral (or outside the
	# safe range) is forbidden by the spec (§2.2): poison the segment rather
	# than silently truncating a value that was signed/hashed.
	if value == floor(value) and absf(value) <= float(MAX_SAFE_INT):
		return str(int(value))
	push_error("GDW canonical JSON forbids non-integer numbers: %s" % value)
	return ""


## Escape a string exactly as SPEC.md §2.2 requires (lowercase \u00xx).
static func encode_string(s: String) -> String:
	var out := "\""
	for i in s.length():
		var c := s.unicode_at(i)
		match c:
			0x22:
				out += "\\\""
			0x5c:
				out += "\\\\"
			0x08:
				out += "\\b"
			0x09:
				out += "\\t"
			0x0a:
				out += "\\n"
			0x0c:
				out += "\\f"
			0x0d:
				out += "\\r"
			_:
				if c < 0x20:
					out += "\\u%04x" % c
				else:
					out += String.chr(c)
	out += "\""
	return out


# ---- canonical segments ----------------------------------------------------

static func json_segment(value: Variant) -> String:
	return base64url_encode(canonical(value).to_utf8_buffer())


const MAX_SAFE_INT := 9007199254740991  # 2^53 - 1


## Parse a canonical JSON document, rejecting floats, exponents, "-0", leading
## zeros and integers outside +/-(2^53 - 1). Integers become native ints.
## Returns a Dictionary ``{"ok": true, "value": ...}`` or ``{"ok": false}``.
static func parse_segment_strict(text: String) -> Dictionary:
	var parser := _JsonParser.new(text)
	var value: Variant = parser.parse_document()
	if not parser.ok:
		return {"ok": false}
	return {"ok": true, "value": value}


static func parse_segment(segment: String) -> Variant:
	var text := base64url_decode(segment).get_string_from_utf8()
	var result := parse_segment_strict(text)
	return result["value"] if result["ok"] else null


class _JsonParser:
	extends RefCounted

	var _text: String
	var _pos: int = 0
	var ok: bool = true

	func _init(text: String) -> void:
		_text = text

	func _peek() -> String:
		return _text[_pos] if _pos < _text.length() else ""

	func _fail() -> Variant:
		ok = false
		return null

	func parse_document() -> Variant:
		var value: Variant = _parse_value()
		if not ok:
			return null
		_skip_ws()
		if _pos != _text.length():
			return _fail()
		return value

	func _skip_ws() -> void:
		while _pos < _text.length():
			var c := _text[_pos]
			if c == " " or c == "\t" or c == "\n" or c == "\r":
				_pos += 1
			else:
				break

	func _parse_value() -> Variant:
		_skip_ws()
		var c := _peek()
		match c:
			"{":
				return _parse_object()
			"[":
				return _parse_array()
			"\"":
				return _parse_string()
			"t":
				return _parse_literal("true", true)
			"f":
				return _parse_literal("false", false)
			"n":
				return _parse_literal("null", null)
			_:
				if c == "-" or (c >= "0" and c <= "9"):
					return _parse_number()
				return _fail()

	func _parse_literal(word: String, value: Variant) -> Variant:
		if _text.substr(_pos, word.length()) != word:
			return _fail()
		_pos += word.length()
		return value

	func _parse_object() -> Variant:
		_pos += 1  # {
		var obj := {}
		_skip_ws()
		if _peek() == "}":
			_pos += 1
			return obj
		while true:
			_skip_ws()
			if _peek() != "\"":
				return _fail()
			var key: Variant = _parse_string()
			if not ok:
				return null
			_skip_ws()
			if _peek() != ":":
				return _fail()
			_pos += 1
			var value: Variant = _parse_value()
			if not ok:
				return null
			obj[key] = value
			_skip_ws()
			var c := _peek()
			if c == ",":
				_pos += 1
				continue
			if c == "}":
				_pos += 1
				return obj
			return _fail()
		return _fail()

	func _parse_array() -> Variant:
		_pos += 1  # [
		var arr := []
		_skip_ws()
		if _peek() == "]":
			_pos += 1
			return arr
		while true:
			var value: Variant = _parse_value()
			if not ok:
				return null
			arr.append(value)
			_skip_ws()
			var c := _peek()
			if c == ",":
				_pos += 1
				continue
			if c == "]":
				_pos += 1
				return arr
			return _fail()
		return _fail()

	func _parse_string() -> Variant:
		_pos += 1  # opening quote
		var out := ""
		while true:
			if _pos >= _text.length():
				return _fail()
			var c := _text[_pos]
			_pos += 1
			if c == "\"":
				return out
			if c == "\\":
				if _pos >= _text.length():
					return _fail()
				var e := _text[_pos]
				_pos += 1
				match e:
					"\"":
						out += "\""
					"\\":
						out += "\\"
					"/":
						out += "/"
					"b":
						out += "\b"
					"f":
						out += "\f"
					"n":
						out += "\n"
					"r":
						out += "\r"
					"t":
						out += "\t"
					"u":
						var cp: Variant = _parse_hex4()
						if not ok:
							return null
						if cp >= 0xD800 and cp <= 0xDBFF and _pos + 1 < _text.length() and _text[_pos] == "\\" and _text[_pos + 1] == "u":
							_pos += 2
							var low: Variant = _parse_hex4()
							if not ok:
								return null
							if low >= 0xDC00 and low <= 0xDFFF:
								cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00)
						out += String.chr(cp)
					_:
						return _fail()
			else:
				out += c
		return _fail()

	func _parse_hex4() -> Variant:
		if _pos + 4 > _text.length():
			return _fail()
		var value := 0
		for i in 4:
			var c := _text[_pos]
			_pos += 1
			value <<= 4
			if c >= "0" and c <= "9":
				value |= c.unicode_at(0) - 0x30
			elif c >= "a" and c <= "f":
				value |= c.unicode_at(0) - 0x61 + 10
			elif c >= "A" and c <= "F":
				value |= c.unicode_at(0) - 0x41 + 10
			else:
				return _fail()
		return value

	func _parse_number() -> Variant:
		var start := _pos
		if _peek() == "-":
			_pos += 1
		while _pos < _text.length() and _text[_pos] >= "0" and _text[_pos] <= "9":
			_pos += 1
		if _pos < _text.length():
			var c := _text[_pos]
			if c == "." or c == "e" or c == "E":
				return _fail()
		var digits := _text.substr(start, _pos - start)
		if digits == "-0":
			return _fail()
		var body := digits.substr(1) if digits.begins_with("-") else digits
		if body.length() > 1 and body.begins_with("0"):
			return _fail()
		if body.is_empty():
			return _fail()
		var value := int(digits)
		if value < -MAX_SAFE_INT or value > MAX_SAFE_INT:
			return _fail()
		return value


# ---- splits ----------------------------------------------------------------

static func split_tilde(text: String) -> PackedStringArray:
	return text.split("~")

static func split_dot(text: String) -> PackedStringArray:
	return text.split(".")


# ---- disclosures -----------------------------------------------------------

static func make_disclosure(salt_b64: String, name: String, value: Variant) -> String:
	assert(is_valid_claim_name(name))
	assert(base64url_decode(salt_b64).size() >= 16)
	var arr := [salt_b64, name, value]
	return base64url_encode(canonical(arr).to_utf8_buffer())


## Returns ``{}`` when the segment is not a well-formed disclosure (bad JSON,
## wrong shape, short salt, or an invalid claim name), matching the reference
## implementation's ERR_MALFORMED outcome.
static func parse_disclosure(segment: String) -> Dictionary:
	var arr: Variant = parse_segment(segment)
	if typeof(arr) != TYPE_ARRAY or arr.size() != 3:
		return {}
	if typeof(arr[0]) != TYPE_STRING or typeof(arr[1]) != TYPE_STRING:
		return {}
	if not is_valid_claim_name(arr[1]):
		return {}
	if base64url_decode(arr[0]).size() < 16:
		return {}
	return {"salt": arr[0], "name": arr[1], "value": arr[2]}


static func disclosure_digest(segment: String) -> String:
	return base64url_encode(sha256(segment.to_utf8_buffer()))


static func sd_hash(base_text: String) -> String:
	return base64url_encode(sha256(base_text.to_utf8_buffer()))


# ---- salt ------------------------------------------------------------------

static func random_base64url(bytes: int) -> String:
	return base64url_encode(Crypto.new().generate_random_bytes(bytes))
