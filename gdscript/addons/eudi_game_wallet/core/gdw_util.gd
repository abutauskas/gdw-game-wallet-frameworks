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


# ---- base64url -------------------------------------------------------------

static func base64url_encode(data: PackedByteArray) -> String:
	return Marshalls.raw_to_base64(data).rstrip("=").replace("+", "-").replace("/", "_")


static func base64url_decode(text: String) -> PackedByteArray:
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
	# Integers only. JSON.parse_string yields floats; emit without a fraction.
	if value == floor(value) and absf(value) < 9007199254740992.0:
		return str(int(value))
	# Non-integers are forbidden by the spec; surface them clearly.
	push_error("GDW canonical JSON forbids non-integer numbers: %s" % value)
	return str(int(value))


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


static func parse_segment(segment: String) -> Variant:
	var text := base64url_decode(segment).get_string_from_utf8()
	var parsed: Variant = JSON.parse_string(text)
	if parsed == null:
		return null
	return parsed


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


static func parse_disclosure(segment: String) -> Dictionary:
	var arr: Variant = parse_segment(segment)
	if typeof(arr) != TYPE_ARRAY or arr.size() != 3:
		return {}
	if typeof(arr[0]) != TYPE_STRING or typeof(arr[1]) != TYPE_STRING:
		return {}
	return {"salt": arr[0], "name": arr[1], "value": arr[2]}


static func disclosure_digest(segment: String) -> String:
	return base64url_encode(sha256(segment.to_utf8_buffer()))


static func sd_hash(base_text: String) -> String:
	return base64url_encode(sha256(base_text.to_utf8_buffer()))


# ---- salt ------------------------------------------------------------------

static func random_base64url(bytes: int) -> String:
	return base64url_encode(Crypto.new().generate_random_bytes(bytes))
