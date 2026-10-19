## GDW Verifier (relying party): checks presentations and derives claims.
##
## SPDX-License-Identifier: CC-BY-4.0
class_name GdwVerifier
extends RefCounted

const Util := preload("res://addons/eudi_game_wallet/core/gdw_util.gd")
const Core := preload("res://addons/eudi_game_wallet/core/gdw.gd")
const Key := preload("res://addons/eudi_game_wallet/core/gdw_key.gd")

var aud: String
var clock_skew: int = 300
var _trust: Dictionary = {}
var _used_nonces: Dictionary = {}


func _init(audience: String) -> void:
	aud = audience


func trust(issuer: String, key: GdwKey) -> void:
	_trust[issuer] = key


func mark_nonce_used(iss: String, nonce: String) -> void:
	_used_nonces[iss + "|" + nonce] = true


func create_request(vct: PackedStringArray, claims: PackedStringArray, ttl: int = 60) -> Dictionary:
	return {
		"aud": aud,
		"nonce": Util.random_base64url(16),
		"vct": Array(vct),
		"claims": Array(claims),
		"iat": Core.now(),
		"expires_at": Core.now() + ttl,
	}


func verify(request: Dictionary, presentation: String, current_time: int) -> Dictionary:
	var result := {"ok": false, "claims": {}, "errors": []}
	var outcome := _verify(request, presentation, current_time)
	if not outcome.has("__claims"):
		# Any abort inside _verify (an unexpected runtime error) returns the
		# declared Dictionary's default value, which lacks __claims. Fail closed
		# rather than treating it as success.
		result["errors"] = [outcome.get("__error", Core.ERR_MALFORMED)]
		return result
	result["claims"] = outcome["__claims"]
	result["ok"] = true
	return result


func _fail(code: String) -> Dictionary:
	return {"__error": code}


func _verify(request: Dictionary, presentation: String, current_time: int) -> Dictionary:
	var parts := Util.split_tilde(presentation)
	if parts.size() < 2:
		return _fail(Core.ERR_MALFORMED)

	var jwt := parts[0]
	var has_kb := parts[parts.size() - 1] != ""
	var kb_jwt := parts[parts.size() - 1] if has_kb else ""
	var disclosures := PackedStringArray()
	var end := parts.size() - 1 if has_kb else parts.size()
	for i in range(1, end):
		if parts[i] != "":
			disclosures.append(parts[i])

	var token := Core.decode_token(jwt)
	if token.is_empty() or Util.json_as_str(Util.json_get(token.header, "typ")) != "gw+jwt":
		return _fail(Core.ERR_MALFORMED)

	var iss: Variant = Util.json_as_str(Util.json_get(token.payload, "iss"))
	if iss == null or iss == "":
		return _fail(Core.ERR_MALFORMED)
	if not _trust.has(iss):
		return _fail(Core.ERR_ISSUER_UNKNOWN)
	var trusted: GdwKey = _trust[iss]
	if Util.json_as_str(Util.json_get(token.header, "alg")) != trusted.alg:
		return _fail(Core.ERR_MALFORMED)
	if not trusted.verify(token.signing_input, token.signature):
		return _fail(Core.ERR_SIGNATURE_INVALID)

	var exp: Variant = Util.json_as_int(Util.json_get(token.payload, "exp"))
	var iat: Variant = Util.json_as_int(Util.json_get(token.payload, "iat"))
	if exp == null or iat == null or exp < 0 or iat < 0:
		return _fail(Core.ERR_MALFORMED)
	if current_time > exp + clock_skew:
		return _fail(Core.ERR_EXPIRED)
	if current_time < iat - clock_skew:
		return _fail(Core.ERR_NOT_YET_VALID)

	var vct: Variant = Util.json_as_str(Util.json_get(token.payload, "vct"))
	if vct == null:
		vct = ""
	var vct_allowed := false
	var allowed: Variant = Util.json_get(request, "vct")
	if Util.json_is_array(allowed):
		for candidate in allowed:
			if Util.json_as_str(candidate) == vct:
				vct_allowed = true
	if not vct_allowed:
		return _fail(Core.ERR_VCT_NOT_ALLOWED)

	if Util.json_as_str(Util.json_get(token.payload, "_sd_alg")) != "sha-256":
		return _fail(Core.ERR_MALFORMED)
	var sd: Variant = Util.json_get(token.payload, "_sd")
	if not Util.json_is_array(sd):
		return _fail(Core.ERR_MALFORMED)

	var claims := {}
	for name in token.payload:
		if not Util.is_reserved(name):
			claims[name] = token.payload[name]

	var covered := []
	for digest in sd:
		if typeof(digest) == TYPE_STRING:
			covered.append(digest)

	var seen := []
	for segment in disclosures:
		var digest := Util.disclosure_digest(segment)
		if not covered.has(digest) or seen.has(digest):
			return _fail(Core.ERR_DISCLOSURE_UNKNOWN)
		seen.append(digest)
		var parsed := Util.parse_disclosure(segment)
		if parsed.is_empty():
			return _fail(Core.ERR_MALFORMED)
		var claim_name: String = parsed["name"]
		if claims.has(claim_name):
			return _fail(Core.ERR_DUPLICATE_CLAIM)
		claims[claim_name] = parsed["value"]

	var required: Variant = Util.json_get(request, "claims")
	if Util.json_is_array(required):
		for name in required:
			if typeof(name) == TYPE_STRING and not claims.has(name):
				return _fail(Core.ERR_CLAIM_MISSING)

	# key binding
	if kb_jwt == "":
		return _fail(Core.ERR_KB_MISSING)
	var kb_token := Core.decode_token(kb_jwt)
	if kb_token.is_empty() or Util.json_as_str(Util.json_get(kb_token.header, "typ")) != "kb+jwt":
		return _fail(Core.ERR_KB_INVALID)
	var cnf: Variant = Util.json_get(token.payload, "cnf")
	if not Util.json_is_dict(cnf):
		return _fail(Core.ERR_KB_INVALID)
	var cnf_key := Key.from_dict(cnf)
	if cnf_key == null:
		return _fail(Core.ERR_KB_INVALID)
	if Util.json_as_str(Util.json_get(kb_token.header, "alg")) != cnf_key.alg:
		return _fail(Core.ERR_KB_INVALID)
	if not cnf_key.verify(kb_token.signing_input, kb_token.signature):
		return _fail(Core.ERR_KB_INVALID)

	var base_text := jwt
	for segment in disclosures:
		base_text += "~" + segment
	if Util.json_as_str(Util.json_get(kb_token.payload, "sd_hash")) != Util.sd_hash(base_text):
		return _fail(Core.ERR_SD_HASH_MISMATCH)
	if Util.json_as_str(Util.json_get(kb_token.payload, "aud")) != Util.json_as_str(Util.json_get(request, "aud")):
		return _fail(Core.ERR_AUD_MISMATCH)
	if Util.json_as_str(Util.json_get(kb_token.payload, "nonce")) != Util.json_as_str(Util.json_get(request, "nonce")):
		return _fail(Core.ERR_NONCE_MISMATCH)

	var kb_iat: Variant = Util.json_as_int(Util.json_get(kb_token.payload, "iat"))
	if kb_iat == null or kb_iat < 0 or current_time > kb_iat + clock_skew or current_time < kb_iat - clock_skew:
		return _fail(Core.ERR_KB_INVALID)

	# Mirror the reference: a falsy nonce (null/""/0/false) contributes nothing.
	var nonce_val: Variant = Util.json_get(request, "nonce")
	var nonce_text := ""
	var truthy := nonce_val != null
	if truthy and typeof(nonce_val) == TYPE_STRING and nonce_val == "":
		truthy = false
	elif truthy and typeof(nonce_val) == TYPE_BOOL and not nonce_val:
		truthy = false
	elif truthy and (typeof(nonce_val) == TYPE_INT or typeof(nonce_val) == TYPE_FLOAT) and nonce_val == 0:
		truthy = false
	if truthy:
		nonce_text = str(nonce_val)
	var nonce_key: String = str(iss) + "|" + nonce_text
	if _used_nonces.has(nonce_key):
		return _fail(Core.ERR_REPLAY)
	_used_nonces[nonce_key] = true

	return {"__claims": claims}
