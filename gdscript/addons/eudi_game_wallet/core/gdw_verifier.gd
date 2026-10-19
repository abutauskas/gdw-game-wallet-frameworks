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
	var claims := _verify(request, presentation, current_time)
	if claims.has("__error"):
		result["errors"] = [claims["__error"]]
		return result
	result["claims"] = claims
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
	if token.is_empty() or token.header.get("typ", "") != "gw+jwt":
		return _fail(Core.ERR_MALFORMED)

	var iss: String = token.payload.get("iss", "")
	if iss == "":
		return _fail(Core.ERR_MALFORMED)
	if not _trust.has(iss):
		return _fail(Core.ERR_ISSUER_UNKNOWN)
	var trusted: GdwKey = _trust[iss]
	if token.header.get("alg", "") != trusted.alg:
		return _fail(Core.ERR_MALFORMED)
	if not trusted.verify(token.signing_input, token.signature):
		return _fail(Core.ERR_SIGNATURE_INVALID)

	var exp := int(token.payload.get("exp", -1))
	var iat := int(token.payload.get("iat", -1))
	if exp < 0 or iat < 0:
		return _fail(Core.ERR_MALFORMED)
	if current_time > exp + clock_skew:
		return _fail(Core.ERR_EXPIRED)
	if current_time < iat - clock_skew:
		return _fail(Core.ERR_NOT_YET_VALID)

	var vct: String = token.payload.get("vct", "")
	var vct_allowed := false
	var allowed: Variant = request.get("vct", null)
	if typeof(allowed) == TYPE_ARRAY:
		for candidate in allowed:
			if candidate == vct:
				vct_allowed = true
	if not vct_allowed:
		return _fail(Core.ERR_VCT_NOT_ALLOWED)

	if token.payload.get("_sd_alg", "") != "sha-256":
		return _fail(Core.ERR_MALFORMED)
	var sd: Variant = token.payload.get("_sd", null)
	if typeof(sd) != TYPE_ARRAY:
		return _fail(Core.ERR_MALFORMED)

	var claims := {}
	for name in token.payload:
		if not Util.is_reserved(name):
			claims[name] = token.payload[name]

	var covered := []
	for digest in sd:
		covered.append(digest)

	var seen := []
	for segment in disclosures:
		var digest := Util.disclosure_digest(segment)
		if not covered.has(digest) or seen.has(digest):
			return _fail(Core.ERR_DISCLOSURE_UNKNOWN)
		seen.append(digest)
		var parsed := Util.parse_disclosure(segment)
		var claim_name: String = parsed.get("name", "")
		if claims.has(claim_name):
			return _fail(Core.ERR_DUPLICATE_CLAIM)
		claims[claim_name] = parsed.get("value")

	var required: Variant = request.get("claims", null)
	if typeof(required) == TYPE_ARRAY:
		for name in required:
			if not claims.has(name):
				return _fail(Core.ERR_CLAIM_MISSING)

	# key binding
	if kb_jwt == "":
		return _fail(Core.ERR_KB_MISSING)
	var kb_token := Core.decode_token(kb_jwt)
	if kb_token.is_empty() or kb_token.header.get("typ", "") != "kb+jwt":
		return _fail(Core.ERR_KB_INVALID)
	var cnf: Variant = token.payload.get("cnf", null)
	if typeof(cnf) != TYPE_DICTIONARY:
		return _fail(Core.ERR_KB_INVALID)
	var cnf_key := Key.from_dict(cnf)
	if kb_token.header.get("alg", "") != cnf_key.alg:
		return _fail(Core.ERR_KB_INVALID)
	if not cnf_key.verify(kb_token.signing_input, kb_token.signature):
		return _fail(Core.ERR_KB_INVALID)

	var base_text := jwt
	for segment in disclosures:
		base_text += "~" + segment
	if kb_token.payload.get("sd_hash", "") != Util.sd_hash(base_text):
		return _fail(Core.ERR_SD_HASH_MISMATCH)
	if kb_token.payload.get("aud", "") != request.get("aud", ""):
		return _fail(Core.ERR_AUD_MISMATCH)
	if kb_token.payload.get("nonce", "") != request.get("nonce", ""):
		return _fail(Core.ERR_NONCE_MISMATCH)

	var kb_iat := int(kb_token.payload.get("iat", -1))
	if kb_iat < 0 or current_time > kb_iat + clock_skew or current_time < kb_iat - clock_skew:
		return _fail(Core.ERR_KB_INVALID)

	var nonce_key := iss + "|" + str(request.get("nonce", ""))
	if _used_nonces.has(nonce_key):
		return _fail(Core.ERR_REPLAY)
	_used_nonces[nonce_key] = true

	return claims
