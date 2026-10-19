## GDW error codes and token/credential decoding (statics only).
##
## Mirrors the C++ and C# frameworks; see frameworks/SPEC.md. Issuer, Wallet and
## Verifier live in gdw_issuer.gd / gdw_wallet.gd / gdw_verifier.gd.
##
## SPDX-License-Identifier: CC-BY-4.0
class_name Gdw
extends RefCounted

const Util := preload("res://addons/eudi_game_wallet/core/gdw_util.gd")

const ERR_MALFORMED := "ERR_MALFORMED"
const ERR_SIGNATURE_INVALID := "ERR_SIGNATURE_INVALID"
const ERR_ISSUER_UNKNOWN := "ERR_ISSUER_UNKNOWN"
const ERR_VCT_NOT_ALLOWED := "ERR_VCT_NOT_ALLOWED"
const ERR_EXPIRED := "ERR_EXPIRED"
const ERR_NOT_YET_VALID := "ERR_NOT_YET_VALID"
const ERR_DISCLOSURE_UNKNOWN := "ERR_DISCLOSURE_UNKNOWN"
const ERR_CLAIM_MISSING := "ERR_CLAIM_MISSING"
const ERR_DUPLICATE_CLAIM := "ERR_DUPLICATE_CLAIM"
const ERR_KB_MISSING := "ERR_KB_MISSING"
const ERR_KB_INVALID := "ERR_KB_INVALID"
const ERR_AUD_MISMATCH := "ERR_AUD_MISMATCH"
const ERR_NONCE_MISMATCH := "ERR_NONCE_MISMATCH"
const ERR_SD_HASH_MISMATCH := "ERR_SD_HASH_MISMATCH"
const ERR_REPLAY := "ERR_REPLAY"


static func now() -> int:
	return int(Time.get_unix_time_from_system())


# ---- token decoding --------------------------------------------------------

static func decode_token(token: String) -> Dictionary:
	var parts := Util.split_dot(token)
	if parts.size() != 3:
		return {}
	var header: Variant = Util.parse_segment(parts[0])
	var payload: Variant = Util.parse_segment(parts[1])
	if typeof(header) != TYPE_DICTIONARY or typeof(payload) != TYPE_DICTIONARY:
		return {}
	return {
		"header": header,
		"payload": payload,
		"signing_input": parts[0] + "." + parts[1],
		"signature": parts[2],
	}


static func parse_credential(credential: String) -> Dictionary:
	if credential.is_empty() or not credential.ends_with("~"):
		return {}
	var parts := Util.split_tilde(credential)
	if parts.size() < 2:
		return {}
	var token := decode_token(parts[0])
	if token.is_empty() or token.header.get("typ", "") != "gw+jwt":
		return {}
	var disclosures := PackedStringArray()
	for i in range(1, parts.size()):
		if parts[i] != "":
			disclosures.append(parts[i])
	token["disclosures"] = disclosures
	return token
