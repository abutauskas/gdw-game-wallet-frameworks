## GDW Wallet (holder): stores credentials and produces presentations.
##
## SPDX-License-Identifier: CC-BY-4.0
class_name GdwWallet
extends RefCounted

const Util := preload("res://addons/eudi_game_wallet/core/gdw_util.gd")
const Core := preload("res://addons/eudi_game_wallet/core/gdw.gd")
const Key := preload("res://addons/eudi_game_wallet/core/gdw_key.gd")

var _key: GdwKey
var _credentials: Array[String] = []


func _init(holder_key: GdwKey) -> void:
	_key = holder_key


func store(credential: String) -> bool:
	if Core.parse_credential(credential).is_empty():
		return false
	_credentials.append(credential)
	return true


func credentials() -> Array[String]:
	return _credentials


func claims_of(credential: String) -> PackedStringArray:
	var parsed := Core.parse_credential(credential)
	var names := PackedStringArray()
	if parsed.is_empty():
		return names
	for name in parsed.payload:
		if not Util.is_reserved(name):
			names.append(name)
	for segment in parsed.disclosures:
		names.append(Util.parse_disclosure(segment).get("name", ""))
	return names


func present(credential: String, requested_claims: PackedStringArray,
		aud: String, nonce: String, issued_at: int) -> String:
	var parsed := Core.parse_credential(credential)
	if parsed.is_empty():
		return ""
	var by_digest := {}
	for segment in parsed.disclosures:
		by_digest[Util.disclosure_digest(segment)] = segment

	var selected := PackedStringArray()
	var sd: Variant = parsed.payload.get("_sd", null)
	for name in requested_claims:
		if not Util.is_reserved(name) and parsed.payload.has(name):
			continue  # plaintext claim
		var found := false
		if typeof(sd) == TYPE_ARRAY:
			for digest in sd:
				if typeof(digest) != TYPE_STRING or not by_digest.has(digest):
					continue
				var seg: String = by_digest[digest]
				if Util.parse_disclosure(seg).get("name", "") == name:
					selected.append(seg)
					found = true
					break
		if not found:
			return ""  # ERR_CLAIM_MISSING

	var base_text: String = parsed.signing_input + "." + parsed.signature
	for segment in selected:
		base_text += "~" + segment

	var cnf: Variant = parsed.payload.get("cnf", null)
	if typeof(cnf) == TYPE_DICTIONARY:
		var cnf_key := Key.from_dict(cnf)
		if not cnf_key.same_secret(_key):
			return ""  # ERR_KB_INVALID

	var kb := {
		"aud": aud,
		"iat": issued_at,
		"nonce": nonce,
		"sd_hash": Util.sd_hash(base_text),
	}
	var header := {"alg": _key.alg, "typ": "kb+jwt"}
	var signing_input := Util.json_segment(header) + "." + Util.json_segment(kb)
	var kb_jwt := signing_input + "." + _key.sign(signing_input)
	return base_text + "~" + kb_jwt
