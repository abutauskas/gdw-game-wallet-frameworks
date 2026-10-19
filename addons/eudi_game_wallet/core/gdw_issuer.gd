## GDW Issuer: signs credentials and builds selective-disclosure disclosures.
##
## SPDX-License-Identifier: CC-BY-4.0
class_name GdwIssuer
extends RefCounted

const Util := preload("res://addons/eudi_game_wallet/core/gdw_util.gd")
const Key := preload("res://addons/eudi_game_wallet/core/gdw_key.gd")

var iss: String
var _key: GdwKey


func _init(issuer_id: String, issuer_key: GdwKey) -> void:
	iss = issuer_id
	_key = issuer_key


func issue(options: Dictionary) -> String:
	var vct: String = options.get("vct", "")
	var claims: Dictionary = options.get("claims", {})
	var disclosable: PackedStringArray = options.get("disclosable", PackedStringArray())
	var iat: int = options.get("iat", 0)
	var exp: int = options.get("exp", 0)
	var sub: String = options.get("sub", "")
	var holder_key: GdwKey = options.get("holder_key", null)
	var salts: PackedStringArray = options.get("salts", PackedStringArray())
	if iat == 0 or exp == 0 or vct == "" or holder_key == null:
		return ""

	var segments := PackedStringArray()
	var sd := []
	for i in disclosable.size():
		var name := disclosable[i]
		if not claims.has(name) or Util.is_reserved(name):
			return ""
		var salt := salts[i] if i < salts.size() else Util.random_base64url(16)
		var segment := Util.make_disclosure(salt, name, claims[name])
		segments.append(segment)
		sd.append(Util.disclosure_digest(segment))

	var payload := {
		"_sd": sd,
		"_sd_alg": "sha-256",
		"cnf": holder_key.to_dict(),
		"exp": exp,
		"iat": iat,
		"iss": iss,
		"vct": vct,
	}
	if sub != "":
		payload["sub"] = sub
	for name in claims:
		if disclosable.has(name):
			continue
		if payload.has(name):
			return ""
		payload[name] = claims[name]

	var header := {"alg": _key.alg, "typ": "gw+jwt"}
	var signing_input := Util.json_segment(header) + "." + Util.json_segment(payload)
	var jwt := signing_input + "." + _key.sign(signing_input)

	var out := jwt
	for segment in segments:
		out += "~" + segment
	out += "~"
	return out
