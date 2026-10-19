## GDW keys and the HS256 signer.
##
## Only HS256 is implemented natively: Godot's Crypto class has no ECDSA key
## generation API and cannot load EC private keys from PEM, so ES256 requires a
## GDExtension that binds platform crypto. See frameworks/SPEC.md §2.4 and the
## addon README.
##
## SPDX-License-Identifier: CC-BY-4.0
class_name GdwKey
extends RefCounted

const Util := preload("res://addons/eudi_game_wallet/core/gdw_util.gd")

var alg := "HS256"
var k := ""      # base64url raw HS256 secret
var crv := ""    # ES256 curve (parsed but unsupported for signing)
var x := ""
var y := ""
var d := ""


static func hs256(raw_secret: String) -> GdwKey:
	var key := GdwKey.new()
	key.alg = "HS256"
	key.k = Util.base64url_utf8(raw_secret)
	return key


static func hs256_from_bytes(raw: PackedByteArray) -> GdwKey:
	var key := GdwKey.new()
	key.alg = "HS256"
	key.k = Util.base64url_encode(raw)
	return key


func to_dict() -> Dictionary:
	var obj := {"alg": alg}
	if alg == "HS256":
		obj["k"] = k
	else:
		obj["crv"] = crv if crv != "" else "P-256"
		obj["x"] = x
		obj["y"] = y
		# PROTOTYPE ONLY: mirrors the C++/C# frameworks, which embed the private
		# scalar in cnf. Never do this in production. See SPEC.md §2.4.
		if d != "":
			obj["d"] = d
	return obj


## Build a key from a JSON object. Returns ``null`` if any present field has a
## non-string type, so callers fail closed instead of aborting on a typed
## assignment (which would return a default value and bypass a check).
static func from_dict(j: Dictionary) -> GdwKey:
	var key := GdwKey.new()
	var alg_val: Variant = j.get("alg")
	if alg_val == null:
		key.alg = "HS256"
	elif typeof(alg_val) == TYPE_STRING and alg_val != "":
		key.alg = alg_val
	elif typeof(alg_val) == TYPE_STRING:
		key.alg = "HS256"
	else:
		return null
	for field in ["k", "crv", "x", "y", "d"]:
		var value: Variant = j.get(field)
		if value == null:
			continue
		if typeof(value) != TYPE_STRING:
			return null
		key.set(field, value)
	return key


func same_secret(other: GdwKey) -> bool:
	if alg == "HS256":
		return k == other.k
	return d != "" and d == other.d


# ---- signing ---------------------------------------------------------------

func sign(signing_input: String) -> String:
	if alg != "HS256":
		push_error("GDW: only HS256 can be signed in GDScript; ES256 needs a GDExtension")
		return ""
	var mac := Util.hmac_sha256(
		Util.base64url_decode(k), signing_input.to_utf8_buffer())
	return Util.base64url_encode(mac)


func verify(signing_input: String, signature: String) -> bool:
	if alg != "HS256":
		return false
	var expected := Util.hmac_sha256(
		Util.base64url_decode(k), signing_input.to_utf8_buffer())
	var actual := Util.base64url_decode(signature)
	if expected.size() != actual.size():
		return false
	# constant_time_compare on the raw MACs
	return Crypto.new().constant_time_compare(expected, actual)
