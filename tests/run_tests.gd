## Conformance tests for the EudiGameWallet GDScript framework.
##
## Replays frameworks/test-vectors/vectors.json byte-for-byte. Run from the
## frameworks/gdscript directory:
##
##   godot --headless --path . --script res://tests/run_tests.gd
##
## SPDX-License-Identifier: CC-BY-4.0
extends SceneTree

const Util := preload("res://addons/eudi_game_wallet/core/gdw_util.gd")
const Core := preload("res://addons/eudi_game_wallet/core/gdw.gd")
const Key := preload("res://addons/eudi_game_wallet/core/gdw_key.gd")
const Issuer := preload("res://addons/eudi_game_wallet/core/gdw_issuer.gd")
const Verifier := preload("res://addons/eudi_game_wallet/core/gdw_verifier.gd")

var checks := 0
var failures := 0


func _check(condition: bool, label: String) -> void:
	checks += 1
	if not condition:
		failures += 1
		print("  FAIL: ", label)


func _check_equal(actual: String, expected: String, label: String) -> void:
	checks += 1
	if actual != expected:
		failures += 1
		print("  FAIL: ", label)
		print("    expected: ", expected)
		print("    actual:   ", actual)


func _load_vectors() -> Dictionary:
	for candidate in ["res://test-vectors/vectors.json", "res://../test-vectors/vectors.json"]:
		var path := ProjectSettings.globalize_path(candidate).simplify_path()
		var f := FileAccess.open(path, FileAccess.READ)
		if f != null:
			return JSON.parse_string(f.get_as_text())
	push_error("cannot open vectors.json")
	return {}


func _init() -> void:
	var vectors := _load_vectors()
	if vectors.is_empty():
		quit(2)
		return

	_test_canonical_json(vectors)
	_test_disclosures(vectors)
	_test_hs256(vectors)
	_test_issue_flow(vectors)
	_test_verify_flow(vectors)
	_test_type_confusion(vectors)
	_test_negative_cases(vectors)
	# ES256 is intentionally not tested: GDScript cannot sign it natively.

	print("")
	print("%d/%d checks passed" % [checks - failures, checks])
	quit(0 if failures == 0 else 1)


func _test_canonical_json(vectors: Dictionary) -> void:
	print("canonical JSON")
	for case in vectors["canonical_json"]:
		var expected: String = case["canonical"]
		_check_equal(Util.canonical(case["input"]), expected, case["name"])
		_check_equal(Util.canonical(JSON.parse_string(expected)), expected, case["name"] + " (round trip)")


func _test_disclosures(vectors: Dictionary) -> void:
	print("disclosures")
	for case in vectors["disclosures"]:
		var segment := Util.make_disclosure(case["salt_b64"], case["claim_name"], case["claim_value"])
		_check_equal(segment, case["segment"], case["name"] + " segment")
		_check_equal(Util.disclosure_digest(segment), case["digest"], case["name"] + " digest")
		var parsed := Util.parse_disclosure(segment)
		_check_equal(str(parsed.get("name", "")), case["claim_name"], case["name"] + " parsed name")


func _test_hs256(vectors: Dictionary) -> void:
	print("HS256")
	var hs: Dictionary = vectors["hs256"]
	var key := Key.from_dict(hs["key"])
	var input: String = hs["signing_input"]
	_check_equal(key.sign(input), hs["signature"], "signature")
	_check(key.verify(input, hs["signature"]), "verify")
	_check(not key.verify(input, hs["signature"] + "x"), "verify rejects tamper")


func _test_issue_flow(vectors: Dictionary) -> void:
	print("issue flow")
	var flow: Dictionary = vectors["issue_flow"]
	var issuer := Issuer.new(flow["iss"], Key.from_dict(flow["issuer_key"]))
	var options := {
		"vct": flow["vct"],
		"claims": flow["claims"],
		"disclosable": PackedStringArray(flow["disclosable"]),
		"iat": int(flow["iat"]),
		"exp": int(flow["exp"]),
		"sub": flow["sub"],
		"holder_key": Key.from_dict(flow["holder_key"]),
		"salts": PackedStringArray(flow["salts"]),
	}
	var credential := issuer.issue(options)
	_check_equal(credential, flow["credential"], "credential string")

	var parsed := Core.parse_credential(credential)
	_check_equal(Util.canonical(parsed["payload"]), Util.canonical(flow["expected_payload"]), "payload")
	var expected_disclosures: Array = flow["expected_disclosures"]
	_check(parsed["disclosures"].size() == expected_disclosures.size(), "disclosure count")
	for i in min(parsed["disclosures"].size(), expected_disclosures.size()):
		_check_equal(parsed["disclosures"][i], expected_disclosures[i]["segment"], "disclosure segment %d" % i)
		_check_equal(Util.disclosure_digest(parsed["disclosures"][i]), expected_disclosures[i]["digest"], "disclosure digest %d" % i)


func _test_verify_flow(vectors: Dictionary) -> void:
	print("verify flow")
	var flow: Dictionary = vectors["verify_flow"]
	var verifier := Verifier.new(flow["request"]["aud"])
	for issuer in flow["trust"]:
		verifier.trust(issuer, Key.from_dict(flow["trust"][issuer]))
	var result := verifier.verify(flow["request"], flow["presentation"], int(flow["now"]))
	_check(result["ok"], "verification succeeds")
	if not result["ok"]:
		print("    errors: ", result["errors"])
	_check_equal(Util.canonical(result["claims"]), Util.canonical(flow["expected"]["claims"]), "derived claims")


func _seg(text: String) -> String:
	return Util.base64url_encode(text.to_utf8_buffer())


func _test_type_confusion(vectors: Dictionary) -> void:
	# Regression: a non-string/non-int JSON field in the header or payload used
	# to abort _verify on a runtime type error, which verify() then reported as
	# ok=true. Every case here must fail closed.
	print("type confusion")
	var flow: Dictionary = vectors["verify_flow"]
	var request: Dictionary = flow["request"]
	var parts := (flow["presentation"] as String).split("~")
	var kb_jwt: String = parts[parts.size() - 1]
	var jwt_parts := (parts[0] as String).split(".")
	var raw_header := Util.base64url_decode(jwt_parts[0]).get_string_from_utf8()
	var raw_payload := Util.base64url_decode(jwt_parts[1]).get_string_from_utf8()

	# Each entry is [side, key, literal JSON value to inject]. The signature is
	# intentionally left stale: a strict verifier must reject before (or at) the
	# type check regardless.
	var cases := [
		["header", "typ", "1"],
		["header", "typ", "true"],
		["header", "alg", "1"],
		["payload", "iss", "5"],
		["payload", "iss", "null"],
		["payload", "exp", "1.5"],
		["payload", "exp", "null"],
		["payload", "vct", "5"],
		["payload", "_sd_alg", "5"],
	]
	for case in cases:
		var side: String = case[0]
		var key: String = case[1]
		var value_json: String = case[2]
		var header_text := _inject(raw_header, key, value_json) if side == "header" else raw_header
		var payload_text := _inject(raw_payload, key, value_json) if side == "payload" else raw_payload
		var signing_input := _seg(header_text) + "." + _seg(payload_text)
		# Sign with the trusted issuer key so tampered fields reach the checks
		# that follow signature verification (header typ/alg are checked before
		# it, so a stale signature already exercises those).
		var signer := Key.from_dict(flow["trust"].values()[0])
		var jwt := signing_input + "." + signer.sign(signing_input)
		var rebuilt := jwt + "~"
		for i in range(1, parts.size() - 1):
			rebuilt += parts[i] + "~"
		rebuilt += kb_jwt
		var verifier := Verifier.new(request["aud"])
		for issuer in flow["trust"]:
			verifier.trust(issuer, Key.from_dict(flow["trust"][issuer]))
		var result := verifier.verify(request, rebuilt, int(flow["now"]))
		_check(not result["ok"], "tampered JWT (%s.%s=%s) must not verify" % [side, key, value_json])


## Replace the value of `key` in a raw JSON object text with a literal value.
func _inject(raw: String, key: String, value_json: String) -> String:
	var needle := "\"" + key + "\":"
	var at := raw.find(needle)
	if at < 0:
		return raw
	var start := at + needle.length()
	var end := start
	while end < raw.length() and raw[end] != "," and raw[end] != "}":
		end += 1
	return raw.substr(0, start) + value_json + raw.substr(end)


func _test_negative_cases(vectors: Dictionary) -> void:
	print("negative cases")
	for case in vectors["negative_cases"]:
		var request: Dictionary = case["request"]
		var verifier := Verifier.new(request["aud"])
		for issuer in case["trust"]:
			verifier.trust(issuer, Key.from_dict(case["trust"][issuer]))
		for seed in case["used_nonces"]:
			var pair: String = seed
			var bar := pair.find("|")
			verifier.mark_nonce_used(pair.substr(0, bar), pair.substr(bar + 1))

		var result := verifier.verify(request, case["presentation"], int(case["now"]))
		var expected: Array = case["expected_errors"]
		_check(result["ok"] == expected.is_empty(), case["name"] + " ok flag")
		if not result["ok"] and not expected.is_empty():
			var errors: Array = result["errors"]
			var actual: String = "" if errors.is_empty() else str(errors[0])
			_check_equal(actual, str(expected[0]), case["name"] + " error code")
