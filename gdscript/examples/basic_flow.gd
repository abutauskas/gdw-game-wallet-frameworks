## Minimal end-to-end flow: an age-over-18 attestation is issued, stored in a
## game wallet, selectively disclosed to a matchmaking server, then verified.
##
## Run headless from frameworks/gdscript:
##
##   godot --headless --path . --script res://examples/basic_flow.gd
##
## SPDX-License-Identifier: CC-BY-4.0
extends SceneTree

const Core := preload("res://addons/eudi_game_wallet/core/gdw.gd")
const Key := preload("res://addons/eudi_game_wallet/core/gdw_key.gd")
const Issuer := preload("res://addons/eudi_game_wallet/core/gdw_issuer.gd")
const Wallet := preload("res://addons/eudi_game_wallet/core/gdw_wallet.gd")
const Verifier := preload("res://addons/eudi_game_wallet/core/gdw_verifier.gd")


func _init() -> void:
	# 1. Trust anchors. In production these come from a signed trust list
	#    (see SPEC.md); here we use shared secrets for a self-contained demo.
	var issuer_key := Key.hs256("issuer-shared-secret-used-only-for-this-demo")
	var player_key := Key.hs256("holder-key-derived-on-the-players-device-----")

	# 2. A PID/attestation provider issues an age attestation to one account.
	var age_issuer := Issuer.new("https://issuer.example/age-service", issuer_key)
	var credential := age_issuer.issue({
		"vct": "urn:eudi:game:attestation:age-over-18",
		"claims": {
			"age_over_18": true,
			"country": "NL",
			"nickname": "pixel_knight",
		},
		"disclosable": PackedStringArray(["age_over_18", "country"]),
		"sub": "player-8241",
		"holder_key": player_key,
		"iat": Core.now(),
		"exp": Core.now() + 30 * 24 * 3600,
	})
	print("credential bytes: ", credential.length())
	print("stored claims:    ", " ".join(Wallet.new(player_key).claims_of(credential)))
	print("")

	# 3. The player's game wallet stores the credential.
	var wallet := Wallet.new(player_key)
	wallet.store(credential)

	# 4. A matchmaking server (relying party) asks for a single claim and, being
	#    a game backend, wants proof the response is fresh (nonce) and bound to
	#    this holder (key binding, cnf).
	var server := Verifier.new("matchmaking-eu-1")
	server.trust(age_issuer.iss, issuer_key)
	var request := server.create_request(
		PackedStringArray(["urn:eudi:game:attestation:age-over-18"]),
		PackedStringArray(["age_over_18"]))

	# 5. The wallet discloses only what was asked for; nickname/country stay hidden.
	var presentation := wallet.present(
		credential, PackedStringArray(["age_over_18"]), request["aud"], request["nonce"], Core.now())
	print("presentation bytes: ", presentation.length())
	print("")

	# 6. The server verifies and reads the derived claims.
	var result := server.verify(request, presentation, Core.now())
	if result["ok"]:
		print("verified: age_over_18 = ", result["claims"].get("age_over_18", false))
		quit(0)
	else:
		print("verification failed: ", result["errors"])
		quit(1)
