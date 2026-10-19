--- Minimal end-to-end flow: an age-over-18 attestation is issued, stored in a
--- game wallet, selectively disclosed to a matchmaking server, then verified.
---
--- Run from frameworks/lua:
---
---   lua examples/basic_flow.lua
---   luajit examples/basic_flow.lua
---
--- SPDX-License-Identifier: CC-BY-4.0

package.path = "./?.lua;" .. package.path

local core = require("eudi_game_wallet.core")
local Key = require("eudi_game_wallet.key")

-- 1. Trust anchors. In production these come from a signed trust list
--    (see SPEC.md); here we use shared secrets for a self-contained demo.
local issuer_key = Key.GdwKey.hs256("issuer-shared-secret-used-only-for-this-demo")
local player_key = Key.GdwKey.hs256("holder-key-derived-on-the-players-device-----")

-- 2. A PID/attestation provider issues an age attestation to one account.
local age_issuer = core.new_issuer("https://issuer.example/age-service", issuer_key)
local credential = age_issuer:issue({
	vct = "urn:eudi:game:attestation:age-over-18",
	claims = {
		age_over_18 = true,
		country = "NL",
		nickname = "pixel_knight",
	},
	disclosable = { "age_over_18", "country" },
	sub = "player-8241",
	holder_key = player_key,
	iat = core.now(),
	exp = core.now() + 30 * 24 * 3600,
})
print("credential bytes: " .. #credential)
print("stored claims:    " .. table.concat(core.new_wallet(player_key):claims_of(credential), " "))
print("")

-- 3. The player's game wallet stores the credential.
local wallet = core.new_wallet(player_key)
wallet:store(credential)

-- 4. A matchmaking server (relying party) asks for a single claim and, being
--    a game backend, wants proof the response is fresh (nonce) and bound to
--    this holder (key binding, cnf).
local server = core.new_verifier("matchmaking-eu-1")
server:trust(age_issuer.iss, issuer_key)
local request = server:create_request(
	{ "urn:eudi:game:attestation:age-over-18" },
	{ "age_over_18" })

-- 5. The wallet discloses only what was asked for; nickname/country stay hidden.
local presentation = wallet:present(
	credential, { "age_over_18" }, request.aud, request.nonce, core.now())
print("presentation bytes: " .. #presentation)
print("")

-- 6. The server verifies and reads the derived claims.
local result = server:verify(request, presentation, core.now())
if result.ok then
	print("verified: age_over_18 = " .. tostring(result.claims.age_over_18))
	os.exit(0)
else
	print("verification failed: " .. table.concat(result.errors, ","))
	os.exit(1)
end
