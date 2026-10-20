--- Conformance tests for the EudiGameWallet Lua framework.
---
--- Replays frameworks/test-vectors/vectors.json byte-for-byte. Run from the
--- frameworks/lua directory:
---
---   lua tests/run_tests.lua
---   luajit tests/run_tests.lua
---   lua5.1 tests/run_tests.lua
---
--- SPDX-License-Identifier: CC-BY-4.0

local here = arg and arg[0] and arg[0]:match("^(.*)[/\\]") or "."
package.path = here .. "/../?.lua;" .. here .. "/?.lua;" .. package.path
-- allow running from either the repo's lua/ dir or the tests/ dir
package.path = "./?.lua;" .. package.path

local json = require("eudi_game_wallet.json")
local P = require("eudi_game_wallet.primitives")
local core = require("eudi_game_wallet.core")
local Key = require("eudi_game_wallet.key")

local checks = 0
local failures = 0

local function check(condition, label)
	checks = checks + 1
	if not condition then
		failures = failures + 1
		print("  FAIL: " .. label)
	end
end

local function check_equal(actual, expected, label)
	checks = checks + 1
	if actual ~= expected then
		failures = failures + 1
		print("  FAIL: " .. label)
		print("    expected: " .. tostring(expected))
		print("    actual:   " .. tostring(actual))
	end
end

local function load_vectors()
	local candidates = {
		"test-vectors/vectors.json",
		here .. "/../test-vectors/vectors.json",
		here .. "/../../test-vectors/vectors.json",
		"./../test-vectors/vectors.json",
		"../test-vectors/vectors.json",
	}
	for _, path in ipairs(candidates) do
		local f = io.open(path, "rb")
		if f then
			local text = f:read("*a")
			f:close()
			return json.parse(text)
		end
	end
	error("cannot open vectors.json")
end

local function test_canonical_json(vectors)
	print("canonical JSON")
	for _, case in ipairs(vectors.canonical_json) do
		local expected = case.canonical
		check_equal(json.canonical(case.input), expected, case.name)
		check_equal(json.canonical(json.parse(expected)), expected, case.name .. " (round trip)")
	end
end

local function test_disclosures(vectors)
	print("disclosures")
	for _, case in ipairs(vectors.disclosures) do
		local segment = P.make_disclosure(case.salt_b64, case.claim_name, case.claim_value)
		check_equal(segment, case.segment, case.name .. " segment")
		check_equal(P.disclosure_digest(segment), case.digest, case.name .. " digest")
		local parsed = P.parse_disclosure(segment)
		check_equal(parsed and parsed.name or "", case.claim_name, case.name .. " parsed name")
	end
end

local function test_hs256(vectors)
	print("HS256")
	local hs = vectors.hs256
	local k = Key.GdwKey.from_dict(hs.key)
	check_equal(k:sign(hs.signing_input), hs.signature, "signature")
	check(k:verify(hs.signing_input, hs.signature), "verify")
	check(not k:verify(hs.signing_input, hs.signature .. "x"), "verify rejects tamper")
end

local function test_issue_flow(vectors)
	print("issue flow")
	local flow = vectors.issue_flow
	local issuer = core.new_issuer(flow.iss, Key.GdwKey.from_dict(flow.issuer_key))
	local credential = issuer:issue({
		vct = flow.vct,
		claims = flow.claims,
		disclosable = flow.disclosable,
		iat = flow.iat,
		exp = flow.exp,
		sub = flow.sub,
		holder_key = Key.GdwKey.from_dict(flow.holder_key),
		salts = flow.salts,
	})
	check_equal(credential, flow.credential, "credential string")

	local parsed = core.parse_credential(credential)
	check_equal(json.canonical(parsed.token.payload), json.canonical(flow.expected_payload), "payload")
	local expected_disclosures = flow.expected_disclosures
	check(#parsed.disclosures == #expected_disclosures, "disclosure count")
	for i = 1, math.min(#parsed.disclosures, #expected_disclosures) do
		check_equal(parsed.disclosures[i], expected_disclosures[i].segment, "disclosure segment " .. i)
		check_equal(P.disclosure_digest(parsed.disclosures[i]), expected_disclosures[i].digest, "disclosure digest " .. i)
	end
end

local function test_verify_flow(vectors)
	print("verify flow")
	local flow = vectors.verify_flow
	local verifier = core.new_verifier(flow.request.aud)
	for issuer, key in pairs(flow.trust) do
		verifier:trust(issuer, Key.GdwKey.from_dict(key))
	end
	local result = verifier:verify(flow.request, flow.presentation, flow.now)
	check(result.ok, "verification succeeds")
	if not result.ok then
		print("    errors: " .. table.concat(result.errors, ","))
	end
	check_equal(json.canonical(result.claims), json.canonical(flow.expected.claims), "derived claims")
end

local function test_negative_cases(vectors)
	print("negative cases")
	for _, case in ipairs(vectors.negative_cases) do
		local request = case.request
		local verifier = core.new_verifier(request.aud)
		for issuer, key in pairs(case.trust) do
			verifier:trust(issuer, Key.GdwKey.from_dict(key))
		end
		for _, pair in ipairs(case.used_nonces) do
			local bar = string.find(pair, "|", 1, true)
			verifier:mark_nonce_used(string.sub(pair, 1, bar - 1), string.sub(pair, bar + 1))
		end

		local result = verifier:verify(request, case.presentation, case.now)
		local expected = case.expected_errors
		check(result.ok == (#expected == 0), case.name .. " ok flag")
		if not result.ok and #expected > 0 then
			local actual = #result.errors > 0 and tostring(result.errors[1]) or ""
			check_equal(actual, tostring(expected[1]), case.name .. " error code")
		end
	end
end

local vectors = load_vectors()

test_canonical_json(vectors)
test_disclosures(vectors)
test_hs256(vectors)
test_issue_flow(vectors)
test_verify_flow(vectors)
test_negative_cases(vectors)
-- ES256 is intentionally not tested: Lua cannot sign it natively.

print("")
print(("%d/%d checks passed"):format(checks - failures, checks))
os.exit(failures == 0 and 0 or 1)
