--- Small unit tests for the EudiGameWallet Lua primitives, mirroring the
--- `#[cfg(test)]` modules in the Rust framework and the equivalent tests in the
--- C++ / C# / GDScript / Python frameworks.
---
--- Run from frameworks/lua:
---
---   lua tests/test_units.lua
---   luajit tests/test_units.lua
---
--- SPDX-License-Identifier: CC-BY-4.0

package.path = "./?.lua;" .. package.path

local json = require("eudi_game_wallet.json")
local b64 = require("eudi_game_wallet.base64url")
local P = require("eudi_game_wallet.primitives")

local failures = 0

local function check(condition, label)
	if not condition then
		failures = failures + 1
		print("  FAIL: " .. label)
	end
end

local function rejects(text)
	local ok = pcall(json.parse, text)
	return not ok
end

for length = 0, 39 do
	local bytes = {}
	for i = 0, length - 1 do
		bytes[#bytes + 1] = string.char((length * 7 + 3 + i) % 256)
	end
	local data = table.concat(bytes)
	local encoded = b64.encode(data)
	check(not encoded:find("=", 1, true), "no padding " .. length)
	check(b64.decode(encoded) == data, "b64url round trip " .. length)
end

check(rejects("1.5"), "rejects float")
check(rejects("1e3"), "rejects exponent")
check(rejects("-0"), "rejects negative zero")
check(rejects("01"), "rejects leading zero")
check(
	json.canonical(json.parse("9007199254740991")) == "9007199254740991",
	"accepts max safe integer")
check(
	json.canonical({ b = 2, a = 1, c = { y = "ü" } }) == '{"a":1,"b":2,"c":{"y":"ü"}}',
	"canonical sorts and keeps unicode")
check(
	json.canonical(json.parse('{"a":1,"b":[true,null,"x"]}')) == '{"a":1,"b":[true,null,"x"]}',
	"round trip")

local segment = P.make_disclosure("AAECAwQFBgcICQoLDA0ODw", "age_over_18", true)
check(segment == "WyJBQUVDQXdRRkJnY0lDUW9MREEwT0R3IiwiYWdlX292ZXJfMTgiLHRydWVd",
	"disclosure vector segment")
check(P.disclosure_digest(segment) == "zhurxLJSJKI_XNO-e_L644W0SwqsTD5LDd3yPwd4ZWs",
	"disclosure vector digest")

print("")
print(failures == 0 and "OK" or (failures .. " FAILED"))
os.exit(failures == 0 and 0 or 1)
