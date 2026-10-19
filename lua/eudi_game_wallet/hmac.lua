--- HMAC-SHA256 (RFC 2104), built on the pure-Lua SHA-256.
---
--- Part of the EudiGameWallet Lua framework. See frameworks/SPEC.md.
--- SPDX-License-Identifier: CC-BY-4.0

local sha256 = require("eudi_game_wallet.sha256")

local hmac = {}

local BLOCK = 64

--- byte-wise XOR with a single-byte constant.
local function bxor8(a, b)
	local r, bit, x, y = 0, 1, a, b
	for _ = 1, 8 do
		local p, q = x % 2, y % 2
		if p ~= q then r = r + bit end
		bit = bit * 2
		x = math.floor(x / 2)
		y = math.floor(y / 2)
	end
	return r
end

--- HMAC-SHA256 of a message under a key. Returns the raw 32-byte MAC.
--- @param key string
--- @param message string
--- @return string
function hmac.sha256(key, message)
	if #key > BLOCK then
		key = sha256.sha256(key)
	end
	if #key < BLOCK then
		key = key .. string.rep("\0", BLOCK - #key)
	end

	local opad, ipad = {}, {}
	for i = 1, BLOCK do
		local b = string.byte(key, i)
		opad[i] = string.char(bxor8(b, 0x5c))
		ipad[i] = string.char(bxor8(b, 0x36))
	end
	local inner = sha256.sha256(table.concat(ipad) .. message)
	return sha256.sha256(table.concat(opad) .. inner)
end

return hmac
