--- base64url (RFC 4648 §5) encode/decode, unpadded.
---
--- Implemented in pure Lua so it works on LuaJIT, Lua 5.1–5.4 with no C
--- dependencies. Operates on raw byte strings.
---
--- Part of the EudiGameWallet Lua framework. See frameworks/SPEC.md.
--- SPDX-License-Identifier: CC-BY-4.0

local base64url = {}

local ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

local DECODE = {}
for i = 1, #ALPHABET do
	DECODE[string.byte(ALPHABET, i)] = i - 1
end

--- Encode a byte string as unpadded base64url.
--- @param data string
--- @return string
function base64url.encode(data)
	local out = {}
	local b = { string.byte(data, 1, #data) }
	local n = #b
	local i = 1
	while i + 2 <= n do
		local v = b[i] * 65536 + b[i + 1] * 256 + b[i + 2]
		out[#out + 1] = string.sub(ALPHABET, math.floor(v / 262144) + 1, math.floor(v / 262144) + 1)
		out[#out + 1] = string.sub(ALPHABET, math.floor(v / 4096) % 64 + 1, math.floor(v / 4096) % 64 + 1)
		out[#out + 1] = string.sub(ALPHABET, math.floor(v / 64) % 64 + 1, math.floor(v / 64) % 64 + 1)
		out[#out + 1] = string.sub(ALPHABET, v % 64 + 1, v % 64 + 1)
		i = i + 3
	end
	local rem = n - i + 1
	if rem == 1 then
		local v = b[i]
		out[#out + 1] = string.sub(ALPHABET, math.floor(v / 4) + 1, math.floor(v / 4) + 1)
		out[#out + 1] = string.sub(ALPHABET, (v % 4) * 16 + 1, (v % 4) * 16 + 1)
	elseif rem == 2 then
		local v = b[i] * 256 + b[i + 1]
		out[#out + 1] = string.sub(ALPHABET, math.floor(v / 1024) + 1, math.floor(v / 1024) + 1)
		out[#out + 1] = string.sub(ALPHABET, math.floor(v / 16) % 64 + 1, math.floor(v / 16) % 64 + 1)
		out[#out + 1] = string.sub(ALPHABET, (v % 16) * 4 + 1, (v % 16) * 4 + 1)
	end
	return table.concat(out)
end

--- Decode unpadded (or padded) base64url into a byte string.
--- @param text string
--- @return string
function base64url.decode(text)
	local s = text:gsub("=", "")
	local n = #s
	local out = {}
	local i = 1
	while i <= n do
		local take = math.min(4, n - i + 1)
		if take == 1 then
			error("invalid base64url length")
		end
		local a = DECODE[string.byte(s, i)]
		local b = take >= 2 and DECODE[string.byte(s, i + 1)] or 0
		local c = take >= 3 and DECODE[string.byte(s, i + 2)] or 0
		local d = take >= 4 and DECODE[string.byte(s, i + 3)] or 0
		if a == nil or b == nil or c == nil or d == nil then
			error("invalid base64url character")
		end
		-- Concatenate the 6-bit values into a bit stream, emit whole bytes.
		-- byte1 = aaaaaabb, byte2 = bbbbcccc, byte3 = ccdddddd
		out[#out + 1] = string.char(a * 4 + math.floor(b / 16))
		if take >= 3 then
			out[#out + 1] = string.char((b % 16) * 16 + math.floor(c / 4))
		end
		if take >= 4 then
			out[#out + 1] = string.char((c % 4) * 64 + d)
		end
		i = i + take
	end
	return table.concat(out)
end

--- Encode a UTF-8 text string (base64url of its bytes).
--- @param text string
--- @return string
function base64url.encode_utf8(text)
	return base64url.encode(text)
end

return base64url
