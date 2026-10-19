--- Byte helpers that work on every supported Lua host (LuaJIT / 5.1–5.4),
--- avoiding `string.pack` / `string.unpack` which are missing from LuaJIT and
--- Lua 5.1.
---
--- Part of the EudiGameWallet Lua framework. See frameworks/SPEC.md.
--- SPDX-License-Identifier: CC-BY-4.0

local bytes = {}

--- Big-endian 32-bit unsigned integer -> 4-byte string.
--- @param n number
--- @return string
function bytes.u32be(n)
	n = n % 0x100000000
	return string.char(
		math.floor(n / 0x1000000) % 256,
		math.floor(n / 0x10000) % 256,
		math.floor(n / 0x100) % 256,
		n % 256
	)
end

--- Big-endian 64-bit length -> 8-byte string (hi32, lo32).
--- @param n number
--- @return string
function bytes.u64be(n)
	local lo = n % 0x100000000
	local hi = math.floor(n / 0x100000000)
	return bytes.u32be(hi) .. bytes.u32be(lo)
end

--- Read 4 bytes at a 1-based offset as a big-endian unsigned integer.
--- @param s string
--- @param pos integer
--- @return integer
function bytes.read_u32be(s, pos)
	local b1, b2, b3, b4 = string.byte(s, pos, pos + 3)
	return ((b1 * 256 + b2) * 256 + b3) * 256 + b4
end

return bytes
