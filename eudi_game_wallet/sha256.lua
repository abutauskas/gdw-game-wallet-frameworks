--- Pure-Lua SHA-256 (FIPS 180-4).
---
--- Works on LuaJIT, Lua 5.1/5.2/5.3/5.4 with no C dependencies, using the
--- `bit` compatibility shim. Behaviour is byte-for-byte identical to the other
--- language frameworks, which the shared test vectors pin down.
---
--- This is a small, readable prototype implementation. If you ship it, prefer a
--- vetted implementation, but the output here matches the reference exactly.
---
--- Part of the EudiGameWallet Lua framework. See frameworks/SPEC.md.
--- SPDX-License-Identifier: CC-BY-4.0

local bit = require("eudi_game_wallet.bit")
local bytes = require("eudi_game_wallet.bytes")

local band, bor, bxor = bit.band, bit.bor, bit.bxor
local bnot, lshift, rshift = bit.bnot, bit.lshift, bit.rshift
local rrotate = bit.rrotate
local U32 = bit.U32

local K = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local H0 = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

local function u32(x)
	return x % (U32 + 1)
end

local function xor3(x, y, z)
	return bxor(bxor(x, y), z)
end

local function add(...)
	local sum = 0
	for i = 1, select("#", ...) do
		sum = sum + (select(i, ...) % (U32 + 1))
	end
	return sum % (U32 + 1)
end

--- SHA-256 of a byte string. Returns the raw 32-byte digest.
--- @param data string
--- @return string
local function sha256(data)
	local len = #data
	local bit_len = len * 8

	-- Padding: 0x80, then zeros, then 64-bit big-endian length.
	local pad = 64 - ((len + 9) % 64)
	if pad == 64 then pad = 0 end
	local msg = data .. "\128" .. string.rep("\0", pad) .. bytes.u64be(bit_len)

	local h = { H0[1], H0[2], H0[3], H0[4], H0[5], H0[6], H0[7], H0[8] }

	for chunk = 0, #msg - 1, 64 do
		local w = {}
		for i = 0, 15 do
			local b = chunk + i * 4
			local b1, b2, b3, b4 = string.byte(msg, b + 1, b + 4)
			w[i + 1] = add(lshift(b1, 24), lshift(b2, 16), lshift(b3, 8), b4)
		end
		for i = 17, 64 do
			local w15, w2 = w[i - 15], w[i - 2]
			local s0 = xor3(rrotate(w15, 7), rrotate(w15, 18), rshift(w15, 3))
			local s1 = xor3(rrotate(w2, 17), rrotate(w2, 19), rshift(w2, 10))
			w[i] = add(w[i - 16], s0, w[i - 7], s1)
		end

		local a, b, c, d = h[1], h[2], h[3], h[4]
		local e, f, g, hh = h[5], h[6], h[7], h[8]

		for i = 1, 64 do
			local S1 = xor3(rrotate(e, 6), rrotate(e, 11), rrotate(e, 25))
			local ch = bxor(band(e, f), band(bnot(e), g))
			local temp1 = add(hh, S1, ch, K[i], w[i])
			local S0 = xor3(rrotate(a, 2), rrotate(a, 13), rrotate(a, 22))
			local maj = xor3(band(a, b), band(a, c), band(b, c))
			local temp2 = add(S0, maj)

			hh = g
			g = f
			f = e
			e = add(d, temp1)
			d = c
			c = b
			b = a
			a = add(temp1, temp2)
		end

		h[1] = add(h[1], a)
		h[2] = add(h[2], b)
		h[3] = add(h[3], c)
		h[4] = add(h[4], d)
		h[5] = add(h[5], e)
		h[6] = add(h[6], f)
		h[7] = add(h[7], g)
		h[8] = add(h[8], hh)
	end

	local out = {}
	for i = 1, 8 do
		out[i] = bytes.u32be(h[i])
	end
	return table.concat(out)
end

return { sha256 = sha256 }
