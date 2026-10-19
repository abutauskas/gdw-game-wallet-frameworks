--- 32-bit bitwise compatibility shim.
---
--- The framework targets Defold and LÖVE (both LuaJIT, which ships `bit`),
--- standard Lua 5.3+, and plain Lua 5.1/5.2. Lua 5.3+ has native bitwise
--- operators; LuaJIT/5.1/5.2 use the `bit` library; if neither is available we
--- fall back to a (slow but correct) pure-Lua implementation.
---
--- All results are normalised to unsigned 32-bit values so the SHA-256 code
--- behaves identically on every host. The native-operator implementation lives
--- in `bit_native.lua` so the LuaJIT / 5.1 parser never sees `& | ~ << >>`.
---
--- Part of the EudiGameWallet Lua framework. See frameworks/SPEC.md.
--- SPDX-License-Identifier: CC-BY-4.0

local U32 = 0xFFFFFFFF
local native

-- Backend 1: Lua 5.3+ native operators (loaded from a separate file).
if _VERSION == "Lua 5.3" or _VERSION == "Lua 5.4" then
	local ok, mod = pcall(require, "eudi_game_wallet.bit_native")
	if ok then
		native = mod
	end
end

-- Backend 2: LuaJIT / 5.1 / 5.2 `bit` library.
if not native then
	local ok, b = pcall(require, "bit")
	if ok and b then
		native = {
			band = function(a, c) return b.band(a, c) % (U32 + 1) end,
			bor = function(a, c) return b.bor(a, c) % (U32 + 1) end,
			bxor = function(a, c) return b.bxor(a, c) % (U32 + 1) end,
			bnot = function(a) return b.bnot(a) % (U32 + 1) end,
			lshift = function(a, n) return b.lshift(a, n) % (U32 + 1) end,
			rshift = function(a, n) return b.rshift(a, n) % (U32 + 1) end,
			arshift = function(a, n) return b.arshift(a, n) % (U32 + 1) end,
			rrotate = function(a, n) return b.ror(a, n) % (U32 + 1) end,
		}
	end
end

-- Backend 3: pure-Lua fallback.
if not native then
	local function tobits(x)
		x = x % (U32 + 1)
		local t = {}
		for i = 0, 31 do
			t[i] = x % 2
			x = math.floor(x / 2)
		end
		return t
	end
	local function frombits(t)
		local x, m = 0, 1
		for i = 0, 31 do
			if t[i] == 1 then x = x + m end
			m = m * 2
		end
		return x
	end
	local function zbin(a, c, f)
		local x, y = tobits(a), tobits(c)
		local r = {}
		for i = 0, 31 do r[i] = f(x[i], y[i]) end
		return frombits(r)
	end

	native = {}
	native.band = function(a, c) return zbin(a, c, function(p, q) return (p == 1 and q == 1) and 1 or 0 end) end
	native.bor = function(a, c) return zbin(a, c, function(p, q) return (p == 1 or q == 1) and 1 or 0 end) end
	native.bxor = function(a, c) return zbin(a, c, function(p, q) return (p ~= q) and 1 or 0 end) end
	native.bnot = function(a) return zbin(a, U32, function(p) return 1 - p end) end
	native.lshift = function(a, n) return (a * (2 ^ n)) % (U32 + 1) end
	native.rshift = function(a, n) return math.floor(a / (2 ^ n)) % (U32 + 1) end
	native.arshift = function(a, n)
		if n == 0 then return a % (U32 + 1) end
		local neg = a >= 0x80000000
		local r = math.floor(a / (2 ^ n))
		if neg then r = r + (U32 + 1) - (2 ^ (32 - n)) end
		return r % (U32 + 1)
	end
	native.rrotate = function(a, n)
		return native.bor(
			math.floor(a / (2 ^ n)) % (U32 + 1),
			(a * (2 ^ (32 - n))) % (U32 + 1)
		)
	end
end

return {
	band = native.band,
	bor = native.bor,
	bxor = native.bxor,
	bnot = native.bnot,
	lshift = native.lshift,
	rshift = native.rshift,
	arshift = native.arshift,
	rrotate = native.rrotate,
	U32 = U32,
}
