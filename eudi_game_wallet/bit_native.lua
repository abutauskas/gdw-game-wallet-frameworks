--- Native Lua 5.3+ bitwise operators.
---
--- This file is only loaded on Lua 5.3 / 5.4: it uses the `& | ~ << >>`
--- operators, which the LuaJIT / 5.1 / 5.2 parser cannot even parse. Keeping it
--- in its own module means those hosts never compile it.
---
--- Part of the EudiGameWallet Lua framework. See frameworks/SPEC.md.
--- SPDX-License-Identifier: CC-BY-4.0

local U32 = 0xFFFFFFFF

return {
	band = function(a, b) return (a & b) & U32 end,
	bor = function(a, b) return (a | b) & U32 end,
	bxor = function(a, b) return (a ~ b) & U32 end,
	bnot = function(a) return (~a) & U32 end,
	lshift = function(a, n) return (a << n) & U32 end,
	rshift = function(a, n) return (a >> n) & U32 end,
	arshift = function(a, n) return (a >> n) end,
	rrotate = function(a, n) return (((a >> n) | (a << (32 - n))) & U32) end,
}
