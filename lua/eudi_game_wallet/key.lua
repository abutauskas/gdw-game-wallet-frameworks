--- Keys and signers.
---
--- Like the GDScript framework, this Lua port implements **HS256 only**: Lua
--- has no built-in asymmetric crypto and the target runtimes (Defold, LÖVE)
--- ship none either. HS256 is the dependency-free prototype algorithm; for the
--- production ES256 path use the C++/C#/Rust/Python frameworks or a native
--- extension that exposes a sign/verify pair. See SPEC.md §2.4.
---
--- Part of the EudiGameWallet Lua framework. See frameworks/SPEC.md.
--- SPDX-License-Identifier: CC-BY-4.0

local json = require("eudi_game_wallet.json")
local err = require("eudi_game_wallet.errors")
local P = require("eudi_game_wallet.primitives")

local key = {}

local GdwKey = {}
GdwKey.__index = GdwKey

--- HS256 key from a raw secret string (its bytes become the key material).
--- @param raw_secret string
--- @return table
function GdwKey.hs256(raw_secret)
	return setmetatable({ alg = "HS256", k = P.b64url_utf8(raw_secret) }, GdwKey)
end

--- HS256 key from raw bytes.
--- @param raw string
--- @return table
function GdwKey.hs256_from_bytes(raw)
	return setmetatable({ alg = "HS256", k = P.b64url_encode(raw) }, GdwKey)
end

--- JSON `cnf`/key object for this key.
--- @return table
function GdwKey:to_dict()
	local out = { alg = self.alg }
	if self.alg == "HS256" then
		out.k = self.k or ""
	else
		out.crv = self.crv or "P-256"
		out.x = self.x or ""
		out.y = self.y or ""
		-- PROTOTYPE ONLY: mirrors the other frameworks, which embed the private
		-- scalar in `cnf` so the toy holder-binding check is self-contained.
		-- NEVER do this in production. See SPEC.md §2.4.
		if self.d ~= nil then out.d = self.d end
	end
	return out
end

--- Parse a key from a JSON object (dict).
--- @param j table
--- @return table
function GdwKey.from_dict(j)
	local function get(n)
		local v = json.get and json.get(j, n) or (type(j) == "table" and j[n] or nil)
		return type(v) == "string" and v or nil
	end
	return setmetatable({
		alg = get("alg") or "HS256",
		k = get("k"),
		crv = get("crv"),
		x = get("x"),
		y = get("y"),
		d = get("d"),
	}, GdwKey)
end

--- Sign a signing input with this key (HS256).
--- @param signing_input string
--- @return string
function GdwKey:sign(signing_input)
	return key.signer_for(self):sign(signing_input)
end

--- Verify a signature with this key (HS256).
--- @param signing_input string
--- @param signature string
--- @return boolean
function GdwKey:verify(signing_input, signature)
	return key.signer_for(self):verify(signing_input, signature)
end

--- True if both keys carry the same secret material (prototype check).
--- @param other table
--- @return boolean
function GdwKey:same_secret(other)
	if other == nil then return false end
	if self.alg == "HS256" then
		return self.k == other.k
	end
	return self.d ~= nil and self.d == other.d
end

--- HS256 signer (sign + verify with HMAC-SHA256).
local Hs256Signer = {}
Hs256Signer.__index = Hs256Signer
Hs256Signer.alg = "HS256"

function Hs256Signer.new(gdw_key)
	if gdw_key.alg ~= "HS256" then
		error(err.ERR_MALFORMED)
	end
	return setmetatable({ _secret = P.b64url_decode(gdw_key.k or "") }, Hs256Signer)
end

function Hs256Signer:sign(signing_input)
	return P.b64url_encode(P.hmac_sha256(self._secret, signing_input))
end

function Hs256Signer:verify(signing_input, signature)
	local expected = P.hmac_sha256(self._secret, signing_input)
	local ok, actual = pcall(P.b64url_decode, signature)
	if not ok then return false end
	return P.constant_time_eq(expected, actual)
end

--- Build the appropriate signer for a key (HS256 only).
--- @param gdw_key table
--- @return table
function key.signer_for(gdw_key)
	if gdw_key.alg == "HS256" then
		return Hs256Signer.new(gdw_key)
	end
	error(err.ERR_MALFORMED)
end

key.GdwKey = GdwKey
key.Hs256Signer = Hs256Signer

return key
