--- Shared primitives: base64url, canonical JSON segments, disclosure
--- construction/parsing, random salting, claim-name rules (SPEC.md §2, §3).
---
--- SHA-256 and HMAC-SHA256 are implemented in pure Lua (see sha256.lua and
--- hmac.lua) so the package needs no C dependency and stays byte-for-byte
--- identical to the other frameworks.
---
--- Part of the EudiGameWallet Lua framework. See frameworks/SPEC.md.
--- SPDX-License-Identifier: CC-BY-4.0

local b64 = require("eudi_game_wallet.base64url")
local gdwjson = require("eudi_game_wallet.json")
local sha = require("eudi_game_wallet.sha256")
local hm = require("eudi_game_wallet.hmac")

local primitives = {}

local RESERVED = {
	_sd = true, _sd_alg = true, cnf = true, iss = true, sub = true,
	iat = true, exp = true, vct = true,
}

-- ---- base64url -------------------------------------------------------------

primitives.b64url_encode = b64.encode
primitives.b64url_decode = b64.decode
primitives.b64url_utf8 = function(text) return b64.encode(text) end

-- ---- hashing ---------------------------------------------------------------

primitives.sha256 = sha.sha256

function primitives.hmac_sha256(key, message)
	return hm.sha256(key, message)
end

--- Constant-time-ish comparison (best effort in Lua; length leak only).
function primitives.constant_time_eq(a, b)
	if #a ~= #b then return false end
	local diff = 0
	for i = 1, #a do
		diff = diff + (string.byte(a, i) == string.byte(b, i) and 0 or 1)
	end
	return diff == 0
end

-- ---- canonical segments ----------------------------------------------------

function primitives.json_segment(value)
	return b64.encode(gdwjson.canonical(value))
end

function primitives.parse_segment(segment)
	local raw = b64.decode(segment)
	local parsed = gdwjson.parse(raw)
	if parsed == nil then
		return nil
	end
	return parsed
end

-- ---- claim names -----------------------------------------------------------

--- A valid disclosure claim name: `^[A-Za-z0-9_-]{1,64}$`, not leading `_`.
--- @param name string
--- @return boolean
function primitives.is_valid_claim_name(name)
	if type(name) ~= "string" then return false end
	if #name == 0 or #name > 64 then return false end
	if string.sub(name, 1, 1) == "_" then return false end
	return name:match("^[A-Za-z0-9_%-]+$") ~= nil
end

function primitives.is_reserved(name)
	return RESERVED[name] == true
end

-- ---- disclosures -----------------------------------------------------------

--- Build a disclosure segment from a salt, claim name and value.
--- @param salt_b64 string
--- @param name string
--- @param value any
--- @return string
function primitives.make_disclosure(salt_b64, name, value)
	assert(primitives.is_valid_claim_name(name), "invalid claim name")
	assert(#b64.decode(salt_b64) >= 16, "salt too short")
	return primitives.json_segment(gdwjson.array({ salt_b64, name, value }))
end

--- Parse a disclosure segment into { salt, name, value } or nil.
--- @param segment string
--- @return table|nil
function primitives.parse_disclosure(segment)
	local ok, arr = pcall(primitives.parse_segment, segment)
	if not ok or type(arr) ~= "table" or not gdwjson.is_array(arr) then
		return nil
	end
	if #arr ~= 3 then
		return nil
	end
	if type(arr[1]) ~= "string" or type(arr[2]) ~= "string" then
		return nil
	end
	if not primitives.is_valid_claim_name(arr[2]) then
		return nil
	end
	local ok2, salt = pcall(b64.decode, arr[1])
	if not ok2 or #salt < 16 then
		return nil
	end
	return { salt = arr[1], name = arr[2], value = arr[3] }
end

--- SHA-256 digest of the disclosure *segment*, base64url-encoded.
function primitives.disclosure_digest(segment)
	return b64.encode(sha.sha256(segment))
end

--- SHA-256 digest of a presentation base string, base64url-encoded.
function primitives.sd_hash(base_text)
	return b64.encode(sha.sha256(base_text))
end

-- ---- random salts ----------------------------------------------------------

--- Cryptographically-random base64url string of `num_bytes` bytes.
---
--- Reads `/dev/urandom` where available (Linux, macOS, and on-device consoles
--- that expose it). Falls back to `math.random` seeded from the clock, which is
--- NOT suitable for production — see SPEC.md §3 for salting requirements.
--- @param num_bytes integer
--- @return string
function primitives.random_base64url(num_bytes)
	local bytes = primitives._random_bytes(num_bytes)
	if bytes == nil then
		local out = {}
		for i = 1, num_bytes do out[i] = string.char(math.random(0, 255)) end
		bytes = table.concat(out)
	end
	return b64.encode(bytes)
end

function primitives._random_bytes(num_bytes)
	local f = io.open("/dev/urandom", "rb")
	if not f then return nil end
	local data = f:read(num_bytes)
	f:close()
	if not data or #data < num_bytes then return nil end
	return data
end

-- ensure a seed exists for the fallback path
do
	local seed = math.floor(tonumber(tostring(os.time()):reverse():sub(1, 6))
		+ (os.clock() * 1000) % 100000)
	pcall(math.randomseed, seed)
end

-- ---- splits ----------------------------------------------------------------

--- Split on a single-character delimiter, preserving empty fields (matching
--- the `split` behaviour of the other frameworks).
local function split(text, delim)
	local parts = {}
	local start = 1
	while true do
		local pos = string.find(text, delim, start, true)
		if not pos then
			parts[#parts + 1] = string.sub(text, start)
			break
		end
		parts[#parts + 1] = string.sub(text, start, pos - 1)
		start = pos + 1
	end
	return parts
end

function primitives.split_tilde(text)
	return split(text, "~")
end

function primitives.split_dot(text)
	return split(text, ".")
end

return primitives
