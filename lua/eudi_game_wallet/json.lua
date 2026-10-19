--- A deterministic JSON value with canonical (JCS-style) encoding, plus a
--- small hand-written parser.
---
--- Lua has no JSON in its standard library and no way to tell an empty array
--- from an empty object, so:
---   * arrays are tagged with a metatable (`json.array`), and
---   * JSON `null` is the unique sentinel `json.null` (distinct from `nil`,
---     which means "absent").
--- Both the canonical encoder and the parser respect those two conventions.
---
--- Numbers are integers only; floats, exponents, `-0` and leading zeros are
--- rejected, exactly as SPEC.md §2.2 requires.
---
--- Part of the EudiGameWallet Lua framework. See frameworks/SPEC.md.
--- SPDX-License-Identifier: CC-BY-4.0

local json = {}

local ARRAY_MT = { __json_array = true }

--- Unique JSON `null` sentinel.
json.null = setmetatable({}, { __tostring = function() return "json.null" end })

--- Tag a Lua sequence table as a JSON array.
--- @param t table|nil
--- @return table
function json.array(t)
	t = t or {}
	return setmetatable(t, ARRAY_MT)
end

--- True if a table was tagged as a JSON array.
--- @param t table
--- @return boolean
function json.is_array(t)
	return getmetatable(t) == ARRAY_MT
end

--- True if a table should be encoded as a JSON array: either tagged, or a
--- non-empty sequence with consecutive integer keys.
--- @param t table
--- @return boolean
function json.looks_like_array(t)
	if json.is_array(t) then return true end
	local n = #t
	if n == 0 then return false end
	for k in pairs(t) do
		if type(k) ~= "number" or k < 1 or k > n or k % 1 ~= 0 then
			return false
		end
	end
	return true
end

-- ---------------------------------------------------------------------------
-- Accessors (mirror the helper API of the other frameworks)
-- ---------------------------------------------------------------------------

--- Fetch `value[key]` if `value` is a JSON object, else nil.
--- @param value any
--- @param key string
--- @return any
function json.get(value, key)
	if type(value) == "table" and not json.is_array(value) then
		return value[key]
	end
	return nil
end

--- True if `value` is a JSON object with `key` present.
--- @param value any
--- @param key string
--- @return boolean
function json.has(value, key)
	return type(value) == "table" and not json.is_array(value) and value[key] ~= nil
end

--- True if `value` is a JSON object (a table that is not an array).
--- @param value any
--- @return boolean
function json.is_object(value)
	return type(value) == "table" and not json.is_array(value)
end

--- Return `value` if it is a JSON integer (and not a boolean), else nil.
--- @param value any
--- @return integer|nil
function json.as_int(value)
	if type(value) == "number" and value % 1 == 0 then
		return value
	end
	return nil
end

--- Return `value` if it is a string, else nil.
--- @param value any
--- @return string|nil
function json.as_str(value)
	return type(value) == "string" and value or nil
end

--- Iterate an object's entries in canonical (sorted) order.
--- @param value table
--- @return function
function json.entries(value)
	local keys = {}
	if type(value) == "table" and not json.is_array(value) then
		for k in pairs(value) do keys[#keys + 1] = k end
		table.sort(keys)
	end
	local i = 0
	return function()
		i = i + 1
		local k = keys[i]
		if k == nil then return nil end
		return k, value[k]
	end
end

-- ---------------------------------------------------------------------------
-- Canonical encoding
-- ---------------------------------------------------------------------------

local ESCAPES = {
	[0x22] = '\\"', [0x5c] = "\\\\", [0x08] = "\\b", [0x09] = "\\t",
	[0x0a] = "\\n", [0x0c] = "\\f", [0x0d] = "\\r",
}

local function encode_string(out, s)
	out[#out + 1] = '"'
	local i, n = 1, #s
	while i <= n do
		local b = string.byte(s, i)
		local esc = ESCAPES[b]
		if esc then
			out[#out + 1] = esc
			i = i + 1
		elseif b < 0x20 then
			out[#out + 1] = string.format("\\u%04x", b)
			i = i + 1
		else
			out[#out + 1] = string.sub(s, i, i)
			i = i + 1
		end
	end
	out[#out + 1] = '"'
end

--- Encode a character's UTF-8 bytes; used by encode_string via string.char.
local function write_value(out, value)
	local t = type(value)
	if value == json.null or value == nil then
		out[#out + 1] = "null"
	elseif t == "boolean" then
		out[#out + 1] = value and "true" or "false"
	elseif t == "number" then
		if value % 1 ~= 0 then
			error("GDW canonical JSON forbids non-integer numbers: " .. tostring(value))
		end
		out[#out + 1] = string.format("%d", value)
	elseif t == "string" then
		encode_string(out, value)
	elseif t == "table" then
		if json.looks_like_array(value) then
			out[#out + 1] = "["
			local n = 0
			for i = 1, #value do
				if n > 0 then out[#out + 1] = "," end
				write_value(out, value[i])
				n = n + 1
			end
			out[#out + 1] = "]"
		else
			local keys = {}
			for k in pairs(value) do
				if type(k) ~= "string" then
					error("GDW canonical JSON object keys must be strings")
				end
				keys[#keys + 1] = k
			end
			table.sort(keys)
			out[#out + 1] = "{"
			for i = 1, #keys do
				if i > 1 then out[#out + 1] = "," end
				encode_string(out, keys[i])
				out[#out + 1] = ":"
				write_value(out, value[keys[i]])
			end
			out[#out + 1] = "}"
		end
	else
		error("GDW canonical JSON cannot encode a " .. t)
	end
end

--- Canonical serialisation (sorted keys, no whitespace, integers only).
--- @param value any
--- @return string
function json.canonical(value)
	local out = {}
	write_value(out, value)
	return table.concat(out)
end

-- ---------------------------------------------------------------------------
-- Parsing
-- ---------------------------------------------------------------------------

local Parser = {}
Parser.__index = Parser

local function fail(p)
	error({ json_error = true, pos = p.pos })
end

local function skip_ws(p)
	while true do
		local c = string.byte(p.s, p.pos)
		if c == 0x20 or c == 0x09 or c == 0x0a or c == 0x0d then
			p.pos = p.pos + 1
		else
			break
		end
	end
end

local function parse_value(p)

	skip_ws(p)
	local c = string.byte(p.s, p.pos)
	if c == nil then fail(p) end

	if c == 0x7b then -- {
		p.pos = p.pos + 1
		local obj = {}
		skip_ws(p)
		if string.byte(p.s, p.pos) == 0x7d then
			p.pos = p.pos + 1
			return obj
		end
		while true do
			skip_ws(p)
			if string.byte(p.s, p.pos) ~= 0x22 then fail(p) end
			local key = parse_string(p)
			skip_ws(p)
			if string.byte(p.s, p.pos) ~= 0x3a then fail(p) end -- :
			p.pos = p.pos + 1
			obj[key] = parse_value(p)
			skip_ws(p)
			local d = string.byte(p.s, p.pos)
			if d == 0x2c then -- ,
				p.pos = p.pos + 1
			elseif d == 0x7d then -- }
				p.pos = p.pos + 1
				return obj
			else
				fail(p)
			end
		end
	elseif c == 0x5b then -- [
		p.pos = p.pos + 1
		local arr = json.array({})
		skip_ws(p)
		if string.byte(p.s, p.pos) == 0x5d then
			p.pos = p.pos + 1
			return arr
		end
		while true do
			arr[#arr + 1] = parse_value(p)
			skip_ws(p)
			local d = string.byte(p.s, p.pos)
			if d == 0x2c then
				p.pos = p.pos + 1
			elseif d == 0x5d then
				p.pos = p.pos + 1
				return arr
			else
				fail(p)
			end
		end
	elseif c == 0x22 then
		return parse_string(p)
	elseif c == 0x74 then -- t
		if string.sub(p.s, p.pos, p.pos + 3) == "true" then
			p.pos = p.pos + 4
			return true
		end
		fail(p)
	elseif c == 0x66 then -- f
		if string.sub(p.s, p.pos, p.pos + 4) == "false" then
			p.pos = p.pos + 5
			return false
		end
		fail(p)
	elseif c == 0x6e then -- n
		if string.sub(p.s, p.pos, p.pos + 3) == "null" then
			p.pos = p.pos + 4
			return json.null
		end
		fail(p)
	elseif c == 0x2d or (c >= 0x30 and c <= 0x39) then
		return parse_number(p)
	else
		fail(p)
	end
end

function parse_string(p)
	-- p.s[p.pos] == '"'
	p.pos = p.pos + 1
	local out = {}
	local s = p.s
	while true do
		local c = string.byte(s, p.pos)
		if c == nil then fail(p) end
		if c == 0x22 then
			p.pos = p.pos + 1
			return table.concat(out)
		elseif c == 0x5c then -- backslash
			local e = string.byte(s, p.pos + 1)
			if e == 0x22 then out[#out + 1] = '"'; p.pos = p.pos + 2
			elseif e == 0x5c then out[#out + 1] = "\\"; p.pos = p.pos + 2
			elseif e == 0x2f then out[#out + 1] = "/"; p.pos = p.pos + 2
			elseif e == 0x62 then out[#out + 1] = "\b"; p.pos = p.pos + 2
			elseif e == 0x66 then out[#out + 1] = "\f"; p.pos = p.pos + 2
			elseif e == 0x6e then out[#out + 1] = "\n"; p.pos = p.pos + 2
			elseif e == 0x72 then out[#out + 1] = "\r"; p.pos = p.pos + 2
			elseif e == 0x74 then out[#out + 1] = "\t"; p.pos = p.pos + 2
			elseif e == 0x75 then -- \uXXXX
				local hex = string.sub(s, p.pos + 2, p.pos + 5)
				if #hex ~= 4 or not hex:match("^%x%x%x%x$") then fail(p) end
				local code = tonumber(hex, 16)
				p.pos = p.pos + 6
				if code >= 0xd800 and code <= 0xdbff then
					-- surrogate pair
					if string.byte(s, p.pos) == 0x5c and string.byte(s, p.pos + 1) == 0x75 then
						local hex2 = string.sub(s, p.pos + 2, p.pos + 5)
						if #hex2 ~= 4 or not hex2:match("^%x%x%x%x$") then fail(p) end
						local low = tonumber(hex2, 16)
						if low < 0xdc00 or low > 0xdfff then fail(p) end
						code = 0x10000 + (code - 0xd800) * 0x400 + (low - 0xdc00)
						p.pos = p.pos + 6
					else
						fail(p)
					end
				elseif code >= 0xdc00 and code <= 0xdfff then
					fail(p)
				end
				out[#out + 1] = utf8_char(code)
			else
				fail(p)
			end
		elseif c < 0x20 then
			fail(p)
		else
			out[#out + 1] = string.sub(s, p.pos, p.pos)
			p.pos = p.pos + 1
		end
	end
end

--- Encode a Unicode code point as UTF-8 (Lua 5.1/5.2-friendly).
--- @param code integer
--- @return string
function utf8_char(code)
	if code < 0x80 then
		return string.char(code)
	elseif code < 0x800 then
		return string.char(0xc0 + math.floor(code / 0x40), 0x80 + code % 0x40)
	elseif code < 0x10000 then
		return string.char(
			0xe0 + math.floor(code / 0x1000),
			0x80 + math.floor(code / 0x40) % 0x40,
			0x80 + code % 0x40
		)
	else
		return string.char(
			0xf0 + math.floor(code / 0x40000),
			0x80 + math.floor(code / 0x1000) % 0x40,
			0x80 + math.floor(code / 0x40) % 0x40,
			0x80 + code % 0x40
		)
	end
end

function parse_number(p)
	local s = p.s
	local start = p.pos
	if string.byte(s, p.pos) == 0x2d then p.pos = p.pos + 1 end
	-- integer part
	local ds = p.pos
	if string.byte(s, p.pos) == 0x30 then
		p.pos = p.pos + 1
		if string.byte(s, p.pos) and string.byte(s, p.pos) >= 0x30 and string.byte(s, p.pos) <= 0x39 then
			fail(p) -- leading zero
		end
	elseif string.byte(s, p.pos) and string.byte(s, p.pos) >= 0x31 and string.byte(s, p.pos) <= 0x39 then
		while string.byte(s, p.pos) and string.byte(s, p.pos) >= 0x30 and string.byte(s, p.pos) <= 0x39 do
			p.pos = p.pos + 1
		end
	else
		fail(p)
	end
	local c = string.byte(s, p.pos)
	if c == 0x2e or c == 0x65 or c == 0x45 then -- . e E
		fail(p) -- floats / exponents forbidden
	end
	local text = string.sub(s, start, p.pos - 1)
	if text == "-0" then fail(p) end
	local value = tonumber(text)
	if not value then fail(p) end
	if value < -(2 ^ 53 - 1) or value > 2 ^ 53 - 1 then fail(p) end
	return value
end

--- Parse a JSON document, rejecting floats/exponents (integers only).
--- @param text string
--- @return any
function json.parse(text)
	local p = setmetatable({ s = text, pos = 1 }, Parser)
	local ok, value = pcall(parse_value, p)
	if not ok then
		error("malformed JSON")
	end
	skip_ws(p)
	if p.pos <= #text then
		error("malformed JSON")
	end
	return value
end

return json
