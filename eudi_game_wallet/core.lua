--- Token decoding + Issuer + Wallet + Verifier (SPEC.md §4–§7).
---
--- Mirrors the C++ / C# / GDScript / Rust / Python frameworks exactly, so the
--- same credentials and presentations verify across all of them.
---
--- Part of the EudiGameWallet Lua framework. See frameworks/SPEC.md.
--- SPDX-License-Identifier: CC-BY-4.0

local json = require("eudi_game_wallet.json")
local err = require("eudi_game_wallet.errors")
local P = require("eudi_game_wallet.primitives")
local Key = require("eudi_game_wallet.key")

local GdwKey = Key.GdwKey

local core = {}

core.errors = err
core.KEY_ALG = "HS256"

--- Current unix time in seconds.
--- @return integer
function core.now()
	return os.time()
end

-- ---------------------------------------------------------------------------
-- Token / credential decoding
-- ---------------------------------------------------------------------------

--- Decode a compact JWS token into { header, payload, signing_input, signature,
--- header_segment }. Raises an error code string on malformed input.
--- @param token string
--- @return table
function core.decode_token(token)
	local parts = P.split_dot(token)
	if #parts ~= 3 then
		error(err.ERR_MALFORMED)
	end
	local header = P.parse_segment(parts[1])
	local payload = P.parse_segment(parts[2])
	if not json.is_object(header) or not json.is_object(payload) then
		error(err.ERR_MALFORMED)
	end
	return {
		header = header,
		payload = payload,
		signing_input = parts[1] .. "." .. parts[2],
		signature = parts[3],
		header_segment = parts[1],
	}
end

--- Parse a `gw+jwt ~ disclosure ~ … ~` credential string.
--- @param credential string
--- @return table|nil
function core.parse_credential(credential)
	if type(credential) ~= "string" or #credential == 0 then
		return nil
	end
	if string.sub(credential, -1) ~= "~" then
		return nil
	end
	local ok, result = pcall(function()
		local parts = P.split_tilde(credential)
		if #parts < 2 then
			error(err.ERR_MALFORMED)
		end
		local token = core.decode_token(parts[1])
		if json.get(token.header, "typ") ~= "gw+jwt" then
			error(err.ERR_MALFORMED)
		end
		local disclosures = {}
		for i = 2, #parts do
			if parts[i] ~= "" then
				disclosures[#disclosures + 1] = parts[i]
			end
		end
		return { token = token, disclosures = disclosures }
	end)
	if not ok then
		return nil
	end
	return result
end

-- ---------------------------------------------------------------------------
-- Issuer
-- ---------------------------------------------------------------------------

local Issuer = {}
Issuer.__index = Issuer

--- @param iss string
--- @param issuer_key table (GdwKey)
--- @return table
function core.new_issuer(iss, issuer_key)
	local signer = Key.signer_for(issuer_key)
	return setmetatable({
		iss = iss,
		_alg = issuer_key.alg,
		_signer = signer,
	}, Issuer)
end

--- Issue a credential. `options` mirrors the other frameworks:
---   vct, claims, disclosable, iat, exp, sub, holder_key, salts, extra_payload.
--- Returns the credential string, or raises an error code string on bad input.
--- @param options table
--- @return string
function Issuer:issue(options)
	local vct = options.vct or ""
	local claims = options.claims or {}
	local disclosable = options.disclosable or {}
	local iat = options.iat or 0
	local exp = options.exp or 0
	local sub = options.sub or ""
	local holder_key = options.holder_key
	local salts = options.salts or {}
	local extra_payload = options.extra_payload or {}

	if iat == 0 or exp == 0 or vct == "" or holder_key == nil then
		error(err.ERR_MALFORMED)
	end
	for _, name in ipairs(disclosable) do
		if claims[name] == nil or P.is_reserved(name) then
			error(err.ERR_MALFORMED)
		end
	end

	local disclosures = {}
	local sd = json.array({})
	for i, name in ipairs(disclosable) do
		if claims[name] == nil then
			error(err.ERR_MALFORMED)
		end
		local salt = salts[i] or P.random_base64url(16)
		local segment = P.make_disclosure(salt, name, claims[name])
		disclosures[#disclosures + 1] = segment
		sd[#sd + 1] = P.disclosure_digest(segment)
	end

	local payload = {
		_sd = sd,
		_sd_alg = "sha-256",
		cnf = holder_key:to_dict(),
		exp = exp,
		iat = iat,
		iss = self.iss,
		vct = vct,
	}
	if sub ~= "" then
		payload.sub = sub
	end

	local disclosable_set = {}
	for _, n in ipairs(disclosable) do disclosable_set[n] = true end

	-- plaintext claims (preserve any explicit ordering; object key order is
	-- irrelevant because canonical encoding sorts keys anyway)
	for name, value in pairs(claims) do
		if not disclosable_set[name] then
			if payload[name] ~= nil then
				error(err.ERR_MALFORMED)
			end
			payload[name] = value
		end
	end
	for name, value in pairs(extra_payload) do
		if payload[name] ~= nil then
			error(err.ERR_MALFORMED)
		end
		payload[name] = value
	end

	local header = { alg = self._alg, typ = "gw+jwt" }
	local signing_input = P.json_segment(header) .. "." .. P.json_segment(payload)
	local jwt = signing_input .. "." .. self._signer:sign(signing_input)

	local out = { jwt }
	for _, segment in ipairs(disclosures) do
		out[#out + 1] = "~" .. segment
	end
	out[#out + 1] = "~"
	return table.concat(out)
end

-- ---------------------------------------------------------------------------
-- Wallet (holder)
-- ---------------------------------------------------------------------------

local Wallet = {}
Wallet.__index = Wallet

--- @param holder_key table (GdwKey)
--- @return table
function core.new_wallet(holder_key)
	return setmetatable({
		_key = holder_key,
		_signer = Key.signer_for(holder_key),
		_credentials = {},
	}, Wallet)
end

--- Store a credential. Raises an error code string if it is malformed.
--- @param credential string
function Wallet:store(credential)
	if core.parse_credential(credential) == nil then
		error(err.ERR_MALFORMED)
	end
	self._credentials[#self._credentials + 1] = credential
end

--- @return table list of stored credentials
function Wallet:credentials()
	return self._credentials
end

--- Names of the claims a credential carries (plaintext + disclosable).
--- @param credential string
--- @return table
function Wallet:claims_of(credential)
	local parsed = core.parse_credential(credential)
	local names = {}
	if parsed == nil then
		return names
	end
	for name in json.entries(parsed.token.payload) do
		if not P.is_reserved(name) then
			names[#names + 1] = name
		end
	end
	for _, segment in ipairs(parsed.disclosures) do
		local parsed_d = P.parse_disclosure(segment)
		names[#names + 1] = parsed_d and parsed_d.name or ""
	end
	return names
end

--- Build a presentation revealing only `requested_claims`, with a key binding.
--- Returns the presentation string, or raises an error code string.
--- @param credential string
--- @param requested_claims table
--- @param aud string
--- @param nonce string
--- @param issued_at integer
--- @return string
function Wallet:present(credential, requested_claims, aud, nonce, issued_at)
	local parsed = core.parse_credential(credential)
	if parsed == nil then
		error(err.ERR_MALFORMED)
	end

	local by_digest = {}
	for _, segment in ipairs(parsed.disclosures) do
		by_digest[P.disclosure_digest(segment)] = segment
	end

	local selected = {}
	local sd = json.get(parsed.token.payload, "_sd")
	for _, name in ipairs(requested_claims) do
		local is_plaintext = (not P.is_reserved(name)) and json.has(parsed.token.payload, name)
		if not is_plaintext then
			local found = false
			if json.is_array(sd) then
				for _, digest in ipairs(sd) do
					if type(digest) == "string" and by_digest[digest] then
						local segment = by_digest[digest]
						local pd = P.parse_disclosure(segment)
						if pd and pd.name == name then
							selected[#selected + 1] = segment
							found = true
							break
						end
					end
				end
			end
			if not found then
				error(err.ERR_CLAIM_MISSING)
			end
		end
	end

	local base_text = parsed.token.signing_input .. "." .. parsed.token.signature
	for _, segment in ipairs(selected) do
		base_text = base_text .. "~" .. segment
	end

	local cnf = json.get(parsed.token.payload, "cnf")
	if json.is_object(cnf) then
		local cnf_key = GdwKey.from_dict(cnf)
		if not cnf_key:same_secret(self._key) then
			error(err.ERR_KB_INVALID)
		end
	end

	local kb = {
		aud = aud,
		iat = issued_at,
		nonce = nonce,
		sd_hash = P.sd_hash(base_text),
	}
	local header = { alg = self._signer.alg, typ = "kb+jwt" }
	local signing_input = P.json_segment(header) .. "." .. P.json_segment(kb)
	local kb_jwt = signing_input .. "." .. self._signer:sign(signing_input)
	return base_text .. "~" .. kb_jwt
end

-- ---------------------------------------------------------------------------
-- Verifier (relying party)
-- ---------------------------------------------------------------------------

local Verifier = {}
Verifier.__index = Verifier

--- @param aud string
--- @return table
function core.new_verifier(aud)
	return setmetatable({
		aud = aud,
		clock_skew = 300,
		_trust = {},
		_used_nonces = {},
	}, Verifier)
end

function Verifier:set_clock_skew(skew)
	self.clock_skew = skew
end

function Verifier:trust(issuer, gdw_key)
	self._trust[issuer] = gdw_key
end

function Verifier:mark_nonce_used(iss, nonce)
	self._used_nonces[iss .. "|" .. nonce] = true
end

--- Create a verification request for game clients.
--- @param vct table
--- @param claims table
--- @param ttl integer|nil (default 60)
--- @return table
function Verifier:create_request(vct, claims, ttl)
	local current = core.now()
	local out = {
		aud = self.aud,
		nonce = P.random_base64url(16),
		vct = json.array(vct or {}),
		claims = json.array(claims or {}),
		iat = current,
		expires_at = current + (ttl or 60),
	}
	return out
end

--- Verify a presentation. Never raises for bad input; returns
--- `{ ok = bool, claims = table, errors = table }`.
--- @param request table
--- @param presentation string
--- @param current_time integer
--- @return table
function Verifier:verify(request, presentation, current_time)
	local ok, claims = pcall(function()
		return self:_verify_internal(request, presentation, current_time)
	end)
	if ok then
		return { ok = true, claims = claims, errors = {} }
	end
	-- raisals are error-code strings; Lua prepends "file:line: " to propagated
	-- string errors, so take the trailing ERR_* code.
	local code = tostring(claims):match("(ERR_[A-Z_]+)%s*$") or tostring(claims)
	return { ok = false, claims = {}, errors = { code } }
end

function Verifier:_verify_internal(request, presentation, current_time)
	local parts = P.split_tilde(presentation)
	if #parts < 2 then
		error(err.ERR_MALFORMED)
	end

	local jwt = parts[1]
	local has_kb = parts[#parts] ~= ""
	local kb_jwt = has_kb and parts[#parts] or ""
	local end_i = has_kb and (#parts - 1) or #parts
	local disclosures = {}
	for i = 2, end_i do
		if parts[i] ~= "" then
			disclosures[#disclosures + 1] = parts[i]
		end
	end

	local token = core.decode_token(jwt)
	if json.get(token.header, "typ") ~= "gw+jwt" then
		error(err.ERR_MALFORMED)
	end

	local iss = json.get(token.payload, "iss")
	if type(iss) ~= "string" or iss == "" then
		error(err.ERR_MALFORMED)
	end
	local trusted = self._trust[iss]
	if trusted == nil then
		error(err.ERR_ISSUER_UNKNOWN)
	end
	if json.get(token.header, "alg") ~= trusted.alg then
		error(err.ERR_MALFORMED)
	end
	local issuer_signer = Key.signer_for(trusted)
	if not issuer_signer:verify(token.signing_input, token.signature) then
		error(err.ERR_SIGNATURE_INVALID)
	end

	local exp = json.as_int(json.get(token.payload, "exp"))
	local iat = json.as_int(json.get(token.payload, "iat"))
	if exp == nil or iat == nil or exp < 0 or iat < 0 then
		error(err.ERR_MALFORMED)
	end
	if current_time > exp + self.clock_skew then
		error(err.ERR_EXPIRED)
	end
	if current_time < iat - self.clock_skew then
		error(err.ERR_NOT_YET_VALID)
	end

	local vct = json.get(token.payload, "vct") or ""
	local allowed = json.get(request, "vct")
	local vct_allowed = false
	if json.is_array(allowed) then
		for _, candidate in ipairs(allowed) do
			if candidate == vct then vct_allowed = true end
		end
	end
	if not vct_allowed then
		error(err.ERR_VCT_NOT_ALLOWED)
	end

	if json.get(token.payload, "_sd_alg") ~= "sha-256" then
		error(err.ERR_MALFORMED)
	end
	local sd = json.get(token.payload, "_sd")
	if not json.is_array(sd) then
		error(err.ERR_MALFORMED)
	end

	local claims = {}
	for name, value in json.entries(token.payload) do
		if not P.is_reserved(name) then
			claims[name] = value
		end
	end

	local covered = {}
	for _, digest in ipairs(sd) do
		if type(digest) == "string" then
			covered[digest] = true
		end
	end

	local seen = {}
	for _, segment in ipairs(disclosures) do
		local digest = P.disclosure_digest(segment)
		if not covered[digest] or seen[digest] then
			error(err.ERR_DISCLOSURE_UNKNOWN)
		end
		seen[digest] = true
		local pd = P.parse_disclosure(segment)
		if pd == nil then
			error(err.ERR_MALFORMED)
		end
		if claims[pd.name] ~= nil then
			error(err.ERR_DUPLICATE_CLAIM)
		end
		claims[pd.name] = pd.value
	end

	local required = json.get(request, "claims")
	if json.is_array(required) then
		for _, name in ipairs(required) do
			if type(name) == "string" and claims[name] == nil then
				error(err.ERR_CLAIM_MISSING)
			end
		end
	end

	-- ---- key binding ----
	if kb_jwt == "" then
		error(err.ERR_KB_MISSING)
	end
	local kb_token = core.decode_token(kb_jwt)
	if json.get(kb_token.header, "typ") ~= "kb+jwt" then
		error(err.ERR_KB_INVALID)
	end
	local cnf = json.get(token.payload, "cnf")
	if not json.is_object(cnf) then
		error(err.ERR_KB_INVALID)
	end
	local cnf_key = GdwKey.from_dict(cnf)
	if json.get(kb_token.header, "alg") ~= cnf_key.alg then
		error(err.ERR_KB_INVALID)
	end
	local kb_signer = Key.signer_for(cnf_key)
	if not kb_signer:verify(kb_token.signing_input, kb_token.signature) then
		error(err.ERR_KB_INVALID)
	end

	local base_text = jwt
	for _, segment in ipairs(disclosures) do
		base_text = base_text .. "~" .. segment
	end
	if json.get(kb_token.payload, "sd_hash") ~= P.sd_hash(base_text) then
		error(err.ERR_SD_HASH_MISMATCH)
	end
	if json.get(kb_token.payload, "aud") ~= json.get(request, "aud") then
		error(err.ERR_AUD_MISMATCH)
	end
	if json.get(kb_token.payload, "nonce") ~= json.get(request, "nonce") then
		error(err.ERR_NONCE_MISMATCH)
	end

	local kb_iat = json.as_int(json.get(kb_token.payload, "iat"))
	if kb_iat == nil or kb_iat < 0
		or current_time > kb_iat + self.clock_skew
		or current_time < kb_iat - self.clock_skew then
		error(err.ERR_KB_INVALID)
	end

	local nonce_key = iss .. "|" .. (json.get(request, "nonce") or "")
	if self._used_nonces[nonce_key] then
		error(err.ERR_REPLAY)
	end
	self._used_nonces[nonce_key] = true

	return claims
end

core.Issuer = Issuer
core.Wallet = Wallet
core.Verifier = Verifier

return core
