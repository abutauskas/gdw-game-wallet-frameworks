//! Token decoding + Issuer + Wallet + Verifier (SPEC.md §4–§7).
//!
//! SPDX-License-Identifier: CC-BY-4.0

use std::collections::{BTreeMap, HashSet};

use crate::errors::{GdwError, GdwResult};
use crate::json::Json;
use crate::key::{signer_for, GdwKey};
use crate::primitives::{
    disclosure_digest, is_reserved, json_segment, make_disclosure, parse_disclosure, parse_segment,
    random_base64url, sd_hash, split_dot, split_tilde,
};

/// A decoded JWT-style token.
pub struct DecodedToken {
    pub header: Json,
    pub payload: Json,
    pub signing_input: String,
    pub signature: String,
    pub header_segment: String,
}

pub fn decode_token(token: &str) -> GdwResult<DecodedToken> {
    let parts = split_dot(token);
    if parts.len() != 3 {
        return Err(GdwError::Malformed);
    }
    let header = parse_segment(parts[0])?;
    let payload = parse_segment(parts[1])?;
    if !header.is_object() || !payload.is_object() {
        return Err(GdwError::Malformed);
    }
    Ok(DecodedToken {
        header,
        payload,
        signing_input: format!("{}.{}", parts[0], parts[1]),
        signature: parts[2].to_string(),
        header_segment: parts[0].to_string(),
    })
}

pub struct ParsedCredential {
    pub token: DecodedToken,
    pub disclosures: Vec<String>,
}

/// Parse a `gw+jwt ~ disclosure ~ … ~` credential string.
pub fn parse_credential(credential: &str) -> GdwResult<ParsedCredential> {
    if credential.is_empty() || !credential.ends_with('~') {
        return Err(GdwError::Malformed);
    }
    let parts = split_tilde(credential);
    if parts.len() < 2 {
        return Err(GdwError::Malformed);
    }
    let token = decode_token(parts[0])?;
    if token.header.get("typ").and_then(Json::as_str) != Some("gw+jwt") {
        return Err(GdwError::Malformed);
    }
    let disclosures = parts[1..]
        .iter()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    Ok(ParsedCredential { token, disclosures })
}

// ===========================================================================
// Issuer
// ===========================================================================

pub struct IssueOptions {
    pub vct: String,
    pub claims: BTreeMap<String, Json>,
    pub disclosable: Vec<String>,
    pub iat: i64,
    pub exp: i64,
    pub sub: String,
    pub holder_key: GdwKey,
    /// Deterministic salts for tests; falls back to random when shorter.
    pub salts: Vec<String>,
    pub extra_payload: BTreeMap<String, Json>,
}

impl Default for IssueOptions {
    fn default() -> Self {
        IssueOptions {
            vct: String::new(),
            claims: BTreeMap::new(),
            disclosable: Vec::new(),
            iat: 0,
            exp: 0,
            sub: String::new(),
            holder_key: GdwKey::default(),
            salts: Vec::new(),
            extra_payload: BTreeMap::new(),
        }
    }
}

pub struct Issuer {
    iss: String,
    signer: Box<dyn crate::key::Signer>,
    alg: String,
}

impl Issuer {
    /// Construct an issuer. Key material is NOT checked here for ES256 keys
    /// missing private parts until a sign occurs.
    pub fn new(iss: &str, issuer_key: &GdwKey) -> GdwResult<Issuer> {
        let signer = signer_for(issuer_key)?;
        Ok(Issuer {
            iss: iss.to_string(),
            alg: issuer_key.alg.clone(),
            signer,
        })
    }

    pub fn id(&self) -> &str {
        &self.iss
    }

    pub fn issue(&self, options: &IssueOptions) -> GdwResult<String> {
        if options.iat == 0 || options.exp == 0 || options.vct.is_empty() {
            return Err(GdwError::Malformed);
        }
        for name in &options.disclosable {
            if !options.claims.contains_key(name) || is_reserved(name) {
                return Err(GdwError::Malformed);
            }
        }

        let mut disclosures = Vec::new();
        let mut sd = Json::array();
        for (i, name) in options.disclosable.iter().enumerate() {
            let salt = options
                .salts
                .get(i)
                .cloned()
                .unwrap_or_else(|| random_base64url(16));
            let value = options.claims.get(name).ok_or(GdwError::Malformed)?;
            let segment = make_disclosure(&salt, name, value)?;
            disclosures.push(segment.clone());
            if let Json::Array(items) = &mut sd {
                items.push(Json::str(disclosure_digest(&segment)));
            }
        }

        let mut payload = Json::object();
        payload.set("_sd", sd);
        payload.set("_sd_alg", Json::str("sha-256"));
        payload.set("cnf", options.holder_key.to_json());
        payload.set("exp", Json::Int(options.exp));
        payload.set("iat", Json::Int(options.iat));
        payload.set("iss", Json::str(self.iss.clone()));
        payload.set("vct", Json::str(options.vct.clone()));
        if !options.sub.is_empty() {
            payload.set("sub", Json::str(options.sub.clone()));
        }

        for (key, value) in &options.claims {
            if options.disclosable.contains(key) {
                continue;
            }
            if payload.has(key) {
                return Err(GdwError::Malformed);
            }
            payload.set(key.clone(), value.clone());
        }
        for (key, value) in &options.extra_payload {
            if payload.has(key) {
                return Err(GdwError::Malformed);
            }
            payload.set(key.clone(), value.clone());
        }

        let mut header = Json::object();
        header.set("alg", Json::str(self.alg.clone()));
        header.set("typ", Json::str("gw+jwt"));
        let signing_input = format!("{}.{}", json_segment(&header), json_segment(&payload));
        let jwt = format!("{signing_input}.{}", self.signer.sign(&signing_input));

        let mut out = jwt;
        for d in &disclosures {
            out.push('~');
            out.push_str(d);
        }
        out.push('~');
        Ok(out)
    }
}

// ===========================================================================
// Wallet (holder)
// ===========================================================================

pub struct Wallet {
    key: GdwKey,
    signer: Box<dyn crate::key::Signer>,
    credentials: Vec<String>,
}

impl Wallet {
    pub fn new(holder_key: GdwKey) -> GdwResult<Wallet> {
        let signer = signer_for(&holder_key)?;
        Ok(Wallet {
            key: holder_key,
            signer,
            credentials: Vec::new(),
        })
    }

    pub fn credentials(&self) -> &[String] {
        &self.credentials
    }

    pub fn store(&mut self, credential: &str) -> GdwResult<()> {
        parse_credential(credential)?;
        self.credentials.push(credential.to_string());
        Ok(())
    }

    /// Names of the claims a credential carries (plaintext + disclosable).
    pub fn claims_of(&self, credential: &str) -> GdwResult<Vec<String>> {
        let parsed = parse_credential(credential)?;
        let mut names = Vec::new();
        for (key, _) in parsed.token.payload.entries() {
            if !is_reserved(key) {
                names.push(key.clone());
            }
        }
        for segment in &parsed.disclosures {
            names.push(parse_disclosure(segment)?.name);
        }
        Ok(names)
    }

    /// Build a presentation revealing only `requested_claims`, with a key binding.
    pub fn present(
        &self,
        credential: &str,
        requested_claims: &[&str],
        aud: &str,
        nonce: &str,
        issued_at: i64,
    ) -> GdwResult<String> {
        let parsed = parse_credential(credential)?;

        let mut by_digest: BTreeMap<String, String> = BTreeMap::new();
        for segment in &parsed.disclosures {
            by_digest.insert(disclosure_digest(segment), segment.clone());
        }

        let mut selected: Vec<String> = Vec::new();
        let sd = parsed.token.payload.get("_sd");
        for name in requested_claims {
            if !is_reserved(name) && parsed.token.payload.has(name) {
                continue; // plaintext claim is always revealed
            }
            let mut found = false;
            if let Some(sd) = sd {
                if sd.is_array() {
                    for digest_json in sd.items() {
                        let digest = match digest_json.as_str() {
                            Some(d) => d,
                            None => continue,
                        };
                        if let Some(seg) = by_digest.get(digest) {
                            if parse_disclosure(seg)?.name == *name {
                                selected.push(seg.clone());
                                found = true;
                                break;
                            }
                        }
                    }
                }
            }
            if !found {
                return Err(GdwError::ClaimMissing);
            }
        }

        let mut base_text = parsed.token.signing_input.clone();
        base_text.push('.');
        base_text.push_str(&parsed.token.signature);
        for seg in &selected {
            base_text.push('~');
            base_text.push_str(seg);
        }

        let cnf = parsed.token.payload.get("cnf");
        if let Some(cnf) = cnf {
            if cnf.is_object() {
                let cnf_key = GdwKey::from_json(cnf);
                if !cnf_key.same_secret(&self.key) {
                    return Err(GdwError::KbInvalid);
                }
            }
        }

        let mut kb = Json::object();
        kb.set("aud", Json::str(aud));
        kb.set("iat", Json::Int(issued_at));
        kb.set("nonce", Json::str(nonce));
        kb.set("sd_hash", Json::str(sd_hash(&base_text)));

        let mut header = Json::object();
        header.set("alg", Json::str(self.signer.alg()));
        header.set("typ", Json::str("kb+jwt"));
        let signing_input = format!("{}.{}", json_segment(&header), json_segment(&kb));
        let kb_jwt = format!("{signing_input}.{}", self.signer.sign(&signing_input));
        Ok(format!("{base_text}~{kb_jwt}"))
    }
}

// ===========================================================================
// Verifier (relying party)
// ===========================================================================

pub struct VerifyResult {
    pub ok: bool,
    pub claims: Json,
    pub errors: Vec<String>,
}

impl VerifyResult {
    fn fail(code: GdwError) -> VerifyResult {
        VerifyResult {
            ok: false,
            claims: Json::object(),
            errors: vec![code.code().to_string()],
        }
    }
}

pub struct Verifier {
    aud: String,
    trust: BTreeMap<String, GdwKey>,
    used_nonces: HashSet<String>,
    clock_skew: i64,
}

impl Verifier {
    pub fn new(aud: &str) -> Verifier {
        Verifier {
            aud: aud.to_string(),
            trust: BTreeMap::new(),
            used_nonces: HashSet::new(),
            clock_skew: 300,
        }
    }

    pub fn set_clock_skew(&mut self, skew: i64) {
        self.clock_skew = skew;
    }

    pub fn trust(&mut self, issuer: &str, key: GdwKey) {
        self.trust.insert(issuer.to_string(), key);
    }

    pub fn mark_nonce_used(&mut self, iss: &str, nonce: &str) {
        self.used_nonces.insert(format!("{iss}|{nonce}"));
    }

    pub fn create_request(&self, vct: &[&str], claims: &[&str], ttl_seconds: i64) -> Json {
        let now = now();
        let mut obj = Json::object();
        obj.set("aud", Json::str(self.aud.clone()));
        obj.set("nonce", Json::str(random_base64url(16)));
        obj.set("vct", Json::array_of_strings(vct.iter().copied()));
        obj.set("claims", Json::array_of_strings(claims.iter().copied()));
        obj.set("iat", Json::Int(now));
        obj.set("expires_at", Json::Int(now + ttl_seconds));
        obj
    }

    /// Verify a presentation. Never panics on bad input; returns `ok:false`
    /// with a single error code.
    pub fn verify(
        &mut self,
        request: &Json,
        presentation: &str,
        current_time: i64,
    ) -> VerifyResult {
        match self.verify_internal(request, presentation, current_time) {
            Ok(claims) => VerifyResult {
                ok: true,
                claims,
                errors: Vec::new(),
            },
            Err(code) => VerifyResult::fail(code),
        }
    }

    fn verify_internal(
        &mut self,
        request: &Json,
        presentation: &str,
        current_time: i64,
    ) -> GdwResult<Json> {
        let parts = split_tilde(presentation);
        if parts.len() < 2 {
            return Err(GdwError::Malformed);
        }

        let jwt = parts[0];
        let has_kb = !parts[parts.len() - 1].is_empty();
        let kb_jwt = if has_kb { parts[parts.len() - 1] } else { "" };
        let end = if has_kb { parts.len() - 1 } else { parts.len() };
        let disclosures: Vec<String> = parts[1..end]
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        let token = decode_token(jwt)?;
        if token.header.get("typ").and_then(Json::as_str) != Some("gw+jwt") {
            return Err(GdwError::Malformed);
        }

        let iss = token
            .payload
            .get("iss")
            .and_then(Json::as_str)
            .ok_or(GdwError::Malformed)?;
        if iss.is_empty() {
            return Err(GdwError::Malformed);
        }
        let trusted = self.trust.get(iss).ok_or(GdwError::IssuerUnknown)?;
        if token.header.get("alg").and_then(Json::as_str) != Some(trusted.alg.as_str()) {
            return Err(GdwError::Malformed);
        }
        let issuer_signer = signer_for(trusted)?;
        if !issuer_signer.verify(&token.signing_input, &token.signature) {
            return Err(GdwError::SignatureInvalid);
        }

        let exp = token
            .payload
            .get("exp")
            .and_then(Json::as_i64)
            .unwrap_or(-1);
        let iat = token
            .payload
            .get("iat")
            .and_then(Json::as_i64)
            .unwrap_or(-1);
        if exp < 0 || iat < 0 {
            return Err(GdwError::Malformed);
        }
        if current_time > exp + self.clock_skew {
            return Err(GdwError::Expired);
        }
        if current_time < iat - self.clock_skew {
            return Err(GdwError::NotYetValid);
        }

        let vct = token
            .payload
            .get("vct")
            .and_then(Json::as_str)
            .unwrap_or("");
        let mut vct_allowed = false;
        if let Some(allowed) = request.get("vct") {
            if allowed.is_array() {
                for candidate in allowed.items() {
                    if candidate.as_str() == Some(vct) {
                        vct_allowed = true;
                    }
                }
            }
        }
        if !vct_allowed {
            return Err(GdwError::VctNotAllowed);
        }

        if token.payload.get("_sd_alg").and_then(Json::as_str) != Some("sha-256") {
            return Err(GdwError::Malformed);
        }
        let sd = token.payload.get("_sd").ok_or(GdwError::Malformed)?;
        if !sd.is_array() {
            return Err(GdwError::Malformed);
        }

        let mut claims = Json::object();
        for (key, value) in token.payload.entries() {
            if !is_reserved(key) {
                claims.set(key.clone(), value.clone());
            }
        }

        let covered: Vec<String> = sd
            .items()
            .iter()
            .filter_map(|d| d.as_str().map(str::to_string))
            .collect();

        let mut seen: HashSet<String> = HashSet::new();
        for segment in &disclosures {
            let digest = disclosure_digest(segment);
            if !covered.contains(&digest) || seen.contains(&digest) {
                return Err(GdwError::DisclosureUnknown);
            }
            seen.insert(digest);
            let parsed = parse_disclosure(segment)?;
            if claims.has(&parsed.name) {
                return Err(GdwError::DuplicateClaim);
            }
            claims.set(parsed.name, parsed.value);
        }

        if let Some(required) = request.get("claims") {
            if required.is_array() {
                for name in required.items() {
                    if let Some(name) = name.as_str() {
                        if !claims.has(name) {
                            return Err(GdwError::ClaimMissing);
                        }
                    }
                }
            }
        }

        // ---- key binding ----
        if kb_jwt.is_empty() {
            return Err(GdwError::KbMissing);
        }
        let kb_token = decode_token(kb_jwt)?;
        if kb_token.header.get("typ").and_then(Json::as_str) != Some("kb+jwt") {
            return Err(GdwError::KbInvalid);
        }
        let cnf = token.payload.get("cnf").ok_or(GdwError::KbInvalid)?;
        if !cnf.is_object() {
            return Err(GdwError::KbInvalid);
        }
        let cnf_key = GdwKey::from_json(cnf);
        if kb_token.header.get("alg").and_then(Json::as_str) != Some(cnf_key.alg.as_str()) {
            return Err(GdwError::KbInvalid);
        }
        let kb_signer = signer_for(&cnf_key)?;
        if !kb_signer.verify(&kb_token.signing_input, &kb_token.signature) {
            return Err(GdwError::KbInvalid);
        }

        let mut base_text = jwt.to_string();
        for segment in &disclosures {
            base_text.push('~');
            base_text.push_str(segment);
        }
        if kb_token.payload.get("sd_hash").and_then(Json::as_str)
            != Some(sd_hash(&base_text).as_str())
        {
            return Err(GdwError::SdHashMismatch);
        }
        if kb_token.payload.get("aud").and_then(Json::as_str)
            != request.get("aud").and_then(Json::as_str)
        {
            return Err(GdwError::AudMismatch);
        }
        if kb_token.payload.get("nonce").and_then(Json::as_str)
            != request.get("nonce").and_then(Json::as_str)
        {
            return Err(GdwError::NonceMismatch);
        }

        let kb_iat = kb_token
            .payload
            .get("iat")
            .and_then(Json::as_i64)
            .unwrap_or(-1);
        if kb_iat < 0
            || current_time > kb_iat + self.clock_skew
            || current_time < kb_iat - self.clock_skew
        {
            return Err(GdwError::KbInvalid);
        }

        let nonce_key = format!(
            "{}|{}",
            iss,
            request.get("nonce").and_then(Json::as_str).unwrap_or("")
        );
        if self.used_nonces.contains(&nonce_key) {
            return Err(GdwError::Replay);
        }
        self.used_nonces.insert(nonce_key);

        Ok(claims)
    }
}

/// Current unix time in seconds.
pub fn now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
