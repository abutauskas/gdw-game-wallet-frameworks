// Token decoding + Issuer + Wallet + Verifier.
//
// SPDX-License-Identifier: CC-BY-4.0

using System.Security.Cryptography;

namespace Eudi.GameWallet;

public sealed class DecodedToken
{
    public required GdwJson Header { get; init; }
    public required GdwJson Payload { get; init; }
    public required string SigningInput { get; init; }
    public required string Signature { get; init; }
    public required string HeaderSegment { get; init; }
}

public static class GdwTokenCodec
{
    public static DecodedToken Decode(string token)
    {
        string[] parts = GdwPrimitives.SplitDot(token);
        if (parts.Length != 3) throw new GdwException(GdwErrors.Malformed);
        GdwJson header = GdwPrimitives.ParseSegment(parts[0]);
        GdwJson payload = GdwPrimitives.ParseSegment(parts[1]);
        if (!header.IsObject || !payload.IsObject) throw new GdwException(GdwErrors.Malformed);
        return new DecodedToken
        {
            Header = header,
            Payload = payload,
            SigningInput = parts[0] + "." + parts[1],
            Signature = parts[2],
            HeaderSegment = parts[0],
        };
    }
}

public sealed class ParsedCredential
{
    public required DecodedToken Token { get; init; }
    public required List<string> Disclosures { get; init; }
}

public static class GdwCredential
{
    public static ParsedCredential Parse(string credential)
    {
        if (string.IsNullOrEmpty(credential) || credential[^1] != '~')
            throw new GdwException(GdwErrors.Malformed);
        string[] parts = GdwPrimitives.SplitTilde(credential);
        if (parts.Length < 2) throw new GdwException(GdwErrors.Malformed);
        var token = GdwTokenCodec.Decode(parts[0]);
        if (token.Header.Get("typ")?.AsString() != "gw+jwt")
            throw new GdwException(GdwErrors.Malformed);
        var disclosures = new List<string>();
        for (int i = 1; i < parts.Length; i++)
            if (parts[i].Length > 0) disclosures.Add(parts[i]);
        return new ParsedCredential { Token = token, Disclosures = disclosures };
    }
}

// ===========================================================================
// Issuer
// ===========================================================================

public sealed class IssueOptions
{
    public string Vct { get; set; } = "";
    public GdwJson Claims { get; set; } = GdwJson.Object();
    public List<string> Disclosable { get; set; } = new();
    public long Iat { get; set; }
    public long Exp { get; set; }
    public string Sub { get; set; } = "";
    public GdwKey HolderKey { get; set; } = null!;
    public List<string> Salts { get; set; } = new(); // deterministic tests
    public GdwJson ExtraPayload { get; set; } = GdwJson.Object();
}

public sealed class Issuer
{
    private readonly string _iss;
    private readonly ISigner _signer;

    public Issuer(string iss, GdwKey issuerKey)
    {
        _iss = iss;
        _signer = SignerFactory.Create(issuerKey);
    }

    public string Id => _iss;

    public string Issue(IssueOptions options)
    {
        if (options.Iat == 0 || options.Exp == 0) throw new GdwException(GdwErrors.Malformed);
        if (string.IsNullOrEmpty(options.Vct)) throw new GdwException(GdwErrors.Malformed);

        foreach (var name in options.Disclosable)
        {
            if (!options.Claims.Has(name)) throw new GdwException(GdwErrors.Malformed);
            if (GdwPrimitives.IsReserved(name)) throw new GdwException(GdwErrors.Malformed);
        }

        var disclosures = new List<string>();
        var sd = GdwJson.Array();
        for (int i = 0; i < options.Disclosable.Count; i++)
        {
            string name = options.Disclosable[i];
            string salt = i < options.Salts.Count ? options.Salts[i] : GdwPrimitives.RandomBase64Url(16);
            string segment = GdwPrimitives.MakeDisclosure(salt, name, options.Claims[name]);
            disclosures.Add(segment);
            sd.Add(GdwJson.Str(GdwPrimitives.DisclosureDigest(segment)));
        }

        var payload = GdwJson.Object();
        payload["_sd"] = sd;
        payload["_sd_alg"] = GdwJson.Str("sha-256");
        payload["cnf"] = options.HolderKey.ToJson();
        payload["exp"] = GdwJson.Int(options.Exp);
        payload["iat"] = GdwJson.Int(options.Iat);
        payload["iss"] = GdwJson.Str(_iss);
        payload["vct"] = GdwJson.Str(options.Vct);
        if (options.Sub.Length > 0) payload["sub"] = GdwJson.Str(options.Sub);

        foreach (var kv in options.Claims.Entries)
        {
            if (options.Disclosable.Contains(kv.Key)) continue;
            if (payload.Has(kv.Key)) throw new GdwException(GdwErrors.Malformed);
            payload[kv.Key] = kv.Value;
        }
        foreach (var kv in options.ExtraPayload.Entries)
        {
            if (payload.Has(kv.Key)) throw new GdwException(GdwErrors.Malformed);
            payload[kv.Key] = kv.Value;
        }

        var header = GdwJson.Object();
        header["alg"] = GdwJson.Str(_signer.Alg);
        header["typ"] = GdwJson.Str("gw+jwt");
        string signingInput = GdwPrimitives.JsonSegment(header) + "." + GdwPrimitives.JsonSegment(payload);
        string jwt = signingInput + "." + _signer.Sign(signingInput);

        var sb = new System.Text.StringBuilder(jwt);
        foreach (var d in disclosures) sb.Append('~').Append(d);
        sb.Append('~');
        return sb.ToString();
    }
}

// ===========================================================================
// Wallet (holder)
// ===========================================================================

public sealed class Wallet
{
    private readonly GdwKey _key;
    private readonly ISigner _signer;
    private readonly List<string> _credentials = new();

    public Wallet(GdwKey holderKey)
    {
        _key = holderKey;
        _signer = SignerFactory.Create(holderKey);
    }

    public IReadOnlyList<string> Credentials => _credentials;

    public void Store(string credential)
    {
        GdwCredential.Parse(credential); // validate before storing
        _credentials.Add(credential);
    }

    public List<string> ClaimsOf(string credential)
    {
        var parsed = GdwCredential.Parse(credential);
        var names = new List<string>();
        foreach (var kv in parsed.Token.Payload.Entries)
            if (!GdwPrimitives.IsReserved(kv.Key)) names.Add(kv.Key);
        foreach (var segment in parsed.Disclosures)
            names.Add(GdwPrimitives.ParseDisclosure(segment).Name);
        return names;
    }

    public string Present(string credential, IEnumerable<string> requestedClaims,
                          string aud, string nonce, long issuedAt)
    {
        var parsed = GdwCredential.Parse(credential);
        var byDigest = new Dictionary<string, string>();
        foreach (var segment in parsed.Disclosures)
            byDigest[GdwPrimitives.DisclosureDigest(segment)] = segment;

        var selected = new List<string>();
        GdwJson? sd = parsed.Token.Payload.Get("_sd");
        foreach (var name in requestedClaims)
        {
            if (!GdwPrimitives.IsReserved(name) && parsed.Token.Payload.Has(name)) continue; // plaintext
            bool found = false;
            if (sd is { IsArray: true })
            {
                foreach (var digestJson in sd.Items)
                {
                    if (!digestJson.IsString) continue;
                    if (!byDigest.TryGetValue(digestJson.AsString(), out var seg)) continue;
                    if (GdwPrimitives.ParseDisclosure(seg).Name == name)
                    {
                        selected.Add(seg);
                        found = true;
                        break;
                    }
                }
            }
            if (!found) throw new GdwException(GdwErrors.ClaimMissing);
        }

        string baseText = parsed.Token.SigningInput + "." + parsed.Token.Signature;
        foreach (var seg in selected) baseText += "~" + seg;

        GdwJson? cnf = parsed.Token.Payload.Get("cnf");
        if (cnf is { IsObject: true })
        {
            var cnfKey = GdwKey.FromJson(cnf);
            if (!cnfKey.SameSecret(_key)) throw new GdwException(GdwErrors.KbInvalid);
        }

        var kb = GdwJson.Object();
        kb["aud"] = GdwJson.Str(aud);
        kb["iat"] = GdwJson.Int(issuedAt);
        kb["nonce"] = GdwJson.Str(nonce);
        kb["sd_hash"] = GdwJson.Str(GdwPrimitives.SdHash(baseText));

        var header = GdwJson.Object();
        header["alg"] = GdwJson.Str(_signer.Alg);
        header["typ"] = GdwJson.Str("kb+jwt");
        string signingInput = GdwPrimitives.JsonSegment(header) + "." + GdwPrimitives.JsonSegment(kb);
        string kbJwt = signingInput + "." + _signer.Sign(signingInput);
        return baseText + "~" + kbJwt;
    }
}

// ===========================================================================
// Verifier (relying party)
// ===========================================================================

public sealed class VerifyResult
{
    public bool Ok { get; set; }
    public GdwJson Claims { get; set; } = GdwJson.Object();
    public List<string> Errors { get; set; } = new();
}

public sealed class Verifier
{
    private readonly string _aud;
    private readonly Dictionary<string, GdwKey> _trust = new();
    private readonly HashSet<string> _usedNonces = new();
    private long _clockSkew = 300;

    public Verifier(string aud) => _aud = aud;

    public long ClockSkew { get => _clockSkew; set => _clockSkew = value; }

    public void Trust(string issuer, GdwKey key) => _trust[issuer] = key;

    public void MarkNonceUsed(string iss, string nonce) => _usedNonces.Add(iss + "|" + nonce);

    public GdwJson CreateRequest(IEnumerable<string> vct, IEnumerable<string> claims, long ttlSeconds = 60)
    {
        var obj = GdwJson.Object();
        obj["aud"] = GdwJson.Str(_aud);
        obj["nonce"] = GdwJson.Str(GdwPrimitives.RandomBase64Url(16));
        obj["vct"] = GdwJson.ArrayOfStrings(vct);
        obj["claims"] = GdwJson.ArrayOfStrings(claims);
        obj["iat"] = GdwJson.Int(Now());
        obj["expires_at"] = GdwJson.Int(Now() + ttlSeconds);
        return obj;
    }

    public VerifyResult Verify(GdwJson request, string presentation, long currentTime)
    {
        var result = new VerifyResult();
        try
        {
            result.Claims = VerifyInternal(request, presentation, currentTime);
            result.Ok = true;
        }
        catch (GdwException err)
        {
            result.Errors.Add(err.Code);
        }
        catch (Exception)
        {
            result.Errors.Add(GdwErrors.Malformed);
        }
        return result;
    }

    private GdwJson VerifyInternal(GdwJson request, string presentation, long currentTime)
    {
        string[] parts = GdwPrimitives.SplitTilde(presentation);
        if (parts.Length < 2) throw new GdwException(GdwErrors.Malformed);

        string jwt = parts[0];
        bool hasKb = parts[^1].Length > 0;
        string kbJwt = hasKb ? parts[^1] : "";
        var disclosures = new List<string>();
        int end = hasKb ? parts.Length - 1 : parts.Length;
        for (int i = 1; i < end; i++)
            if (parts[i].Length > 0) disclosures.Add(parts[i]);

        var token = GdwTokenCodec.Decode(jwt);
        if (token.Header.Get("typ")?.AsString() != "gw+jwt") throw new GdwException(GdwErrors.Malformed);

        string iss = token.Payload.Get("iss")?.AsString() ?? "";
        if (iss.Length == 0) throw new GdwException(GdwErrors.Malformed);
        if (!_trust.TryGetValue(iss, out var trustedKey)) throw new GdwException(GdwErrors.IssuerUnknown);
        if (token.Header.Get("alg")?.AsString() != trustedKey.Alg) throw new GdwException(GdwErrors.Malformed);

        var issuerSigner = SignerFactory.Create(trustedKey);
        if (!issuerSigner.Verify(token.SigningInput, token.Signature))
            throw new GdwException(GdwErrors.SignatureInvalid);

        long exp = token.Payload.Get("exp")?.AsInt(-1) ?? -1;
        long iat = token.Payload.Get("iat")?.AsInt(-1) ?? -1;
        if (exp < 0 || iat < 0) throw new GdwException(GdwErrors.Malformed);
        if (currentTime > exp + _clockSkew) throw new GdwException(GdwErrors.Expired);
        if (currentTime < iat - _clockSkew) throw new GdwException(GdwErrors.NotYetValid);

        string vct = token.Payload.Get("vct")?.AsString() ?? "";
        bool vctAllowed = false;
        var allowedVct = request.Get("vct");
        if (allowedVct is { IsArray: true })
            foreach (var candidate in allowedVct.Items)
                if (candidate.IsString && candidate.AsString() == vct) vctAllowed = true;
        if (!vctAllowed) throw new GdwException(GdwErrors.VctNotAllowed);

        if (token.Payload.Get("_sd_alg")?.AsString() != "sha-256") throw new GdwException(GdwErrors.Malformed);
        GdwJson? sd = token.Payload.Get("_sd");
        if (sd is not { IsArray: true }) throw new GdwException(GdwErrors.Malformed);

        var claims = GdwJson.Object();
        foreach (var kv in token.Payload.Entries)
            if (!GdwPrimitives.IsReserved(kv.Key)) claims[kv.Key] = kv.Value;

        var covered = new List<string>();
        foreach (var digest in sd.Items)
            if (digest.IsString) covered.Add(digest.AsString());

        var seen = new List<string>();
        foreach (var segment in disclosures)
        {
            string digest = GdwPrimitives.DisclosureDigest(segment);
            if (!covered.Contains(digest)) throw new GdwException(GdwErrors.DisclosureUnknown);
            if (seen.Contains(digest)) throw new GdwException(GdwErrors.DisclosureUnknown);
            seen.Add(digest);
            var parsed = GdwPrimitives.ParseDisclosure(segment);
            if (claims.Has(parsed.Name)) throw new GdwException(GdwErrors.DuplicateClaim);
            claims[parsed.Name] = parsed.Value;
        }

        var requiredClaims = request.Get("claims");
        if (requiredClaims is { IsArray: true })
            foreach (var name in requiredClaims.Items)
                if (name.IsString && !claims.Has(name.AsString()))
                    throw new GdwException(GdwErrors.ClaimMissing);

        // key binding
        if (kbJwt.Length == 0) throw new GdwException(GdwErrors.KbMissing);
        var kbToken = GdwTokenCodec.Decode(kbJwt);
        if (kbToken.Header.Get("typ")?.AsString() != "kb+jwt") throw new GdwException(GdwErrors.KbInvalid);
        var cnf = token.Payload.Get("cnf");
        if (cnf is not { IsObject: true }) throw new GdwException(GdwErrors.KbInvalid);
        var cnfKey = GdwKey.FromJson(cnf);
        if (kbToken.Header.Get("alg")?.AsString() != cnfKey.Alg) throw new GdwException(GdwErrors.KbInvalid);
        var kbSigner = SignerFactory.Create(cnfKey);
        if (!kbSigner.Verify(kbToken.SigningInput, kbToken.Signature)) throw new GdwException(GdwErrors.KbInvalid);

        string baseText = jwt;
        foreach (var segment in disclosures) baseText += "~" + segment;
        if (kbToken.Payload.Get("sd_hash")?.AsString() != GdwPrimitives.SdHash(baseText))
            throw new GdwException(GdwErrors.SdHashMismatch);
        if (kbToken.Payload.Get("aud")?.AsString() != request.Get("aud")?.AsString())
            throw new GdwException(GdwErrors.AudMismatch);
        if (kbToken.Payload.Get("nonce")?.AsString() != request.Get("nonce")?.AsString())
            throw new GdwException(GdwErrors.NonceMismatch);

        long kbIat = kbToken.Payload.Get("iat")?.AsInt(-1) ?? -1;
        if (kbIat < 0 || currentTime > kbIat + _clockSkew || currentTime < kbIat - _clockSkew)
            throw new GdwException(GdwErrors.KbInvalid);

        if (_usedNonces.Contains(iss + "|" + (request.Get("nonce")?.AsString() ?? "")))
            throw new GdwException(GdwErrors.Replay);
        _usedNonces.Add(iss + "|" + (request.Get("nonce")?.AsString() ?? ""));

        return claims;
    }

    public static long Now() => DateTimeOffset.UtcNow.ToUnixTimeSeconds();
}
