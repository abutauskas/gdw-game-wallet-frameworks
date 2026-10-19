// Keys and signers (HS256 prototype + ES256 production path).
//
// SPDX-License-Identifier: CC-BY-4.0

using System.Security.Cryptography;

namespace Eudi.GameWallet;

/// <summary>A GDW key. HS256 uses <see cref="K"/>; ES256 uses <see cref="D"/>/<see cref="X"/>/<see cref="Y"/>.</summary>
public sealed class GdwKey
{
    public string Alg { get; set; } = "HS256";
    public string? K { get; set; }          // HS256 secret (base64url)
    public string? Crv { get; set; }        // ES256 curve, "P-256"
    public string? X { get; set; }          // ES256 public x (base64url)
    public string? Y { get; set; }          // ES256 public y (base64url)
    public string? D { get; set; }          // ES256 private scalar (base64url)

    public static GdwKey Hs256(string rawSecret) =>
        new() { Alg = "HS256", K = GdwPrimitives.Base64UrlUtf8(rawSecret) };

    public static GdwKey Hs256FromBytes(byte[] raw) =>
        new() { Alg = "HS256", K = GdwPrimitives.Base64UrlEncode(raw) };

    public GdwJson ToJson()
    {
        var obj = GdwJson.Object();
        obj["alg"] = GdwJson.Str(Alg);
        if (Alg == "HS256")
        {
            obj["k"] = GdwJson.Str(K ?? "");
        }
        else
        {
            obj["crv"] = GdwJson.Str(Crv ?? "P-256");
            obj["x"] = GdwJson.Str(X ?? "");
            obj["y"] = GdwJson.Str(Y ?? "");
            // PROTOTYPE ONLY: mirrors the C++ framework, which embeds the
            // private scalar in cnf so the toy holder-binding check is
            // self-contained. NEVER do this in production — a real cnf must
            // carry only the public key and the holder must hold the private
            // half. See SPEC.md §2.4.
            if (!string.IsNullOrEmpty(D)) obj["d"] = GdwJson.Str(D);
        }
        return obj;
    }

    public static GdwKey FromJson(GdwJson j) => new()
    {
        Alg = j.Get("alg")?.AsString("HS256") ?? "HS256",
        K = j.Get("k")?.AsString(),
        Crv = j.Get("crv")?.AsString(),
        X = j.Get("x")?.AsString(),
        Y = j.Get("y")?.AsString(),
        D = j.Get("d")?.AsString(),
    };

    public bool SameSecret(GdwKey other) =>
        Alg == "HS256" ? K == other.K : (D != null && D == other.D);
}

public interface ISigner
{
    string Alg { get; }
    string Sign(string signingInput);
    bool Verify(string signingInput, string signature);
}

public sealed class Hs256Signer : ISigner
{
    private readonly byte[] _secret;

    public Hs256Signer(GdwKey key)
    {
        if (key.Alg != "HS256") throw new GdwException(GdwErrors.Malformed);
        _secret = GdwPrimitives.Base64UrlDecode(key.K ?? "");
    }

    public string Alg => "HS256";

    public string Sign(string signingInput)
    {
        using var hmac = new HMACSHA256(_secret);
        return GdwPrimitives.Base64UrlEncode(hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(signingInput)));
    }

    public bool Verify(string signingInput, string signature)
    {
        byte[] expected = GdwPrimitives.Base64UrlDecode(Sign(signingInput));
        byte[] actual;
        try
        {
            actual = GdwPrimitives.Base64UrlDecode(signature);
        }
        catch (GdwException)
        {
            return false;
        }
        return CryptographicOperations.FixedTimeEquals(expected, actual);
    }
}

public sealed class EcdsaP256Signer : ISigner
{
    private readonly ECDsa _ec;

    public EcdsaP256Signer(GdwKey key)
    {
        if (key.Alg != "ES256") throw new GdwException(GdwErrors.Malformed);
        if (string.IsNullOrEmpty(key.D) || string.IsNullOrEmpty(key.X) || string.IsNullOrEmpty(key.Y))
            throw new GdwException(GdwErrors.Malformed);

        var p = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = GdwPrimitives.Base64UrlDecode(key.D),
            Q = new ECPoint
            {
                X = GdwPrimitives.Base64UrlDecode(key.X),
                Y = GdwPrimitives.Base64UrlDecode(key.Y),
            },
        };
        _ec = ECDsa.Create(p);
    }

    public string Alg => "ES256";

    public string Sign(string signingInput)
    {
        // ES256 signatures are raw r||s (64 bytes), not ASN.1/DER.
        byte[] raw = _ec.SignData(
            System.Text.Encoding.UTF8.GetBytes(signingInput),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return GdwPrimitives.Base64UrlEncode(raw);
    }

    public bool Verify(string signingInput, string signature)
    {
        try
        {
            byte[] raw = GdwPrimitives.Base64UrlDecode(signature);
            if (raw.Length != 64) return false;
            return _ec.VerifyData(
                System.Text.Encoding.UTF8.GetBytes(signingInput),
                raw,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (GdwException)
        {
            return false;
        }
    }
}

public static class SignerFactory
{
    public static ISigner Create(GdwKey key) => key.Alg switch
    {
        "HS256" => new Hs256Signer(key),
        "ES256" => new EcdsaP256Signer(key),
        _ => throw new GdwException(GdwErrors.Malformed),
    };
}
