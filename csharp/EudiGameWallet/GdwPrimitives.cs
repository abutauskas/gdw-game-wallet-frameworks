// Shared primitives: base64url, SHA-256, HMAC-SHA256, canonical JSON segments,
// disclosure construction/parsing, random salting, claim-name rules.
//
// SPDX-License-Identifier: CC-BY-4.0

using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Eudi.GameWallet;

public static class GdwPrimitives
{
    private static readonly Regex ClaimName = new("^[A-Za-z0-9_-]{1,64}$", RegexOptions.Compiled);

    private static readonly HashSet<string> Reserved = new(StringComparer.Ordinal)
    {
        "_sd", "_sd_alg", "cnf", "iss", "sub", "iat", "exp", "vct",
    };

    public static bool IsValidClaimName(string name) =>
        !string.IsNullOrEmpty(name) && ClaimName.IsMatch(name) && !name.StartsWith('_');

    public static bool IsReserved(string name) => Reserved.Contains(name);

    // ---- base64url --------------------------------------------------------

    public static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] Base64UrlDecode(string text)
    {
        string s = text.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        try
        {
            return Convert.FromBase64String(s);
        }
        catch (FormatException)
        {
            throw new GdwException(GdwErrors.Malformed);
        }
    }

    public static string Base64UrlUtf8(string text) =>
        Base64UrlEncode(Encoding.UTF8.GetBytes(text));

    // ---- hashing ----------------------------------------------------------

    public static byte[] Sha256(byte[] data) => SHA256.HashData(data);

    public static string Sha256Base64Url(byte[] data) => Base64UrlEncode(Sha256(data));

    // ---- canonical segments ----------------------------------------------

    public static string JsonSegment(GdwJson value) =>
        Base64UrlEncode(Encoding.UTF8.GetBytes(value.Canonical()));

    public static GdwJson ParseSegment(string segment)
    {
        try
        {
            return GdwJson.Parse(Encoding.UTF8.GetString(Base64UrlDecode(segment)));
        }
        catch (GdwException)
        {
            throw;
        }
        catch (Exception)
        {
            throw new GdwException(GdwErrors.Malformed);
        }
    }

    // ---- splits -----------------------------------------------------------

    public static string[] SplitTilde(string text) => text.Split('~');

    public static string[] SplitDot(string text) => text.Split('.');

    // ---- disclosures ------------------------------------------------------

    public static string MakeDisclosure(string saltB64, string name, GdwJson value)
    {
        if (!IsValidClaimName(name)) throw new GdwException(GdwErrors.Malformed);
        if (Base64UrlDecode(saltB64).Length < 16) throw new GdwException(GdwErrors.Malformed);
        var arr = GdwJson.ArrayOf(GdwJson.Str(saltB64), GdwJson.Str(name), value);
        return Base64UrlEncode(Encoding.UTF8.GetBytes(arr.Canonical()));
    }

    public sealed record ParsedDisclosure(string Salt, string Name, GdwJson Value);

    public static ParsedDisclosure ParseDisclosure(string segment)
    {
        GdwJson arr = ParseSegment(segment);
        if (!arr.IsArray || arr.Items.Count != 3 ||
            !arr.Items[0].IsString || !arr.Items[1].IsString)
        {
            throw new GdwException(GdwErrors.Malformed);
        }
        string salt = arr.Items[0].AsString();
        string name = arr.Items[1].AsString();
        if (!IsValidClaimName(name)) throw new GdwException(GdwErrors.Malformed);
        if (Base64UrlDecode(salt).Length < 16) throw new GdwException(GdwErrors.Malformed);
        return new ParsedDisclosure(salt, name, arr.Items[2]);
    }

    public static string DisclosureDigest(string segment) =>
        Base64UrlEncode(Sha256(Encoding.UTF8.GetBytes(segment)));

    public static string SdHash(string baseText) =>
        Base64UrlEncode(Sha256(Encoding.UTF8.GetBytes(baseText)));

    // ---- salt -------------------------------------------------------------

    public static string RandomBase64Url(int bytes)
    {
        var buffer = new byte[bytes];
        RandomNumberGenerator.Fill(buffer);
        return Base64UrlEncode(buffer);
    }
}
