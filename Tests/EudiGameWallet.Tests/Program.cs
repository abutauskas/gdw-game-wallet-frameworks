// Conformance tests for the EudiGameWallet C# framework.
//
// Replays frameworks/test-vectors/vectors.json byte-for-byte. Run:
//
//   dotnet run --project Tests/EudiGameWallet.Tests -- ../test-vectors/vectors.json
//
// SPDX-License-Identifier: CC-BY-4.0

using System.Security.Cryptography;
using Eudi.GameWallet;

int checks = 0;
int failures = 0;

void Check(bool condition, string label)
{
    checks++;
    if (!condition)
    {
        failures++;
        Console.WriteLine($"  FAIL: {label}");
    }
}

void CheckEqual(string actual, string expected, string label)
{
    checks++;
    if (actual != expected)
    {
        failures++;
        Console.WriteLine($"  FAIL: {label}");
        Console.WriteLine($"    expected: {expected}");
        Console.WriteLine($"    actual:   {actual}");
    }
}

string path = args.Length > 0 ? args[0] : "test-vectors/vectors.json";
GdwJson vectors = GdwJson.Parse(File.ReadAllText(path));

// ---- canonical JSON -------------------------------------------------------
Console.WriteLine("canonical JSON");
foreach (var c in vectors.Get("canonical_json")!.Items)
{
    string name = c.Get("name")!.AsString();
    string expected = c.Get("canonical")!.AsString();
    string actual = c.Get("input")!.Canonical();
    CheckEqual(actual, expected, name);
    CheckEqual(GdwJson.Parse(expected).Canonical(), expected, name + " (round trip)");
}

// ---- disclosures ----------------------------------------------------------
Console.WriteLine("disclosures");
foreach (var c in vectors.Get("disclosures")!.Items)
{
    string name = c.Get("name")!.AsString();
    string segment = GdwPrimitives.MakeDisclosure(
        c.Get("salt_b64")!.AsString(), c.Get("claim_name")!.AsString(), c.Get("claim_value")!);
    CheckEqual(segment, c.Get("segment")!.AsString(), name + " segment");
    CheckEqual(GdwPrimitives.DisclosureDigest(segment), c.Get("digest")!.AsString(), name + " digest");
    var parsed = GdwPrimitives.ParseDisclosure(segment);
    CheckEqual(parsed.Name, c.Get("claim_name")!.AsString(), name + " parsed name");
    CheckEqual(parsed.Value.Canonical(), c.Get("claim_value")!.Canonical(), name + " parsed value");
}

// ---- HS256 ----------------------------------------------------------------
Console.WriteLine("HS256");
{
    var hs = vectors.Get("hs256")!;
    var signer = new Hs256Signer(GdwKey.FromJson(hs.Get("key")!));
    string input = hs.Get("signing_input")!.AsString();
    CheckEqual(signer.Sign(input), hs.Get("signature")!.AsString(), "signature");
    Check(signer.Verify(input, hs.Get("signature")!.AsString()), "verify");
    Check(!signer.Verify(input, hs.Get("signature")!.AsString() + "x"), "verify rejects tamper");
}

// ---- issue flow -----------------------------------------------------------
Console.WriteLine("issue flow");
{
    var flow = vectors.Get("issue_flow")!;
    var issuer = new Issuer(flow.Get("iss")!.AsString(), GdwKey.FromJson(flow.Get("issuer_key")!));
    var options = new IssueOptions
    {
        Vct = flow.Get("vct")!.AsString(),
        Claims = flow.Get("claims")!,
        Iat = flow.Get("iat")!.AsInt(),
        Exp = flow.Get("exp")!.AsInt(),
        Sub = flow.Get("sub")?.AsString() ?? "",
        HolderKey = GdwKey.FromJson(flow.Get("holder_key")!),
    };
    foreach (var name in flow.Get("disclosable")!.Items) options.Disclosable.Add(name.AsString());
    foreach (var salt in flow.Get("salts")!.Items) options.Salts.Add(salt.AsString());

    string credential = issuer.Issue(options);
    CheckEqual(credential, flow.Get("credential")!.AsString(), "credential string");

    var parsed = GdwCredential.Parse(credential);
    CheckEqual(parsed.Token.Payload.Canonical(), flow.Get("expected_payload")!.Canonical(), "payload");
    var expectedDisclosures = flow.Get("expected_disclosures")!.Items;
    Check(parsed.Disclosures.Count == expectedDisclosures.Count, "disclosure count");
    for (int i = 0; i < parsed.Disclosures.Count && i < expectedDisclosures.Count; i++)
    {
        var expected = expectedDisclosures[i];
        CheckEqual(parsed.Disclosures[i], expected.Get("segment")!.AsString(), "disclosure segment " + i);
        CheckEqual(GdwPrimitives.DisclosureDigest(parsed.Disclosures[i]), expected.Get("digest")!.AsString(), "disclosure digest " + i);
    }
}

// ---- verify flow ----------------------------------------------------------
Console.WriteLine("verify flow");
{
    var flow = vectors.Get("verify_flow")!;
    var verifier = new Verifier(flow.Get("request")!.Get("aud")!.AsString());
    foreach (var kv in flow.Get("trust")!.Entries) verifier.Trust(kv.Key, GdwKey.FromJson(kv.Value));

    var result = verifier.Verify(flow.Get("request")!, flow.Get("presentation")!.AsString(), flow.Get("now")!.AsInt());
    Check(result.Ok, "verification succeeds");
    if (!result.Ok) foreach (var e in result.Errors) Console.WriteLine("    error: " + e);
    CheckEqual(result.Claims.Canonical(), flow.Get("expected")!.Get("claims")!.Canonical(), "derived claims");
}

// ---- negative cases -------------------------------------------------------
Console.WriteLine("negative cases");
foreach (var c in vectors.Get("negative_cases")!.Items)
{
    string name = c.Get("name")!.AsString();
    var request = c.Get("request")!;
    var verifier = new Verifier(request.Get("aud")!.AsString());
    foreach (var kv in c.Get("trust")!.Entries) verifier.Trust(kv.Key, GdwKey.FromJson(kv.Value));
    foreach (var seed in c.Get("used_nonces")!.Items)
    {
        string pair = seed.AsString();
        int bar = pair.IndexOf('|');
        verifier.MarkNonceUsed(pair[..bar], pair[(bar + 1)..]);
    }

    var result = verifier.Verify(request, c.Get("presentation")!.AsString(), c.Get("now")!.AsInt());
    var expected = c.Get("expected_errors")!.Items;
    Check(result.Ok == (expected.Count == 0), name + " ok flag");
    if (!result.Ok && expected.Count > 0)
        CheckEqual(result.Errors.Count > 0 ? result.Errors[0] : "", expected[0].AsString(), name + " error code");
}

// ---- ES256 end-to-end (real asymmetric crypto) ----------------------------
Console.WriteLine("ES256 round trip");
{
    var issuerKey = GenerateEs256Key(out var holderKey);

    var issuer = new Issuer("https://issuer.example/es256", issuerKey);
    var options = new IssueOptions
    {
        Vct = "urn:eudi:game:attestation:guild-member",
        Iat = Verifier.Now(),
        Exp = Verifier.Now() + 3600,
        HolderKey = holderKey,
    };
    options.Claims["guild"] = GdwJson.Str("Night Owls");
    options.Claims["rank"] = GdwJson.Int(3);
    options.Disclosable.Add("rank");
    string credential = issuer.Issue(options);

    var wallet = new Wallet(holderKey);
    wallet.Store(credential);

    var verifier = new Verifier("game-server-eu-1");
    verifier.Trust("https://issuer.example/es256", issuerKey);
    var request = verifier.CreateRequest(
        new[] { "urn:eudi:game:attestation:guild-member" }, new[] { "guild", "rank" });
    string presentation = wallet.Present(
        credential, new[] { "guild", "rank" },
        request.Get("aud")!.AsString(), request.Get("nonce")!.AsString(), Verifier.Now());

    var result = verifier.Verify(request, presentation, Verifier.Now());
    Check(result.Ok, "ES256 verification succeeds");
    if (result.Ok)
    {
        CheckEqual(result.Claims.Get("guild")!.AsString(), "Night Owls", "guild claim");
        Check(result.Claims.Get("rank")!.AsInt() == 3, "rank claim");
    }
    else
    {
        foreach (var e in result.Errors) Console.WriteLine("    error: " + e);
    }
}

// ---- ES256 verify-only (public) key ---------------------------------------
Console.WriteLine("ES256 verify-only key");
{
    var issuerKey = GenerateEs256Key(out var holderKey);
    var issuer = new Issuer("https://issuer.example/es256-pub", issuerKey);
    var options = new IssueOptions
    {
        Vct = "urn:eudi:game:attestation:guild-member",
        Iat = Verifier.Now(),
        Exp = Verifier.Now() + 3600,
        HolderKey = holderKey,
    };
    options.Claims["guild"] = GdwJson.Str("Night Owls");
    string credential = issuer.Issue(options);

    // A verifier must be able to trust the issuer's *public* key (no D).
    var publicKey = new GdwKey
    {
        Alg = "ES256",
        Crv = "P-256",
        X = issuerKey.X,
        Y = issuerKey.Y,
    };
    // Creating a signer over a public-only key must not throw.
    ISigner publicSigner = SignerFactory.Create(publicKey);
    Check(!publicSigner.Verify("x", "AAAA"), "public-only signer verifies without throwing");

    var wallet = new Wallet(holderKey);
    wallet.Store(credential);
    var verifier = new Verifier("game-server-eu-1");
    verifier.Trust("https://issuer.example/es256-pub", publicKey);
    var request = verifier.CreateRequest(
        new[] { "urn:eudi:game:attestation:guild-member" }, new[] { "guild" });
    string presentation = wallet.Present(
        credential, new[] { "guild" },
        request.Get("aud")!.AsString(), request.Get("nonce")!.AsString(), Verifier.Now());
    var result = verifier.Verify(request, presentation, Verifier.Now());
    Check(result.Ok, "verification with a public-only issuer key succeeds");
}

// ---- Strict JSON parsing ---------------------------------------------------
Console.WriteLine("strict JSON parsing");
{
    Check(Throws(() => GdwJson.Parse("-0")), "rejects -0");
    Check(Throws(() => GdwJson.Parse("00")), "rejects leading zeros");
    Check(Throws(() => GdwJson.Parse("9007199254740992")), "rejects 2^53");
    Check(Throws(() => GdwJson.Parse("-9007199254740992")), "rejects -2^53");
    Check(Throws(() => GdwJson.Parse("1 2")), "rejects trailing content");
    Check(Throws(() => GdwJson.Parse("{} {}")), "rejects trailing object");
    CheckEqual(GdwJson.Parse("9007199254740991").Canonical(), "9007199254740991", "accepts 2^53-1");
}

Console.WriteLine();
Console.WriteLine($"{checks - failures}/{checks} checks passed");
return failures == 0 ? 0 : 1;

static bool Throws(Action action)
{
    try { action(); return false; }
    catch (GdwException) { return true; }
    catch (System.Text.Json.JsonException) { return true; }
}

// Generate a fresh P-256 key pair as GDW keys.
static GdwKey GenerateEs256Key(out GdwKey holder)
{
    holder = MakeKey();
    return MakeKey();

    static GdwKey MakeKey()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var p = ec.ExportParameters(true);
        return new GdwKey
        {
            Alg = "ES256",
            Crv = "P-256",
            D = GdwPrimitives.Base64UrlEncode(p.D!),
            X = GdwPrimitives.Base64UrlEncode(p.Q.X!),
            Y = GdwPrimitives.Base64UrlEncode(p.Q.Y!),
        };
    }
}
