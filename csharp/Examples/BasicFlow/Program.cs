// Minimal end-to-end flow: an age-over-18 attestation is issued, stored in a
// game wallet, selectively disclosed to a matchmaking server, then verified.
// Run:  dotnet run --project Examples/BasicFlow
//
// SPDX-License-Identifier: CC-BY-4.0

using Eudi.GameWallet;

// 1. Trust anchors. In production these come from a signed trust list
//    (see SPEC.md); here we use a shared secret for a self-contained demo.
var issuerKey = GdwKey.Hs256("issuer-shared-secret-used-only-for-this-demo");
var playerKey = GdwKey.Hs256("holder-key-derived-on-the-players-device-----");

// 2. A PID/attestation provider issues an age attestation to one account.
var ageIssuer = new Issuer("https://issuer.example/age-service", issuerKey);
var options = new IssueOptions
{
    Vct = "urn:eudi:game:attestation:age-over-18",
    Sub = "player-8241",
    HolderKey = playerKey,
    Iat = Verifier.Now(),
    Exp = Verifier.Now() + 30L * 24 * 3600,
};
options.Claims["age_over_18"] = GdwJson.Bool(true);
options.Claims["country"] = GdwJson.Str("NL");
options.Claims["nickname"] = GdwJson.Str("pixel_knight");
options.Disclosable.Add("age_over_18");
options.Disclosable.Add("country");
string credential = ageIssuer.Issue(options);

Console.WriteLine($"credential bytes: {credential.Length}");
Console.WriteLine($"stored claims:    {string.Join(" ", new Wallet(playerKey).ClaimsOf(credential))}");
Console.WriteLine();

// 3. The player's game wallet stores the credential.
var wallet = new Wallet(playerKey);
wallet.Store(credential);

// 4. A matchmaking server (relying party) asks for a single claim and, being a
//    game backend, wants proof the response is fresh (nonce) and bound to this
//    holder (key binding, cnf).
var server = new Verifier("matchmaking-eu-1");
server.Trust(ageIssuer.Id, issuerKey);
GdwJson request = server.CreateRequest(
    new[] { "urn:eudi:game:attestation:age-over-18" }, new[] { "age_over_18" });

// 5. The wallet discloses only what was asked for; nickname/country stay hidden.
string presentation = wallet.Present(
    credential, new[] { "age_over_18" },
    request.Get("aud")!.AsString(), request.Get("nonce")!.AsString(), Verifier.Now());
Console.WriteLine($"presentation bytes: {presentation.Length}\n");

// 6. The server verifies and reads the derived claims.
var result = server.Verify(request, presentation, Verifier.Now());
if (result.Ok)
{
    Console.WriteLine($"verified: age_over_18 = {result.Claims.Get("age_over_18")!.AsBool().ToString().ToLowerInvariant()}");
    return 0;
}

Console.Write("verification failed:");
foreach (var error in result.Errors) Console.Write(" " + error);
Console.WriteLine();
return 1;
