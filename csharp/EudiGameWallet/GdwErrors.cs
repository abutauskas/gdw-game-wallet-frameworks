// Error codes shared with the specification (SPEC.md §8).
//
// SPDX-License-Identifier: CC-BY-4.0

namespace Eudi.GameWallet;

public static class GdwErrors
{
    public const string Malformed = "ERR_MALFORMED";
    public const string SignatureInvalid = "ERR_SIGNATURE_INVALID";
    public const string IssuerUnknown = "ERR_ISSUER_UNKNOWN";
    public const string VctNotAllowed = "ERR_VCT_NOT_ALLOWED";
    public const string Expired = "ERR_EXPIRED";
    public const string NotYetValid = "ERR_NOT_YET_VALID";
    public const string DisclosureUnknown = "ERR_DISCLOSURE_UNKNOWN";
    public const string ClaimMissing = "ERR_CLAIM_MISSING";
    public const string DuplicateClaim = "ERR_DUPLICATE_CLAIM";
    public const string KbMissing = "ERR_KB_MISSING";
    public const string KbInvalid = "ERR_KB_INVALID";
    public const string AudMismatch = "ERR_AUD_MISMATCH";
    public const string NonceMismatch = "ERR_NONCE_MISMATCH";
    public const string SdHashMismatch = "ERR_SD_HASH_MISMATCH";
    public const string Replay = "ERR_REPLAY";
}

/// <summary>Thrown with a stable GDW error code.</summary>
public sealed class GdwException : Exception
{
    public string Code { get; }

    public GdwException(string code) : base(code) => Code = code;
}
