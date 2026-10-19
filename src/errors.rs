//! Error codes shared with the specification (SPEC.md §8).
//!
//! SPDX-License-Identifier: CC-BY-4.0

/// Stable GDW error codes. Every failure path in the framework maps to one of
/// these; they are part of the wire contract and must match the specification
/// and the other language frameworks byte-for-byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GdwError {
    Malformed,
    SignatureInvalid,
    IssuerUnknown,
    VctNotAllowed,
    Expired,
    NotYetValid,
    DisclosureUnknown,
    ClaimMissing,
    DuplicateClaim,
    KbMissing,
    KbInvalid,
    AudMismatch,
    NonceMismatch,
    SdHashMismatch,
    Replay,
}

impl GdwError {
    pub fn code(self) -> &'static str {
        match self {
            GdwError::Malformed => "ERR_MALFORMED",
            GdwError::SignatureInvalid => "ERR_SIGNATURE_INVALID",
            GdwError::IssuerUnknown => "ERR_ISSUER_UNKNOWN",
            GdwError::VctNotAllowed => "ERR_VCT_NOT_ALLOWED",
            GdwError::Expired => "ERR_EXPIRED",
            GdwError::NotYetValid => "ERR_NOT_YET_VALID",
            GdwError::DisclosureUnknown => "ERR_DISCLOSURE_UNKNOWN",
            GdwError::ClaimMissing => "ERR_CLAIM_MISSING",
            GdwError::DuplicateClaim => "ERR_DUPLICATE_CLAIM",
            GdwError::KbMissing => "ERR_KB_MISSING",
            GdwError::KbInvalid => "ERR_KB_INVALID",
            GdwError::AudMismatch => "ERR_AUD_MISMATCH",
            GdwError::NonceMismatch => "ERR_NONCE_MISMATCH",
            GdwError::SdHashMismatch => "ERR_SD_HASH_MISMATCH",
            GdwError::Replay => "ERR_REPLAY",
        }
    }
}

impl std::fmt::Display for GdwError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for GdwError {}

/// Convenience alias: framework functions return `Result<T, GdwError>`.
pub type GdwResult<T> = Result<T, GdwError>;
