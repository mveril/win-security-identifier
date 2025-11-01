//! Minimal and idiomatic handling of `DOMAIN\Name` pairs with simple validation.
//!
//! - `DomainAndName` stores parts as `OsString` (Windows-friendly).
//! - `Display` prints as `DOMAIN\Name` using `to_string_lossy()`.
//! - `FromStr` parses with the default policy (exactly one `\`).
//! - Optional validation is controlled by a lightweight `ParsePolicy`.

use core::{
    fmt::{self, Display},
    str::FromStr,
};
use std::ffi::{OsStr, OsString};

use thiserror::Error;

/// Which component an error refers to.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Component {
    Domain,
    Name,
}

impl Display for Component {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain => f.write_str("domain"),
            Self::Name => f.write_str("name"),
        }
    }
}

/// Parsing/validation errors for `DOMAIN\Name`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DomainParsingError {
    /// Input did not contain a `\` separator.
    #[error("Missing '\\' separator")]
    MissingSeparator,

    /// Input contained more than one `\` separator.
    #[error("Too many '\\' separators")]
    TooManySeparators,

    /// Left part is empty while policy forbids it.
    #[error("Domain is empty")]
    EmptyDomain,

    /// Right part is empty while policy forbids it.
    #[error("Name is empty")]
    EmptyName,

    /// A component exceeded the configured maximum length.
    #[error("{which} too long: max={max}, actual={actual}")]
    ComponentTooLong {
        which: Component,
        max: usize,
        actual: usize,
    },

    /// A forbidden code unit/byte was found (e.g., `\` or NUL).
    #[error("Forbidden code unit 0x{unit:02X} in {which} at index {index}")]
    ForbiddenUnit {
        which: Component,
        unit: u32,
        index: usize,
    },
}

/// Simple, const-friendly validation policy.
/// Validation itself happens at runtime to keep things straightforward.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ParsePolicy {
    /// Allow empty domain (e.g., `\User`)?
    pub allow_empty_domain: bool,
    /// Allow empty name (e.g., `DOMAIN\`)?
    pub allow_empty_name: bool,
    /// Optional max *byte/count* for each component:
    /// - Windows: count is in UTF-16 code units
    /// - Unix: count is in raw bytes
    pub max_component_len: Option<usize>,
    /// ASCII code points disallowed in components (default: backslash and NUL).
    /// They are checked as:
    /// - Windows: UTF-16 code units equal to `u8` value (e.g. `b'\\' as u16`)
    /// - Unix: raw bytes
    pub forbidden_ascii: &'static [u8],
}

impl ParsePolicy {
    /// Sensible default for Windows-style `DOMAIN\Name`.
    pub const DEFAULT: Self = Self {
        allow_empty_domain: true,
        allow_empty_name: false,
        max_component_len: None,
        forbidden_ascii: b"\\\0",
    };

    /// Const constructor for convenience.
    #[inline]
    #[must_use]
    pub const fn new(
        allow_empty_domain: bool,
        allow_empty_name: bool,
        max_component_len: Option<usize>,
        forbidden_ascii: &'static [u8],
    ) -> Self {
        Self {
            allow_empty_domain,
            allow_empty_name,
            max_component_len,
            forbidden_ascii,
        }
    }

    /// Validate a single component against this policy (runtime, cross‑platform).
    pub(super) fn validate_component(
        &self,
        which: Component,
        s: &OsStr,
    ) -> Result<(), DomainParsingError> {
        if s.is_empty() {
            return match which {
                Component::Domain => {
                    if self.allow_empty_domain {
                        Ok(())
                    } else {
                        Err(DomainParsingError::EmptyDomain)
                    }
                }
                Component::Name => {
                    if self.allow_empty_name {
                        Ok(())
                    } else {
                        Err(DomainParsingError::EmptyName)
                    }
                }
            };
        }

        // Length limit (platform-specific notion of "length")
        if let Some(max) = self.max_component_len {
            let len = platform_len(s);
            if len > max {
                return Err(DomainParsingError::ComponentTooLong {
                    which,
                    max,
                    actual: len,
                });
            }
        }

        // Forbidden units (ASCII set, checked as code units / bytes)
        platform_forbidden_check(self, which, s)?;

        Ok(())
    }

    /// Validate both components (runtime).
    pub(super) fn validate_pair(
        &self,
        domain: &OsStr,
        name: &OsStr,
    ) -> Result<(), DomainParsingError> {
        self.validate_component(Component::Domain, domain)?;
        self.validate_component(Component::Name, name)?;
        Ok(())
    }
}

impl Default for ParsePolicy {
    #[inline]
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Platform-specific length:
/// - Windows: number of UTF-16 code units
/// - Unix: number of raw bytes
fn platform_len(s: &OsStr) -> usize {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        s.encode_wide().count()
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::ffi::OsStrExt;
        s.as_bytes().len()
    }
}

/// Platform-specific forbidden check:
/// - Windows: iterate UTF-16; match against ASCII `forbidden_ascii` (cast to u16)
/// - Unix: iterate raw bytes; match against ASCII `forbidden_ascii`
fn platform_forbidden_check(
    policy: &ParsePolicy,
    which: Component,
    s: &OsStr,
) -> Result<(), DomainParsingError> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        for (idx, unit) in s.encode_wide().enumerate() {
            // NUL always forbidden (0), plus any ASCII units in policy
            if unit == 0 || policy.forbidden_ascii.iter().any(|&b| unit == u16::from(b)) {
                return Err(DomainParsingError::ForbiddenUnit {
                    which,
                    unit: u32::from(unit),
                    index: idx,
                });
            }
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::ffi::OsStrExt;
        for (idx, &b) in s.as_bytes().iter().enumerate() {
            if policy.forbidden_ascii.contains(&b) {
                return Err(DomainParsingError::ForbiddenUnit {
                    which,
                    unit: u32::from(b),
                    index: idx,
                });
            }
        }
        Ok(())
    }
}

/// Runtime-friendly pair (`OsString`) with `Display`/`FromStr`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct DomainAndName {
    /// The domain part (before the `\`).
    pub domain: OsString,
    /// The name part (after the `\`).
    pub name: OsString,
}

impl DomainAndName {
    #[inline]
    /// Non-validating constructor (domain, then name).
    pub fn new<D: Into<OsString>, N: Into<OsString>>(domain: D, name: N) -> Self {
        Self {
            domain: domain.into(),
            name: name.into(),
        }
    }

    /// Validating constructor from owned parts.
    /// # Errors
    /// See [`DomainParsingError`].
    #[inline]
    pub fn try_new_with_policy<D: Into<OsString>, N: Into<OsString>>(
        policy: &ParsePolicy,
        domain: D,
        name: N,
    ) -> Result<Self, DomainParsingError> {
        let d_os: OsString = domain.into();
        let n_os: OsString = name.into();
        policy.validate_pair(d_os.as_os_str(), n_os.as_os_str())?;
        Ok(Self {
            domain: d_os,
            name: n_os,
        })
    }

    /// Parse `"DOMAIN\Name"` with a specific policy (runtime).
    /// # Errors
    /// See [`DomainParsingError`] and [`ParsePolicy`].
    #[inline]
    pub fn parse_with_policy(policy: &ParsePolicy, s: &str) -> Result<Self, DomainParsingError> {
        // Split into at most 3 parts to detect "too many separators"
        let mut iter = s.splitn(3, '\\');
        let domain = iter.next().ok_or(DomainParsingError::MissingSeparator)?;
        let name = iter.next().ok_or(DomainParsingError::MissingSeparator)?;
        if iter.next().is_some() {
            return Err(DomainParsingError::TooManySeparators);
        }
        policy.validate_pair(OsStr::new(domain), OsStr::new(name))?;
        Ok(Self::new(domain, name))
    }
}

impl Display for DomainAndName {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}\\{}",
            self.domain.to_string_lossy(),
            self.name.to_string_lossy()
        )
    }
}

impl FromStr for DomainAndName {
    type Err = DomainParsingError;

    /// Parses with `ParsePolicy::DEFAULT`.
    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_with_policy(&ParsePolicy::DEFAULT, s)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "Unwrap is not an issue in test")]
#[allow(clippy::expect_used, reason = "Unwrap is not an issue in test")]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn roundtrip_default_policy(domain in r"[^\x00\\]*", name in r"[^\x00\\]+") {
        let input = format!("{domain}\\{name}");
        let parsed = DomainAndName::from_str(&input).expect("parse failed");
        assert_eq!(parsed.to_string(), input);
        assert_eq!(parsed.domain, OsString::from(&domain));
        assert_eq!(parsed.name, OsString::from(&name));
    }
    }

    #[test]
    fn missing_or_extra_separators() {
        assert!(matches!(
            DomainAndName::from_str("NoSlash"),
            Err(DomainParsingError::MissingSeparator)
        ));
        assert!(matches!(
            DomainAndName::from_str("A\\B\\C"),
            Err(DomainParsingError::TooManySeparators)
        ));
    }

    #[test]
    fn empty_segments_by_policy() {
        // Custom: forbid empty domain too.
        const P: ParsePolicy = ParsePolicy::new(false, false, None, b"\\\0");
        // Default: empty domain OK, empty name not OK.
        assert!(DomainAndName::from_str("\\user").is_ok());
        assert!(matches!(
            DomainAndName::from_str("DOMAIN\\"),
            Err(DomainParsingError::EmptyName)
        ));

        assert!(matches!(
            DomainAndName::parse_with_policy(&P, "\\user"),
            Err(DomainParsingError::EmptyDomain)
        ));
    }

    #[test]
    fn max_len_and_forbidden_ascii() {
        const P: ParsePolicy = ParsePolicy::new(true, false, Some(5), b"\\\0/");
        assert!(matches!(
            DomainAndName::try_new_with_policy(&P, "LONGER", "ok"),
            Err(DomainParsingError::ComponentTooLong { .. })
        ));
        assert!(matches!(
            DomainAndName::try_new_with_policy(&P, "AC/ME", "john"),
            Err(DomainParsingError::ForbiddenUnit { .. })
        ));
    }
}
