use std::{
    ffi::OsString,
    fmt::{self, Display},
    str::FromStr,
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DomainParsingError;
impl std::fmt::Display for DomainParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Failed to parse domain and name")
    }
}
impl std::error::Error for DomainParsingError {}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct DomainAndName {
    pub domain: OsString,
    pub name: OsString,
}

impl DomainAndName {
    pub fn new<D: Into<OsString>, N: Into<OsString>>(domain: D, name: N) -> Self {
        DomainAndName {
            domain: domain.into(),
            name: name.into(),
        }
    }
}

impl Display for DomainAndName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
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

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split('\\');
        let domain = parts
            .next()
            .and_then(|s| OsString::from_str(s).ok())
            .ok_or(DomainParsingError)?;
        let name = parts
            .next()
            .and_then(|s| OsString::from_str(s).ok())
            .ok_or(DomainParsingError)?;
        if parts.next().is_some() {
            return Err(DomainParsingError);
        }
        Ok(DomainAndName::new(domain, name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_domain_and_name_parsing(domain in "[^\\\\]+", name in "[^\\\\]+") {
            let input = format!("{}\\{}", domain, name);
            let parsed = DomainAndName::from_str(&input).expect("Failed to parse domain and name");
            assert_eq!(parsed.domain, OsString::from(domain));
            assert_eq!(parsed.name, OsString::from(name));
            assert_eq!(parsed.to_string(), input);
            assert_eq!(parsed, DomainAndName::new(domain, name));
        }
    }
}
