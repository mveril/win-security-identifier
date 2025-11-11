#[cfg(all(windows, feature = "std"))]
use crate::sid_lookup::DomainAndName;
#[cfg(not(feature = "alloc"))]
use arrayvec::ArrayString;
use cfg_if::cfg_if;
use core::fmt;
#[cfg(not(feature = "alloc"))]
use core::fmt::Write;
use core::marker::PhantomData;
use core::str::FromStr;
use serde::{Deserialize, Deserializer, de};
use serde::{Serialize, Serializer, ser};

#[cfg(feature = "alloc")]
use crate::SecurityIdentifier;
use crate::StackSid;
use crate::{ConstSid, Sid, internal::SidLenValid};

impl Serialize for Sid {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        S::Error: ser::Error, // ensure S::Error implements serde::ser::Error
    {
        if serializer.is_human_readable() {
            cfg_if! {
                if #[cfg(feature = "alloc")] {
                    serializer.collect_str(self)
                } else {
                    let mut output_string = ArrayString::<256>::new();
                    write!(&mut output_string, "{}", &self).map_err(|_| ser::Error::custom("failed to format Sid for human-readable serialization"))?;
                    serializer.serialize_str(output_string.as_str())
                }
            }
        } else {
            serializer.serialize_bytes(self.as_binary())
        }
    }
}

impl<'de> Deserialize<'de> for &'de Sid {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SidVisitor;

        impl<'de> de::Visitor<'de> for SidVisitor {
            type Value = &'de Sid;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("A Windows SID as raw binary")
            }

            fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Sid::from_bytes(v).map_err(|_| E::invalid_value(de::Unexpected::Bytes(v), &self))
            }
        }
        deserializer.deserialize_bytes(SidVisitor)
    }
}

#[cfg(feature = "alloc")]
impl Serialize for SecurityIdentifier {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_sid().serialize(serializer)
    }
}

// Generic helper to deserialize types that support FromStr and TryFrom<&[u8]>
fn deserialize_sid_like<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    for<'a> T: FromStr + TryFrom<&'a [u8]>,
    <T as FromStr>::Err: core::fmt::Display,
    for<'a> <T as TryFrom<&'a [u8]>>::Error: core::fmt::Display,
{
    #[derive(Clone, Copy)]
    struct Visitor<T> {
        _marker: PhantomData<T>,
    }

    impl<T> Default for Visitor<T> {
        fn default() -> Self {
            Self {
                _marker: PhantomData,
            }
        }
    }

    impl<T> de::Visitor<'_> for Visitor<T>
    where
        for<'a> T: FromStr + TryFrom<&'a [u8]>,
        for<'a> T:,
        <T as FromStr>::Err: core::fmt::Display,
        for<'a> <T as TryFrom<&'a [u8]>>::Error: core::fmt::Display,
    {
        type Value = T;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a Windows SID as a string (e.g., \"S-1-...\") or as raw binary")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            T::from_str(v).map_err(|_| E::invalid_value(de::Unexpected::Str(v), &self))
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            T::try_from(v).map_err(|_| E::invalid_value(de::Unexpected::Bytes(v), &self))
        }
    }

    if deserializer.is_human_readable() {
        deserializer.deserialize_str(Visitor::<T>::default())
    } else {
        deserializer.deserialize_bytes(Visitor::<T>::default())
    }
}

#[cfg(feature = "alloc")]
impl<'de> Deserialize<'de> for SecurityIdentifier {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_sid_like(deserializer)
    }
}

impl<'de> Deserialize<'de> for StackSid {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_sid_like(deserializer)
    }
}

impl Serialize for StackSid {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_sid().serialize(serializer)
    }
}

impl<const N: usize> Serialize for ConstSid<N>
where
    [u32; N]: SidLenValid,
{
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_sid().serialize(serializer)
    }
}

#[cfg(all(windows, feature = "std"))]
impl<'de> Deserialize<'de> for DomainAndName {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DomainAndNameVisitor;

        impl de::Visitor<'_> for DomainAndNameVisitor {
            type Value = DomainAndName;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a domain and name in the format 'DOMAIN\\NAME'")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                DomainAndName::from_str(v)
                    .map_err(|_| E::invalid_value(de::Unexpected::Str(v), &self))
            }
        }

        deserializer.deserialize_str(DomainAndNameVisitor)
    }
}

#[cfg(all(windows, feature = "std"))]
impl Serialize for DomainAndName {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

#[cfg(test)]
mod test {
    const SID: ConstSid<3> =
        ConstSid::new(1, crate::SidIdentifierAuthority::NT_AUTHORITY, [5, 32, 544]);
    const BYTES: &[u8] = SID.as_sid().as_binary();

    use crate::ConstSid;
    use serde_test::{self, Configure, Token};
    #[test]
    fn test_binary_const() {
        serde_test::assert_ser_tokens(&SID.as_sid().compact(), &[Token::Bytes(BYTES)]);
    }

    #[test]
    fn test_human_const() {
        serde_test::assert_ser_tokens(&SID.as_sid().readable(), &[Token::String("S-1-5-5-32-544")]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_binary_owned() {
        serde_test::assert_ser_tokens(
            &SID.as_sid().to_owned().readable(),
            &[Token::String("S-1-5-5-32-544")],
        );
        serde_test::assert_tokens(
            &SID.as_sid().to_owned().readable(),
            &[Token::String("S-1-5-5-32-544")],
        );
    }
}
