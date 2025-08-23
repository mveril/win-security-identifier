use arrayvec::ArrayString;
use core::fmt::{self, Display, Write};
use core::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

#[cfg(feature = "alloc")]
use crate::SecurityIdentifier;
use crate::{ConstSid, Sid, internal::SidLenValid};

impl Serialize for Sid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let mut output_string = ArrayString::<256>::new();
            write!(&mut output_string, "{}", &self);
            serializer.serialize_str(&output_string.as_str())
        } else {
            unsafe { serializer.serialize_bytes(self.as_binary()) }
        }
    }
}

#[cfg(feature = "alloc")]
impl Serialize for SecurityIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_ref().serialize(serializer)
    }
}

#[cfg(feature = "std")]
impl<'de> Deserialize<'de> for SecurityIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SidVisitor;

        impl<'de> de::Visitor<'de> for SidVisitor {
            type Value = SecurityIdentifier;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a Windows SID as a string (e.g., \"S-1-5-32-544\") or as raw binary")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                SecurityIdentifier::from_str(v)
                    .map_err(|_| E::invalid_value(de::Unexpected::Str(v), &self))
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                SecurityIdentifier::from_bytes(v)
                    .map(SecurityIdentifier::from)
                    .map_err(|_| E::invalid_value(de::Unexpected::Bytes(v), &self))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(SidVisitor)
        } else {
            deserializer.deserialize_bytes(SidVisitor)
        }
    }
}

impl<const N: usize> Serialize for ConstSid<N>
where
    [u32; N]: SidLenValid,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_ref().serialize(serializer)
    }
}

#[cfg(test)]
mod test {
    const SID: ConstSid<3> =
        ConstSid::new(1, crate::SidIdentifierAuthority::NT_AUTHORITY, [5, 32, 544]);
    const bytes: &'static [u8] = SID.as_sid().as_binary();
    use core::ops::Deref;

    use crate::ConstSid;
    use proptest::prelude::*;
    use serde_test::{self, Configure, Token};
    #[test]
    fn test_binary_const() {
        serde_test::assert_ser_tokens(&SID.as_sid().compact(), &[Token::Bytes(bytes)]);
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
