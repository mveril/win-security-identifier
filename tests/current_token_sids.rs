#![cfg(all(windows, not(miri)))]
#![cfg(feature = "std")]
#![allow(clippy::expect_used, reason = "Expect is not an issue in tests")]

use core::fmt::Debug;
use core::marker::PhantomData;
use rstest::rstest;
use win_security_identifier::prelude::*;
use windows_sys::Win32::{Foundation::GetLastError, Security::IsValidSid};

#[rstest]
#[case::security_identifier(PhantomData::<SecurityIdentifier>)]
#[case::stack_sid(PhantomData::<StackSid>)]
fn current_token_sids<T>(#[case] type_marker: PhantomData<T>)
where
    T: CloneSidFromRaw + GetCurrentSid + AsRef<Sid> + Debug,
{
    let _ = type_marker;

    let primary_group =
        T::get_current_primary_group_sid().expect("Failed to get primary group SID");
    assert_valid_sid(primary_group.as_ref(), "primary group SID");

    let groups = T::get_current_user_group_sids().expect("Failed to get current group SIDs");
    assert!(
        !groups.is_empty(),
        "current token should expose at least one group SID"
    );
    for group in &groups {
        assert_valid_sid(group.as_ref(), "group SID");
    }

    let logon_sid = T::get_current_logon_sid().expect("Failed to get current logon SID");
    if let Some(logon_sid) = logon_sid.as_ref() {
        assert_valid_sid(logon_sid.as_ref(), "logon SID");
    }

    let current_user = T::get_current_user_sid().expect("Failed to get current user SID");
    assert!(
        T::is_current_user_member_of(current_user.as_ref())
            .expect("Failed to check current user membership"),
        "current user SID should be reported as current user membership"
    );
}

fn assert_valid_sid(sid: &Sid, label: &str) {
    assert_eq!(sid.revision, Sid::REVISION, "{label} revision is invalid");
    assert!(
        !sid.sub_authorities().is_empty(),
        "{label} should contain at least one sub-authority"
    );

    // SAFETY: `sid.as_raw()` returns a pointer to a live SID value and IsValidSid
    // only reads that SID.
    let result = unsafe { (IsValidSid(sid.as_raw()) == 0).then_some(GetLastError()) };
    assert_eq!(
        result, None,
        "{label} is not a valid Windows SID: {result:?}"
    );
}
