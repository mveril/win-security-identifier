// Windows-only integration test that fetches SID + DOMAIN\Name with canonical casing
#![cfg(windows)]
#![cfg(feature = "std")]
#![cfg(feature = "serde")]
#![allow(clippy::expect_used, reason = "Expect is not an issue in tests")]
#![allow(clippy::std_instead_of_core)]

use core::marker::PhantomData;
use core::ptr;
use proptest::prelude::*;
use rstest::rstest;
use serde::Deserialize;
use std::{
    fmt::Debug,
    process::{Command, Stdio},
};
use win_security_identifier::{
    CloneSidFromRaw, GetCurrentSid, LookupAccountName, SecurityIdentifier, Sid,
    SidIdentifierAuthority, StackSid,
    sid_lookup::{AccountLookup, DomainAndName, SidLookup, SidType},
};

type CheckedSidType = Result<SidType, ()>;
type OptionalLookup<T> = Option<Result<T, ()>>;
type AccountAndType = (DomainAndName, CheckedSidType);
type AccountNameLookup = (bool, DomainAndName, CheckedSidType);

#[derive(Debug, Deserialize)]
struct PsUser {
    sid: StackSid,
    account: DomainAndName,
}

fn run_powershell(args: &[&str]) -> std::io::Result<std::process::Output> {
    Command::new("pwsh")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .or_else(|_| {
            Command::new("powershell")
                .args(args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
        })
}

proptest! {
    #[test]
    fn clone_sid_from_raw_clones_sid(sid in arb_stack_sid()) {
        clone_sid_from_raw_clones_sid_as::<SecurityIdentifier>(&sid);
        clone_sid_from_raw_clones_sid_as::<StackSid>(&sid);
        clone_sid_from_raw_clones_sid_as::<Box<Sid>>(&sid);
    }

    #[test]
    fn psid_to_sid_ref_to_stack_sid_clones_sid(sid in arb_stack_sid()) {
        let source = sid.as_sid();
        let raw = source.as_raw();

        // SAFETY: `raw` points to `source`, which remains alive for this test.
        let sid_ref = unsafe { Sid::from_raw(raw) };
        let current = StackSid::from(sid_ref);

        prop_assert_eq!(
            current.as_sid(),
            source,
            "PSID -> &Sid -> StackSid must preserve the source SID"
        );
        prop_assert!(
            !ptr::addr_eq(current.as_sid(), source),
            "PSID -> &Sid -> StackSid must clone rather than borrow"
        );
    }
}

fn clone_sid_from_raw_clones_sid_as<T>(source: &StackSid)
where
    T: CloneSidFromRaw + AsRef<Sid>,
{
    let source = source.as_sid();

    // SAFETY: `source.as_raw()` points to `source`, which remains alive for the
    // duration of this call.
    let current = unsafe { T::clone_sid_from_raw(source.as_raw()) };

    assert_eq!(
        current.as_ref(),
        source,
        "cloned SID must preserve the source value"
    );
    assert!(
        !ptr::addr_eq(current.as_ref(), source),
        "cloned SID must not borrow the source buffer"
    );
}

fn arb_stack_sid() -> impl Strategy<Value = StackSid> {
    (
        any::<[u8; 6]>(),
        proptest::collection::vec(any::<u32>(), 1..=15),
    )
        .prop_map(|(identifier_authority, sub_authorities)| {
            StackSid::try_new(
                SidIdentifierAuthority::new(identifier_authority),
                &sub_authorities,
            )
            .expect("generated SID parts must be valid")
        })
}
#[rstest]
#[case::security_identifier(PhantomData::<SecurityIdentifier>)]
#[case::stack_sid(PhantomData::<StackSid>)]
fn current_user_sid_and_account<T>(#[case] type_marker: PhantomData<T>)
where
    T: CloneSidFromRaw + LookupAccountName + AsRef<Sid> + PartialEq<StackSid> + Debug,
{
    let _ = type_marker;
    let user = current_user_from_powershell();
    let sid = T::get_current_user_sid().expect("Failed to get current user SID");

    assert_eq!(
        sid.as_ref(),
        user.sid.as_sid(),
        "SID does not match expected value"
    );

    let sid_lookup = sid_lookup_account(sid.as_ref());

    assert_eq!(
        sid_lookup,
        Some(Ok((user.account.clone(), Ok(SidType::User)))),
        "Domain and name do not match expected value"
    );

    let local_sid_type = local_sid_type(sid.as_ref());

    assert_eq!(
        local_sid_type,
        Some(Ok(SidType::User)),
        "Local SID type does not match expected value"
    );

    let account_lookup = account_lookup_matches_current_sid::<T>(&user.account, sid.as_ref());

    assert_eq!(
        account_lookup,
        Some(Ok((true, user.account, Ok(SidType::User)))),
        "Account name lookup should roundtrip to the current user SID"
    );
}

fn current_user_from_powershell() -> PsUser {
    const PS_SCRIPT: &str = include_str!("assets/get_sid_account.ps1");

    let args = &[
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        PS_SCRIPT,
    ];

    let out = run_powershell(args).expect("Failed to launch PowerShell");
    assert!(
        out.status.success(),
        "PowerShell failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    serde_json::from_slice(out.stdout.as_slice()).expect("Invalid JSON from PowerShell")
}

fn assert_valid_sid(sid: &Sid, label: &str) {
    assert_eq!(sid.revision, Sid::REVISION, "{label} revision is invalid");
    assert!(
        !sid.sub_authorities().is_empty(),
        "{label} should contain at least one sub-authority"
    );
}

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

fn sid_lookup_account(sid: &Sid) -> OptionalLookup<AccountAndType> {
    sid.lookup_local_sid()
        .map(|lookup| lookup.map(sid_lookup_parts).map_err(drop_error))
}

fn sid_lookup_parts(lookup: SidLookup) -> AccountAndType {
    let sid_type = checked_sid_type(lookup.sid_type());

    (lookup.domain_name, sid_type)
}

fn local_sid_type(sid: &Sid) -> Option<CheckedSidType> {
    sid.local_sid_type().map(checked_sid_type)
}

fn account_lookup_matches_current_sid<T>(
    account: &DomainAndName,
    sid: &Sid,
) -> OptionalLookup<AccountNameLookup>
where
    T: CloneSidFromRaw + LookupAccountName + AsRef<Sid>,
{
    T::lookup_local_account_name(account.to_string()).map(|lookup| {
        lookup
            .map(|lookup| account_lookup_parts(lookup, sid))
            .map_err(drop_error)
    })
}

fn account_lookup_parts<T>(lookup: AccountLookup<T>, sid: &Sid) -> AccountNameLookup
where
    T: CloneSidFromRaw + AsRef<Sid>,
{
    let sid_matches = lookup.sid.as_ref() == sid;
    let sid_type = checked_sid_type(lookup.sid_type());

    (sid_matches, lookup.domain_name, sid_type)
}

fn checked_sid_type<E>(sid_type: Result<SidType, E>) -> CheckedSidType {
    sid_type.map_err(drop_error)
}

fn drop_error<E>(_: E) {}
