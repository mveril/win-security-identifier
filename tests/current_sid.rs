// Windows-only integration test that fetches SID + DOMAIN\Name with canonical casing
#![cfg(windows)]
#![allow(clippy::expect_used, reason = "Expect is not an issue in tests")]
#![allow(clippy::std_instead_of_core)]

use core::marker::PhantomData;
use rstest::rstest;
use serde::Deserialize;
use std::{
    fmt::Debug,
    process::{Command, Stdio},
};
use win_security_identifier::{
    prelude::*,
    sid_lookup::{AccountLookup, DomainAndName, SidLookup, SidType},
};

type OptionalLookup<T> = Option<Option<T>>;
type AccountAndType = (DomainAndName, Option<SidType>);
type AccountNameLookup = (bool, DomainAndName, Option<SidType>);

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
        Some(Some((user.account.clone(), Some(SidType::User)))),
        "Domain and name do not match expected value"
    );

    let local_sid_type = local_sid_type(sid.as_ref());

    assert_eq!(
        local_sid_type,
        Some(SidType::User),
        "Local SID type does not match expected value"
    );

    let account_lookup = account_lookup_matches_current_sid::<T>(&user.account, sid.as_ref());

    assert_eq!(
        account_lookup,
        Some(Some((true, user.account, Some(SidType::User)))),
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

fn sid_lookup_account(sid: &Sid) -> OptionalLookup<AccountAndType> {
    sid.lookup_local_sid()
        .map(|lookup| lookup.map(sid_lookup_parts).ok())
}

fn sid_lookup_parts(lookup: SidLookup) -> AccountAndType {
    let sid_type = lookup.sid_type().ok();

    (lookup.domain_name, sid_type)
}

fn local_sid_type(sid: &Sid) -> Option<SidType> {
    sid.local_sid_type().and_then(Result::ok)
}

fn account_lookup_matches_current_sid<T>(
    account: &DomainAndName,
    sid: &Sid,
) -> OptionalLookup<AccountNameLookup>
where
    T: CloneSidFromRaw + LookupAccountName + AsRef<Sid>,
{
    T::lookup_local_account_name(account.to_string())
        .map(|lookup| lookup.map(|lookup| account_lookup_parts(lookup, sid)).ok())
}

fn account_lookup_parts<T>(lookup: AccountLookup<T>, sid: &Sid) -> AccountNameLookup
where
    T: CloneSidFromRaw + AsRef<Sid>,
{
    let sid_matches = lookup.sid.as_ref() == sid;
    let sid_type = lookup.sid_type().ok();

    (sid_matches, lookup.domain_name, sid_type)
}
