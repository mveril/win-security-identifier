// Windows-only integration test that fetches SID + DOMAIN\Name with canonical casing
#![cfg(windows)]
#![cfg(feature = "std")]
#![allow(clippy::expect_used, reason = "Expect is not an issue in tests")]
#![allow(clippy::unwrap_used, reason = "Unwrap is not an issue in tests")]

use serde::Deserialize;
use std::{
    fmt::Debug,
    process::{Command, Stdio},
};
use win_security_identifier::{
    GetCurrentSid, SecurityIdentifier, Sid, StackSid,
    sid_lookup::{DomainAndName, SidType},
};

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

#[test]
fn current_user_sid_and_account_heap() {
    current_user_sid_and_account::<SecurityIdentifier>();
}
#[test]
fn current_user_sid_and_account_stack() {
    current_user_sid_and_account::<StackSid>();
}

fn current_user_sid_and_account<T>()
where
    T: Sized + AsRef<Sid> + PartialEq<StackSid> + Debug,
    for<'a> &'a Sid: Into<T>,
{
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

    let user: PsUser =
        serde_json::from_slice(out.stdout.as_slice()).expect("Invalid JSON from PowerShell");

    let sid = T::get_current_user_sid().expect("Failed to get current user SID");

    assert_eq!(sid, user.sid, "SID does not match expected value");

    let lookup = sid.as_ref().lookup_local_sid().unwrap().unwrap();

    assert_eq!(
        lookup.domain_name, user.account,
        "Domain and name do not match expected value"
    );

    assert_eq!(
        lookup.sid_type().unwrap(),
        SidType::User,
        "Domain and name do not match expected value"
    );
    assert_eq!(
        lookup.sid_type().unwrap(),
        SidType::User,
        "Domain and name do not match expected value"
    );
}
