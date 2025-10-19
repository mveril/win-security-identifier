// Windows-only integration test that fetches SID + DOMAIN\Name with canonical casing
#![cfg(windows)]
#![cfg(feature = "std")]
#![allow(clippy::expect_used, reason = "Expect is not an issue in tests")]
#![allow(clippy::unwrap_used, reason = "Unwrap is not an issue in tests")]

use serde::Deserialize;
use std::process::{Command, Stdio};
use win_security_identifier::{DomainAndName, SecurityIdentifier, SidType};

#[derive(Debug, Deserialize)]
struct PsUser {
    sid: String,
    account: String,
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
fn current_user_sid_and_account() {
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

    let expected_domain_name = user
        .account
        .parse::<DomainAndName>()
        .expect("Failed to parse Account into DomainAndName");

    let sid = SecurityIdentifier::get_current_user_sid().expect("Failed to get current user SID");

    assert_eq!(
        sid.to_string(),
        user.sid,
        "SID does not match expected value"
    );

    let lookup = sid.lookup_local_sid().unwrap().unwrap();

    assert_eq!(
        lookup.domain_name, expected_domain_name,
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
