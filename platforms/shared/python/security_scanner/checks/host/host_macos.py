"""macOS host/endpoint security checks.

Phase 0 reference implementation: a small, no-admin, read-only vertical slice
(A: system integrity, C: network exposure) that proves the host pipeline end to
end. Phase 1 expands coverage (BitLocker-equivalents, TPM/Secure Enclave, more
network and malware-defense checks) by adding functions to ``HOST_CHECKS``.
"""

from __future__ import annotations

import re

from ...models import Finding
from .common import host_finding, host_unverified
from .runner import run_command

FIREWALL_BIN = "/usr/libexec/ApplicationFirewall/socketfilterfw"


def check_system_integrity_protection() -> list[Finding]:
    result = run_command(["csrutil", "status"])
    if not result.ok:
        return [
            host_unverified(
                "host.macos.sip-unverified",
                "System Integrity Protection state was not verified",
                "macos/system-integrity-protection",
                evidence=result.error or result.stderr.strip(),
                recommendation="Check with 'csrutil status'; changes require macOS Recovery.",
            )
        ]
    enabled = "enabled" in result.text.lower()
    if enabled:
        return [
            host_finding(
                "host.macos.sip-enabled",
                "info",
                "System Integrity Protection is enabled",
                "macos/system-integrity-protection",
                evidence=result.text,
            )
        ]
    return [
        host_finding(
            "host.macos.sip-disabled",
            "high",
            "System Integrity Protection is disabled",
            "macos/system-integrity-protection",
            evidence=result.text,
            description="SIP protects critical system files and processes from tampering. Disabling it broadens the attack surface for persistent malware.",
            recommendation="Re-enable SIP by running 'csrutil enable' from macOS Recovery, then reboot.",
        )
    ]


def check_filevault() -> list[Finding]:
    result = run_command(["fdesetup", "status"])
    if not result.ok:
        return [
            host_unverified(
                "host.macos.filevault-unverified",
                "FileVault disk encryption state was not verified",
                "macos/filevault",
                evidence=result.error or result.stderr.strip(),
                recommendation="Check System Settings > Privacy & Security > FileVault.",
            )
        ]
    on = "filevault is on" in result.text.lower()
    if on:
        return [
            host_finding(
                "host.macos.filevault-on",
                "info",
                "FileVault disk encryption is on",
                "macos/filevault",
                evidence=result.text,
            )
        ]
    return [
        host_finding(
            "host.macos.filevault-off",
            "high",
            "FileVault disk encryption is off",
            "macos/filevault",
            evidence=result.text,
            description="Without full-disk encryption, data on a lost or stolen Mac can be read by removing the drive or booting externally.",
            recommendation="Enable FileVault in System Settings > Privacy & Security > FileVault and store the recovery key securely.",
        )
    ]


def check_gatekeeper() -> list[Finding]:
    result = run_command(["spctl", "--status"])
    if not result.ok:
        return [
            host_unverified(
                "host.macos.gatekeeper-unverified",
                "Gatekeeper assessment state was not verified",
                "macos/gatekeeper",
                evidence=result.error or result.stderr.strip(),
                recommendation="Check System Settings > Privacy & Security > Security.",
            )
        ]
    enabled = "assessments enabled" in result.text.lower()
    if enabled:
        return [
            host_finding(
                "host.macos.gatekeeper-enabled",
                "info",
                "Gatekeeper assessments are enabled",
                "macos/gatekeeper",
                evidence=result.text,
            )
        ]
    return [
        host_finding(
            "host.macos.gatekeeper-disabled",
            "high",
            "Gatekeeper assessments are disabled",
            "macos/gatekeeper",
            evidence=result.text,
            description="Gatekeeper blocks unsigned or un-notarized applications. Disabling it allows unverified code to run.",
            recommendation="Re-enable Gatekeeper in System Settings > Privacy & Security (on macOS 15 Sequoia and later 'spctl --master-enable' is no longer supported); enforce it fleet-wide with an MDM configuration profile.",
        )
    ]


def check_application_firewall() -> list[Finding]:
    result = run_command([FIREWALL_BIN, "--getglobalstate"])
    if not result.ok:
        return [
            host_unverified(
                "host.macos.firewall-unverified",
                "Application Firewall state was not verified",
                "macos/application-firewall",
                evidence=result.error or result.stderr.strip(),
                recommendation="Check System Settings > Network > Firewall.",
            )
        ]
    text = result.text
    enabled = "state = 1" in text.lower() or "state = 2" in text.lower() or "enabled" in text.lower()
    if enabled:
        return [
            host_finding(
                "host.macos.firewall-enabled",
                "info",
                "Application Firewall is enabled",
                "macos/application-firewall",
                evidence=text,
            )
        ]
    return [
        host_finding(
            "host.macos.firewall-disabled",
            "medium",
            "Application Firewall is disabled",
            "macos/application-firewall",
            evidence=text,
            description="The application firewall limits inbound connections to listening services. With it off, exposed services accept connections from any network.",
            recommendation="Enable the firewall in System Settings > Network > Firewall.",
        )
    ]


def check_firewall_stealth_mode() -> list[Finding]:
    result = run_command([FIREWALL_BIN, "--getstealthmode"])
    if not result.ok:
        return [
            host_unverified(
                "host.macos.firewall-stealth-unverified",
                "Firewall stealth mode state was not verified",
                "macos/firewall-stealth-mode",
                evidence=result.error or result.stderr.strip(),
                recommendation="Check System Settings > Network > Firewall > Options.",
            )
        ]
    text = result.text
    on = "stealth mode is on" in text.lower() or "enabled" in text.lower()
    if on:
        return [
            host_finding(
                "host.macos.firewall-stealth-enabled",
                "info",
                "Firewall stealth mode is enabled",
                "macos/firewall-stealth-mode",
                evidence=text,
            )
        ]
    return [
        host_finding(
            "host.macos.firewall-stealth-disabled",
            "low",
            "Firewall stealth mode is disabled",
            "macos/firewall-stealth-mode",
            evidence=text,
            description="Stealth mode makes the Mac ignore probing requests (e.g. ICMP ping, closed-port scans), reducing its visibility to network scanners.",
            recommendation="Enable stealth mode in System Settings > Network > Firewall > Options.",
        )
    ]


def check_automatic_security_updates() -> list[Finding]:
    domain = "/Library/Preferences/com.apple.SoftwareUpdate"
    # CIS Apple macOS software-update controls (1.x): automatic check, download,
    # macOS-update install, and security responses/system files must all be on.
    keys = (
        "AutomaticCheckEnabled",
        "AutomaticDownload",
        "AutomaticallyInstallMacOSUpdates",
        "ConfigDataInstall",
        "CriticalUpdateInstall",
    )
    states: dict[str, str] = {}
    for key in keys:
        result = run_command(["defaults", "read", domain, key])
        states[key] = result.text.strip() if result.ok else "unset"
    evidence = ", ".join(f"{key}={value}" for key, value in states.items())
    disabled = [key for key, value in states.items() if value != "1"]
    if not disabled:
        return [
            host_finding(
                "host.macos.auto-security-updates-enabled",
                "info",
                "All CIS automatic update settings are enabled",
                "macos/automatic-security-updates",
                evidence=evidence,
            )
        ]
    return [
        host_finding(
            "host.macos.auto-security-updates-disabled",
            "medium",
            "Automatic update settings are not fully enabled",
            "macos/automatic-security-updates",
            evidence=evidence,
            description=(
                "CIS requires automatic update check, download, and install (including macOS updates, "
                "security responses, and system data files). Missing: " + ", ".join(disabled) + "."
            ),
            recommendation="Enable every automatic-update option in System Settings > General > Software Update > Automatic Updates.",
        )
    ]


def check_automatic_login() -> list[Finding]:
    result = run_command(["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"])
    if result.ok and result.text.strip():
        return [
            host_finding(
                "host.macos.auto-login-enabled",
                "high",
                "Automatic login is enabled",
                "macos/automatic-login",
                evidence=f"autoLoginUser={result.text.strip()}",
                description="Automatic login bypasses the login password, so a lost or stolen Mac is accessible without authentication.",
                recommendation="Turn off automatic login in System Settings > Lock Screen.",
            )
        ]
    return [
        host_finding(
            "host.macos.auto-login-disabled", "info", "Automatic login is disabled",
            "macos/automatic-login", evidence="autoLoginUser unset",
        )
    ]


def check_guest_account() -> list[Finding]:
    result = run_command(["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"])
    if result.ok and result.text.strip() == "1":
        return [
            host_finding(
                "host.macos.guest-account-enabled", "medium", "Guest account is enabled",
                "macos/guest-account", evidence="GuestEnabled=1",
                description="The guest account allows unauthenticated local access to the machine.",
                recommendation="Disable the guest user in System Settings > Users & Groups.",
            )
        ]
    return [
        host_finding(
            "host.macos.guest-account-disabled", "info", "Guest account is disabled",
            "macos/guest-account", evidence=f"GuestEnabled={result.text.strip() or 'unset'}",
        )
    ]


def check_screen_lock() -> list[Finding]:
    # `sysadminctl -screenLock status` is the supported probe and matches the
    # macOS app. The com.apple.screensaver askForPassword pair it replaced is
    # unset on current macOS, so that read fails and the control is unreadable.
    # sysadminctl reports on stderr, so both streams are considered.
    status = run_command(["sysadminctl", "-screenLock", "status"])
    combined = f"{status.stdout}\n{status.stderr}".strip()
    lowered = combined.lower()
    if not combined or "screenlock" not in lowered:
        return [
            host_unverified(
                "host.macos.screen-lock-unverified",
                "Screen lock password state was not verified",
                "macos/screen-lock",
                evidence=status.error or combined,
                recommendation="Check System Settings > Lock Screen.",
            )
        ]
    # CIS 2.10.2/2.11.2: a password must be required within 0-5 seconds
    # (effectively immediate). A large delay leaves a window of unlocked access.
    delay_match = re.search(r"screenlock delay is (\d+(?:\.\d+)?)", lowered)
    delay_seconds = float(delay_match.group(1)) if delay_match else None
    ask_on = "screenlock is off" not in lowered and "screenlock disabled" not in lowered
    delay_ok = "delay is immediate" in lowered or (delay_seconds is not None and 0 <= delay_seconds <= 5)
    evidence = combined
    if ask_on and delay_ok:
        return [
            host_finding(
                "host.macos.screen-lock-enabled", "info", "A password is required within 5s of screen saver/lock",
                "macos/screen-lock", evidence=evidence,
            )
        ]
    return [
        host_finding(
            "host.macos.screen-lock-disabled", "medium", "Password after screen saver/lock is missing or delayed beyond 5s",
            "macos/screen-lock", evidence=evidence,
            description="CIS requires a password within 5 seconds of the screen locking; without it, anyone with physical access can use the machine.",
            recommendation="Require a password immediately (0-5 seconds) after sleep/screen saver in System Settings > Lock Screen.",
        )
    ]


HOST_CHECKS: tuple = (
    check_system_integrity_protection,
    check_filevault,
    check_gatekeeper,
    check_application_firewall,
    check_firewall_stealth_mode,
    check_automatic_security_updates,
    check_automatic_login,
    check_guest_account,
    check_screen_lock,
)
