"""macOS host/endpoint security checks.

Phase 0 reference implementation: a small, no-admin, read-only vertical slice
(A: system integrity, C: network exposure) that proves the host pipeline end to
end. Phase 1 expands coverage (BitLocker-equivalents, TPM/Secure Enclave, more
network and malware-defense checks) by adding functions to ``HOST_CHECKS``.
"""

from __future__ import annotations

from ...models import Finding
from .common import host_finding
from .runner import run_command

FIREWALL_BIN = "/usr/libexec/ApplicationFirewall/socketfilterfw"


def check_system_integrity_protection() -> list[Finding]:
    result = run_command(["csrutil", "status"])
    if not result.ok:
        return []
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
        return []
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
        return []
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
            recommendation="Re-enable Gatekeeper by running 'sudo spctl --master-enable'.",
        )
    ]


def check_application_firewall() -> list[Finding]:
    result = run_command([FIREWALL_BIN, "--getglobalstate"])
    if not result.ok:
        return []
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
        return []
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
    config_data = run_command(["defaults", "read", domain, "ConfigDataInstall"])
    critical = run_command(["defaults", "read", domain, "CriticalUpdateInstall"])
    # A missing key (ok=False) is treated as not explicitly enabled.
    config_on = config_data.ok and config_data.text.strip() == "1"
    critical_on = critical.ok and critical.text.strip() == "1"
    evidence = f"ConfigDataInstall={config_data.text or 'unset'}, CriticalUpdateInstall={critical.text or 'unset'}"
    if config_on and critical_on:
        return [
            host_finding(
                "host.macos.auto-security-updates-enabled",
                "info",
                "Automatic security responses and system files are enabled",
                "macos/automatic-security-updates",
                evidence=evidence,
            )
        ]
    return [
        host_finding(
            "host.macos.auto-security-updates-disabled",
            "medium",
            "Automatic security responses or system files are not enabled",
            "macos/automatic-security-updates",
            evidence=evidence,
            description="These settings let macOS install XProtect/security data files and rapid security responses without waiting for a full OS update. Disabling them delays protection against active threats.",
            recommendation="Enable 'Install Security Responses and system files' in System Settings > General > Software Update > Automatic Updates.",
        )
    ]


HOST_CHECKS: tuple = (
    check_system_integrity_protection,
    check_filevault,
    check_gatekeeper,
    check_application_firewall,
    check_firewall_stealth_mode,
    check_automatic_security_updates,
)
