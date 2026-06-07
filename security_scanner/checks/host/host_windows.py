"""Windows host/endpoint security checks.

Phase 0 scaffold: BitLocker (A) and Microsoft Defender (E) reference checks via
read-only PowerShell. These run only on Windows (the dispatcher in
``__init__.py`` selects this module by platform), so they are inert on other OSes.
Phase 1 expands coverage (Secure Boot, TPM, firewall profiles, listening ports,
Defender signature age, etc.) by adding functions to ``HOST_CHECKS``.
"""

from __future__ import annotations

from ...models import Finding
from .common import host_finding
from .runner import powershell


def check_bitlocker() -> list[Finding]:
    # Reports the OS volume protection status; "On"/"Off"/error are handled gracefully.
    result = powershell(
        "(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus"
    )
    if not result.ok:
        return []
    value = result.text.lower()
    if value in {"on", "1"}:
        return [
            host_finding(
                "host.windows.bitlocker-on",
                "info",
                "BitLocker is enabled on the system drive",
                "windows/bitlocker",
                evidence=result.text,
            )
        ]
    return [
        host_finding(
            "host.windows.bitlocker-off",
            "high",
            "BitLocker is not protecting the system drive",
            "windows/bitlocker",
            evidence=result.text or "ProtectionStatus: Off",
            description="Without full-disk encryption, data on a lost or stolen device can be read by removing the drive.",
            recommendation="Enable BitLocker on the system drive and back up the recovery key.",
        )
    ]


def check_defender() -> list[Finding]:
    result = powershell("(Get-MpComputerStatus).RealTimeProtectionEnabled")
    if not result.ok:
        return []
    value = result.text.lower()
    if value in {"true", "1"}:
        return [
            host_finding(
                "host.windows.defender-realtime-on",
                "info",
                "Microsoft Defender real-time protection is on",
                "windows/defender-realtime",
                evidence=result.text,
            )
        ]
    return [
        host_finding(
            "host.windows.defender-realtime-off",
            "high",
            "Microsoft Defender real-time protection is off",
            "windows/defender-realtime",
            evidence=result.text or "RealTimeProtectionEnabled: False",
            description="Real-time protection blocks malware as it is encountered. With it off, the endpoint relies only on periodic scans.",
            recommendation="Enable real-time protection in Windows Security, or verify a third-party AV is registered and active.",
        )
    ]


def check_secure_boot() -> list[Finding]:
    # Confirm-SecureBootUEFI throws on legacy BIOS; we capture stdout only.
    result = powershell(
        "try { [string](Confirm-SecureBootUEFI) } catch { 'unsupported' }"
    )
    if not result.ok:
        return []
    value = result.text.lower()
    if value in {"true", "1"}:
        return [
            host_finding(
                "host.windows.secure-boot-on",
                "info",
                "Secure Boot is enabled",
                "windows/secure-boot",
                evidence=result.text,
            )
        ]
    if "unsupported" in value or value == "":
        return [
            host_finding(
                "host.windows.secure-boot-unsupported",
                "low",
                "Secure Boot state could not be confirmed (legacy BIOS or unsupported)",
                "windows/secure-boot",
                evidence=result.text or "unsupported",
                description="Secure Boot blocks unsigned bootloaders and boot-time malware. Legacy BIOS systems cannot enforce it.",
                recommendation="Where hardware allows, switch firmware to UEFI and enable Secure Boot.",
            )
        ]
    return [
        host_finding(
            "host.windows.secure-boot-off",
            "high",
            "Secure Boot is disabled",
            "windows/secure-boot",
            evidence=result.text,
            description="With Secure Boot off, tampered or unsigned bootloaders can run before the OS loads.",
            recommendation="Enable Secure Boot in UEFI firmware settings.",
        )
    ]


def check_firewall_profiles() -> list[Finding]:
    # Reports any firewall profile (Domain/Private/Public) that is disabled.
    result = powershell(
        "(Get-NetFirewallProfile | Where-Object { -not $_.Enabled } | "
        "Select-Object -ExpandProperty Name) -join ','"
    )
    if not result.ok:
        return []
    disabled = [name for name in result.text.split(",") if name.strip()]
    if not disabled:
        return [
            host_finding(
                "host.windows.firewall-all-profiles-enabled",
                "info",
                "All Windows Firewall profiles are enabled",
                "windows/firewall-profiles",
                evidence="Domain, Private, Public all enabled",
            )
        ]
    return [
        host_finding(
            "host.windows.firewall-profile-disabled",
            "high",
            "One or more Windows Firewall profiles are disabled",
            "windows/firewall-profiles",
            evidence=f"Disabled profiles: {', '.join(disabled)}",
            description="A disabled firewall profile allows unsolicited inbound connections on networks using that profile.",
            recommendation="Enable the firewall for all profiles: Set-NetFirewallProfile -All -Enabled True.",
        )
    ]


HOST_CHECKS: tuple = (
    check_bitlocker,
    check_defender,
    check_secure_boot,
    check_firewall_profiles,
)
