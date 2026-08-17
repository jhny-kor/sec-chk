from __future__ import annotations

import stat
from pathlib import Path

from ...models import Finding
from .common import HostCheck, host_finding, host_unverified
from .runner import run_command

SSHD_CONFIG = Path("/etc/ssh/sshd_config")
TMP_DIR = Path("/tmp")


def check_ssh_root_login() -> list[Finding]:
    value = _sshd_option("PermitRootLogin")
    if value == "yes":
        return [
            host_finding(
                "host.linux.ssh-root-login-enabled",
                "high",
                "SSH root login is explicitly enabled",
                "linux/ssh-root-login",
                evidence="PermitRootLogin yes",
                description="Direct root SSH login increases the blast radius of credential theft and bypasses named-user accountability.",
                recommendation="Set PermitRootLogin no, then restart sshd after validating named sudo access.",
            )
        ]
    if value in {"no", "prohibit-password", "forced-commands-only"}:
        return [
            host_finding(
                "host.linux.ssh-root-login-restricted",
                "info",
                "SSH root login is restricted",
                "linux/ssh-root-login",
                evidence=f"PermitRootLogin {value}",
            )
        ]
    return [
        host_unverified(
            "host.linux.ssh-root-login-unverified",
            "SSH root login policy was not verified",
            "linux/ssh-root-login",
            evidence=f"PermitRootLogin resolved to {value or 'no sshd_config value'}",
            recommendation="Check the effective sshd_config with 'sshd -T | grep permitrootlogin'.",
        )
    ]


def check_ssh_password_authentication() -> list[Finding]:
    value = _sshd_option("PasswordAuthentication")
    if value == "yes":
        return [
            host_finding(
                "host.linux.ssh-password-auth-enabled",
                "medium",
                "SSH password authentication is explicitly enabled",
                "linux/ssh-password-authentication",
                evidence="PasswordAuthentication yes",
                description="Password-based SSH is more exposed to brute-force and credential-stuffing attacks than key-based access.",
                recommendation="Use key-based SSH and set PasswordAuthentication no after confirming emergency access.",
            )
        ]
    if value == "no":
        return [
            host_finding(
                "host.linux.ssh-password-auth-disabled",
                "info",
                "SSH password authentication is disabled",
                "linux/ssh-password-authentication",
                evidence="PasswordAuthentication no",
            )
        ]
    return [
        host_unverified(
            "host.linux.ssh-password-auth-unverified",
            "SSH password authentication policy was not verified",
            "linux/ssh-password-authentication",
            evidence=f"PasswordAuthentication resolved to {value or 'no sshd_config value'}",
            recommendation="Check the effective sshd_config with 'sshd -T | grep passwordauthentication'.",
        )
    ]


def check_ip_forwarding() -> list[Finding]:
    result = run_command(["sysctl", "-n", "net.ipv4.ip_forward"])
    if not result.ok:
        return [
            host_unverified(
                "host.linux.ip-forwarding-unverified",
                "IPv4 forwarding state was not verified",
                "linux/ip-forwarding",
                evidence=result.error or result.stderr.strip(),
                recommendation="Check with 'sysctl net.ipv4.ip_forward'.",
            )
        ]
    if result.text == "1":
        return [
            host_finding(
                "host.linux.ip-forwarding-enabled",
                "medium",
                "IPv4 packet forwarding is enabled",
                "linux/ip-forwarding",
                evidence="net.ipv4.ip_forward=1",
                description="Packet forwarding can turn an application server into a router and widen lateral movement paths when not required.",
                recommendation="Set net.ipv4.ip_forward=0 unless this server is intentionally routing traffic.",
            )
        ]
    return [
        host_finding(
            "host.linux.ip-forwarding-disabled",
            "info",
            "IPv4 packet forwarding is disabled",
            "linux/ip-forwarding",
            evidence=f"net.ipv4.ip_forward={result.text}",
        )
    ]


def check_firewall_service() -> list[Finding]:
    firewalld = run_command(["systemctl", "is-active", "firewalld"])
    ufw_service = run_command(["systemctl", "is-active", "ufw"])
    if firewalld.text == "active" or ufw_service.text == "active":
        active = "firewalld" if firewalld.text == "active" else "ufw"
        return [
            host_finding(
                "host.linux.firewall-service-active",
                "info",
                "A Linux firewall service is active",
                "linux/firewall-service",
                evidence=f"{active}=active",
            )
        ]

    ufw_status = run_command(["ufw", "status"])
    if "status: active" in ufw_status.text.lower():
        return [
            host_finding(
                "host.linux.firewall-service-active",
                "info",
                "A Linux firewall service is active",
                "linux/firewall-service",
                evidence="ufw status: active",
            )
        ]
    return [
        host_finding(
            "host.linux.firewall-service-inactive",
            "medium",
            "No active firewalld or ufw service was detected",
            "linux/firewall-service",
            evidence="firewalld inactive; ufw inactive or unavailable",
            description="Without a host firewall, exposed services rely only on network perimeter controls.",
            recommendation="Enable firewalld or ufw and allow only required inbound ports.",
        )
    ]


def check_tmp_sticky_bit() -> list[Finding]:
    try:
        mode = TMP_DIR.stat().st_mode
    except OSError:
        return [
            host_unverified(
                "host.linux.tmp-sticky-bit-unverified",
                "/tmp sticky bit was not verified",
                "linux/tmp-sticky-bit",
                evidence=f"could not stat {TMP_DIR}",
                recommendation="Check with 'ls -ld /tmp'; the mode should be 1777.",
            )
        ]
    has_sticky_bit = bool(mode & stat.S_ISVTX)
    if has_sticky_bit:
        return [
            host_finding(
                "host.linux.tmp-sticky-bit-set",
                "info",
                "/tmp has the sticky bit set",
                "linux/tmp-sticky-bit",
                evidence=oct(stat.S_IMODE(mode)),
            )
        ]
    return [
        host_finding(
            "host.linux.tmp-sticky-bit-missing",
            "high",
            "/tmp is missing the sticky bit",
            "linux/tmp-sticky-bit",
            evidence=oct(stat.S_IMODE(mode)),
            description="A world-writable temporary directory without the sticky bit lets users delete or replace other users' files.",
            recommendation="Run chmod 1777 /tmp and investigate who changed the mode.",
        )
    ]


def check_listening_services() -> list[Finding]:
    result = run_command(["ss", "-tuln"])
    if not result.ok:
        return [
            host_unverified(
                "host.linux.listening-services-unverified",
                "Listening services were not verified",
                "linux/listening-services",
                evidence=result.error or result.stderr.strip(),
                recommendation="Install iproute2 so 'ss -tuln' can enumerate listening sockets.",
            )
        ]
    exposed = sorted(_all_interface_listeners(result.stdout))
    if not exposed:
        return [
            host_finding(
                "host.linux.no-all-interface-listeners",
                "info",
                "No all-interface listening sockets were detected",
                "linux/listening-services",
                evidence="ss -tuln",
            )
        ]
    return [
        host_finding(
            "host.linux.all-interface-listeners",
            "low",
            "One or more services listen on all interfaces",
            "linux/listening-services",
            evidence=", ".join(exposed[:10]),
            description="Services bound to all interfaces are reachable from every network path allowed by firewall and routing policy.",
            recommendation="Confirm each listener is required, bind internal services to 127.0.0.1, and restrict inbound firewall rules.",
        )
    ]


def _sshd_option(name: str) -> str:
    try:
        lines = SSHD_CONFIG.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if parts and parts[0].lower() == name.lower():
            return parts[1].lower() if len(parts) > 1 else ""
    return ""


def _listens_on_all_interfaces(line: str) -> bool:
    return " 0.0.0.0:" in line or " [::]:" in line or " *:" in line


def _all_interface_listeners(output: str) -> set[str]:
    listeners: set[str] = set()
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) > 4 and _listens_on_all_interfaces(line):
            listeners.add(parts[4])
    return listeners


HOST_CHECKS: tuple[HostCheck, ...] = (
    check_ssh_root_login,
    check_ssh_password_authentication,
    check_ip_forwarding,
    check_firewall_service,
    check_tmp_sticky_bit,
    check_listening_services,
)
