"""
Center for Internet Security (CIS) Configuration Benchmarks Catalog.
Provides security configuration benchmarks for Linux, Windows Server,
Amazon Web Services, and Kubernetes with audit and automated remediation commands.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Set


class BenchmarkPlatform(str, Enum):
    LINUX = "Linux"
    WINDOWS = "Windows"
    CLOUD = "Cloud"
    CONTAINERS = "Containers"


class ProfileLevel(str, Enum):
    LEVEL_1 = "Level 1"
    LEVEL_2 = "Level 2"


@dataclass(frozen=True)
class BenchmarkMetadata:
    id: str
    name: str
    version: str
    platform: BenchmarkPlatform


@dataclass
class CisRecommendation:
    id: str
    benchmark_id: str
    benchmark_name: str
    rule_number: str
    title: str
    description: str
    audit_command: str
    remediation_command: str
    profile: ProfileLevel
    scored: bool
    platform: BenchmarkPlatform


BENCHMARKS_CATALOG: Dict[str, BenchmarkMetadata] = {
    "CIS-UBUNTU-22.04": BenchmarkMetadata(
        id="CIS-UBUNTU-22.04",
        name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        version="v1.0.0",
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9": BenchmarkMetadata(
        id="CIS-RHEL-9",
        name="CIS Red Hat Enterprise Linux 9 Benchmark",
        version="v1.0.0",
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-WINDOWS-2022": BenchmarkMetadata(
        id="CIS-WINDOWS-2022",
        name="CIS Microsoft Windows Server 2022 Benchmark",
        version="v2.0.0",
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-AWS-3.0": BenchmarkMetadata(
        id="CIS-AWS-3.0",
        name="CIS Amazon Web Services Foundations Benchmark",
        version="v3.0.0",
        platform=BenchmarkPlatform.CLOUD
    ),
    "CIS-K8S-1.8": BenchmarkMetadata(
        id="CIS-K8S-1.8",
        name="CIS Kubernetes Benchmark",
        version="v1.8.0",
        platform=BenchmarkPlatform.CONTAINERS
    ),
}

RECOMMENDATIONS_CATALOG: Dict[str, CisRecommendation] = {
    "CIS-UBUNTU-22.04-1.1.1": CisRecommendation(
        id="CIS-UBUNTU-22.04-1.1.1",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="1.1.1",
        title="Disable unused legacy filesystems",
        description="""Removing unneeded filesystem modules reduces kernel attack surface.""",
        audit_command="""modprobe -n -v cramfs""",
        remediation_command="""install cramfs /bin/true""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-1.1.2": CisRecommendation(
        id="CIS-UBUNTU-22.04-1.1.2",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="1.1.2",
        title="Ensure /tmp is mounted with nodev",
        description="""The nodev mount option prevents character or block devices from being mounted on temporary directories.""",
        audit_command="""findmnt -n /tmp""",
        remediation_command="""mount -o remount,nodev /tmp""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-1.1.3": CisRecommendation(
        id="CIS-UBUNTU-22.04-1.1.3",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="1.1.3",
        title="Ensure /tmp is mounted with nosuid",
        description="""The nosuid mount option prevents setuid and setgid bit execution on temporary partitions.""",
        audit_command="""findmnt -n /tmp""",
        remediation_command="""mount -o remount,nosuid /tmp""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-1.1.4": CisRecommendation(
        id="CIS-UBUNTU-22.04-1.1.4",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="1.1.4",
        title="Ensure /tmp is mounted with noexec",
        description="""The noexec mount option prevents direct execution of malicious binaries from world-writable directories.""",
        audit_command="""findmnt -n /tmp""",
        remediation_command="""mount -o remount,noexec /tmp""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-1.2.1": CisRecommendation(
        id="CIS-UBUNTU-22.04-1.2.1",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="1.2.1",
        title="Verify package repository GPG keys",
        description="""GPG signature verification guarantees authenticity of installed system binaries.""",
        audit_command="""apt-key list""",
        remediation_command="""apt-key update""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-1.3.1": CisRecommendation(
        id="CIS-UBUNTU-22.04-1.3.1",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="1.3.1",
        title="Ensure filesystem integrity monitoring is active",
        description="""Periodic integrity audits detect unauthorized modification to system libraries.""",
        audit_command="""crontab -l | grep aide""",
        remediation_command="""systemctl enable aide.timer""",
        profile=ProfileLevel.LEVEL_2,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-1.4.1": CisRecommendation(
        id="CIS-UBUNTU-22.04-1.4.1",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="1.4.1",
        title="Ensure bootloader password is set",
        description="""Setting a bootloader password prevents unauthorized alteration of kernel parameters during reboot.""",
        audit_command="""grep -E password /boot/grub/grub.cfg""",
        remediation_command="""grub-mkpasswd-pbkdf2""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-1.4.2": CisRecommendation(
        id="CIS-UBUNTU-22.04-1.4.2",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="1.4.2",
        title="Ensure bootloader configuration permissions are 600",
        description="""Restricting grub.cfg prevents non-root access to kernel boot configs.""",
        audit_command="""stat -c %a /boot/grub/grub.cfg""",
        remediation_command="""chmod 600 /boot/grub/grub.cfg""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-1.5.1": CisRecommendation(
        id="CIS-UBUNTU-22.04-1.5.1",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="1.5.1",
        title="Ensure ASLR address space layout randomization is active",
        description="""ASLR randomizes memory layout to prevent memory corruption exploits.""",
        audit_command="""sysctl kernel.randomize_va_space""",
        remediation_command="""sysctl -w kernel.randomize_va_space=2""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-1.5.2": CisRecommendation(
        id="CIS-UBUNTU-22.04-1.5.2",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="1.5.2",
        title="Ensure ptrace process debugging scope is restricted",
        description="""Restricting ptrace prevents unprivileged processes from injecting memory into other processes.""",
        audit_command="""sysctl kernel.yama.ptrace_scope""",
        remediation_command="""sysctl -w kernel.yama.ptrace_scope=1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-1.5.3": CisRecommendation(
        id="CIS-UBUNTU-22.04-1.5.3",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="1.5.3",
        title="Ensure core dump memory dumps are restricted",
        description="""Core dumps may contain sensitive plaintext passwords or cryptographic keys.""",
        audit_command="""grep core /etc/security/limits.conf""",
        remediation_command="""echo * hard core 0 >> /etc/security/limits.conf""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-2.1.1": CisRecommendation(
        id="CIS-UBUNTU-22.04-2.1.1",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="2.1.1",
        title="Ensure network time synchronization chrony is active",
        description="""Synchronized system clocks are critical for SIEM forensic timeline analysis.""",
        audit_command="""timedatectl status""",
        remediation_command="""systemctl enable --now chrony""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-3.1.1": CisRecommendation(
        id="CIS-UBUNTU-22.04-3.1.1",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="3.1.1",
        title="Ensure IP packet redirect sending is disabled",
        description="""Sending ICMP redirects allows systems to alter routing tables on remote hosts.""",
        audit_command="""sysctl net.ipv4.conf.all.send_redirects""",
        remediation_command="""sysctl -w net.ipv4.conf.all.send_redirects=0""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-3.1.2": CisRecommendation(
        id="CIS-UBUNTU-22.04-3.1.2",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="3.1.2",
        title="Ensure IP packet forwarding is disabled",
        description="""Disabling IP forwarding ensures standard servers do not act as network routers.""",
        audit_command="""sysctl net.ipv4.ip_forward""",
        remediation_command="""sysctl -w net.ipv4.ip_forward=0""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-3.1.3": CisRecommendation(
        id="CIS-UBUNTU-22.04-3.1.3",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="3.1.3",
        title="Ensure source routed packets are ignored",
        description="""Source routing allows adversaries to bypass firewall boundaries by specifying custom paths.""",
        audit_command="""sysctl net.ipv4.conf.all.accept_source_route""",
        remediation_command="""sysctl -w net.ipv4.conf.all.accept_source_route=0""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-3.1.4": CisRecommendation(
        id="CIS-UBUNTU-22.04-3.1.4",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="3.1.4",
        title="Ensure ICMP redirects are ignored",
        description="""Ignoring ICMP redirects prevents malicious route manipulation and traffic interception.""",
        audit_command="""sysctl net.ipv4.conf.all.accept_redirects""",
        remediation_command="""sysctl -w net.ipv4.conf.all.accept_redirects=0""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-3.1.5": CisRecommendation(
        id="CIS-UBUNTU-22.04-3.1.5",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="3.1.5",
        title="Ensure broadcast ICMP requests are dropped",
        description="""Ignoring ICMP broadcast requests protects against network amplification attacks.""",
        audit_command="""sysctl net.ipv4.icmp_echo_ignore_broadcasts""",
        remediation_command="""sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-3.1.6": CisRecommendation(
        id="CIS-UBUNTU-22.04-3.1.6",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="3.1.6",
        title="Ensure suspicious martian packets are logged",
        description="""Logging martian packets detects spoofed source IP addresses arriving on network interfaces.""",
        audit_command="""sysctl net.ipv4.conf.all.log_martians""",
        remediation_command="""sysctl -w net.ipv4.conf.all.log_martians=1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-3.1.7": CisRecommendation(
        id="CIS-UBUNTU-22.04-3.1.7",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="3.1.7",
        title="Ensure TCP SYN Cookies protection is enabled",
        description="""SYN cookies defend against TCP SYN flood denial of service attacks.""",
        audit_command="""sysctl net.ipv4.tcp_syncookies""",
        remediation_command="""sysctl -w net.ipv4.tcp_syncookies=1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-3.2.1": CisRecommendation(
        id="CIS-UBUNTU-22.04-3.2.1",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="3.2.1",
        title="Ensure host-based firewall UFW/iptables is active",
        description="""A host-based firewall protects against unauthorized inbound network connections.""",
        audit_command="""ufw status""",
        remediation_command="""ufw enable""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-4.1.1": CisRecommendation(
        id="CIS-UBUNTU-22.04-4.1.1",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="4.1.1",
        title="Ensure system auditd auditing daemon is enabled",
        description="""The audit daemon captures security-relevant system calls, file access, and auth events.""",
        audit_command="""systemctl is-enabled auditd""",
        remediation_command="""systemctl enable auditd""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-4.1.2": CisRecommendation(
        id="CIS-UBUNTU-22.04-4.1.2",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="4.1.2",
        title="Ensure audit log max file size is configured",
        description="""Configuring adequate log storage prevents premature rollover and telemetry loss.""",
        audit_command="""grep max_log_file /etc/audit/auditd.conf""",
        remediation_command="""sed -i s/^max_log_file.*/max_log_file=100/ /etc/audit/auditd.conf""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-4.1.3": CisRecommendation(
        id="CIS-UBUNTU-22.04-4.1.3",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="4.1.3",
        title="Ensure audit log retention keep_logs is set",
        description="""Preserving audit logs is necessary to maintain forensic integrity.""",
        audit_command="""grep max_log_file_action /etc/audit/auditd.conf""",
        remediation_command="""sed -i s/^max_log_file_action.*/max_log_file_action=keep_logs/ /etc/audit/auditd.conf""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-4.1.4": CisRecommendation(
        id="CIS-UBUNTU-22.04-4.1.4",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="4.1.4",
        title="Ensure administrative scope changes are audited",
        description="""Auditing sudoers configuration changes detects unauthorized privilege escalation.""",
        audit_command="""grep sudoers /etc/audit/rules.d/*.rules""",
        remediation_command="""echo -w /etc/sudoers -p wa -k scope >> /etc/audit/rules.d/50-scope.rules""",
        profile=ProfileLevel.LEVEL_2,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-4.1.5": CisRecommendation(
        id="CIS-UBUNTU-22.04-4.1.5",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="4.1.5",
        title="Ensure identity modifications are audited",
        description="""Auditing user database changes detects unauthorized account provisioning.""",
        audit_command="""grep identity /etc/audit/rules.d/*.rules""",
        remediation_command="""echo -w /etc/passwd -p wa -k identity >> /etc/audit/rules.d/50-identity.rules""",
        profile=ProfileLevel.LEVEL_2,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-5.1.1": CisRecommendation(
        id="CIS-UBUNTU-22.04-5.1.1",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="5.1.1",
        title="Ensure cron task scheduler is enabled",
        description="""Cron services execute scheduled maintenance and security monitoring tasks.""",
        audit_command="""systemctl is-enabled cron""",
        remediation_command="""systemctl enable --now cron""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-5.1.2": CisRecommendation(
        id="CIS-UBUNTU-22.04-5.1.2",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="5.1.2",
        title="Ensure permissions on crontab are 600",
        description="""Restricting permissions on crontab prevents unprivileged users from scheduling tasks.""",
        audit_command="""stat -c %a /etc/crontab""",
        remediation_command="""chmod 600 /etc/crontab""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-5.2.1": CisRecommendation(
        id="CIS-UBUNTU-22.04-5.2.1",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="5.2.1",
        title="Ensure SSH server protocol 2 is enforced",
        description="""SSH protocol 1 contains critical vulnerabilities that allow interception.""",
        audit_command="""sshd -T | grep protocol""",
        remediation_command="""echo Protocol 2 >> /etc/ssh/sshd_config""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-5.2.2": CisRecommendation(
        id="CIS-UBUNTU-22.04-5.2.2",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="5.2.2",
        title="Ensure SSH direct root login is disabled",
        description="""Disabling direct root login forces administrators to authenticate as named users first.""",
        audit_command="""sshd -T | grep permitrootlogin""",
        remediation_command="""sed -i s/^PermitRootLogin.*/PermitRootLogin no/ /etc/ssh/sshd_config""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-5.2.3": CisRecommendation(
        id="CIS-UBUNTU-22.04-5.2.3",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="5.2.3",
        title="Ensure SSH password authentication is disabled",
        description="""Key-based authentication mitigates password brute-force attacks.""",
        audit_command="""sshd -T | grep passwordauthentication""",
        remediation_command="""sed -i s/^PasswordAuthentication.*/PasswordAuthentication no/ /etc/ssh/sshd_config""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-5.2.4": CisRecommendation(
        id="CIS-UBUNTU-22.04-5.2.4",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="5.2.4",
        title="Ensure SSH MaxAuthTries is set to 4 or less",
        description="""Restricting authentication attempts protects against rapid password guessing.""",
        audit_command="""sshd -T | grep maxauthtries""",
        remediation_command="""sed -i s/^MaxAuthTries.*/MaxAuthTries 4/ /etc/ssh/sshd_config""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-5.2.5": CisRecommendation(
        id="CIS-UBUNTU-22.04-5.2.5",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="5.2.5",
        title="Ensure SSH idle session timeout is configured",
        description="""Terminating idle sessions prevents unauthorized access to unattended terminals.""",
        audit_command="""sshd -T | grep clientaliveinterval""",
        remediation_command="""echo ClientAliveInterval 300 >> /etc/ssh/sshd_config""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-5.3.1": CisRecommendation(
        id="CIS-UBUNTU-22.04-5.3.1",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="5.3.1",
        title="Ensure password hashing algorithm is SHA-512 or yescrypt",
        description="""Strong cryptographic hashing algorithms resist offline dictionary cracking.""",
        audit_command="""grep ENCRYPT_METHOD /etc/login.defs""",
        remediation_command="""sed -i s/^ENCRYPT_METHOD.*/ENCRYPT_METHOD YESCRYPT/ /etc/login.defs""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-5.3.2": CisRecommendation(
        id="CIS-UBUNTU-22.04-5.3.2",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="5.3.2",
        title="Ensure minimum password length is 14 characters",
        description="""Long passwords exponentially increase the difficulty of brute-force attacks.""",
        audit_command="""grep pam_pwquality /etc/pam.d/common-password""",
        remediation_command="""sed -i s/pam_pwquality.*/& minlen=14/ /etc/pam.d/common-password""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-5.4.1": CisRecommendation(
        id="CIS-UBUNTU-22.04-5.4.1",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="5.4.1",
        title="Ensure password maximum age is 90 days or less",
        description="""Periodic credential rotation limits the window of opportunity for stolen credentials.""",
        audit_command="""grep PASS_MAX_DAYS /etc/login.defs""",
        remediation_command="""sed -i s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/ /etc/login.defs""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-5.4.2": CisRecommendation(
        id="CIS-UBUNTU-22.04-5.4.2",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="5.4.2",
        title="Ensure password minimum age is 1 day or more",
        description="""Preventing immediate password changes prevents users from cycling passwords.""",
        audit_command="""grep PASS_MIN_DAYS /etc/login.defs""",
        remediation_command="""sed -i s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/ /etc/login.defs""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-6.1.1": CisRecommendation(
        id="CIS-UBUNTU-22.04-6.1.1",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="6.1.1",
        title="Ensure permissions on password file are 644",
        description="""System password accounts database must be readable by all users but only writable by root.""",
        audit_command="""stat -c %a /etc/passwd""",
        remediation_command="""chmod 644 /etc/passwd""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-6.1.2": CisRecommendation(
        id="CIS-UBUNTU-22.04-6.1.2",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="6.1.2",
        title="Ensure permissions on shadow credential file are 640",
        description="""System password hashes must be restricted to root or shadow group.""",
        audit_command="""stat -c %a /etc/shadow""",
        remediation_command="""chmod 640 /etc/shadow""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-6.1.3": CisRecommendation(
        id="CIS-UBUNTU-22.04-6.1.3",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="6.1.3",
        title="Ensure permissions on group file are 644",
        description="""System group database must be readable by all users but only writable by root.""",
        audit_command="""stat -c %a /etc/group""",
        remediation_command="""chmod 644 /etc/group""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-UBUNTU-22.04-6.1.4": CisRecommendation(
        id="CIS-UBUNTU-22.04-6.1.4",
        benchmark_id="CIS-UBUNTU-22.04",
        benchmark_name="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rule_number="6.1.4",
        title="Ensure permissions on gshadow file are 640",
        description="""System group credential hashes must be restricted to root or shadow group.""",
        audit_command="""stat -c %a /etc/gshadow""",
        remediation_command="""chmod 640 /etc/gshadow""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-1.1.1": CisRecommendation(
        id="CIS-RHEL-9-1.1.1",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="1.1.1",
        title="Disable unused legacy filesystems",
        description="""Removing unneeded filesystem modules reduces kernel attack surface.""",
        audit_command="""modprobe -n -v cramfs""",
        remediation_command="""install cramfs /bin/true""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-1.1.2": CisRecommendation(
        id="CIS-RHEL-9-1.1.2",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="1.1.2",
        title="Ensure /tmp is mounted with nodev",
        description="""The nodev mount option prevents character or block devices from being mounted on temporary directories.""",
        audit_command="""findmnt -n /tmp""",
        remediation_command="""mount -o remount,nodev /tmp""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-1.1.3": CisRecommendation(
        id="CIS-RHEL-9-1.1.3",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="1.1.3",
        title="Ensure /tmp is mounted with nosuid",
        description="""The nosuid mount option prevents setuid and setgid bit execution on temporary partitions.""",
        audit_command="""findmnt -n /tmp""",
        remediation_command="""mount -o remount,nosuid /tmp""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-1.1.4": CisRecommendation(
        id="CIS-RHEL-9-1.1.4",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="1.1.4",
        title="Ensure /tmp is mounted with noexec",
        description="""The noexec mount option prevents direct execution of malicious binaries from world-writable directories.""",
        audit_command="""findmnt -n /tmp""",
        remediation_command="""mount -o remount,noexec /tmp""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-1.2.1": CisRecommendation(
        id="CIS-RHEL-9-1.2.1",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="1.2.1",
        title="Verify package repository GPG keys",
        description="""GPG signature verification guarantees authenticity of installed system binaries.""",
        audit_command="""apt-key list""",
        remediation_command="""apt-key update""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-1.3.1": CisRecommendation(
        id="CIS-RHEL-9-1.3.1",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="1.3.1",
        title="Ensure filesystem integrity monitoring is active",
        description="""Periodic integrity audits detect unauthorized modification to system libraries.""",
        audit_command="""crontab -l | grep aide""",
        remediation_command="""systemctl enable aide.timer""",
        profile=ProfileLevel.LEVEL_2,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-1.4.1": CisRecommendation(
        id="CIS-RHEL-9-1.4.1",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="1.4.1",
        title="Ensure bootloader password is set",
        description="""Setting a bootloader password prevents unauthorized alteration of kernel parameters during reboot.""",
        audit_command="""grep -E password /boot/grub/grub.cfg""",
        remediation_command="""grub-mkpasswd-pbkdf2""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-1.4.2": CisRecommendation(
        id="CIS-RHEL-9-1.4.2",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="1.4.2",
        title="Ensure bootloader configuration permissions are 600",
        description="""Restricting grub.cfg prevents non-root access to kernel boot configs.""",
        audit_command="""stat -c %a /boot/grub/grub.cfg""",
        remediation_command="""chmod 600 /boot/grub/grub.cfg""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-1.5.1": CisRecommendation(
        id="CIS-RHEL-9-1.5.1",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="1.5.1",
        title="Ensure ASLR address space layout randomization is active",
        description="""ASLR randomizes memory layout to prevent memory corruption exploits.""",
        audit_command="""sysctl kernel.randomize_va_space""",
        remediation_command="""sysctl -w kernel.randomize_va_space=2""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-1.5.2": CisRecommendation(
        id="CIS-RHEL-9-1.5.2",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="1.5.2",
        title="Ensure ptrace process debugging scope is restricted",
        description="""Restricting ptrace prevents unprivileged processes from injecting memory into other processes.""",
        audit_command="""sysctl kernel.yama.ptrace_scope""",
        remediation_command="""sysctl -w kernel.yama.ptrace_scope=1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-1.5.3": CisRecommendation(
        id="CIS-RHEL-9-1.5.3",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="1.5.3",
        title="Ensure core dump memory dumps are restricted",
        description="""Core dumps may contain sensitive plaintext passwords or cryptographic keys.""",
        audit_command="""grep core /etc/security/limits.conf""",
        remediation_command="""echo * hard core 0 >> /etc/security/limits.conf""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-2.1.1": CisRecommendation(
        id="CIS-RHEL-9-2.1.1",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="2.1.1",
        title="Ensure network time synchronization chrony is active",
        description="""Synchronized system clocks are critical for SIEM forensic timeline analysis.""",
        audit_command="""timedatectl status""",
        remediation_command="""systemctl enable --now chrony""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-3.1.1": CisRecommendation(
        id="CIS-RHEL-9-3.1.1",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="3.1.1",
        title="Ensure IP packet redirect sending is disabled",
        description="""Sending ICMP redirects allows systems to alter routing tables on remote hosts.""",
        audit_command="""sysctl net.ipv4.conf.all.send_redirects""",
        remediation_command="""sysctl -w net.ipv4.conf.all.send_redirects=0""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-3.1.2": CisRecommendation(
        id="CIS-RHEL-9-3.1.2",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="3.1.2",
        title="Ensure IP packet forwarding is disabled",
        description="""Disabling IP forwarding ensures standard servers do not act as network routers.""",
        audit_command="""sysctl net.ipv4.ip_forward""",
        remediation_command="""sysctl -w net.ipv4.ip_forward=0""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-3.1.3": CisRecommendation(
        id="CIS-RHEL-9-3.1.3",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="3.1.3",
        title="Ensure source routed packets are ignored",
        description="""Source routing allows adversaries to bypass firewall boundaries by specifying custom paths.""",
        audit_command="""sysctl net.ipv4.conf.all.accept_source_route""",
        remediation_command="""sysctl -w net.ipv4.conf.all.accept_source_route=0""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-3.1.4": CisRecommendation(
        id="CIS-RHEL-9-3.1.4",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="3.1.4",
        title="Ensure ICMP redirects are ignored",
        description="""Ignoring ICMP redirects prevents malicious route manipulation and traffic interception.""",
        audit_command="""sysctl net.ipv4.conf.all.accept_redirects""",
        remediation_command="""sysctl -w net.ipv4.conf.all.accept_redirects=0""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-3.1.5": CisRecommendation(
        id="CIS-RHEL-9-3.1.5",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="3.1.5",
        title="Ensure broadcast ICMP requests are dropped",
        description="""Ignoring ICMP broadcast requests protects against network amplification attacks.""",
        audit_command="""sysctl net.ipv4.icmp_echo_ignore_broadcasts""",
        remediation_command="""sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-3.1.6": CisRecommendation(
        id="CIS-RHEL-9-3.1.6",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="3.1.6",
        title="Ensure suspicious martian packets are logged",
        description="""Logging martian packets detects spoofed source IP addresses arriving on network interfaces.""",
        audit_command="""sysctl net.ipv4.conf.all.log_martians""",
        remediation_command="""sysctl -w net.ipv4.conf.all.log_martians=1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-3.1.7": CisRecommendation(
        id="CIS-RHEL-9-3.1.7",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="3.1.7",
        title="Ensure TCP SYN Cookies protection is enabled",
        description="""SYN cookies defend against TCP SYN flood denial of service attacks.""",
        audit_command="""sysctl net.ipv4.tcp_syncookies""",
        remediation_command="""sysctl -w net.ipv4.tcp_syncookies=1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-3.2.1": CisRecommendation(
        id="CIS-RHEL-9-3.2.1",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="3.2.1",
        title="Ensure host-based firewall UFW/iptables is active",
        description="""A host-based firewall protects against unauthorized inbound network connections.""",
        audit_command="""ufw status""",
        remediation_command="""ufw enable""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-4.1.1": CisRecommendation(
        id="CIS-RHEL-9-4.1.1",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="4.1.1",
        title="Ensure system auditd auditing daemon is enabled",
        description="""The audit daemon captures security-relevant system calls, file access, and auth events.""",
        audit_command="""systemctl is-enabled auditd""",
        remediation_command="""systemctl enable auditd""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-4.1.2": CisRecommendation(
        id="CIS-RHEL-9-4.1.2",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="4.1.2",
        title="Ensure audit log max file size is configured",
        description="""Configuring adequate log storage prevents premature rollover and telemetry loss.""",
        audit_command="""grep max_log_file /etc/audit/auditd.conf""",
        remediation_command="""sed -i s/^max_log_file.*/max_log_file=100/ /etc/audit/auditd.conf""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-4.1.3": CisRecommendation(
        id="CIS-RHEL-9-4.1.3",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="4.1.3",
        title="Ensure audit log retention keep_logs is set",
        description="""Preserving audit logs is necessary to maintain forensic integrity.""",
        audit_command="""grep max_log_file_action /etc/audit/auditd.conf""",
        remediation_command="""sed -i s/^max_log_file_action.*/max_log_file_action=keep_logs/ /etc/audit/auditd.conf""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-4.1.4": CisRecommendation(
        id="CIS-RHEL-9-4.1.4",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="4.1.4",
        title="Ensure administrative scope changes are audited",
        description="""Auditing sudoers configuration changes detects unauthorized privilege escalation.""",
        audit_command="""grep sudoers /etc/audit/rules.d/*.rules""",
        remediation_command="""echo -w /etc/sudoers -p wa -k scope >> /etc/audit/rules.d/50-scope.rules""",
        profile=ProfileLevel.LEVEL_2,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-4.1.5": CisRecommendation(
        id="CIS-RHEL-9-4.1.5",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="4.1.5",
        title="Ensure identity modifications are audited",
        description="""Auditing user database changes detects unauthorized account provisioning.""",
        audit_command="""grep identity /etc/audit/rules.d/*.rules""",
        remediation_command="""echo -w /etc/passwd -p wa -k identity >> /etc/audit/rules.d/50-identity.rules""",
        profile=ProfileLevel.LEVEL_2,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-5.1.1": CisRecommendation(
        id="CIS-RHEL-9-5.1.1",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="5.1.1",
        title="Ensure cron task scheduler is enabled",
        description="""Cron services execute scheduled maintenance and security monitoring tasks.""",
        audit_command="""systemctl is-enabled cron""",
        remediation_command="""systemctl enable --now cron""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-5.1.2": CisRecommendation(
        id="CIS-RHEL-9-5.1.2",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="5.1.2",
        title="Ensure permissions on crontab are 600",
        description="""Restricting permissions on crontab prevents unprivileged users from scheduling tasks.""",
        audit_command="""stat -c %a /etc/crontab""",
        remediation_command="""chmod 600 /etc/crontab""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-5.2.1": CisRecommendation(
        id="CIS-RHEL-9-5.2.1",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="5.2.1",
        title="Ensure SSH server protocol 2 is enforced",
        description="""SSH protocol 1 contains critical vulnerabilities that allow interception.""",
        audit_command="""sshd -T | grep protocol""",
        remediation_command="""echo Protocol 2 >> /etc/ssh/sshd_config""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-5.2.2": CisRecommendation(
        id="CIS-RHEL-9-5.2.2",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="5.2.2",
        title="Ensure SSH direct root login is disabled",
        description="""Disabling direct root login forces administrators to authenticate as named users first.""",
        audit_command="""sshd -T | grep permitrootlogin""",
        remediation_command="""sed -i s/^PermitRootLogin.*/PermitRootLogin no/ /etc/ssh/sshd_config""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-5.2.3": CisRecommendation(
        id="CIS-RHEL-9-5.2.3",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="5.2.3",
        title="Ensure SSH password authentication is disabled",
        description="""Key-based authentication mitigates password brute-force attacks.""",
        audit_command="""sshd -T | grep passwordauthentication""",
        remediation_command="""sed -i s/^PasswordAuthentication.*/PasswordAuthentication no/ /etc/ssh/sshd_config""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-5.2.4": CisRecommendation(
        id="CIS-RHEL-9-5.2.4",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="5.2.4",
        title="Ensure SSH MaxAuthTries is set to 4 or less",
        description="""Restricting authentication attempts protects against rapid password guessing.""",
        audit_command="""sshd -T | grep maxauthtries""",
        remediation_command="""sed -i s/^MaxAuthTries.*/MaxAuthTries 4/ /etc/ssh/sshd_config""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-5.2.5": CisRecommendation(
        id="CIS-RHEL-9-5.2.5",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="5.2.5",
        title="Ensure SSH idle session timeout is configured",
        description="""Terminating idle sessions prevents unauthorized access to unattended terminals.""",
        audit_command="""sshd -T | grep clientaliveinterval""",
        remediation_command="""echo ClientAliveInterval 300 >> /etc/ssh/sshd_config""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-5.3.1": CisRecommendation(
        id="CIS-RHEL-9-5.3.1",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="5.3.1",
        title="Ensure password hashing algorithm is SHA-512 or yescrypt",
        description="""Strong cryptographic hashing algorithms resist offline dictionary cracking.""",
        audit_command="""grep ENCRYPT_METHOD /etc/login.defs""",
        remediation_command="""sed -i s/^ENCRYPT_METHOD.*/ENCRYPT_METHOD YESCRYPT/ /etc/login.defs""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-5.3.2": CisRecommendation(
        id="CIS-RHEL-9-5.3.2",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="5.3.2",
        title="Ensure minimum password length is 14 characters",
        description="""Long passwords exponentially increase the difficulty of brute-force attacks.""",
        audit_command="""grep pam_pwquality /etc/pam.d/common-password""",
        remediation_command="""sed -i s/pam_pwquality.*/& minlen=14/ /etc/pam.d/common-password""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-5.4.1": CisRecommendation(
        id="CIS-RHEL-9-5.4.1",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="5.4.1",
        title="Ensure password maximum age is 90 days or less",
        description="""Periodic credential rotation limits the window of opportunity for stolen credentials.""",
        audit_command="""grep PASS_MAX_DAYS /etc/login.defs""",
        remediation_command="""sed -i s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/ /etc/login.defs""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-5.4.2": CisRecommendation(
        id="CIS-RHEL-9-5.4.2",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="5.4.2",
        title="Ensure password minimum age is 1 day or more",
        description="""Preventing immediate password changes prevents users from cycling passwords.""",
        audit_command="""grep PASS_MIN_DAYS /etc/login.defs""",
        remediation_command="""sed -i s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/ /etc/login.defs""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-6.1.1": CisRecommendation(
        id="CIS-RHEL-9-6.1.1",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="6.1.1",
        title="Ensure permissions on password file are 644",
        description="""System password accounts database must be readable by all users but only writable by root.""",
        audit_command="""stat -c %a /etc/passwd""",
        remediation_command="""chmod 644 /etc/passwd""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-6.1.2": CisRecommendation(
        id="CIS-RHEL-9-6.1.2",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="6.1.2",
        title="Ensure permissions on shadow credential file are 640",
        description="""System password hashes must be restricted to root or shadow group.""",
        audit_command="""stat -c %a /etc/shadow""",
        remediation_command="""chmod 640 /etc/shadow""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-6.1.3": CisRecommendation(
        id="CIS-RHEL-9-6.1.3",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="6.1.3",
        title="Ensure permissions on group file are 644",
        description="""System group database must be readable by all users but only writable by root.""",
        audit_command="""stat -c %a /etc/group""",
        remediation_command="""chmod 644 /etc/group""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-RHEL-9-6.1.4": CisRecommendation(
        id="CIS-RHEL-9-6.1.4",
        benchmark_id="CIS-RHEL-9",
        benchmark_name="CIS Red Hat Enterprise Linux 9 Benchmark",
        rule_number="6.1.4",
        title="Ensure permissions on gshadow file are 640",
        description="""System group credential hashes must be restricted to root or shadow group.""",
        audit_command="""stat -c %a /etc/gshadow""",
        remediation_command="""chmod 640 /etc/gshadow""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.LINUX
    ),
    "CIS-WINDOWS-2022-1.1.1": CisRecommendation(
        id="CIS-WINDOWS-2022-1.1.1",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="1.1.1",
        title="Disable unused legacy filesystems",
        description="""Removing unneeded filesystem modules reduces kernel attack surface.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_1.1.1""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_1.1.1 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-1.1.2": CisRecommendation(
        id="CIS-WINDOWS-2022-1.1.2",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="1.1.2",
        title="Ensure System32 is mounted with nodev",
        description="""The nodev mount option prevents character or block devices from being mounted on temporary directories.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_1.1.2""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_1.1.2 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-1.1.3": CisRecommendation(
        id="CIS-WINDOWS-2022-1.1.3",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="1.1.3",
        title="Ensure System32 is mounted with nosuid",
        description="""The nosuid mount option prevents setuid and setgid bit execution on temporary partitions.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_1.1.3""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_1.1.3 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-1.1.4": CisRecommendation(
        id="CIS-WINDOWS-2022-1.1.4",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="1.1.4",
        title="Ensure System32 is mounted with noexec",
        description="""The noexec mount option prevents direct execution of malicious binaries from world-writable directories.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_1.1.4""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_1.1.4 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-1.2.1": CisRecommendation(
        id="CIS-WINDOWS-2022-1.2.1",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="1.2.1",
        title="Verify Windows Update repository GPG keys",
        description="""GPG signature verification guarantees authenticity of installed system binaries.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_1.2.1""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_1.2.1 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-1.3.1": CisRecommendation(
        id="CIS-WINDOWS-2022-1.3.1",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="1.3.1",
        title="Ensure filesystem integrity monitoring is active",
        description="""Periodic integrity audits detect unauthorized modification to system libraries.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_1.3.1""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_1.3.1 -Value 1""",
        profile=ProfileLevel.LEVEL_2,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-1.4.1": CisRecommendation(
        id="CIS-WINDOWS-2022-1.4.1",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="1.4.1",
        title="Ensure bootloader password is set",
        description="""Setting a bootloader password prevents unauthorized alteration of kernel parameters during reboot.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_1.4.1""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_1.4.1 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-1.4.2": CisRecommendation(
        id="CIS-WINDOWS-2022-1.4.2",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="1.4.2",
        title="Ensure bootloader configuration permissions are 600",
        description="""Restricting grub.cfg prevents non-root access to kernel boot configs.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_1.4.2""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_1.4.2 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-1.5.1": CisRecommendation(
        id="CIS-WINDOWS-2022-1.5.1",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="1.5.1",
        title="Ensure ASLR address space layout randomization is active",
        description="""ASLR randomizes memory layout to prevent memory corruption exploits.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_1.5.1""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_1.5.1 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-1.5.2": CisRecommendation(
        id="CIS-WINDOWS-2022-1.5.2",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="1.5.2",
        title="Ensure ptrace process debugging scope is restricted",
        description="""Restricting ptrace prevents unprivileged processes from injecting memory into other processes.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_1.5.2""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_1.5.2 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-1.5.3": CisRecommendation(
        id="CIS-WINDOWS-2022-1.5.3",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="1.5.3",
        title="Ensure core dump memory dumps are restricted",
        description="""Core dumps may contain sensitive plaintext passwords or cryptographic keys.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_1.5.3""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_1.5.3 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-2.1.1": CisRecommendation(
        id="CIS-WINDOWS-2022-2.1.1",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="2.1.1",
        title="Ensure network time synchronization chrony is active",
        description="""Synchronized system clocks are critical for SIEM forensic timeline analysis.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_2.1.1""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_2.1.1 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-3.1.1": CisRecommendation(
        id="CIS-WINDOWS-2022-3.1.1",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="3.1.1",
        title="Ensure IP packet redirect sending is disabled",
        description="""Sending ICMP redirects allows systems to alter routing tables on remote hosts.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_3.1.1""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_3.1.1 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-3.1.2": CisRecommendation(
        id="CIS-WINDOWS-2022-3.1.2",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="3.1.2",
        title="Ensure IP packet forwarding is disabled",
        description="""Disabling IP forwarding ensures standard servers do not act as network routers.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_3.1.2""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_3.1.2 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-3.1.3": CisRecommendation(
        id="CIS-WINDOWS-2022-3.1.3",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="3.1.3",
        title="Ensure source routed packets are ignored",
        description="""Source routing allows adversaries to bypass firewall boundaries by specifying custom paths.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_3.1.3""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_3.1.3 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-3.1.4": CisRecommendation(
        id="CIS-WINDOWS-2022-3.1.4",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="3.1.4",
        title="Ensure ICMP redirects are ignored",
        description="""Ignoring ICMP redirects prevents malicious route manipulation and traffic interception.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_3.1.4""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_3.1.4 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-3.1.5": CisRecommendation(
        id="CIS-WINDOWS-2022-3.1.5",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="3.1.5",
        title="Ensure broadcast ICMP requests are dropped",
        description="""Ignoring ICMP broadcast requests protects against network amplification attacks.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_3.1.5""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_3.1.5 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-3.1.6": CisRecommendation(
        id="CIS-WINDOWS-2022-3.1.6",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="3.1.6",
        title="Ensure suspicious martian packets are logged",
        description="""Logging martian packets detects spoofed source IP addresses arriving on network interfaces.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_3.1.6""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_3.1.6 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-3.1.7": CisRecommendation(
        id="CIS-WINDOWS-2022-3.1.7",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="3.1.7",
        title="Ensure TCP SYN Cookies protection is enabled",
        description="""SYN cookies defend against TCP SYN flood denial of service attacks.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_3.1.7""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_3.1.7 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-3.2.1": CisRecommendation(
        id="CIS-WINDOWS-2022-3.2.1",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="3.2.1",
        title="Ensure host-based firewall UFW/iptables is active",
        description="""A host-based firewall protects against unauthorized inbound network connections.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_3.2.1""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_3.2.1 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-4.1.1": CisRecommendation(
        id="CIS-WINDOWS-2022-4.1.1",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="4.1.1",
        title="Ensure system auditd auditing daemon is enabled",
        description="""The audit daemon captures security-relevant system calls, file access, and auth events.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_4.1.1""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_4.1.1 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-4.1.2": CisRecommendation(
        id="CIS-WINDOWS-2022-4.1.2",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="4.1.2",
        title="Ensure audit log max file size is configured",
        description="""Configuring adequate log storage prevents premature rollover and telemetry loss.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_4.1.2""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_4.1.2 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-4.1.3": CisRecommendation(
        id="CIS-WINDOWS-2022-4.1.3",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="4.1.3",
        title="Ensure audit log retention keep_logs is set",
        description="""Preserving audit logs is necessary to maintain forensic integrity.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_4.1.3""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_4.1.3 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-4.1.4": CisRecommendation(
        id="CIS-WINDOWS-2022-4.1.4",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="4.1.4",
        title="Ensure administrative scope changes are audited",
        description="""Auditing sudoers configuration changes detects unauthorized privilege escalation.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_4.1.4""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_4.1.4 -Value 1""",
        profile=ProfileLevel.LEVEL_2,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-4.1.5": CisRecommendation(
        id="CIS-WINDOWS-2022-4.1.5",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="4.1.5",
        title="Ensure identity modifications are audited",
        description="""Auditing user database changes detects unauthorized account provisioning.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_4.1.5""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_4.1.5 -Value 1""",
        profile=ProfileLevel.LEVEL_2,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-5.1.1": CisRecommendation(
        id="CIS-WINDOWS-2022-5.1.1",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="5.1.1",
        title="Ensure Task Scheduler task scheduler is enabled",
        description="""Cron services execute scheduled maintenance and security monitoring tasks.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_5.1.1""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_5.1.1 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-5.1.2": CisRecommendation(
        id="CIS-WINDOWS-2022-5.1.2",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="5.1.2",
        title="Ensure permissions on Task Schedulertab are 600",
        description="""Restricting permissions on crontab prevents unprivileged users from scheduling tasks.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_5.1.2""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_5.1.2 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-5.2.1": CisRecommendation(
        id="CIS-WINDOWS-2022-5.2.1",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="5.2.1",
        title="Ensure RDP server protocol 2 is enforced",
        description="""SSH protocol 1 contains critical vulnerabilities that allow interception.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_5.2.1""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_5.2.1 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-5.2.2": CisRecommendation(
        id="CIS-WINDOWS-2022-5.2.2",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="5.2.2",
        title="Ensure RDP direct root login is disabled",
        description="""Disabling direct root login forces administrators to authenticate as named users first.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_5.2.2""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_5.2.2 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-5.2.3": CisRecommendation(
        id="CIS-WINDOWS-2022-5.2.3",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="5.2.3",
        title="Ensure RDP password authentication is disabled",
        description="""Key-based authentication mitigates password brute-force attacks.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_5.2.3""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_5.2.3 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-5.2.4": CisRecommendation(
        id="CIS-WINDOWS-2022-5.2.4",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="5.2.4",
        title="Ensure RDP MaxAuthTries is set to 4 or less",
        description="""Restricting authentication attempts protects against rapid password guessing.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_5.2.4""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_5.2.4 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-5.2.5": CisRecommendation(
        id="CIS-WINDOWS-2022-5.2.5",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="5.2.5",
        title="Ensure RDP idle session timeout is configured",
        description="""Terminating idle sessions prevents unauthorized access to unattended terminals.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_5.2.5""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_5.2.5 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-5.3.1": CisRecommendation(
        id="CIS-WINDOWS-2022-5.3.1",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="5.3.1",
        title="Ensure password hashing algorithm is SHA-512 or yescrypt",
        description="""Strong cryptographic hashing algorithms resist offline dictionary cracking.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_5.3.1""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_5.3.1 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-5.3.2": CisRecommendation(
        id="CIS-WINDOWS-2022-5.3.2",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="5.3.2",
        title="Ensure minimum password length is 14 characters",
        description="""Long passwords exponentially increase the difficulty of brute-force attacks.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_5.3.2""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_5.3.2 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-WINDOWS-2022-5.4.1": CisRecommendation(
        id="CIS-WINDOWS-2022-5.4.1",
        benchmark_id="CIS-WINDOWS-2022",
        benchmark_name="CIS Microsoft Windows Server 2022 Benchmark",
        rule_number="5.4.1",
        title="Ensure password maximum age is 90 days or less",
        description="""Periodic credential rotation limits the window of opportunity for stolen credentials.""",
        audit_command="""Get-ItemProperty -Path HKLM:/Software/Policies | Select Rule_5.4.1""",
        remediation_command="""Set-ItemProperty -Path HKLM:/Software/Policies -Name Rule_5.4.1 -Value 1""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.WINDOWS
    ),
    "CIS-AWS-3.0-1.1": CisRecommendation(
        id="CIS-AWS-3.0-1.1",
        benchmark_id="CIS-AWS-3.0",
        benchmark_name="CIS Amazon Web Services Foundations Benchmark",
        rule_number="1.1",
        title="Avoid the use of the AWS root account",
        description="""The root user has unrestricted privileges across all account resources.""",
        audit_command="""aws iam get-account-summary""",
        remediation_command="""Lock root credentials in physical vault and use IAM roles.""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.CLOUD
    ),
    "CIS-AWS-3.0-1.2": CisRecommendation(
        id="CIS-AWS-3.0-1.2",
        benchmark_id="CIS-AWS-3.0",
        benchmark_name="CIS Amazon Web Services Foundations Benchmark",
        rule_number="1.2",
        title="Ensure multi-factor authentication (MFA) is enabled for IAM users",
        description="""MFA adds a mandatory second authentication factor for console access.""",
        audit_command="""aws iam list-virtual-mfa-devices""",
        remediation_command="""Enforce MFA policy on all active IAM principals.""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.CLOUD
    ),
    "CIS-AWS-3.0-1.3": CisRecommendation(
        id="CIS-AWS-3.0-1.3",
        benchmark_id="CIS-AWS-3.0",
        benchmark_name="CIS Amazon Web Services Foundations Benchmark",
        rule_number="1.3",
        title="Ensure credentials unused for 90 days are disabled",
        description="""Stale credentials increase attack surface and risk of undetected compromise.""",
        audit_command="""aws iam get-credential-report""",
        remediation_command="""Delete or deactivate unused IAM credentials.""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.CLOUD
    ),
    "CIS-AWS-3.0-1.4": CisRecommendation(
        id="CIS-AWS-3.0-1.4",
        benchmark_id="CIS-AWS-3.0",
        benchmark_name="CIS Amazon Web Services Foundations Benchmark",
        rule_number="1.4",
        title="Ensure IAM access keys are rotated every 90 days",
        description="""Rotating access keys limits the impact of accidentally leaked tokens.""",
        audit_command="""aws iam list-access-keys""",
        remediation_command="""Issue new IAM access key and deprecate old key.""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.CLOUD
    ),
    "CIS-AWS-3.0-1.5": CisRecommendation(
        id="CIS-AWS-3.0-1.5",
        benchmark_id="CIS-AWS-3.0",
        benchmark_name="CIS Amazon Web Services Foundations Benchmark",
        rule_number="1.5",
        title="Ensure IAM password policy requires minimum 14 characters",
        description="""Enforcing complex passwords protects against dictionary and brute force attacks.""",
        audit_command="""aws iam get-account-password-policy""",
        remediation_command="""aws iam update-account-password-policy --minimum-password-length 14""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.CLOUD
    ),
    "CIS-AWS-3.0-2.1": CisRecommendation(
        id="CIS-AWS-3.0-2.1",
        benchmark_id="CIS-AWS-3.0",
        benchmark_name="CIS Amazon Web Services Foundations Benchmark",
        rule_number="2.1",
        title="Ensure S3 Bucket Policy enforces TLS HTTPS encrypted transport",
        description="""Enforcing TLS in S3 bucket policies protects data in transit from eavesdropping.""",
        audit_command="""aws s3api get-bucket-policy""",
        remediation_command="""Attach secure transport policy condition to bucket.""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.CLOUD
    ),
    "CIS-AWS-3.0-2.2": CisRecommendation(
        id="CIS-AWS-3.0-2.2",
        benchmark_id="CIS-AWS-3.0",
        benchmark_name="CIS Amazon Web Services Foundations Benchmark",
        rule_number="2.2",
        title="Ensure S3 Buckets have Block Public Access enabled",
        description="""Public S3 buckets are a leading cause of enterprise cloud data breaches.""",
        audit_command="""aws s3api get-public-access-block""",
        remediation_command="""aws s3api put-public-access-block --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.CLOUD
    ),
    "CIS-AWS-3.0-2.3": CisRecommendation(
        id="CIS-AWS-3.0-2.3",
        benchmark_id="CIS-AWS-3.0",
        benchmark_name="CIS Amazon Web Services Foundations Benchmark",
        rule_number="2.3",
        title="Ensure EBS volume default encryption is enabled in all regions",
        description="""Default EBS encryption ensures all compute storage is encrypted at rest.""",
        audit_command="""aws ec2 get-ebs-encryption-by-default""",
        remediation_command="""aws ec2 enable-ebs-encryption-by-default""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.CLOUD
    ),
    "CIS-AWS-3.0-2.4": CisRecommendation(
        id="CIS-AWS-3.0-2.4",
        benchmark_id="CIS-AWS-3.0",
        benchmark_name="CIS Amazon Web Services Foundations Benchmark",
        rule_number="2.4",
        title="Ensure RDS database storage encryption is enabled",
        description="""Encrypting database storage protects customer data at rest.""",
        audit_command="""aws rds describe-db-instances""",
        remediation_command="""Enable KMS storage encryption on RDS database instances.""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.CLOUD
    ),
    "CIS-AWS-3.0-3.1": CisRecommendation(
        id="CIS-AWS-3.0-3.1",
        benchmark_id="CIS-AWS-3.0",
        benchmark_name="CIS Amazon Web Services Foundations Benchmark",
        rule_number="3.1",
        title="Ensure CloudTrail is enabled across all regions",
        description="""CloudTrail provides audit telemetry of all API operations in the account.""",
        audit_command="""aws cloudtrail describe-trails""",
        remediation_command="""aws cloudtrail create-trail --is-multi-region-trail""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.CLOUD
    ),
    "CIS-AWS-3.0-3.2": CisRecommendation(
        id="CIS-AWS-3.0-3.2",
        benchmark_id="CIS-AWS-3.0",
        benchmark_name="CIS Amazon Web Services Foundations Benchmark",
        rule_number="3.2",
        title="Ensure CloudTrail log file validation is enabled",
        description="""Log file validation uses cryptographic digests to verify audit log integrity.""",
        audit_command="""aws cloudtrail get-trail-status""",
        remediation_command="""aws cloudtrail update-trail --enable-log-file-validation""",
        profile=ProfileLevel.LEVEL_2,
        scored=True,
        platform=BenchmarkPlatform.CLOUD
    ),
    "CIS-AWS-3.0-4.1": CisRecommendation(
        id="CIS-AWS-3.0-4.1",
        benchmark_id="CIS-AWS-3.0",
        benchmark_name="CIS Amazon Web Services Foundations Benchmark",
        rule_number="4.1",
        title="Ensure Security Groups do not allow ingress from 0.0.0.0/0 to port 22",
        description="""Exposing SSH publicly exposes compute instances to continuous brute force attacks.""",
        audit_command="""aws ec2 describe-security-groups""",
        remediation_command="""Revoke 0.0.0.0/0 inbound rules on port 22.""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.CLOUD
    ),
    "CIS-AWS-3.0-4.2": CisRecommendation(
        id="CIS-AWS-3.0-4.2",
        benchmark_id="CIS-AWS-3.0",
        benchmark_name="CIS Amazon Web Services Foundations Benchmark",
        rule_number="4.2",
        title="Ensure Security Groups do not allow ingress from 0.0.0.0/0 to port 3389",
        description="""Exposing RDP publicly allows remote desktop exploits and ransomware entry.""",
        audit_command="""aws ec2 describe-security-groups""",
        remediation_command="""Revoke 0.0.0.0/0 inbound rules on port 3389.""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.CLOUD
    ),
    "CIS-AWS-3.0-4.3": CisRecommendation(
        id="CIS-AWS-3.0-4.3",
        benchmark_id="CIS-AWS-3.0",
        benchmark_name="CIS Amazon Web Services Foundations Benchmark",
        rule_number="4.3",
        title="Ensure default VPC security groups restrict all inbound and outbound traffic",
        description="""Default security groups should not be used for active instance traffic routing.""",
        audit_command="""aws ec2 describe-security-groups""",
        remediation_command="""Remove all authorization rules from default security group.""",
        profile=ProfileLevel.LEVEL_2,
        scored=True,
        platform=BenchmarkPlatform.CLOUD
    ),
    "CIS-K8S-1.8-1.1.1": CisRecommendation(
        id="CIS-K8S-1.8-1.1.1",
        benchmark_id="CIS-K8S-1.8",
        benchmark_name="CIS Kubernetes Benchmark",
        rule_number="1.1.1",
        title="Ensure API server pod specification file permissions are 600",
        description="""Restricting permissions prevents unauthorized tampering with Kubernetes control plane API server configuration.""",
        audit_command="""stat -c %a /etc/kubernetes/manifests/kube-apiserver.yaml""",
        remediation_command="""chmod 600 /etc/kubernetes/manifests/kube-apiserver.yaml""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.CONTAINERS
    ),
    "CIS-K8S-1.8-1.1.2": CisRecommendation(
        id="CIS-K8S-1.8-1.1.2",
        benchmark_id="CIS-K8S-1.8",
        benchmark_name="CIS Kubernetes Benchmark",
        rule_number="1.1.2",
        title="Ensure API server anonymous requests are disabled",
        description="""Disabling anonymous requests forces all incoming API invocations to be authenticated.""",
        audit_command="""grep anonymous-auth /etc/kubernetes/manifests/kube-apiserver.yaml""",
        remediation_command="""Set --anonymous-auth=false in kube-apiserver arguments.""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.CONTAINERS
    ),
    "CIS-K8S-1.8-1.1.3": CisRecommendation(
        id="CIS-K8S-1.8-1.1.3",
        benchmark_id="CIS-K8S-1.8",
        benchmark_name="CIS Kubernetes Benchmark",
        rule_number="1.1.3",
        title="Ensure API server basic authentication is not used",
        description="""Basic authentication passes unencrypted passwords in HTTP headers without revocation capability.""",
        audit_command="""grep basic-auth /etc/kubernetes/manifests/kube-apiserver.yaml""",
        remediation_command="""Remove --basic-auth-file parameter from kube-apiserver manifest.""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.CONTAINERS
    ),
    "CIS-K8S-1.8-1.1.4": CisRecommendation(
        id="CIS-K8S-1.8-1.1.4",
        benchmark_id="CIS-K8S-1.8",
        benchmark_name="CIS Kubernetes Benchmark",
        rule_number="1.1.4",
        title="Ensure API server token authentication file is not used",
        description="""Static token authentication lacks credential rotation and fine-grained authorization.""",
        audit_command="""grep token-auth /etc/kubernetes/manifests/kube-apiserver.yaml""",
        remediation_command="""Remove --token-auth-file parameter from kube-apiserver manifest.""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.CONTAINERS
    ),
    "CIS-K8S-1.8-1.1.5": CisRecommendation(
        id="CIS-K8S-1.8-1.1.5",
        benchmark_id="CIS-K8S-1.8",
        benchmark_name="CIS Kubernetes Benchmark",
        rule_number="1.1.5",
        title="Ensure API server audit logging is enabled",
        description="""Kubernetes audit logging records administrative operations, pod creation, and secret access.""",
        audit_command="""grep audit-log /etc/kubernetes/manifests/kube-apiserver.yaml""",
        remediation_command="""Configure --audit-log-path and --audit-policy-file in kube-apiserver arguments.""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.CONTAINERS
    ),
    "CIS-K8S-1.8-1.2.1": CisRecommendation(
        id="CIS-K8S-1.8-1.2.1",
        benchmark_id="CIS-K8S-1.8",
        benchmark_name="CIS Kubernetes Benchmark",
        rule_number="1.2.1",
        title="Ensure etcd key-value store file permissions are 600",
        description="""etcd holds all cluster secrets, service account tokens, and desired state manifests.""",
        audit_command="""stat -c %a /etc/kubernetes/manifests/etcd.yaml""",
        remediation_command="""chmod 600 /etc/kubernetes/manifests/etcd.yaml""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.CONTAINERS
    ),
    "CIS-K8S-1.8-1.2.2": CisRecommendation(
        id="CIS-K8S-1.8-1.2.2",
        benchmark_id="CIS-K8S-1.8",
        benchmark_name="CIS Kubernetes Benchmark",
        rule_number="1.2.2",
        title="Ensure etcd client TLS mutual authentication is configured",
        description="""Enforcing mutual TLS authentication prevents unauthorized reads or writes to etcd storage.""",
        audit_command="""grep client-cert-auth /etc/kubernetes/manifests/etcd.yaml""",
        remediation_command="""Set --client-cert-auth=true in etcd manifest.""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.CONTAINERS
    ),
    "CIS-K8S-1.8-4.1.1": CisRecommendation(
        id="CIS-K8S-1.8-4.1.1",
        benchmark_id="CIS-K8S-1.8",
        benchmark_name="CIS Kubernetes Benchmark",
        rule_number="4.1.1",
        title="Ensure kubelet anonymous requests are disabled",
        description="""Disabling anonymous access prevents unauthorized users from querying kubelet health and pod stats.""",
        audit_command="""grep anonymous /var/lib/kubelet/config.yaml""",
        remediation_command="""Set authentication.anonymous.enabled to false in kubelet configuration.""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.CONTAINERS
    ),
    "CIS-K8S-1.8-4.1.2": CisRecommendation(
        id="CIS-K8S-1.8-4.1.2",
        benchmark_id="CIS-K8S-1.8",
        benchmark_name="CIS Kubernetes Benchmark",
        rule_number="4.1.2",
        title="Ensure kubelet authorization mode is Webhook",
        description="""Kubelet requests must be verified against Kubernetes RBAC policies.""",
        audit_command="""grep mode /var/lib/kubelet/config.yaml""",
        remediation_command="""Set authorization.mode to Webhook in kubelet configuration.""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.CONTAINERS
    ),
    "CIS-K8S-1.8-5.1.1": CisRecommendation(
        id="CIS-K8S-1.8-5.1.1",
        benchmark_id="CIS-K8S-1.8",
        benchmark_name="CIS Kubernetes Benchmark",
        rule_number="5.1.1",
        title="Ensure default service accounts do not have active API credentials bound",
        description="""Default service accounts in Kubernetes namespaces should not possess cluster-wide administrative privileges.""",
        audit_command="""kubectl get clusterrolebindings""",
        remediation_command="""Create dedicated ServiceAccounts with scoped RoleBindings for containerized workloads.""",
        profile=ProfileLevel.LEVEL_1,
        scored=True,
        platform=BenchmarkPlatform.CONTAINERS
    ),
}


class CisBenchmarkEngine:
    """Query and auditing engine for Center for Internet Security (CIS) benchmarks."""

    @classmethod
    def get_recommendation(cls, rec_id: str) -> Optional[CisRecommendation]:
        return RECOMMENDATIONS_CATALOG.get(rec_id)

    @classmethod
    def get_by_benchmark(cls, benchmark_id: str) -> List[CisRecommendation]:
        return [r for r in RECOMMENDATIONS_CATALOG.values() if r.benchmark_id == benchmark_id]

    @classmethod
    def get_by_platform(cls, platform: BenchmarkPlatform) -> List[CisRecommendation]:
        return [r for r in RECOMMENDATIONS_CATALOG.values() if r.platform == platform]

    @classmethod
    def get_scored_recommendations(cls, benchmark_id: Optional[str] = None) -> List[CisRecommendation]:
        rules = cls.get_by_benchmark(benchmark_id) if benchmark_id else list(RECOMMENDATIONS_CATALOG.values())
        return [r for r in rules if r.scored]

    @classmethod
    def search(cls, query: str) -> List[CisRecommendation]:
        kw = query.lower()
        return [
            r for r in RECOMMENDATIONS_CATALOG.values()
            if kw in r.id.lower() or kw in r.title.lower() or kw in r.description.lower()
        ]

    @classmethod
    def audit_system_posture(cls, benchmark_id: str, passing_rule_ids: Set[str]) -> Dict[str, Any]:
        rules = cls.get_by_benchmark(benchmark_id)
        total = len(rules)
        passed = sum(1 for r in rules if r.id in passing_rule_ids)
        failed = [r.id for r in rules if r.id not in passing_rule_ids]
        score_pct = round((passed / total) * 100, 2) if total > 0 else 0.0

        return {
            "benchmark_id": benchmark_id,
            "total_rules": total,
            "passed_count": passed,
            "failed_count": len(failed),
            "compliance_score_percent": score_pct,
            "failed_rules": failed[:20]
        }

    @classmethod
    def get_catalog_summary(cls) -> Dict[str, Any]:
        bench_summary = {}
        for bid, meta in BENCHMARKS_CATALOG.items():
            rules = cls.get_by_benchmark(bid)
            bench_summary[bid] = {
                "name": meta.name,
                "platform": meta.platform.value,
                "rules_count": len(rules),
                "level1_count": sum(1 for r in rules if r.profile == ProfileLevel.LEVEL_1),
                "level2_count": sum(1 for r in rules if r.profile == ProfileLevel.LEVEL_2),
                "scored_count": sum(1 for r in rules if r.scored)
            }
        return {
            "total_benchmarks": len(BENCHMARKS_CATALOG),
            "total_recommendations": len(RECOMMENDATIONS_CATALOG),
            "benchmarks": bench_summary
        }
