"""Configuration dataclasses and YAML loading."""

from dataclasses import dataclass, field
from typing import Optional
import os
import yaml


# Known per-service extra fields exposed in the dashboard config UI.
# Each entry maps field_name -> {label, default, type, placeholder?}.
SERVICE_EXTRA_SCHEMA = {
    "ssh": {
        "hostname": {"label": "Hostname", "default": "prod-web-01", "type": "text"},
        "prompt": {"label": "Shell Prompt", "default": "root@prod-web-01:~# ", "type": "text"},
        "credentials": {"label": "Honeytoken Creds (user:pass per line)", "default": "", "type": "textarea",
                        "placeholder": "admin:admin123\nroot:toor"},
    },
    "docker": {
        "hostname": {"label": "Docker Hostname", "default": "prod-docker-01", "type": "text"},
    },
    "ftp": {
        "home_dir": {"label": "Home Directory", "default": "/home/admin", "type": "text"},
    },
    "telnet": {
        "hostname": {"label": "Hostname", "default": "gateway-01", "type": "text"},
        "prompt": {"label": "Shell Prompt", "default": "root@gateway-01:~$ ", "type": "text"},
        "additional_ports": {"label": "Additional Ports (comma-sep)", "default": "23", "type": "text"},
        "credentials": {"label": "Honeytoken Creds (user:pass per line)", "default": "", "type": "textarea",
                        "placeholder": "admin:admin123\nroot:toor"},
    },
    "mysql": {
        "databases": {"label": "Fake Databases (comma-sep)", "default": "information_schema,mysql,performance_schema,production_db,user_data", "type": "text"},
    },
    "smtp": {
        "hostname": {"label": "Mail Hostname", "default": "mail.example.com", "type": "text"},
    },
    "mongodb": {
        "databases": {"label": "Fake Databases (comma-sep)", "default": "admin,config,local,production,users", "type": "text"},
    },
    "redis": {
        "version": {"label": "Redis Version", "default": "7.2.4", "type": "text"},
        "password": {"label": "AUTH Password (empty = no auth)", "default": "", "type": "text"},
    },
    "vnc": {
        "resolution": {"label": "Screen Resolution", "default": "1024x768", "type": "text"},
    },
    "smb": {
        "workgroup": {"label": "Workgroup", "default": "WORKGROUP", "type": "text"},
    },
    "adb": {
        "device_model": {"label": "Device Model", "default": "Pixel 7", "type": "text"},
        "android_version": {"label": "Android Version", "default": "14", "type": "text"},
    },
}

# Banner presets per service for quick selection in the UI.
BANNER_PRESETS = {
    "ssh": [
        {"label": "OpenSSH 8.9 Ubuntu", "value": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"},
        {"label": "OpenSSH 7.4 CentOS", "value": "SSH-2.0-OpenSSH_7.4"},
        {"label": "OpenSSH 9.6 Debian", "value": "SSH-2.0-OpenSSH_9.6p1 Debian-4"},
        {"label": "OpenSSH 9.2 Raspbian", "value": "SSH-2.0-OpenSSH_9.2p1 Raspbian-2+deb12u3"},
        {"label": "OpenSSH 8.2 AWS Linux", "value": "SSH-2.0-OpenSSH_8.2"},
        {"label": "Dropbear 2022.83", "value": "SSH-2.0-dropbear_2022.83"},
        {"label": "Dropbear 2020.81 (IoT)", "value": "SSH-2.0-dropbear_2020.81"},
        {"label": "libssh 0.10.6", "value": "SSH-2.0-libssh-0.10.6"},
        {"label": "Cisco IOS", "value": "SSH-2.0-Cisco-1.25"},
        {"label": "MikroTik RouterOS", "value": "SSH-2.0-ROSSSH"},
    ],
    "docker": [
        {"label": "Docker 20.10 (default)", "value": "Docker/20.10.24"},
        {"label": "Docker 24.0", "value": "Docker/24.0.7"},
        {"label": "Docker 25.0", "value": "Docker/25.0.3"},
        {"label": "Podman 4.9", "value": "Podman/4.9.3"},
    ],
    "ftp": [
        {"label": "vsftpd 3.0.5", "value": "220 (vsFTPd 3.0.5)"},
        {"label": "vsftpd 3.0.3 Ubuntu", "value": "220 (vsFTPd 3.0.3)"},
        {"label": "ProFTPD 1.3.8", "value": "220 ProFTPD 1.3.8 Server ready."},
        {"label": "ProFTPD 1.3.5 Debian", "value": "220 ProFTPD 1.3.5e Server (Debian)"},
        {"label": "Pure-FTPd", "value": "220 FTP Server ready."},
        {"label": "FileZilla Server 1.8", "value": "220-FileZilla Server 1.8.0\r\n220 Welcome"},
        {"label": "Microsoft FTP", "value": "220 Microsoft FTP Service"},
        {"label": "WU-FTPD", "value": "220 ftp.example.com FTP server (Version wu-2.6.2) ready."},
    ],
    "smb": [
        {"label": "Samba 4.18 Ubuntu", "value": "Samba 4.18.6-Ubuntu"},
        {"label": "Samba 4.15 CentOS", "value": "Samba 4.15.5"},
        {"label": "Samba 4.19 Debian", "value": "Samba 4.19.4-Debian"},
        {"label": "Windows Server 2019", "value": "Windows Server 2019 Standard 17763"},
        {"label": "Windows Server 2022", "value": "Windows Server 2022 Standard 20348"},
        {"label": "NAS Synology", "value": "Samba 4.15.13-Synology"},
    ],
    "mysql": [
        {"label": "MySQL 5.7 Ubuntu", "value": "5.7.42-0ubuntu0.18.04.1"},
        {"label": "MySQL 8.0 Debian", "value": "8.0.33-0ubuntu0.22.04.2"},
        {"label": "MySQL 8.0.36", "value": "8.0.36"},
        {"label": "MySQL 8.4 LTS", "value": "8.4.0"},
        {"label": "MariaDB 10.11", "value": "5.5.5-10.11.2-MariaDB"},
        {"label": "MariaDB 10.6 Ubuntu", "value": "5.5.5-10.6.16-MariaDB-0ubuntu0.22.04.1"},
        {"label": "MariaDB 11.3", "value": "5.5.5-11.3.2-MariaDB"},
        {"label": "Percona 8.0", "value": "8.0.35-27"},
    ],
    "telnet": [
        {"label": "Linux login", "value": "Linux gateway-01 5.15.0-88-generic"},
        {"label": "Cisco IOS", "value": "User Access Verification"},
        {"label": "MikroTik RouterOS", "value": "MikroTik v7.13.5"},
        {"label": "Juniper JUNOS", "value": "Amnesiac (ttyu0)\n\nlogin:"},
        {"label": "HP ProCurve Switch", "value": "ProCurve J9021A Switch 2810-24G\nPress any key to continue"},
        {"label": "Huawei VRP", "value": "Warning: Telnet is not a secure protocol.\n\nLogin authentication\n\nUsername:"},
    ],
    "smtp": [
        {"label": "Postfix Ubuntu", "value": "220 mail.example.com ESMTP Postfix (Ubuntu)"},
        {"label": "Postfix Debian", "value": "220 mail.example.com ESMTP Postfix (Debian/GNU)"},
        {"label": "Exim4 Debian", "value": "220 mail.example.com ESMTP Exim 4.96 #2"},
        {"label": "Exim4 cPanel", "value": "220-mail.example.com ESMTP Exim 4.96.2 #2"},
        {"label": "Sendmail", "value": "220 mail.example.com ESMTP Sendmail 8.17.1"},
        {"label": "Microsoft Exchange", "value": "220 mail.example.com Microsoft ESMTP MAIL Service ready"},
        {"label": "hMailServer", "value": "220 mail.example.com ESMTP"},
        {"label": "Haraka", "value": "220 mail.example.com ESMTP Haraka/3.0.2 ready"},
    ],
    "mongodb": [
        {"label": "MongoDB 5.0", "value": "5.0.22"},
        {"label": "MongoDB 6.0", "value": "6.0.12"},
        {"label": "MongoDB 7.0", "value": "7.0.4"},
        {"label": "MongoDB 7.0.9", "value": "7.0.9"},
        {"label": "MongoDB 8.0", "value": "8.0.0"},
        {"label": "Percona Server 7.0", "value": "7.0.4-2"},
    ],
    "vnc": [
        {"label": "Workstation", "value": "prod-workstation:0"},
        {"label": "Dev Desktop", "value": "dev-desktop:0"},
        {"label": "Server Console", "value": "srv-console:0"},
        {"label": "Finance Terminal", "value": "fin-terminal-03:0"},
        {"label": "SCADA HMI", "value": "scada-hmi-01:0"},
        {"label": "Lab Desktop", "value": "lab-desktop-12:0"},
        {"label": "Kiosk Display", "value": "kiosk-lobby:0"},
        {"label": "Jump Box", "value": "jumpbox-dmz:0"},
    ],
    "redis": [
        {"label": "Redis 7.2", "value": "7.2.4"},
        {"label": "Redis 7.0", "value": "7.0.15"},
        {"label": "Redis 6.2 LTS", "value": "6.2.14"},
        {"label": "Redis 5.0 (legacy)", "value": "5.0.14"},
        {"label": "KeyDB 6.3", "value": "6.3.4"},
        {"label": "Valkey 7.2", "value": "7.2.5"},
    ],
    "adb": [
        {"label": "Pixel 7", "value": "device::Pixel 7"},
        {"label": "Pixel 8 Pro", "value": "device::Pixel 8 Pro"},
        {"label": "Samsung Galaxy S23", "value": "device::Galaxy S23"},
        {"label": "Samsung Galaxy S24 Ultra", "value": "device::Galaxy S24 Ultra"},
        {"label": "OnePlus 12", "value": "device::OnePlus 12"},
        {"label": "Xiaomi 14", "value": "device::Xiaomi 14"},
        {"label": "Android TV Box", "value": "device::SHIELD Android TV"},
        {"label": "Fire TV Stick", "value": "device::AFTSS (Fire TV Stick)"},
        {"label": "IP Camera (Hikvision)", "value": "device::DS-2CD2143G2-IU"},
    ],
}


@dataclass
class ServiceConfig:
    enabled: bool = True
    port: int = 0
    banner: str = ""
    extra: dict = field(default_factory=dict)


@dataclass
class DashboardConfig:
    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 8080


@dataclass
class AlertConfig:
    enabled: bool = True
    webhook_url: Optional[str] = None
    webhook_headers: dict = field(default_factory=dict)
    rules: dict = field(default_factory=dict)


@dataclass
class HoneypotConfig:
    ssh: ServiceConfig = field(default_factory=lambda: ServiceConfig(port=2222, banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"))
    docker: ServiceConfig = field(default_factory=lambda: ServiceConfig(port=2375))
    ftp: ServiceConfig = field(default_factory=lambda: ServiceConfig(port=21, banner="220 FTP Server ready."))
    smb: ServiceConfig = field(default_factory=lambda: ServiceConfig(port=4450))
    mysql: ServiceConfig = field(default_factory=lambda: ServiceConfig(port=3306, banner="5.7.42-0ubuntu0.18.04.1"))
    telnet: ServiceConfig = field(default_factory=lambda: ServiceConfig(port=2323, banner="gateway-01 login: ", extra={"additional_ports": [23]}))
    smtp: ServiceConfig = field(default_factory=lambda: ServiceConfig(port=25, banner="220 mail.example.com ESMTP Postfix (Ubuntu)"))
    mongodb: ServiceConfig = field(default_factory=lambda: ServiceConfig(port=27017, banner="6.0.12"))
    vnc: ServiceConfig = field(default_factory=lambda: ServiceConfig(port=5900, banner="prod-workstation:0"))
    redis: ServiceConfig = field(default_factory=lambda: ServiceConfig(port=6379))
    adb: ServiceConfig = field(default_factory=lambda: ServiceConfig(port=5555, banner="device::Pixel 7"))
    dashboard: DashboardConfig = field(default_factory=lambda: DashboardConfig(port=8843))
    alerts: AlertConfig = field(default_factory=AlertConfig)
    database_path: str = "honeypot.db"
    log_level: str = "INFO"

    def get_service_config(self, name: str) -> ServiceConfig:
        return getattr(self, name, ServiceConfig(enabled=False))

    def enabled_services(self) -> list:
        services = []
        for name in ("ssh", "docker", "ftp", "smb", "mysql", "telnet", "smtp", "mongodb", "vnc", "redis", "adb"):
            cfg = self.get_service_config(name)
            if cfg.enabled:
                services.append(name)
        return services

    def to_dict(self) -> dict:
        """Serialize entire config to a dictionary."""
        result = {}
        for name in ("ssh", "docker", "ftp", "smb", "mysql", "telnet", "smtp", "mongodb", "vnc", "redis", "adb"):
            cfg = self.get_service_config(name)
            entry = {
                "enabled": cfg.enabled,
                "port": cfg.port,
                "banner": cfg.banner,
            }
            if cfg.extra:
                entry["extra"] = dict(cfg.extra)
            result[name] = entry
        result["dashboard"] = {
            "enabled": self.dashboard.enabled,
            "host": self.dashboard.host,
            "port": self.dashboard.port,
        }
        result["alerts"] = {
            "enabled": self.alerts.enabled,
            "webhook_url": self.alerts.webhook_url,
            "webhook_headers": self.alerts.webhook_headers,
        }
        result["database_path"] = self.database_path
        result["log_level"] = self.log_level
        return result


def _merge_service(base: ServiceConfig, overrides: dict) -> ServiceConfig:
    if "enabled" in overrides:
        base.enabled = overrides["enabled"]
    if "port" in overrides:
        base.port = overrides["port"]
    if "banner" in overrides:
        base.banner = overrides["banner"]
    for k, v in overrides.items():
        if k not in ("enabled", "port", "banner"):
            base.extra[k] = v
    return base


def load_config(path: Optional[str] = None) -> HoneypotConfig:
    """Load config from YAML file, falling back to defaults."""
    config = HoneypotConfig()
    if path is None:
        return config

    with open(path, "r") as f:
        raw = yaml.safe_load(f) or {}

    for svc_name in ("ssh", "docker", "ftp", "smb", "mysql", "telnet", "smtp", "mongodb", "vnc", "redis", "adb"):
        if svc_name in raw:
            _merge_service(getattr(config, svc_name), raw[svc_name])

    if "dashboard" in raw:
        d = raw["dashboard"]
        if "enabled" in d:
            config.dashboard.enabled = d["enabled"]
        if "host" in d:
            config.dashboard.host = d["host"]
        if "port" in d:
            config.dashboard.port = d["port"]

    if "alerts" in raw:
        a = raw["alerts"]
        if "enabled" in a:
            config.alerts.enabled = a["enabled"]
        if "webhook_url" in a:
            config.alerts.webhook_url = a["webhook_url"]
        if "webhook_headers" in a:
            config.alerts.webhook_headers = a["webhook_headers"]
        if "rules" in a:
            config.alerts.rules = a["rules"]

    if "database_path" in raw:
        config.database_path = raw["database_path"]
    if "log_level" in raw:
        config.log_level = raw["log_level"]

    return config


def save_config(config: HoneypotConfig, path: str = "mantis_config.yaml"):
    """Write the current config to a YAML file."""
    data = config.to_dict()
    # Flatten extra into service dicts for clean YAML
    for name in ("ssh", "docker", "ftp", "smb", "mysql", "telnet", "smtp", "mongodb", "vnc", "redis", "adb"):
        svc = data.get(name, {})
        extra = svc.pop("extra", None)
        if extra:
            svc.update(extra)
    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    return os.path.abspath(path)
