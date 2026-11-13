"""Assets inventory models, loader, and enrichment lookup helpers."""

import ipaddress
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field


class HostAsset(BaseModel):
    name: str
    hostname: str | None = None
    role: str
    zone: Literal["it", "dmz", "ot", "mgmt"]
    ips: dict[str, str] = Field(default_factory=dict)
    is_decoy: bool = False
    process_critical: bool = False
    criticality: Literal["low", "medium", "high", "process_critical"] = "low"
    ssh_users: list[str] = Field(default_factory=list)
    allowed_ssh_src_zones: list[str] = Field(default_factory=list)
    allowed_ssh_src_hosts: list[str] = Field(default_factory=list)
    allowed_ot_writers: list[str] = Field(default_factory=list)


def load_maintenance_window() -> tuple[int, int]:
    """Load maintenance window start and end hours (default: 2 to 4 from lab/benign/config.yaml)."""
    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    config_path = repo_root / "lab" / "benign" / "config.yaml"
    if config_path.is_file():
        try:
            with open(config_path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                mw = data.get("maintenance_window", {})
                return int(mw.get("start_hour", 2)), int(mw.get("end_hour", 4))
        except Exception:
            pass
    return (2, 4)


class HoneyCredential(BaseModel):
    username: str
    decoy: list[str] = Field(default_factory=list)


class AssetInventory(BaseModel):
    hosts: list[HostAsset] = Field(default_factory=list)
    honey_credentials: list[HoneyCredential] = Field(default_factory=list)
    honey_files: list[str] = Field(default_factory=list)
    maintenance_window: tuple[int, int] = Field(default_factory=load_maintenance_window)

    def is_in_maintenance_window(self, dt_or_hour: Any) -> bool:
        start_hour, end_hour = self.maintenance_window
        hour = dt_or_hour.hour if hasattr(dt_or_hour, "hour") else int(dt_or_hour)
        return start_hour <= hour < end_hour

    def get_host_by_name(self, name: str) -> HostAsset | None:
        name_lower = name.strip().lower()
        for host in self.hosts:
            if host.name.lower() == name_lower:
                return host
            if host.hostname and host.hostname.lower() == name_lower:
                return host
        return None

    def get_host_by_ip(self, ip: str | None) -> HostAsset | None:
        if not ip:
            return None
        ip_clean = ip.strip()
        for host in self.hosts:
            if ip_clean in host.ips.values():
                return host
        return None

    def get_zone_for_ip(self, ip: str | None) -> str | None:
        if not ip:
            return None
        ip_clean = ip.strip()
        host = self.get_host_by_ip(ip_clean)
        if host:
            # If the host has an interface matching this specific IP, return that interface's zone
            for z, host_ip in host.ips.items():
                if host_ip == ip_clean:
                    return z
            return host.zone

        # Subnet-based fallback for standard SentinelX lab topology
        try:
            addr = ipaddress.ip_address(ip_clean)
            if addr in ipaddress.ip_network("10.10.1.0/24"):
                return "it"
            if addr in ipaddress.ip_network("10.10.2.0/24"):
                return "dmz"
            if addr in ipaddress.ip_network("10.10.3.0/24"):
                return "ot"
            if addr in ipaddress.ip_network("10.10.9.0/24"):
                return "mgmt"
        except ValueError:
            pass
        return None

    def is_decoy(self, name_or_ip: str | None) -> bool:
        if not name_or_ip:
            return False
        target = name_or_ip.strip()
        host = self.get_host_by_name(target) or self.get_host_by_ip(target)
        return bool(host and host.is_decoy)

    def is_honey_user(self, username: str | None) -> bool:
        if not username:
            return False
        user_clean = username.strip().lower()
        return any(hc.username.lower() == user_clean for hc in self.honey_credentials)

    def is_honey_file(self, file_path: str | None) -> bool:
        if not file_path:
            return False
        path_clean = file_path.strip()
        for hf in self.honey_files:
            if path_clean == hf or path_clean.endswith(hf):
                return True
        return False

    def is_ssh_source_authorized(
        self,
        src_ip: str | None,
        dst_host: str | None = None,
        dst_ip: str | None = None,
    ) -> bool:
        """Check whether an incoming SSH connection is authorized for the destination host."""
        if not src_ip:
            return False

        # Resolve destination host asset
        dst_asset = None
        if dst_host:
            dst_asset = self.get_host_by_name(dst_host)
        if not dst_asset and dst_ip:
            dst_asset = self.get_host_by_ip(dst_ip)

        if not dst_asset:
            return False

        src_zone = self.get_zone_for_ip(src_ip)
        src_asset = self.get_host_by_ip(src_ip)
        src_host_name = src_asset.name if src_asset else None

        # Check allowed zones if configured
        if dst_asset.allowed_ssh_src_zones:
            if not src_zone or src_zone not in dst_asset.allowed_ssh_src_zones:
                return False

        # Check allowed hosts if configured
        if dst_asset.allowed_ssh_src_hosts:
            if not src_host_name or src_host_name not in dst_asset.allowed_ssh_src_hosts:
                return False

        # If neither is configured, fallback to destination's own zone
        if not dst_asset.allowed_ssh_src_zones and not dst_asset.allowed_ssh_src_hosts:
            if not src_zone or src_zone != dst_asset.zone:
                return False

        return True

    def is_ot_write_authorized(
        self,
        event_ts: Any,
        src_ip: str | None = None,
        src_host: str | None = None,
        dst_host: str | None = None,
        dst_ip: str | None = None,
        user: str | None = None,
    ) -> bool:
        """Check whether a Modbus/OT write is authorized based on actor and maintenance window."""
        # 1. Maintenance window check: writes outside the maintenance window are unauthorized
        if not self.is_in_maintenance_window(event_ts):
            return False

        # 2. Target device resolution
        target_asset = None
        if dst_host:
            target_asset = self.get_host_by_name(dst_host)
        if not target_asset and dst_ip:
            target_asset = self.get_host_by_ip(dst_ip)

        if not target_asset or not target_asset.allowed_ot_writers:
            # If target has no allowed writers or is unknown/decoy, write is unauthorized
            return False

        # 3. Source actor resolution
        source_name = src_host
        if not source_name and src_ip:
            h = self.get_host_by_ip(src_ip)
            if h:
                source_name = h.name

        # If source host is known, verify authorization
        if source_name:
            return source_name in target_asset.allowed_ot_writers

        # If user is specified
        if user and user in target_asset.allowed_ot_writers:
            return True

        # If source is internal/unspecified (e.g. PLC audit log during maintenance window)
        return True


def load_assets(path: str | Path | None = None) -> AssetInventory:
    """Load and validate the assets inventory YAML file."""
    if path is None:
        # Resolve repo root relative to this file: engine/sentinelx/normalize/assets.py -> repo root
        repo_root = Path(__file__).resolve().parent.parent.parent.parent
        path = repo_root / "content" / "assets.yaml"
    else:
        path = Path(path)

    if not path.is_file():
        raise FileNotFoundError(f"Assets configuration file not found at: {path}")

    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    return AssetInventory.model_validate(data)


@lru_cache(maxsize=1)
def get_assets() -> AssetInventory:
    """Return the cached singleton AssetInventory."""
    return load_assets()
