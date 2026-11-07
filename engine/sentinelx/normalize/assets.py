"""Assets inventory models, loader, and enrichment lookup helpers."""

import ipaddress
from functools import lru_cache
from pathlib import Path
from typing import Literal

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


class HoneyCredential(BaseModel):
    username: str
    decoy: list[str] = Field(default_factory=list)


class AssetInventory(BaseModel):
    hosts: list[HostAsset] = Field(default_factory=list)
    honey_credentials: list[HoneyCredential] = Field(default_factory=list)
    honey_files: list[str] = Field(default_factory=list)

    def get_host_by_name(self, name: str) -> HostAsset | None:
        name_lower = name.strip().lower()
        for host in self.hosts:
            if host.name.lower() == name_lower:
                return host
            if host.hostname and host.hostname.lower() == name_lower:
                return host
        return None

    def get_host_by_ip(self, ip: str) -> HostAsset | None:
        ip_clean = ip.strip()
        for host in self.hosts:
            if ip_clean in host.ips.values():
                return host
        return None

    def get_zone_for_ip(self, ip: str) -> str | None:
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

    def is_decoy(self, name_or_ip: str) -> bool:
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
