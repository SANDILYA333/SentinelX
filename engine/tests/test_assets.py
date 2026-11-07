from pathlib import Path

import pytest
from sentinelx.normalize.assets import AssetInventory, get_assets, load_assets


def test_load_assets_from_file():
    assets = load_assets()
    assert isinstance(assets, AssetInventory)
    assert len(assets.hosts) >= 10
    assert len(assets.honey_credentials) >= 1
    assert len(assets.honey_files) >= 1


def test_get_host_lookups():
    assets = get_assets()
    # By name
    jump = assets.get_host_by_name("jump-host")
    assert jump is not None
    assert jump.role == "jump_host"
    assert jump.criticality == "high"
    assert "10.10.1.10" in jump.ips.values()

    # By hostname (Cowrie)
    cowrie = assets.get_host_by_name("backup-srv-02")
    assert cowrie is not None
    assert cowrie.name == "cowrie"
    assert cowrie.is_decoy is True

    # By IP
    db = assets.get_host_by_ip("10.10.1.30")
    assert db is not None
    assert db.name == "db-srv"


def test_zone_resolution():
    assets = get_assets()
    assert assets.get_zone_for_ip("10.10.1.10") == "it"
    assert assets.get_zone_for_ip("10.10.2.10") == "dmz"
    assert assets.get_zone_for_ip("10.10.3.20") == "ot"
    assert assets.get_zone_for_ip("10.10.9.2") == "mgmt"

    # Subnet fallback
    assert assets.get_zone_for_ip("10.10.1.99") == "it"
    assert assets.get_zone_for_ip("10.10.2.99") == "dmz"
    assert assets.get_zone_for_ip("10.10.3.99") == "ot"


def test_honey_credential_and_file_checks():
    assets = get_assets()
    assert assets.is_honey_user("svc_dbadmin") is True
    assert assets.is_honey_user("SVC_DBADMIN") is True
    assert assets.is_honey_user("alice") is False

    assert assets.is_honey_file("/srv/share/backup/.db_creds") is True
    assert assets.is_honey_file("/etc/passwd") is False


def test_missing_assets_file_raises():
    with pytest.raises(FileNotFoundError):
        load_assets(Path("/nonexistent/assets.yaml"))
