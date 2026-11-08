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


def test_is_ssh_source_authorized():
    get_assets.cache_clear()
    assets = get_assets()

    # Authorized benign workstation into jump-host
    assert assets.is_ssh_source_authorized("10.10.1.50", dst_host="jump-host") is True

    # Authorized jump-host pivot into eng-ws and file-srv
    assert assets.is_ssh_source_authorized("10.10.1.10", dst_host="eng-ws") is True
    assert assets.is_ssh_source_authorized("10.10.1.10", dst_host="file-srv") is True

    # Unauthorized attacker host
    assert assets.is_ssh_source_authorized("10.10.1.5", dst_host="jump-host") is False
    assert assets.is_ssh_source_authorized("10.10.1.5", dst_host="eng-ws") is False
    assert assets.is_ssh_source_authorized("10.10.1.5", dst_host="file-srv") is False

    # Unauthorized origin from unexpected zone (mgmt IP into jump-host)
    assert assets.is_ssh_source_authorized("10.10.9.99", dst_host="jump-host") is False

    # Unknown IP on IT subnet (unauthorized rogue host)
    assert assets.is_ssh_source_authorized("10.10.1.99", dst_host="jump-host") is False


def test_is_ot_write_authorized():
    from datetime import UTC, datetime

    get_assets.cache_clear()
    assets = get_assets()

    # Maintenance window check (02:00-04:00)
    t_in_maint = datetime(2026, 11, 8, 3, 0, 0, tzinfo=UTC)
    t_out_maint = datetime(2026, 11, 8, 14, 0, 0, tzinfo=UTC)

    assert assets.is_in_maintenance_window(t_in_maint) is True
    assert assets.is_in_maintenance_window(t_out_maint) is False

    # Authorized: eng-ws (10.10.3.40) to plc-sim during maintenance window
    assert (
        assets.is_ot_write_authorized(event_ts=t_in_maint, src_ip="10.10.3.40", dst_host="plc-sim")
        is True
    )

    # Unauthorized: eng-ws to plc-sim OUTSIDE maintenance window
    assert (
        assets.is_ot_write_authorized(event_ts=t_out_maint, src_ip="10.10.3.40", dst_host="plc-sim")
        is False
    )

    # Unauthorized actor: attacker (10.10.1.5) even DURING maintenance window
    assert (
        assets.is_ot_write_authorized(event_ts=t_in_maint, src_ip="10.10.1.5", dst_host="plc-sim")
        is False
    )
