"""Unit tests for attack scenarios, scenario runner loading, and benign configuration."""

from pathlib import Path

from sentinelx.attack.runner import SCENARIOS_DIR, load_scenario


def test_scenario_yaml_loading_and_validation():
    """Verify all 3 attack scenario YAMLs load, validate, and have required fields."""
    for name in ("baseline", "reordered", "slow_burn"):
        yaml_path = SCENARIOS_DIR / f"{name}.yaml"
        assert yaml_path.is_file(), f"Scenario file missing: {yaml_path}"

        scenario = load_scenario(yaml_path)
        assert scenario.name == name
        assert scenario.target_duration_seconds > 0
        assert len(scenario.steps) >= 7

        # Validate step invariants
        step_ids = set()
        for step in scenario.steps:
            assert step.id not in step_ids, f"Duplicate step id {step.id} in {name}"
            step_ids.add(step.id)
            assert step.technique.startswith("T"), f"Invalid ATT&CK technique: {step.technique}"
            assert step.action != ""
            assert len(step.pacing_delay) == 2
            assert step.pacing_delay[0] <= step.pacing_delay[1]
            assert step.pacing_delay[0] >= 0.0

    # Specifically verify slow_burn is 10-15x baseline (900-1350s)
    slow_burn = load_scenario(SCENARIOS_DIR / "slow_burn.yaml")
    assert 900 <= slow_burn.target_duration_seconds <= 1350, (
        f"slow_burn duration must be 10-15x baseline: {slow_burn.target_duration_seconds}"
    )


def test_benign_config_validation():
    """Verify benign activity configuration has complete diurnal weights and maintenance window."""
    config_path = Path(__file__).resolve().parent.parent.parent / "lab" / "benign" / "config.yaml"
    assert config_path.is_file(), f"Benign config missing: {config_path}"

    import yaml

    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    assert "sim_speed" in cfg
    assert "diurnal_weights" in cfg
    weights = cfg["diurnal_weights"]
    for hour in range(24):
        assert hour in weights or str(hour) in weights, f"Missing hour {hour} in diurnal weights"

    assert "maintenance_window" in cfg
    maint = cfg["maintenance_window"]
    assert 0 <= maint["start_hour"] < maint["end_hour"] <= 24
    assert 40 <= maint["min_pump_speed"] <= maint["max_pump_speed"] <= 70

    assert "targets" in cfg
    assert "forbidden_decoys" in cfg
    # Ensure forbidden decoys match honeypots
    assert "10.10.2.20" in cfg["forbidden_decoys"]
    assert "10.10.2.30" in cfg["forbidden_decoys"]
    assert "10.10.3.60" in cfg["forbidden_decoys"]
