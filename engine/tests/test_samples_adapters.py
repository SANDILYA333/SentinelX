"""Test all eval/captures/samples against their corresponding adapters.

Verifies:
1. Every line is either parsed into a valid Event or ignored with a documented reason.
2. At least 95% total parse/ignore coverage across all samples with zero exceptions.
3. Golden assertions for key events (sshd Accepted, cmd.jsonl exec, Cowrie honey_user,
   OpenCanary 8001 without passwords, Zeek modbus write is_write=true, syscheck honey_file).
"""

from pathlib import Path

from sentinelx.ingest.adapters import (
    CowrieAdapter,
    OpenCanaryAdapter,
    PlcWritesAdapter,
    WazuhArchivesAdapter,
    ZeekConnAdapter,
    ZeekDnsAdapter,
    ZeekModbusAdapter,
)
from sentinelx.ingest.tailer import SourceContext
from sentinelx.normalize.enricher import EventEnricher
from sentinelx.schemas.common import Outcome

SAMPLES_DIR = Path(__file__).resolve().parent.parent.parent / "eval" / "captures" / "samples"

ADAPTER_MAPPING = {
    "cmd.sample.jsonl": ("wazuh", WazuhArchivesAdapter, "it"),
    "wazuh_archives.sample.jsonl": ("wazuh", WazuhArchivesAdapter, "it"),
    "cowrie.sample.jsonl": ("cowrie", CowrieAdapter, "dmz"),
    "opencanary.sample.jsonl": ("opencanary", OpenCanaryAdapter, "dmz"),
    "plc_writes.sample.jsonl": ("modbus", PlcWritesAdapter, "ot"),
    "zeek_conn.sample.jsonl": ("zeek", ZeekConnAdapter, "it"),
    "zeek_dns.sample.jsonl": ("zeek", ZeekDnsAdapter, "it"),
    "zeek_modbus.sample.jsonl": ("zeek", ZeekModbusAdapter, "ot"),
}


def test_samples_parse_coverage_and_zero_exceptions():
    enricher = EventEnricher()
    total_lines = 0
    accounted_lines = 0  # either parsed into >=1 Event or ignored with a reason

    assert SAMPLES_DIR.exists(), f"Samples dir missing: {SAMPLES_DIR}"

    for sample_filename, (tool, adapter_cls, zone) in ADAPTER_MAPPING.items():
        sample_path = SAMPLES_DIR / sample_filename
        assert sample_path.exists(), f"Sample file missing: {sample_path}"

        adapter = adapter_cls()
        ctx = SourceContext(
            source_key=sample_filename,
            source_tool=tool,
            file_path=sample_path,
            offset=0,
            zone=zone,
        )

        with open(sample_path, "r", encoding="utf-8", errors="replace") as f:
            for offset, line in enumerate(f):
                line_str = line.strip()
                if not line_str:
                    continue

                total_lines += 1
                ctx.offset = offset
                ctx.ignore_reason = None

                events = adapter.parse(line_str, ctx)
                if events is not None and len(events) > 0:
                    for ev in events:
                        enriched = enricher.enrich(ev)
                        assert enriched.event_id.startswith("evt_")
                        assert enriched.ts is not None
                    accounted_lines += 1
                else:
                    reason = getattr(adapter, "last_ignore_reason", None) or ctx.ignore_reason
                    assert reason is not None, f"Unaccounted line in {sample_filename}: {line_str}"
                    accounted_lines += 1

    coverage = (accounted_lines / total_lines) * 100.0 if total_lines > 0 else 0.0
    print(f"\nSamples test coverage: {coverage:.2f}% ({accounted_lines}/{total_lines} lines)")
    assert coverage >= 95.0, f"Parse coverage {coverage}% < 95%"


def test_golden_assertions():
    enricher = EventEnricher()

    # 1. Wazuh archives: sshd Accepted -> authentication/success with user and src_ip
    wazuh_sample = SAMPLES_DIR / "wazuh_archives.sample.jsonl"
    adapter_wazuh = WazuhArchivesAdapter()
    ctx_wazuh = SourceContext("wazuh", "wazuh", wazuh_sample, 0, "it")

    found_sshd_accepted = False
    found_syscheck_honey = False

    with open(wazuh_sample) as f:
        for offset, line in enumerate(f):
            ctx_wazuh.offset = offset
            evs = adapter_wazuh.parse(line.strip(), ctx_wazuh)
            if not evs:
                continue
            for ev in evs:
                enriched = enricher.enrich(ev)
                if (
                    enriched.category == "authentication"
                    and enriched.action == "ssh_login"
                    and enriched.outcome == Outcome.success
                ):
                    assert enriched.user is not None
                    assert enriched.src_ip is not None
                    found_sshd_accepted = True
                if "honey_file" in (enriched.tags or []):
                    assert enriched.category == "file"
                    found_syscheck_honey = True

    assert found_sshd_accepted, "Golden assertion failed: sshd Accepted not found in wazuh sample"
    assert found_syscheck_honey, (
        "Golden assertion failed: syscheck honey_file not found in wazuh sample"
    )

    # 2. cmd.jsonl -> process/exec with cmdline
    cmd_sample = SAMPLES_DIR / "cmd.sample.jsonl"
    ctx_cmd = SourceContext("cmd", "wazuh", cmd_sample, 0, "it")
    found_exec = False

    with open(cmd_sample) as f:
        for offset, line in enumerate(f):
            ctx_cmd.offset = offset
            evs = adapter_wazuh.parse(line.strip(), ctx_cmd)
            if not evs:
                continue
            for ev in evs:
                enriched = enricher.enrich(ev)
                if enriched.category == "process" and enriched.action == "exec":
                    assert enriched.cmdline is not None and len(enriched.cmdline) > 0
                    assert enriched.host is not None
                    found_exec = True

    assert found_exec, "Golden assertion failed: cmd.jsonl exec not found"

    # 3. Cowrie: login success with honey_user tag
    cowrie_sample = SAMPLES_DIR / "cowrie.sample.jsonl"
    adapter_cowrie = CowrieAdapter()
    ctx_cowrie = SourceContext("cowrie", "cowrie", cowrie_sample, 0, "dmz")
    found_cowrie_honey = False

    with open(cowrie_sample) as f:
        for offset, line in enumerate(f):
            ctx_cowrie.offset = offset
            evs = adapter_cowrie.parse(line.strip(), ctx_cowrie)
            if not evs:
                continue
            for ev in evs:
                enriched = enricher.enrich(ev)
                if (
                    enriched.action in ("ssh_login", "ssh_login_success")
                    and enriched.outcome == Outcome.success
                ):
                    if "honey_user" in (enriched.tags or []):
                        assert enriched.user == "svc_dbadmin"
                        found_cowrie_honey = True

    assert found_cowrie_honey, (
        "Golden assertion failed: Cowrie login success with honey_user not found"
    )

    # 4. OpenCanary 8001 with honey_user and NO password anywhere in serialized event
    canary_sample = SAMPLES_DIR / "opencanary.sample.jsonl"
    adapter_canary = OpenCanaryAdapter()
    ctx_canary = SourceContext("opencanary", "opencanary", canary_sample, 0, "dmz")
    found_canary_8001 = False

    with open(canary_sample) as f:
        for offset, line in enumerate(f):
            ctx_canary.offset = offset
            evs = adapter_canary.parse(line.strip(), ctx_canary)
            if not evs:
                continue
            for ev in evs:
                enriched = enricher.enrich(ev)
                if enriched.action == "mysql_login_attempt":
                    assert "honey_user" in (enriched.tags or [])
                    assert enriched.user == "svc_dbadmin"
                    dumped = enriched.model_dump_json()
                    # Ensure secret password 'Winter2026!' is never present
                    assert "Winter2026!" not in dumped
                    assert "password" not in enriched.raw
                    found_canary_8001 = True

    assert found_canary_8001, "Golden assertion failed: OpenCanary 8001 with honey_user not found"

    # 5. Zeek modbus write -> ot.is_write=true
    modbus_sample = SAMPLES_DIR / "zeek_modbus.sample.jsonl"
    adapter_modbus = ZeekModbusAdapter()
    ctx_modbus = SourceContext("zeek_modbus", "zeek", modbus_sample, 0, "ot")
    found_modbus_write = False

    with open(modbus_sample) as f:
        for offset, line in enumerate(f):
            ctx_modbus.offset = offset
            evs = adapter_modbus.parse(line.strip(), ctx_modbus)
            if not evs:
                continue
            for ev in evs:
                enriched = enricher.enrich(ev)
                if enriched.action.startswith("modbus_write"):
                    assert enriched.ot is not None
                    assert enriched.ot.is_write is True
                    found_modbus_write = True

    assert found_modbus_write, (
        "Golden assertion failed: Zeek modbus write with is_write=true not found"
    )


def test_wazuh_adapter_classify_and_malformed():
    """Verify WazuhArchivesAdapter classify() and malformed full_log error handling."""
    adapter = WazuhArchivesAdapter()
    ctx = SourceContext("wazuh", "wazuh", Path("archives.json"), 0)

    # 1. Valid auth line -> emitted:ssh_login
    valid_auth = (
        '{"timestamp":"2026-11-08T02:00:00Z","agent":{"name":"jump-host"},'
        '"location":"/var/log/auth.log","full_log":"Accepted publickey for svc_backup from 10.10.1.5 port 54321 ssh2"}'
    )
    bucket, evs = adapter.classify(valid_auth, ctx)
    assert bucket == "emitted:ssh_login"
    assert evs is not None and len(evs) == 1

    # 2. Key check noise -> ignored:sshd_noise
    noise_auth = (
        '{"timestamp":"2026-11-08T02:00:00Z","agent":{"name":"jump-host"},'
        '"location":"/var/log/auth.log","full_log":"Accepted key ED25519 SHA256:abc found at /home/alice/.ssh/authorized_keys:1"}'
    )
    bucket, evs = adapter.classify(noise_auth, ctx)
    assert bucket == "ignored:sshd_noise"
    assert evs is None

    # 3. Wazuh internal event -> ignored:wazuh_internal
    internal_line = (
        '{"timestamp":"2026-11-08T02:00:00Z","agent":{"name":"jump-host"},'
        '"location":"sca","full_log":"Scanning system"}'
    )
    bucket, evs = adapter.classify(internal_line, ctx)
    assert bucket == "ignored:wazuh_internal"
    assert evs is None

    # 4. Malformed inner full_log in cmd.jsonl -> unparsed (raises ValueError on parse)
    malformed_cmd = (
        '{"timestamp":"2026-11-08T02:00:00Z","agent":{"name":"jump-host"},'
        '"location":"/var/log/sentinelx/cmd.jsonl","full_log":"{\\"ts\\":\\"2026-11-08T02:00:00Z\\",\\"cmd\\":\\"curl'
    )
    bucket, evs = adapter.classify(malformed_cmd, ctx)
    assert bucket.startswith("unparsed:")
    assert evs is None

    # 5. Non-JSON archive line -> unparsed
    bucket, evs = adapter.classify("not a json line", ctx)
    assert bucket.startswith("unparsed:")
    assert evs is None
