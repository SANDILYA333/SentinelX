# SentinelX Data Contracts Specification

## Contract Versioning Rule
**Current Version:** `1.0`
Any breaking change bumps `SCHEMA_VERSION` (defined in `engine/sentinelx/schemas/common.py`) and adds a changelog line below.

### Changelog
- **v1.0 (Phase 0):** Initial frozen data contracts covering `Event`, `Signal`, `Incident`, `GuardDecision`, and `WSMessage`.

---

## Core Models Overview

### 1. Event (`engine/sentinelx/schemas/event.py`)
- **Purpose:** Canonical telemetry schema emitted by all ingestion adapters across IT, OT, and deception sources.
- **Key Characteristics:** Strict validation (`extra="forbid"`), timezone-aware UTC timestamps, optional OT fields (`OTFields`) for SCADA/ICS telemetry, and provenance references (`raw_ref`).

### 2. Signal (`engine/sentinelx/schemas/signal.py`)
- **Purpose:** Discrete detection output emitted by detectors (rule, baseline, anomaly, graph, deception). Detectors emit signals, never alerts.
- **Key Characteristics:** Contains score (0-1), confidence (0-1), associated entities, MITRE ATT&CK techniques, and pointers to evidence event IDs (minimum length 1).

### 3. Incident (`engine/sentinelx/schemas/incident.py`)
- **Purpose:** Correlated multi-stage attack chain and alert-budgeted security incident.
- **Key Characteristics:** Tracks MITRE kill chain stages, TTFMA (Time to First Meaningful Alert), decoy and OT interaction flags, correlated entity graph (`IncidentGraph`), and explainability citations.

### 4. GuardDecision (`engine/sentinelx/schemas/guard.py`)
- **Purpose:** Response safety evaluation before applying automated containment actions.
- **Key Characteristics:** Determines `allow`, `deny`, or `needs_human` based on asset criticality, OT safety constraints, and rule policies.

### 5. WSMessage (`engine/sentinelx/schemas/common.py`)
- **Purpose:** Typed WebSocket streaming envelope for real-time frontend and agent communication.
- **Types:** `hello`, `event`, `signal`, `incident`, `guard`, `health`.

---

## Example JSON Payloads

### Event Example
```json
{
  "event_id": "evt_019313ef9a817b18",
  "ts": "2026-11-07T12:30:00Z",
  "ingested_at": "2026-11-07T12:30:01Z",
  "source_tool": "modbus",
  "domain": "ot",
  "category": "ot_command",
  "action": "modbus_write",
  "outcome": "success",
  "host": "plc-primary",
  "src_ip": "192.168.20.10",
  "dst_ip": "192.168.20.100",
  "src_port": 49210,
  "dst_port": 502,
  "protocol": "modbus",
  "user": null,
  "process": null,
  "parent_process": null,
  "cmdline": null,
  "session_id": null,
  "ot": {
    "unit_id": 1,
    "device_id": "plc-water-pump-01",
    "function_code": 16,
    "register": 40001,
    "value": 1,
    "is_write": true
  },
  "raw_ref": {
    "source_file": "/var/log/zeek/modbus.log",
    "line": 142
  },
  "raw": {
    "uid": "CHg7Gv3r2Z",
    "func": "WRITE_MULTIPLE_REGISTERS",
    "val": [1]
  },
  "tags": ["water_treatment", "pumping_station"]
}
```

### Signal Example
```json
{
  "signal_id": "sig_019313f011234abc",
  "ts": "2026-11-07T12:30:02Z",
  "detector": "rule",
  "rule_id": "R-OT-004",
  "title": "Unauthorized Modbus Write to Critical Actuator Register",
  "score": 0.85,
  "confidence": 0.95,
  "entities": [
    {
      "type": "ip",
      "value": "192.168.20.10"
    },
    {
      "type": "device",
      "value": "plc-water-pump-01"
    }
  ],
  "evidence_event_ids": [
    "evt_019313ef9a817b18"
  ],
  "techniques": [
    {
      "framework": "ics",
      "technique_id": "T0855",
      "name": "Unauthorized Command Message",
      "tactic": "Impair Process Control"
    }
  ],
  "explanation": "Modbus function code 16 write targeting critical holding register 40001 from unauthorized engineering workstation IP 192.168.20.10.",
  "metadata": {
    "severity_hint": "critical",
    "process_zone": "Level 1 Control"
  }
}
```

### Incident Example
```json
{
  "incident_id": "inc_019313f12345def0",
  "status": "open",
  "created_at": "2026-11-07T12:30:05Z",
  "updated_at": "2026-11-07T12:30:05Z",
  "first_signal_ts": "2026-11-07T12:28:10Z",
  "first_meaningful_alert_ts": "2026-11-07T12:30:05Z",
  "ttfma_seconds": 115.0,
  "score": 0.92,
  "severity": "critical",
  "entities": [
    {
      "type": "user",
      "value": "svc_eng"
    },
    {
      "type": "ip",
      "value": "192.168.20.10"
    },
    {
      "type": "device",
      "value": "plc-water-pump-01"
    }
  ],
  "signal_ids": [
    "sig_019313f009988776",
    "sig_019313f011234abc"
  ],
  "event_ids": [
    "evt_019313ef88112233",
    "evt_019313ef9a817b18"
  ],
  "kill_chain_stages": [
    "Initial Access",
    "Lateral Movement",
    "Impair Process Control"
  ],
  "techniques": [
    {
      "framework": "enterprise",
      "technique_id": "T1078",
      "name": "Valid Accounts",
      "tactic": "Initial Access"
    },
    {
      "framework": "ics",
      "technique_id": "T0855",
      "name": "Unauthorized Command Message",
      "tactic": "Impair Process Control"
    }
  ],
  "decoy_touched": true,
  "ot_touched": true,
  "explanation": [
    "Compromised service account svc_eng accessed internal jump host.",
    "Interaction with canary file server decoy triggered tripwire.",
    "Lateral movement to OT subnet resulted in unauthorized Modbus write command to pump PLC."
  ],
  "summary": "Multi-stage cross-domain breach traversing IT jumpbox into OT SCADA zone targeting water pump PLC register.",
  "summary_citations": [
    "evt_019313ef88112233",
    "evt_019313ef9a817b18"
  ],
  "graph": {
    "nodes": [
      {
        "id": "node_usr",
        "type": "user",
        "label": "svc_eng"
      },
      {
        "id": "node_ip",
        "type": "ip",
        "label": "192.168.20.10"
      },
      {
        "id": "node_plc",
        "type": "device",
        "label": "plc-water-pump-01"
      }
    ],
    "edges": [
      {
        "source": "node_usr",
        "target": "node_ip",
        "label": "authenticated_from",
        "ts": "2026-11-07T12:28:10Z",
        "event_ids": ["evt_019313ef88112233"]
      },
      {
        "source": "node_ip",
        "target": "node_plc",
        "label": "modbus_write",
        "ts": "2026-11-07T12:30:00Z",
        "event_ids": ["evt_019313ef9a817b18"]
      }
    ]
  }
}
```

