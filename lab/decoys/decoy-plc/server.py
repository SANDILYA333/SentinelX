#!/usr/bin/env python3
"""Decoy PyModbus server representing secondary pump station PLC.
NEVER contacted by legitimate hosts or benign traffic.
Logs every interaction to /var/log/plc/decoy-plc.jsonl.
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path

from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.server import StartAsyncTcpServer

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("decoy-plc")

LOG_FILE = Path("/var/log/plc/decoy-plc.jsonl")
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)


class CustomDataBlock(ModbusSequentialDataBlock):
    """Custom data block to intercept reads and writes for decoy audit logging."""

    def __init__(self, address, values, block_type):
        super().__init__(address, values)
        self.block_type = block_type

    def getValues(self, address, count=1):
        values = super().getValues(address, count)
        log_entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "station": "decoy-plc-station-02",
            "action": "read",
            "block_type": self.block_type,
            "address": address,
            "count": count,
            "values": values,
        }
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")
        logger.info(f"Decoy read logged: {log_entry}")
        return values

    def setValues(self, address, values):
        super().setValues(address, values)
        log_entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "station": "decoy-plc-station-02",
            "action": "write",
            "block_type": self.block_type,
            "address": address,
            "values": values,
        }
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")
        logger.info(f"Decoy write logged: {log_entry}")


async def run_server():
    # Plausible initial registers for pump station 2
    di = CustomDataBlock(0, [False] * 16, "discrete_inputs")
    co = CustomDataBlock(0, [True, False, False, False], "coils")
    hr = CustomDataBlock(0, [50, 50, 85, 10, 0, 0], "holding_registers")
    ir = CustomDataBlock(0, [55, 320, 24, 100, 0, 0], "input_registers")

    store = ModbusSlaveContext(di=di, co=co, hr=hr, ir=ir, zero_mode=True)
    context = ModbusServerContext(slaves=store, single=True)

    identity = ModbusDeviceIdentification()
    identity.VendorName = "Schneider Electric"
    identity.ProductCode = "Modicon M340 Decoy"
    identity.VendorUrl = "http://www.schneider-electric.com"
    identity.ProductName = "Decoy Water Pump Controller"
    identity.ModelName = "BMX P34 2020"
    identity.MajorMinorRevision = "v2.80"

    logger.info("Starting Decoy PLC Modbus server on 0.0.0.0:502...")
    await StartAsyncTcpServer(
        context=context,
        identity=identity,
        address=("0.0.0.0", 502),
    )


if __name__ == "__main__":
    asyncio.run(run_server())
