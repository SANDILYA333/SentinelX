#!/usr/bin/env python3
"""PyModbus async server simulating a water tank with a 1 Hz physics loop and HTTP state endpoint."""

import asyncio
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.server import StartAsyncTcpServer

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("plc-sim")

STATE_LOG = Path("/var/log/plc/plc-sim-state.jsonl")
WRITES_LOG = Path("/var/log/plc/plc-sim-writes.jsonl")
STATE_LOG.parent.mkdir(parents=True, exist_ok=True)


class TankPhysics:
    def __init__(self):
        self.reset()
        self.last_writes: list[dict[str, Any]] = []

    def reset(self):
        # Holding registers: 0: pump_speed_pct, 1: valve_position_pct, 2: level_high_alarm_setpoint
        self.pump_speed_pct: float = 50.0
        self.valve_position_pct: float = 50.0
        self.level_high_alarm_setpoint: int = 90

        # Coils: 0: pump_run, 1: emergency_stop
        self.pump_run: bool = True
        self.emergency_stop: bool = False

        # Input registers: 0: tank_level_pct, 1: pressure_kpa, 2: temperature_c
        # Settles stably at 55% in "normal"
        self.tank_level_pct: float = 55.0
        self.pressure_kpa: float = 265.0
        self.temperature_c: float = 22.0

    def get_flag(self) -> str:
        if self.tank_level_pct >= 92.0 or self.tank_level_pct <= 8.0:
            return "unsafe"
        if self.tank_level_pct >= 80.0 or self.tank_level_pct <= 20.0:
            return "warning"
        return "normal"

    def record_write(self, function_code: int, register: int, value: Any):
        flag = self.get_flag()
        entry = {
            "ts": datetime.now(UTC).isoformat(),
            "function_code": function_code,
            "register": register,
            "value": value,
            "flag_after_write": flag,
        }
        self.last_writes.append(entry)
        if len(self.last_writes) > 20:
            self.last_writes.pop(0)

        with open(WRITES_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        logger.info(f"Modbus write recorded: {entry}")

    def update_physics(self):
        if self.emergency_stop:
            self.pump_run = False

        # Physics tuning:
        # Defaults (pump 50%, valve 50%) settle stably at 55% in "normal".
        # Benign pump writes (40-70) stay between ~35% and ~75%.
        # Valve=0 with pump>=50 reaches unsafe (>92) in ~82 seconds (within 60-120s).
        inflow = (self.pump_speed_pct * 0.009) if self.pump_run else 0.0
        outflow = (self.valve_position_pct * (self.tank_level_pct / 55.0) * 0.009) if self.tank_level_pct > 0 else 0.0

        net = inflow - outflow
        self.tank_level_pct = max(0.0, min(100.0, self.tank_level_pct + net))
        self.pressure_kpa = 100.0 + (self.tank_level_pct * 3.0)
        self.temperature_c = 22.0 + (inflow * 2.0)


physics = TankPhysics()
global_store: ModbusSlaveContext | None = None


class InterceptHoldingBlock(ModbusSequentialDataBlock):
    def setValues(self, address, values):
        super().setValues(address, values)
        fc = 16 if len(values) > 1 else 6
        for i, val in enumerate(values):
            reg = address + i
            if reg == 0:
                physics.pump_speed_pct = float(val)
                physics.record_write(fc, reg, val)
            elif reg == 1:
                physics.valve_position_pct = float(val)
                physics.record_write(fc, reg, val)
            elif reg == 2:
                physics.level_high_alarm_setpoint = int(val)
                physics.record_write(fc, reg, val)


class InterceptCoilsBlock(ModbusSequentialDataBlock):
    def setValues(self, address, values):
        super().setValues(address, values)
        fc = 15 if len(values) > 1 else 5
        for i, val in enumerate(values):
            coil = address + i
            if coil == 0:
                physics.pump_run = bool(val)
                physics.record_write(fc, coil, int(val))
            elif coil == 1:
                physics.emergency_stop = bool(val)
                physics.record_write(fc, coil, int(val))


async def physics_loop(store: ModbusSlaveContext):
    state_tick = 0
    while True:
        try:
            physics.update_physics()

            # Update datastore input registers
            level_int = int(round(physics.tank_level_pct))
            press_int = int(round(physics.pressure_kpa))
            temp_int = int(round(physics.temperature_c))
            store.setValues(4, 0, [level_int, press_int, temp_int])

            state_tick += 1
            # Log state every 5 s instead of 1 s (simulation itself runs at 1 Hz)
            if state_tick % 5 == 0:
                state_entry = {
                    "ts": datetime.now(UTC).isoformat(),
                    "tank_level_pct": round(physics.tank_level_pct, 2),
                    "pressure_kpa": round(physics.pressure_kpa, 2),
                    "temperature_c": round(physics.temperature_c, 2),
                    "pump_speed_pct": physics.pump_speed_pct,
                    "valve_position_pct": physics.valve_position_pct,
                    "pump_run": physics.pump_run,
                    "emergency_stop": physics.emergency_stop,
                    "flag": physics.get_flag(),
                }
                with open(STATE_LOG, "a", encoding="utf-8") as f:
                    f.write(json.dumps(state_entry) + "\n")
        except Exception as e:
            logger.error(f"Error in physics loop: {e}")

        await asyncio.sleep(1.0)


async def handle_http_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        request_line = await reader.readline()
        while True:
            line = await reader.readline()
            if not line or line == b"\r\n":
                break

        # Check for POST /reset
        if request_line.startswith(b"POST /reset"):
            physics.reset()
            if global_store is not None:
                global_store.setValues(3, 0, [50, 50, 90])
                global_store.setValues(1, 0, [True, False])
                global_store.setValues(4, 0, [55, 265, 22])
            logger.info("PLC reset to baseline parameters via POST /reset")

        state_data = {
            "tank_level_pct": round(physics.tank_level_pct, 2),
            "pressure_kpa": round(physics.pressure_kpa, 2),
            "temperature_c": round(physics.temperature_c, 2),
            "pump_speed_pct": physics.pump_speed_pct,
            "valve_position_pct": physics.valve_position_pct,
            "level_high_alarm_setpoint": physics.level_high_alarm_setpoint,
            "pump_run": physics.pump_run,
            "emergency_stop": physics.emergency_stop,
            "flag": physics.get_flag(),
            "last_writes": physics.last_writes,
        }
        body = json.dumps(state_data, indent=2).encode("utf-8")
        headers = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("utf-8") + b"\r\n"
            b"Connection: close\r\n\r\n"
        )
        writer.write(headers + body)
        await writer.drain()
    except Exception as e:
        logger.error(f"HTTP handler error: {e}")
    finally:
        writer.close()
        await writer.wait_closed()


async def main():
    global global_store
    di = ModbusSequentialDataBlock(0, [False] * 16)
    co = InterceptCoilsBlock(0, [True, False])
    hr = InterceptHoldingBlock(0, [50, 50, 90])
    ir = ModbusSequentialDataBlock(0, [55, 265, 22])

    store = ModbusSlaveContext(di=di, co=co, hr=hr, ir=ir, zero_mode=True)
    global_store = store
    context = ModbusServerContext(slaves=store, single=True)

    identity = ModbusDeviceIdentification()
    identity.VendorName = "Schneider Electric"
    identity.ProductCode = "Modicon M340 PLC"
    identity.ProductName = "Water Tank Primary Controller"
    identity.ModelName = "BMX P34 2020"
    identity.MajorMinorRevision = "v3.10"

    # Start HTTP state server on port 8080
    http_server = await asyncio.start_server(handle_http_client, "0.0.0.0", 8080)
    logger.info("HTTP state endpoint listening on 0.0.0.0:8080/state")

    # Start background physics loop
    asyncio.create_task(physics_loop(store))

    logger.info("Starting PLC Sim Modbus server on 0.0.0.0:502...")
    await StartAsyncTcpServer(
        context=context,
        identity=identity,
        address=("0.0.0.0", 502),
    )


if __name__ == "__main__":
    asyncio.run(main())
