#!/usr/bin/env python3
"""Helper script to read PLC registers via Modbus TCP."""

import json
import sys

from pymodbus.client import ModbusTcpClient


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "10.10.3.20"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 502
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 3

    client = ModbusTcpClient(host, port=port)
    if not client.connect():
        print(f"Error: Unable to connect to Modbus PLC at {host}:{port}", file=sys.stderr)
        sys.exit(1)

    try:
        rr = client.read_input_registers(0, count, slave=1)
        if rr.isError():
            print(f"Error reading input registers: {rr}", file=sys.stderr)
            sys.exit(1)

        result = {
            "host": host,
            "port": port,
            "input_registers": rr.registers,
        }
        if len(rr.registers) >= 3:
            result["tank_level_pct"] = rr.registers[0]
            result["pressure_kpa"] = rr.registers[1]
            result["temperature_c"] = rr.registers[2]
        print(json.dumps(result))
    finally:
        client.close()


if __name__ == "__main__":
    main()
