#!/usr/bin/env python3
"""Helper script to write PLC holding registers via Modbus TCP."""

import json
import sys

from pymodbus.client import ModbusTcpClient


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "10.10.3.20"
    reg = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    val = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    port = int(sys.argv[4]) if len(sys.argv) > 4 else 502

    client = ModbusTcpClient(host, port=port)
    if not client.connect():
        print(f"Error: Unable to connect to Modbus PLC at {host}:{port}", file=sys.stderr)
        sys.exit(1)

    try:
        wr = client.write_register(reg, val, slave=1)
        if wr.isError():
            print(f"Error writing register {reg}: {wr}", file=sys.stderr)
            sys.exit(1)

        result = {
            "status": "success",
            "host": host,
            "port": port,
            "register": reg,
            "value": val,
        }
        print(json.dumps(result))
    finally:
        client.close()


if __name__ == "__main__":
    main()
