#!/usr/bin/env python3
"""Capture real PLC physics traces:
1. 3-minute idle trace (sampled every 15s) proving stability around 50-60% in 'normal'
2. Attack trace (valve=0, pump=50) proving reaching 'unsafe' (>92%) within 60-120s
3. Recovery trace (valve=50, pump=50) proving honest recovery back to 'normal' within ~3 minutes
"""

import json
import subprocess
import time


def get_state() -> dict:
    res = subprocess.run(
        ["docker", "exec", "sentinelx-eng-ws", "curl", "-s", "http://10.10.3.20:8080/state"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return json.loads(res.stdout)


def set_register(reg: int, val: int):
    subprocess.run(
        [
            "docker",
            "exec",
            "sentinelx-eng-ws",
            "/usr/local/bin/write_plc.py",
            "10.10.3.20",
            str(reg),
            str(val),
        ],
        capture_output=True,
        timeout=10,
    )


def reset_plc():
    subprocess.run(
        [
            "docker",
            "exec",
            "sentinelx-eng-ws",
            "curl",
            "-s",
            "-X",
            "POST",
            "http://10.10.3.20:8080/reset",
        ],
        capture_output=True,
        timeout=10,
    )


def main():
    print("=" * 80)
    print("PART 1: 3-MINUTE IDLE BASELINE TRACE (12 samples @ 15s intervals)")
    print("=" * 80)
    reset_plc()
    time.sleep(1)

    print(
        f"{'Time (s)':<10} | {'Level (%)':<12} | {'Pressure (kPa)':<16} | {'Pump (%)':<10} | {'Valve (%)':<10} | {'Flag'}"
    )
    print("-" * 75)
    for i in range(13):
        t = i * 15
        st = get_state()
        print(
            f"{t:<10} | {st['tank_level_pct']:<12.2f} | {st['pressure_kpa']:<16.2f} | {st['pump_speed_pct']:<10.1f} | {st['valve_position_pct']:<10.1f} | {st['flag']}"
        )
        if i < 12:
            time.sleep(15)

    print("\n" + "=" * 80)
    print("PART 2: ATTACK TRACE (Close valve=0%, Pump=50%, reach unsafe >92% in 60-120s)")
    print("=" * 80)
    # Ensure baseline
    reset_plc()
    time.sleep(1)
    set_register(1, 0)  # valve = 0%
    set_register(0, 50)  # pump = 50%

    print(
        f"{'Time (s)':<10} | {'Level (%)':<12} | {'Pressure (kPa)':<16} | {'Pump (%)':<10} | {'Valve (%)':<10} | {'Flag'}"
    )
    print("-" * 75)
    t = 0
    while True:
        st = get_state()
        print(
            f"{t:<10} | {st['tank_level_pct']:<12.2f} | {st['pressure_kpa']:<16.2f} | {st['pump_speed_pct']:<10.1f} | {st['valve_position_pct']:<10.1f} | {st['flag']}"
        )
        if st["flag"] == "unsafe":
            print(f"--> Reached UNSAFE state at t={t}s (level: {st['tank_level_pct']}%)")
            break
        time.sleep(15)
        t += 15

    print("\n" + "=" * 80)
    print("PART 3: HONEST RECOVERY TRACE (Restore valve=50%, pump=50%, return to normal <80%)")
    print("=" * 80)
    set_register(1, 50)  # valve = 50%
    set_register(0, 50)  # pump = 50%

    print(
        f"{'Time (s)':<10} | {'Level (%)':<12} | {'Pressure (kPa)':<16} | {'Pump (%)':<10} | {'Valve (%)':<10} | {'Flag'}"
    )
    print("-" * 75)
    rt = 0
    while True:
        rst = get_state()
        print(
            f"{rt:<10} | {rst['tank_level_pct']:<12.2f} | {rst['pressure_kpa']:<16.2f} | {rst['pump_speed_pct']:<10.1f} | {rst['valve_position_pct']:<10.1f} | {rst['flag']}"
        )
        if rst["flag"] == "normal" and rt >= 60:
            print(
                f"--> Honest recovery completed at t={rt}s: returned to NORMAL baseline (level: {rst['tank_level_pct']}%)"
            )
            break
        time.sleep(15)
        rt += 15
        if rt > 240:
            print("Timeout waiting for recovery.")
            break

    reset_plc()


if __name__ == "__main__":
    main()
