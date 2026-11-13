#!/usr/bin/env python3
"""CLI utility to safely deploy, verify, and manage Living-off-the-Land deception artifacts."""

import argparse
import logging
import sys
from pathlib import Path

# Add engine to sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "engine"))

from sentinelx.deception.lotl.manager import LureManager  # noqa: E402
from sentinelx.deception.lotl.registry import LureRegistry  # noqa: E402
from sentinelx.store.sqlite import init_db  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("deploy_lotl_lures")


def main():
    parser = argparse.ArgumentParser(description="SentinelX LotL Deception Deployment Manager")
    parser.add_argument("--db", default=str(REPO_ROOT / "data" / "sentinelx.db"), help="Path to SQLite database")
    parser.add_argument("--verify", action="store_true", help="Verify existing lures on lab hosts without deploying")
    parser.add_argument("--remove", metavar="LURE_ID", help="Safely remove a specific managed lure artifact")
    args = parser.parse_args()

    db = init_db(args.db)
    registry = LureRegistry(db)
    manager = LureManager(registry)

    if args.verify:
        logger.info("Running physical verification across lab hosts...")
        statuses = manager.verify_all()
        print("\n" + "=" * 60)
        print("LURE VERIFICATION RESULTS")
        print("=" * 60)
        for lure_id, st in sorted(statuses.items()):
            print(f"  {lure_id:<15} : {st.upper()}")
        print("=" * 60)
        return

    if args.remove:
        logger.info("Attempting safe removal of managed artifact: %s", args.remove)
        success, msg = manager.remove_lure(args.remove)
        if success:
            logger.info("SUCCESS: %s", msg)
        else:
            logger.error("FAILURE: %s", msg)
        return

    logger.info("Deploying LotL deception lures to lab endpoints...")
    res = manager.deploy_all()
    print("\n" + "=" * 60)
    print("LOTL DECEPTION DEPLOYMENT SUMMARY")
    print("=" * 60)
    print(f"  Total Registered : {res.total_attempted}")
    print(f"  Deployed/Active  : {res.deployed}")
    print(f"  Verified         : {res.verified}")
    print(f"  Skipped/Disabled : {res.skipped}")
    print(f"  Unsupported      : {res.unsupported} (Windows stubs)")
    print(f"  Failed           : {res.failed}")
    print("=" * 60)

    for detail in res.details:
        st = detail["status"].upper()
        print(f"  [{st:<11}] {detail['lure_id']:<15} - {detail['message']}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()

