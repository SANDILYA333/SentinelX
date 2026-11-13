"""Lure Manager for idempotent deployment, verification, and lifecycle management."""

import hashlib
import json
import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinelx.deception.lotl.registry import (
    DEFAULT_LURE_DEFINITIONS,
    LureRegistry,
    compute_sha256,
)
from sentinelx.schemas.deception import LotLLure, LotLLureStatus
from sentinelx.store.sqlite import upsert_lotl_lure

logger = logging.getLogger(__name__)


@dataclass
class ManagedArtifact:
    """Record of a deployed file managed by the deception engine."""

    lure_id: str
    host: str
    path: str
    sha256_hash: str
    permissions: str
    owner: str
    deployed_at: str


@dataclass
class DeploymentResult:
    """Summary of a deployment or verification run."""

    total_attempted: int = 0
    deployed: int = 0
    verified: int = 0
    failed: int = 0
    skipped: int = 0
    unsupported: int = 0
    details: list[dict[str, Any]] = field(default_factory=list)


class LureManager:
    """Coordinates safe, idempotent deployment and verification of LotL deception artifacts."""

    def __init__(self, registry: LureRegistry, manifest_path: Path | None = None):
        self.registry = registry
        if manifest_path is None:
            self.manifest_path = Path("/home/kafka/innovasia/SentinelX/data/lotl_manifest.json")
        else:
            self.manifest_path = Path(manifest_path)
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        self._manifest: dict[str, dict[str, Any]] = self._load_manifest()

    def _load_manifest(self) -> dict[str, dict[str, Any]]:
        """Load managed artifact manifest from disk."""
        if self.manifest_path.is_file():
            try:
                with open(self.manifest_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return data
            except Exception as e:
                logger.warning("Failed to load manifest %s: %s", self.manifest_path, e)
        return {}

    def _save_manifest(self) -> None:
        """Persist managed artifact manifest to disk."""
        try:
            with open(self.manifest_path, "w", encoding="utf-8") as f:
                json.dump(self._manifest, f, indent=2)
        except Exception as e:
            logger.error("Failed to save manifest %s: %s", self.manifest_path, e)

    def _run_cmd_on_host(self, host: str, cmd: str, timeout: int = 15) -> tuple[int, str]:
        """Execute command inside target lab container via docker exec."""
        container_name = f"sentinelx-{host}"
        docker_cmd = ["docker", "exec", container_name, "bash", "-c", cmd]
        try:
            res = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=timeout)
            return res.returncode, res.stdout + res.stderr
        except Exception as exc:
            return -1, str(exc)

    def deploy_lure(self, lure: LotLLure) -> tuple[bool, str]:
        """Deploy a single deception artifact idempotently to its target host."""
        if lure.platform == "windows" or lure.status == "unsupported":
            return True, "Skipped unsupported platform (Windows)"

        if not lure.enabled:
            return True, "Skipped disabled lure"

        # Find matching content generator
        generator = None
        for d in DEFAULT_LURE_DEFINITIONS:
            if d["lure_id"] == lure.lure_id:
                generator = d.get("content_generator")
                break

        if not generator:
            return False, f"No content generator found for {lure.lure_id}"

        content = generator()
        expected_hash = compute_sha256(content)

        # Set appropriate permissions
        perms = "0600" if "ssh_key" in lure.lure_type else "0644"
        owner = "svc_backup:svc_backup" if "/home/svc_backup" in lure.path else "root:root"

        # Check if already deployed and matching
        code, out = self._run_cmd_on_host(lure.host, f"sha256sum {lure.path} 2>/dev/null || true")
        if code == 0 and expected_hash in out:
            # File already exists and matches expected hash
            self._record_manifest(lure, expected_hash, perms, owner)
            lure_updated = lure.model_copy(update={"status": "active", "sha256_hash": expected_hash})
            upsert_lotl_lure(self.registry.db, lure_updated)
            return True, "Already verified and current"

        # Safe deployment: ensure directory exists, stream exact bytes via tee, set perms
        parent_dir = str(Path(lure.path).parent)
        self._run_cmd_on_host(lure.host, f"mkdir -p {parent_dir}")

        container_name = f"sentinelx-{lure.host}"
        tee_proc = subprocess.run(
            ["docker", "exec", "-i", container_name, "tee", lure.path],
            input=content.encode("utf-8"),
            capture_output=True,
            timeout=15,
        )
        if tee_proc.returncode != 0:
            return False, f"Failed writing to {lure.path}: {tee_proc.stderr.decode()}"

        self._run_cmd_on_host(lure.host, f"chmod {perms} {lure.path} && chown {owner} {lure.path} 2>/dev/null || true")
        code, out = self._run_cmd_on_host(lure.host, f"sha256sum {lure.path}")
        if code == 0 and expected_hash in out:
            self._record_manifest(lure, expected_hash, perms, owner)
            lure_updated = lure.model_copy(update={"status": "active", "sha256_hash": expected_hash})
            upsert_lotl_lure(self.registry.db, lure_updated)
            logger.info("Successfully deployed lure %s on %s:%s", lure.lure_id, lure.host, lure.path)
            return True, "Successfully deployed and verified"
        else:
            lure_updated = lure.model_copy(update={"status": "error"})
            upsert_lotl_lure(self.registry.db, lure_updated)
            logger.warning("Deployment failed for %s on %s: %s", lure.lure_id, lure.host, out)
            return False, f"Deployment failed: {out}"

    def _record_manifest(self, lure: LotLLure, sha: str, perms: str, owner: str) -> None:
        """Add lure to managed artifact manifest."""
        self._manifest[lure.lure_id] = {
            "lure_id": lure.lure_id,
            "host": lure.host,
            "path": lure.path,
            "sha256_hash": sha,
            "permissions": perms,
            "owner": owner,
            "deployed_at": lure.created_at.isoformat(),
        }
        self._save_manifest()

    def deploy_all(self) -> DeploymentResult:
        """Deploy all registered lures idempotently."""
        lures = self.registry.list_lures()
        result = DeploymentResult(total_attempted=len(lures))

        for lure in lures:
            if lure.platform == "windows" or lure.status == "unsupported":
                result.unsupported += 1
                result.details.append({"lure_id": lure.lure_id, "status": "unsupported", "message": "Windows stub"})
                continue

            if not lure.enabled:
                result.skipped += 1
                result.details.append({"lure_id": lure.lure_id, "status": "disabled", "message": "Lure disabled"})
                continue

            success, msg = self.deploy_lure(lure)
            if success:
                result.deployed += 1
                result.verified += 1
                result.details.append({"lure_id": lure.lure_id, "status": "active", "message": msg})
            else:
                result.failed += 1
                result.details.append({"lure_id": lure.lure_id, "status": "error", "message": msg})

        return result

    def verify_all(self) -> dict[str, LotLLureStatus]:
        """Verify the physical presence and integrity of all registered lures."""
        lures = self.registry.list_lures()
        status_map: dict[str, LotLLureStatus] = {}

        for lure in lures:
            if lure.platform == "windows" or lure.status == "unsupported":
                status_map[lure.lure_id] = "unsupported"
                continue

            if not lure.enabled:
                status_map[lure.lure_id] = "disabled"
                continue

            # Check if file exists and checksum matches
            code, out = self._run_cmd_on_host(lure.host, f"sha256sum {lure.path} 2>/dev/null || true")
            if code != 0 or not out.strip():
                status_map[lure.lure_id] = "missing"
                updated = lure.model_copy(update={"status": "missing"})
                upsert_lotl_lure(self.registry.db, updated)
            elif lure.sha256_hash and lure.sha256_hash not in out:
                status_map[lure.lure_id] = "tampered"
                updated = lure.model_copy(update={"status": "tampered"})
                upsert_lotl_lure(self.registry.db, updated)
            else:
                status_map[lure.lure_id] = "active"
                if lure.status != "active":
                    updated = lure.model_copy(update={"status": "active"})
                    upsert_lotl_lure(self.registry.db, updated)

        return status_map

    def remove_lure(self, lure_id: str) -> tuple[bool, str]:
        """Safely remove a deployed lure only if present in the managed manifest."""
        if lure_id not in self._manifest:
            return False, f"Lure {lure_id} is not in managed manifest; refusal to touch unmanaged file"

        record = self._manifest[lure_id]
        host = record["host"]
        path = record["path"]

        code, out = self._run_cmd_on_host(host, f"rm -f {path}")
        if code == 0:
            del self._manifest[lure_id]
            self._save_manifest()
            lure = self.registry.get_lure(lure_id)
            if lure:
                updated = lure.model_copy(update={"status": "missing"})
                upsert_lotl_lure(self.registry.db, updated)
            return True, f"Removed managed artifact {path} from {host}"
        return False, f"Failed to remove {path}: {out}"
