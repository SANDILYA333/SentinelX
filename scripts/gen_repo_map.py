#!/usr/bin/env python3
"""Generate the comprehensive, deterministic repository map for SentinelX.

Extracts directory tree, tracked files and line counts, module docstrings/purposes,
Makefile targets, API routes, Pydantic schemas, YAML content, and test suites.
Outputs directly to docs/REPO_MAP.md without network access.
"""

import ast
import inspect
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "engine"))
sys.path.insert(0, str(REPO_ROOT / "services/api"))

EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "node_modules",
    ".next",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "data/logs",
    "data/sqlite",
}


def get_tracked_files() -> list[str]:
    """Get list of tracked files using git ls-files, relative to REPO_ROOT."""
    res = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    files = [f.strip() for f in res.stdout.splitlines() if f.strip()]
    return sorted(files)


def extract_file_purpose(rel_path: str) -> str:
    """Extract a one-line purpose from module docstring, heading, or YAML title."""
    full_path = REPO_ROOT / rel_path
    if not full_path.is_file():
        return "(no docstring)"

    ext = full_path.suffix.lower()
    name = full_path.name

    try:
        if ext == ".py":
            with open(full_path, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=str(full_path))
                doc = ast.get_docstring(tree)
                if doc:
                    first_line = doc.strip().splitlines()[0].strip()
                    return first_line if first_line else "(no docstring)"
                # check leading comments
            with open(full_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") and not line.startswith("#!"):
                        cmt = line.lstrip("#").strip()
                        if cmt:
                            return cmt
                    elif line:
                        break
            return "(no docstring)"

        elif ext == ".md":
            with open(full_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#"):
                        return line.lstrip("#").strip()
            return "(no docstring)"

        elif ext in (".yaml", ".yml"):
            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read()
                # Check leading comments
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("#") and not line.startswith("#!"):
                        cmt = line.lstrip("#").strip()
                        if cmt:
                            return cmt
                    elif line:
                        break
                data = yaml.safe_load(content)
                if isinstance(data, dict):
                    if "title" in data:
                        return str(data["title"])
                    if "name" in data:
                        desc = data.get("description", "")
                        return f"{data['name']} - {desc}" if desc else str(data["name"])
                    if "description" in data:
                        return str(data["description"]).splitlines()[0]
                    if "id" in data:
                        return f"Rule {data['id']}"
            return "(no docstring)"

        elif ext in (".ts", ".tsx", ".js", ".mjs"):
            with open(full_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("//"):
                        cmt = line.lstrip("/").strip()
                        if cmt:
                            return cmt
                    elif line.startswith("/*"):
                        cmt = line.lstrip("/*").rstrip("*/").strip()
                        if cmt:
                            return cmt
                    elif line:
                        break
            return "(no docstring)"

        elif ext == ".sh":
            with open(full_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") and not line.startswith("#!"):
                        cmt = line.lstrip("#").strip()
                        if cmt:
                            return cmt
                    elif line and not line.startswith("#!"):
                        break
            return "(no docstring)"

        elif name == "Dockerfile" or name.startswith("Dockerfile."):
            with open(full_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#"):
                        cmt = line.lstrip("#").strip()
                        if cmt:
                            return cmt
                    elif line:
                        break
            return "Container build definition"

    except Exception:
        pass

    return "(no docstring)"


def get_language(rel_path: str) -> str:
    """Determine language classification for a file."""
    ext = Path(rel_path).suffix.lower()
    name = Path(rel_path).name
    if ext == ".py":
        return "Python"
    if ext in (".ts", ".tsx"):
        return "TypeScript"
    if ext in (".js", ".mjs"):
        return "JavaScript"
    if ext in (".yaml", ".yml"):
        return "YAML"
    if ext == ".md":
        return "Markdown"
    if ext == ".sh":
        return "Shell"
    if ext == ".json":
        return "JSON"
    if ext in (".css", ".html"):
        return "Web Styles/Markup"
    if name == "Dockerfile" or name.startswith("Dockerfile."):
        return "Dockerfile"
    if name == "Makefile":
        return "Makefile"
    if ext in (".toml", ".ini", ".cfg"):
        return "Configuration"
    return "Other"


def count_lines(full_path: Path) -> int:
    """Count lines in file safely."""
    try:
        with open(full_path, "rb") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


def build_directory_tree() -> tuple[str, list[str]]:
    """Build a depth-limited directory tree with file counts and exclusions."""
    lines: list[str] = []
    exclusions = [
        "node_modules/ (external JS dependencies)",
        ".venv/ (Python virtual environment)",
        "__pycache__/ (compiled Python bytecode)",
        ".next/ (Next.js build cache)",
        "eval/captures/*/*/* (raw capture payloads/logs; manifests tracked)",
        "data/logs/ (ephemeral telemetry logs)",
        "data/sqlite/ (local SQLite database files)",
        ".git/ (version control metadata)",
    ]

    dirs_to_visit = [
        "apps",
        "content",
        "docs",
        "engine",
        "eval",
        "lab",
        "packages",
        "scripts",
        "services",
    ]

    lines.append("```text")
    lines.append("SentinelX/")
    for top_d in dirs_to_visit:
        top_p = REPO_ROOT / top_d
        if not top_p.is_dir():
            continue
        # Count tracked files under top_d
        res = subprocess.run(
            ["git", "ls-files", top_d], cwd=REPO_ROOT, capture_output=True, text=True, check=True
        )
        t_files = [f for f in res.stdout.splitlines() if f.strip()]
        lines.append(f"├── {top_d}/ ({len(t_files)} tracked files)")

        # Subdirectories (depth 2)
        subdirs = sorted([d for d in top_p.iterdir() if d.is_dir() and d.name not in EXCLUDED_DIRS])
        for idx, sd in enumerate(subdirs):
            is_last = idx == len(subdirs) - 1
            connector = "│   └──" if is_last else "│   ├──"
            sd_rel = f"{top_d}/{sd.name}"
            res_sub = subprocess.run(
                ["git", "ls-files", sd_rel],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=True,
            )
            sub_count = len([f for f in res_sub.stdout.splitlines() if f.strip()])
            lines.append(f"{connector} {sd.name}/ ({sub_count} files)")
            # Depth 3 if needed
            if sd.name in ("sentinelx", "web", "hosts", "decoys", "captures", "routes"):
                sub_subdirs = sorted(
                    [
                        d
                        for d in sd.iterdir()
                        if d.is_dir() and d.name not in EXCLUDED_DIRS and not d.name.startswith(".")
                    ]
                )
                for sidx, ssd in enumerate(sub_subdirs):
                    s_is_last = sidx == len(sub_subdirs) - 1
                    s_connector = "│       └──" if (is_last and s_is_last) else "│   │   ├──"
                    ssd_rel = f"{sd_rel}/{ssd.name}"
                    res_ssd = subprocess.run(
                        ["git", "ls-files", ssd_rel],
                        cwd=REPO_ROOT,
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    ssd_count = len([f for f in res_ssd.stdout.splitlines() if f.strip()])
                    lines.append(f"{s_connector} {ssd.name}/ ({ssd_count} files)")

    lines.append("```")
    return "\n".join(lines), exclusions


def extract_makefile_targets() -> list[dict[str, str]]:
    """Extract Makefile targets, help text, and the first command line."""
    targets = []
    makefile = REPO_ROOT / "Makefile"
    if not makefile.is_file():
        return targets

    with open(makefile, "r", encoding="utf-8") as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        line = lines[i]
        if ":" in line and "##" in line and not line.startswith(("#", "\t")):
            parts = line.split(":", 1)
            target_name = parts[0].strip()
            rest = parts[1]
            help_text = rest.split("##", 1)[1].strip() if "##" in rest else ""

            # Find first command line
            first_cmd = ""
            j = i + 1
            while j < len(lines):
                cmd_line = lines[j]
                if cmd_line.startswith("\t"):
                    stripped = cmd_line.strip()
                    if stripped and not stripped.startswith("#"):
                        first_cmd = stripped
                        break
                    j += 1
                elif cmd_line.startswith(("#", "\n", " ")):
                    j += 1
                else:
                    break

            targets.append(
                {
                    "name": target_name,
                    "help": help_text,
                    "first_cmd": first_cmd or "(none)",
                }
            )
        i += 1

    return sorted(targets, key=lambda t: t["name"])


def extract_api_routes() -> list[dict[str, str]]:
    """Programmatically extract FastAPI routes from services/api/app/main.py."""
    routes: list[dict[str, str]] = []
    try:
        from app.main import app

        for r in app.routes:
            # WebSocket routes
            if hasattr(r, "path") and "websocket" in type(r).__name__.lower():
                ep = r.endpoint
                src_file = str(Path(inspect.getsourcefile(ep)).relative_to(REPO_ROOT))
                src_line = inspect.getsourcelines(ep)[1]
                routes.append(
                    {
                        "method": "WS",
                        "path": r.path,
                        "handler": f"{src_file}:{src_line}",
                    }
                )
            elif "Included" in type(r).__name__:
                router = r.original_router
                for sub_r in router.routes:
                    methods = ",".join(
                        sorted(m for m in getattr(sub_r, "methods", set()) if m != "HEAD")
                    )
                    path = sub_r.path
                    ep = sub_r.endpoint
                    src_file = str(Path(inspect.getsourcefile(ep)).relative_to(REPO_ROOT))
                    src_line = inspect.getsourcelines(ep)[1]
                    routes.append(
                        {
                            "method": methods,
                            "path": path,
                            "handler": f"{src_file}:{src_line}",
                        }
                    )
            elif hasattr(r, "methods"):
                methods = ",".join(sorted(m for m in r.methods if m != "HEAD"))
                if (
                    r.path.startswith("/openapi")
                    or r.path.startswith("/docs")
                    or r.path.startswith("/redoc")
                ):
                    continue
                ep = r.endpoint
                try:
                    src_file = str(Path(inspect.getsourcefile(ep)).relative_to(REPO_ROOT))
                    src_line = inspect.getsourcelines(ep)[1]
                except Exception:
                    src_file = "fastapi"
                    src_line = 0
                routes.append(
                    {
                        "method": methods,
                        "path": r.path,
                        "handler": f"{src_file}:{src_line}",
                    }
                )
    except Exception as exc:
        routes.append(
            {
                "method": "ERROR",
                "path": f"Failed to extract routes: {exc}",
                "handler": "error:0",
            }
        )

    # Sort routes by path, then method
    return sorted(routes, key=lambda r: (r["path"], r["method"]))


def extract_pydantic_models() -> list[dict[str, Any]]:
    """Extract Pydantic models from engine/sentinelx/schemas/."""
    import pydantic
    import sentinelx.schemas.api_models as sa
    import sentinelx.schemas.common as sc
    import sentinelx.schemas.event as se
    import sentinelx.schemas.guard as sg
    import sentinelx.schemas.health as sh
    import sentinelx.schemas.incident as si
    import sentinelx.schemas.signal as ss

    schema_modules = [
        ("common", sc, "Core (Frozen)"),
        ("event", se, "Core (Frozen)"),
        ("signal", ss, "Core (Frozen)"),
        ("incident", si, "Core (Frozen with additive novelty_only)"),
        ("guard", sg, "Core (Frozen)"),
        ("health", sh, "Core (Frozen)"),
        ("api_models", sa, "Additive API"),
    ]

    model_records = []
    for mod_name, mod, tier in schema_modules:
        for name, obj in inspect.getmembers(mod, inspect.isclass):
            if issubclass(obj, pydantic.BaseModel) and obj.__module__ == mod.__name__:
                fields_list = []
                for f_name, f_info in obj.model_fields.items():
                    ann = str(f_info.annotation).replace("typing.", "")
                    if f_info.default is not pydantic_core_pydantic_undefined():
                        def_val = f" = {f_info.default}"
                    else:
                        def_val = ""
                    fields_list.append(f"`{f_name}`: `{ann}{def_val}`")

                model_records.append(
                    {
                        "name": obj.__name__,
                        "module": f"{mod_name}.py",
                        "tier": tier,
                        "field_count": len(fields_list),
                        "fields": ", ".join(fields_list),
                    }
                )

    return sorted(model_records, key=lambda m: (m["tier"], m["name"]))


def pydantic_core_pydantic_undefined():
    try:
        from pydantic_core import PydanticUndefined

        return PydanticUndefined
    except Exception:
        return object()


def extract_yaml_content() -> dict[str, Any]:
    """Programmatically parse all content YAML files."""
    content_dir = REPO_ROOT / "content"
    rules: list[dict[str, Any]] = []
    for rf in sorted((content_dir / "rules").glob("*.yaml")):
        with open(rf, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if data and "id" in data:
                rules.append(
                    {
                        "id": data.get("id"),
                        "title": data.get("title"),
                        "severity": data.get("severity_hint", "medium"),
                        "score": data.get("score", 0.0),
                        "techniques": ", ".join(data.get("technique_ids", [])),
                        "file": str(rf.relative_to(REPO_ROOT)),
                    }
                )

    guard_actions = []
    guard_actions_file = content_dir / "guard" / "actions.yaml"
    if guard_actions_file.is_file():
        with open(guard_actions_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            for act_id, act in (data.get("actions") or {}).items():
                guard_actions.append(
                    {
                        "id": act_id,
                        "name": act.get("name"),
                        "category": act.get("category"),
                        "reversibility": act.get("reversibility"),
                        "safety_risk": act.get("safety_risk"),
                    }
                )

    guard_policies = []
    guard_policies_file = content_dir / "guard" / "policies.yaml"
    if guard_policies_file.is_file():
        with open(guard_policies_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            for pol in data.get("policies") or []:
                conds = pol.get("conditions", {})
                cond_str = (
                    ", ".join(f"{k}={v}" for k, v in conds.items())
                    if conds
                    else "(default catch-all)"
                )
                guard_policies.append(
                    {
                        "id": pol.get("id"),
                        "name": pol.get("name"),
                        "outcome": pol.get("outcome"),
                        "conditions": cond_str,
                    }
                )

    scenarios = []
    for sf in sorted((content_dir / "scenarios").glob("*.yaml")):
        with open(sf, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            steps = data.get("steps") or []
            scenarios.append(
                {
                    "name": data.get("name"),
                    "duration": f"{data.get('target_duration_seconds')}s",
                    "step_count": len(steps),
                    "steps": ", ".join(f"{s.get('id')} ({s.get('action')})" for s in steps),
                    "description": data.get("description", ""),
                }
            )

    mappings = []
    for mf in sorted((content_dir / "mappings").glob("*.yaml")):
        with open(mf, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            mappings.append(
                {
                    "name": data.get("name"),
                    "format": data.get("format"),
                    "source_tool": data.get("source_tool"),
                    "domain": data.get("domain"),
                    "fields": ", ".join(list((data.get("fields") or {}).keys())),
                }
            )

    assets_file = content_dir / "assets.yaml"
    hosts_list = []
    honey_creds_list = []
    honey_files_list = []
    if assets_file.is_file():
        with open(assets_file, "r", encoding="utf-8") as f:
            adata = yaml.safe_load(f)
            for h in adata.get("hosts") or []:
                hosts_list.append(
                    {
                        "name": h.get("name"),
                        "zone": h.get("zone"),
                        "criticality": h.get("criticality"),
                        "process_critical": h.get("process_critical", False),
                        "allowed_ssh_src_zones": ", ".join(h.get("allowed_ssh_src_zones") or ["-"]),
                        "allowed_ot_writers": ", ".join(h.get("allowed_ot_writers") or ["-"]),
                    }
                )
            for hc in adata.get("honey_credentials") or []:
                # USERNAME ONLY per security rule
                honey_creds_list.append(
                    {
                        "username": hc.get("username"),
                        "decoys": ", ".join(hc.get("decoy") or []),
                    }
                )
            honey_files_list = adata.get("honey_files") or []

    return {
        "rules": rules,
        "guard_actions": guard_actions,
        "guard_policies": guard_policies,
        "scenarios": scenarios,
        "mappings": mappings,
        "hosts": hosts_list,
        "honey_creds": honey_creds_list,
        "honey_files": honey_files_list,
    }


def extract_tests() -> list[dict[str, Any]]:
    """Extract all test files, test function names, and test counts."""
    test_records = []
    test_files = sorted(
        list((REPO_ROOT / "engine" / "tests").glob("test_*.py"))
        + list((REPO_ROOT / "services" / "api" / "tests").glob("test_*.py"))
    )

    for tf in test_files:
        rel_path = str(tf.relative_to(REPO_ROOT))
        test_names = []
        try:
            with open(tf, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=str(tf))
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                        test_names.append(node.name)
        except Exception:
            pass

        test_records.append(
            {
                "file": rel_path,
                "count": len(test_names),
                "test_names": ", ".join(test_names),
            }
        )

    return sorted(test_records, key=lambda t: t["file"])


def main():
    print("[*] Generating docs/REPO_MAP.md from git index and codebase...")
    tracked = get_tracked_files()

    source_prefixes = (
        "engine/",
        "services/",
        "apps/web/src/",
        "scripts/",
        "eval/",
        "lab/",
        "content/",
        "docs/",
        "packages/",
    )

    tracked_source_files = [f for f in tracked if any(f.startswith(p) for p in source_prefixes)]

    # Compute language stats and directory totals
    dir_stats: dict[str, dict[str, int]] = {}
    lang_stats: dict[str, dict[str, int]] = {}
    file_records = []

    for rf in tracked_source_files:
        full_p = REPO_ROOT / rf
        lines = count_lines(full_p)
        purpose = extract_file_purpose(rf)
        lang = get_language(rf)

        # Directory root
        top_dir = rf.split("/")[0]
        if top_dir not in dir_stats:
            dir_stats[top_dir] = {"files": 0, "lines": 0}
        dir_stats[top_dir]["files"] += 1
        dir_stats[top_dir]["lines"] += lines

        if lang not in lang_stats:
            lang_stats[lang] = {"files": 0, "lines": 0}
        lang_stats[lang]["files"] += 1
        lang_stats[lang]["lines"] += lines

        file_records.append(
            {
                "path": rf,
                "lines": lines,
                "purpose": purpose,
                "language": lang,
            }
        )

    tree_str, exclusions = build_directory_tree()
    makefile_targets = extract_makefile_targets()
    api_routes = extract_api_routes()
    pydantic_models = extract_pydantic_models()
    yaml_content = extract_yaml_content()
    test_suite = extract_tests()

    total_tests = sum(t["count"] for t in test_suite)
    total_files = len(file_records)
    total_lines = sum(f["lines"] for f in file_records)

    # Render Markdown
    doc: list[str] = []
    doc.append("# SentinelX Repository Map & Codebase Inventory")
    doc.append("")
    doc.append(
        "> Deterministic automated codebase inventory generated by `scripts/gen_repo_map.py`."
    )
    doc.append(
        "> Covers all tracked source code, contracts, content, lab definitions, API endpoints, and tests."
    )
    doc.append("")
    doc.append("---")
    doc.append("")
    doc.append("## 1. Directory Tree & Exclusions")
    doc.append("")
    doc.append("### Excluded Directories & Ephemeral Payloads")
    for ex in exclusions:
        doc.append(f"- `{ex}`")
    doc.append("")
    doc.append("### Directory Structure")
    doc.append(tree_str)
    doc.append("")
    doc.append("---")
    doc.append("")
    doc.append("## 2. Directory Totals & Language Breakdown")
    doc.append("")
    doc.append("### Per-Directory Totals")
    doc.append("| Top Directory | Files | Total Lines | Description |")
    doc.append("| :--- | :---: | :---: | :--- |")
    for d, st in sorted(dir_stats.items()):
        doc.append(
            f"| `{d}/` | {st['files']} | {st['lines']} | Tracked source and configuration tree |"
        )
    doc.append(
        f"| **Total** | **{total_files}** | **{total_lines}** | **Full Tracked Source Repository** |"
    )
    doc.append("")
    doc.append("### Language Breakdown")
    doc.append("| Language | Files | Lines | Percentage (Lines) |")
    doc.append("| :--- | :---: | :---: | :---: |")
    for lang_name, st in sorted(lang_stats.items(), key=lambda x: x[1]["lines"], reverse=True):
        pct = (st["lines"] / total_lines * 100.0) if total_lines > 0 else 0.0
        doc.append(f"| {lang_name} | {st['files']} | {st['lines']} | {pct:.1f}% |")
    doc.append("")
    doc.append("---")
    doc.append("")
    doc.append("## 3. Complete Source File Inventory")
    doc.append("")
    doc.append("| Path | Lines | Language | Purpose / One-Line Summary |")
    doc.append("| :--- | :---: | :--- | :--- |")
    for fr in sorted(file_records, key=lambda f: f["path"]):
        # Escape pipe in purpose
        purp = fr["purpose"].replace("|", "\\|")
        doc.append(
            f"| [`{fr['path']}`]({fr['path']}) | {fr['lines']} | {fr['language']} | {purp} |"
        )
    doc.append("")
    doc.append("---")
    doc.append("")
    doc.append("## 4. Makefile Targets Table")
    doc.append("")
    doc.append("| Target | Help Description | First Command Line |")
    doc.append("| :--- | :--- | :--- |")
    for mt in makefile_targets:
        cmd = mt["first_cmd"].replace("|", "\\|")
        doc.append(f"| `make {mt['name']}` | {mt['help']} | `{cmd}` |")
    doc.append("")
    doc.append("---")
    doc.append("")
    doc.append("## 5. API Routes Table")
    doc.append("")
    doc.append("| Method | Path | Handler File & Line |")
    doc.append("| :--- | :--- | :--- |")
    for ar in api_routes:
        doc.append(f"| `{ar['method']}` | `{ar['path']}` | [`{ar['handler']}`]({ar['handler']}) |")
    doc.append("")
    doc.append("---")
    doc.append("")
    doc.append("## 6. Pydantic Schemas & Data Contracts")
    doc.append("")
    doc.append("| Model Name | Tier / Contract Status | Module | Field Count | Fields & Types |")
    doc.append("| :--- | :--- | :--- | :---: | :--- |")
    for pm in pydantic_models:
        f_repr = pm["fields"].replace("|", "\\|")
        doc.append(
            f"| `{pm['name']}` | **{pm['tier']}** | `engine/sentinelx/schemas/{pm['module']}` | {pm['field_count']} | {f_repr} |"
        )
    doc.append("")
    doc.append("---")
    doc.append("")
    doc.append("## 7. Declarative YAML Content")
    doc.append("")
    doc.append("### Detection Rules (`content/rules/*.yaml`)")
    doc.append("| Rule ID | Title | Severity Hint | Score | MITRE Technique IDs | Source File |")
    doc.append("| :--- | :--- | :--- | :---: | :--- | :--- |")
    for r in yaml_content["rules"]:
        doc.append(
            f"| `{r['id']}` | {r['title']} | `{r['severity']}` | {r['score']:.2f} | `{r['techniques']}` | [`{r['file']}`]({r['file']}) |"
        )
    doc.append("")
    doc.append("### Response Safety Guard Actions (`content/guard/actions.yaml`)")
    doc.append("| Action ID | Action Name | Category | Reversibility | Safety Risk |")
    doc.append("| :--- | :--- | :--- | :--- | :--- |")
    for ga in yaml_content["guard_actions"]:
        doc.append(
            f"| `{ga['id']}` | {ga['name']} | `{ga['category']}` | `{ga['reversibility']}` | `{ga['safety_risk']}` |"
        )
    doc.append("")
    doc.append("### Response Safety Guard Policies (`content/guard/policies.yaml`)")
    doc.append("| Policy ID | Policy Name | Outcome | Conditions |")
    doc.append("| :--- | :--- | :--- | :--- |")
    for gp in yaml_content["guard_policies"]:
        doc.append(
            f"| `{gp['id']}` | {gp['name']} | `{gp['outcome'].upper()}` | {gp['conditions']} |"
        )
    doc.append("")
    doc.append("### Attack & Benign Scenarios (`content/scenarios/*.yaml`)")
    doc.append("| Scenario Name | Duration | Steps | Description | Steps List |")
    doc.append("| :--- | :---: | :---: | :--- | :--- |")
    for sc_item in yaml_content["scenarios"]:
        doc.append(
            f"| `{sc_item['name']}` | {sc_item['duration']} | {sc_item['step_count']} | {sc_item['description']} | {sc_item['steps']} |"
        )
    doc.append("")
    doc.append("### Ingestion Telemetry Mappings (`content/mappings/*.yaml`)")
    doc.append("| Mapping Name | Format | Source Tool | Domain | Mapped Fields |")
    doc.append("| :--- | :--- | :--- | :--- | :--- |")
    for mp in yaml_content["mappings"]:
        doc.append(
            f"| `{mp['name']}` | `{mp['format']}` | `{mp['source_tool']}` | `{mp['domain']}` | {mp['fields']} |"
        )
    doc.append("")
    doc.append("### Network & Asset Inventory (`content/assets.yaml`)")
    doc.append(
        "| Host Name | Zone | Criticality | Process Critical | Allowed SSH Source Zones | Allowed OT Writers |"
    )
    doc.append("| :--- | :--- | :--- | :---: | :--- | :--- |")
    for asst in yaml_content["hosts"]:
        doc.append(
            f"| `{asst['name']}` | `{asst['zone']}` | `{asst['criticality']}` | `{asst['process_critical']}` | `{asst['allowed_ssh_src_zones']}` | `{asst['allowed_ot_writers']}` |"
        )
    doc.append("")
    doc.append("### Honeytoken Credentials & Decoy Files (Usernames Only)")
    doc.append("| Honey Username (Decoy) | Associated Decoy Assets |")
    doc.append("| :--- | :--- |")
    for hc in yaml_content["honey_creds"]:
        doc.append(f"| `{hc['username']}` | `{hc['decoys']}` |")
    doc.append("")
    doc.append("**Honeytoken Bait Files:**")
    for hf in yaml_content["honey_files"]:
        doc.append(f"- `{hf}`")
    doc.append("")
    doc.append("---")
    doc.append("")
    doc.append("## 8. Test Suites & Test Count")
    doc.append("")
    doc.append(f"Total Unit and Integration Tests: **{total_tests}**")
    doc.append("")
    doc.append("| Test File | Test Count | Test Function Names |")
    doc.append("| :--- | :---: | :--- |")
    for tst in test_suite:
        doc.append(f"| [`{tst['file']}`]({tst['file']}) | {tst['count']} | `{tst['test_names']}` |")
    doc.append("")

    out_file = REPO_ROOT / "docs" / "REPO_MAP.md"
    out_file.write_text("\n".join(doc), encoding="utf-8")
    print(f"[+] Successfully wrote {out_file} ({len(doc)} lines)")


if __name__ == "__main__":
    main()
