import asyncio
from pathlib import Path

import pytest
from sentinelx.ingest.tailer import AsyncFileTailer, CheckpointManager


@pytest.mark.anyio
async def test_tailer_partial_line_and_incremental(tmp_path: Path):
    log_file = tmp_path / "test.log"
    log_file.write_text("line1\nline2\npartial", encoding="utf-8")

    db_file = tmp_path / "checkpoints.db"
    cm = CheckpointManager(db_file)

    tailer = AsyncFileTailer(
        file_path=log_file,
        source_key="test_src",
        source_tool="test_tool",
        checkpoint_mgr=cm,
        poll_interval=0.05,
    )

    collected = []

    async def run_tailer():
        async for line, ctx in tailer.tail_lines():
            collected.append((line, ctx.offset))
            if len(collected) == 3:
                tailer.stop()

    task = asyncio.create_task(run_tailer())

    # Wait briefly for first two lines
    await asyncio.sleep(0.15)
    assert len(collected) == 2
    assert collected[0][0] == "line1"
    assert collected[1][0] == "line2"

    # Append completion of partial line
    with open(log_file, "a", encoding="utf-8") as f:
        f.write("_completed\n")

    await asyncio.sleep(0.15)
    await task

    assert len(collected) == 3
    assert collected[2][0] == "partial_completed"

    # Checkpoint saved
    cp = cm.get_checkpoint("test_src")
    assert cp is not None
    assert cp[1] == log_file.stat().st_size


@pytest.mark.anyio
async def test_tailer_resume_zero_duplicates(tmp_path: Path):
    log_file = tmp_path / "resume.log"
    log_file.write_text("line1\nline2\n", encoding="utf-8")

    db_file = tmp_path / "checkpoints.db"
    cm = CheckpointManager(db_file)

    tailer1 = AsyncFileTailer(
        file_path=log_file,
        source_key="resume_src",
        source_tool="test_tool",
        checkpoint_mgr=cm,
        poll_interval=0.05,
    )

    collected1 = []

    async def run_first():
        async for line, _ in tailer1.tail_lines():
            collected1.append(line)
            if len(collected1) == 2:
                tailer1.stop()

    await run_first()
    assert collected1 == ["line1", "line2"]

    # Now append line3 and create tailer2 with same checkpoint manager
    with open(log_file, "a", encoding="utf-8") as f:
        f.write("line3\n")

    tailer2 = AsyncFileTailer(
        file_path=log_file,
        source_key="resume_src",
        source_tool="test_tool",
        checkpoint_mgr=cm,
        poll_interval=0.05,
    )

    collected2 = []

    async def run_second():
        async for line, _ in tailer2.tail_lines():
            collected2.append(line)
            if len(collected2) == 1:
                tailer2.stop()

    await run_second()
    # Zero duplicates! line1 and line2 should NOT be re-read
    assert collected2 == ["line3"]


@pytest.mark.anyio
async def test_tailer_file_truncation(tmp_path: Path):
    log_file = tmp_path / "trunc.log"
    log_file.write_text("initial_long_line_here\n", encoding="utf-8")

    tailer = AsyncFileTailer(
        file_path=log_file,
        source_key="trunc_src",
        source_tool="test_tool",
        poll_interval=0.05,
    )

    collected = []

    async def run():
        async for line, _ in tailer.tail_lines():
            collected.append(line)
            if len(collected) == 2:
                tailer.stop()

    task = asyncio.create_task(run())
    await asyncio.sleep(0.1)
    assert collected == ["initial_long_line_here"]

    # Truncate and write shorter content
    log_file.write_text("new\n", encoding="utf-8")
    await asyncio.sleep(0.15)
    await task

    assert collected == ["initial_long_line_here", "new"]


@pytest.mark.anyio
async def test_tailer_file_rotation(tmp_path: Path):
    log_file = tmp_path / "conn.log"
    log_file.write_text("old_line\n", encoding="utf-8")

    tailer = AsyncFileTailer(
        file_path=log_file,
        source_key="rot_src",
        source_tool="test_tool",
        poll_interval=0.05,
    )

    collected = []

    async def run():
        async for line, _ in tailer.tail_lines():
            collected.append(line)
            if len(collected) == 2:
                tailer.stop()

    task = asyncio.create_task(run())
    await asyncio.sleep(0.1)
    assert collected == ["old_line"]

    # Rotate file: rename old and create new active file with new inode
    rotated_file = tmp_path / "conn.2026-11-07.log"
    log_file.rename(rotated_file)
    log_file.write_text("new_line_after_rotation\n", encoding="utf-8")

    await asyncio.sleep(0.15)
    await task

    assert collected == ["old_line", "new_line_after_rotation"]
