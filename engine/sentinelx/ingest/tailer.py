"""Async file tailer supporting incremental reads, rotation, truncation, and checkpoints."""

import asyncio
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncGenerator, Literal


@dataclass
class SourceContext:
    source_key: str
    source_tool: str
    file_path: Path
    offset: int
    line_number: int = 0
    zone: str | None = None
    ignore_reason: str | None = None


class CheckpointManager:
    """Manages persistence of tailer byte offsets and inodes in SQLite."""

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self.init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def init_db(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._get_conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ingest_checkpoints (
                    source_key TEXT PRIMARY KEY,
                    inode INTEGER NOT NULL,
                    offset INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            conn.commit()

    def get_checkpoint(self, source_key: str) -> tuple[int, int] | None:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT inode, offset FROM ingest_checkpoints WHERE source_key = ?;",
                (source_key,),
            ).fetchone()
            if row:
                return (int(row[0]), int(row[1]))
            return None

    def save_checkpoint(self, source_key: str, inode: int, offset: int):
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO ingest_checkpoints (source_key, inode, offset, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(source_key) DO UPDATE SET
                    inode=excluded.inode,
                    offset=excluded.offset,
                    updated_at=excluded.updated_at;
                """,
                (source_key, inode, offset, now_iso),
            )
            conn.commit()


class AsyncFileTailer:
    """Incrementally tails a single log file without blocking the event loop."""

    def __init__(
        self,
        file_path: Path | str,
        source_key: str,
        source_tool: str,
        mode: Literal["from_start", "from_end"] = "from_start",
        zone: str | None = None,
        checkpoint_mgr: CheckpointManager | None = None,
        poll_interval: float = 0.5,
        chunk_size: int = 65536,
    ):
        self.file_path = Path(file_path).resolve()
        self.source_key = source_key
        self.source_tool = source_tool
        self.mode = mode
        self.zone = zone
        self.checkpoint_mgr = checkpoint_mgr
        self.poll_interval = poll_interval
        self.chunk_size = chunk_size

        self.current_inode: int | None = None
        self.current_offset: int = 0
        self.line_count: int = 0
        self.running: bool = False
        self._line_buffer: str = ""

    async def tail_lines(self) -> AsyncGenerator[tuple[str, SourceContext], None]:
        """Async generator yielding (line, SourceContext) pairs."""
        self.running = True

        # 1. Wait for initial file creation
        while self.running and not self.file_path.exists():
            await asyncio.sleep(self.poll_interval)

        if not self.running:
            return

        stat = self.file_path.stat()
        self.current_inode = stat.st_ino

        # Check existing checkpoint
        checkpoint = (
            self.checkpoint_mgr.get_checkpoint(self.source_key) if self.checkpoint_mgr else None
        )
        if checkpoint:
            cp_inode, cp_offset = checkpoint
            if cp_inode == self.current_inode and cp_offset <= stat.st_size:
                self.current_offset = cp_offset
            else:
                self.current_offset = 0 if self.mode == "from_start" else stat.st_size
        else:
            self.current_offset = 0 if self.mode == "from_start" else stat.st_size

        # 2. Open and tail file loop
        f = open(self.file_path, "r", encoding="utf-8", errors="replace")
        f.seek(self.current_offset)

        try:
            while self.running:
                # Check for file existence and rotation / truncation
                if not self.file_path.exists():
                    await asyncio.sleep(self.poll_interval)
                    continue

                try:
                    stat = self.file_path.stat()
                except FileNotFoundError:
                    await asyncio.sleep(self.poll_interval)
                    continue

                # Check for file rotation (inode change)
                if stat.st_ino != self.current_inode:
                    # Read any remaining content from old file before switching
                    while True:
                        chunk = await asyncio.to_thread(f.read, self.chunk_size)
                        if not chunk:
                            break
                        async for item in self._process_chunk(chunk):
                            yield item

                    f.close()
                    # Switch to rotated file
                    self.current_inode = stat.st_ino
                    self.current_offset = 0
                    self._line_buffer = ""
                    f = open(self.file_path, "r", encoding="utf-8", errors="replace")

                # Check for truncation (size shrank)
                elif stat.st_size < self.current_offset:
                    f.seek(0)
                    self.current_offset = 0
                    self._line_buffer = ""

                # Read available data
                chunk = await asyncio.to_thread(f.read, self.chunk_size)
                if chunk:
                    async for item in self._process_chunk(chunk):
                        yield item
                else:
                    await asyncio.sleep(self.poll_interval)

        finally:
            f.close()

    async def _process_chunk(self, chunk: str) -> AsyncGenerator[tuple[str, SourceContext], None]:
        """Process incoming chunk, buffering partial lines and yielding complete lines."""
        text = self._line_buffer + chunk
        lines = text.split("\n")

        # The last segment after split is either an incomplete line or empty if ended with newline
        self._line_buffer = lines[-1]
        complete_lines = lines[:-1]

        for line in complete_lines:
            line_str = line.strip("\r")
            if not line_str:
                # Still advance offset for empty line (\n or \r\n)
                line_bytes = len((line + "\n").encode("utf-8"))
                self.current_offset += line_bytes
                if self.checkpoint_mgr and self.current_inode is not None:
                    self.checkpoint_mgr.save_checkpoint(
                        self.source_key, self.current_inode, self.current_offset
                    )
                continue

            self.line_count += 1
            line_start_offset = self.current_offset
            line_bytes = len((line + "\n").encode("utf-8"))
            self.current_offset += line_bytes

            ctx = SourceContext(
                source_key=self.source_key,
                source_tool=self.source_tool,
                file_path=self.file_path,
                offset=line_start_offset,
                line_number=self.line_count,
                zone=self.zone,
            )

            if self.checkpoint_mgr and self.current_inode is not None:
                self.checkpoint_mgr.save_checkpoint(
                    self.source_key, self.current_inode, self.current_offset
                )

            yield (line_str, ctx)

    def stop(self):
        self.running = False
