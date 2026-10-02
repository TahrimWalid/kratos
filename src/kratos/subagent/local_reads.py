"""
The local socket between an investigating process (the TUI, `kratos
investigate`, a scheduled run, MCP) and the sub-agent listener that holds the
agents' connections (`kratos subagent-serve`, or the TUI's in-window
listener). docs/subagent_read_routing.md D2.

Why a socket: the listener and the investigation are usually different
processes, and only the listener can write onto an agent's connection (the
agent dialed it; core never dials the agent). One request per connection,
same length-prefixed JSON framing as the agent channel.

Locked down on both ends:
  - the socket file is created owner-only (0600) -- umask set BEFORE bind,
    so there is no window where it is reachable by others -- in the data dir
    (or, if that path is too long for a Unix socket, an owner-only 0700
    runtime directory);
  - the listener checks the connecting process's uid (SO_PEERCRED): only its
    own user (or root) is served;
  - the client refuses a socket owned by another user or with loose
    permissions before connecting;
  - a socket left behind by a crashed listener is detected (nothing answers)
    and replaced on start; a live one is never stolen.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import os
import socket
import stat
import struct
import time
from pathlib import Path
from typing import Any

from kratos.subagent import protocol as proto
from kratos.subagent import reads

logger = logging.getLogger("kratos.subagent.local_reads")

SOCKET_NAME = "subagent-reads.sock"
_MAX_SUN_PATH = 100  # sockaddr_un holds 108 bytes; leave room
REQUEST_READ_TIMEOUT_SECONDS = 10.0
# The listener waits this long for a target that isn't connected yet but is
# expected back soon (a listener that just started, or an agent mid-reconnect).
WAIT_FOR_AGENT_SECONDS = 20.0
REPLY_MARGIN_SECONDS = 15.0

MSG_LOCAL_READ = "local_read"
MSG_LOCAL_READ_RESULT = "local_read_result"
MSG_LOCAL_STATUS = "local_status"
MSG_LOCAL_STATUS_RESULT = "local_status_result"
MSG_LOCAL_REFUSED = "local_refused"


class LocalReadError(RuntimeError):
    """The read could not be delivered. `kind` is one of: no_listener,
    refused, timeout, protocol. The message is written for a person."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


NO_LISTENER_MESSAGE = (
    "No Kratos listener is running, so this target's sub-agent can't be reached. "
    "Open /subagent in Kratos (it starts one for this window), or install the always-on "
    "listener there (press L) so investigations work any time."
)


def socket_path(data_dir: Path) -> Path:
    data_dir = Path(data_dir).resolve()
    p = data_dir / SOCKET_NAME
    if len(str(p).encode()) <= _MAX_SUN_PATH:
        return p
    digest = hashlib.sha256(str(data_dir).encode()).hexdigest()[:16]
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    base = Path(runtime) if runtime and Path(runtime).is_dir() else Path(f"/tmp/kratos-{os.getuid()}")
    return base / f"kratos-reads-{digest}.sock"


def _ensure_private_dir(directory: Path) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = os.lstat(directory)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
        raise LocalReadError("refused", f"{directory} is not a directory owned by this user")
    if str(directory).startswith("/tmp/kratos-") and st.st_mode & 0o077:
        os.chmod(directory, 0o700)


def _answers(path: Path) -> bool:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        s.connect(str(path))
        return True
    except OSError:
        return False
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Server (inside the listener's event loop)
# ---------------------------------------------------------------------------
class LocalReadServer:
    def __init__(self, core: Any, path: Path):
        self.core = core
        self.path = Path(path)
        self._server: asyncio.AbstractServer | None = None
        self._inode: tuple[int, int] | None = None
        self.started_monotonic = time.monotonic()

    async def start(self) -> None:
        _ensure_private_dir(self.path.parent)
        try:
            st = os.lstat(self.path)
        except FileNotFoundError:
            st = None
        if st is not None:
            if not stat.S_ISSOCK(st.st_mode):
                raise LocalReadError("refused", f"{self.path} exists and is not a socket -- not touching it")
            if await asyncio.get_event_loop().run_in_executor(None, _answers, self.path):
                raise LocalReadError("refused", f"another Kratos listener already serves {self.path}")
            os.unlink(self.path)  # left behind by a listener that died
        old = os.umask(0o177)  # 0600 from the moment it exists
        try:
            self._server = await asyncio.start_unix_server(self._handle, path=str(self.path))
        finally:
            os.umask(old)
        os.chmod(self.path, 0o600)
        st = os.lstat(self.path)
        self._inode = (st.st_dev, st.st_ino)
        self.started_monotonic = time.monotonic()
        logger.info("local read socket listening at %s", self.path)

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._server.wait_closed(), timeout=2.0)
        with contextlib.suppress(OSError):
            st = os.lstat(self.path)
            if self._inode == (st.st_dev, st.st_ino):  # never remove a successor's socket
                os.unlink(self.path)

    @staticmethod
    def _peer_uid(writer: asyncio.StreamWriter) -> int | None:
        sock = writer.get_extra_info("socket")
        if sock is None or not hasattr(socket, "SO_PEERCRED"):
            return None
        try:
            creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", creds)
            return uid
        except OSError:
            return None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            uid = self._peer_uid(writer)
            if uid is None or uid not in (os.getuid(), 0):
                await proto.write_frame(writer, {"type": MSG_LOCAL_REFUSED,
                                                 "reason": "this listener only serves its own user"})
                return
            msg = await asyncio.wait_for(proto.read_frame(reader), timeout=REQUEST_READ_TIMEOUT_SECONDS)
            if msg is None:
                return
            if msg.get("type") == MSG_LOCAL_STATUS:
                reply = {"type": MSG_LOCAL_STATUS_RESULT, **self.core.local_status()}
            elif msg.get("type") == MSG_LOCAL_READ:
                result = await self._serve_read(msg)
                reply = {"type": MSG_LOCAL_READ_RESULT, **result}
            else:
                reply = {"type": MSG_LOCAL_REFUSED, "reason": f"unknown request {msg.get('type')!r}"}
            try:
                await proto.write_frame(writer, reply)
            except proto.FrameTooLargeError:
                await proto.write_frame(writer, {"type": MSG_LOCAL_READ_RESULT, "status": "error",
                                                 "reason": "the result was too large to pass on"})
        except (asyncio.TimeoutError, proto.ProtocolError, OSError, ConnectionError) as e:
            logger.debug("local read connection ended: %s", e)
        except Exception:  # noqa: BLE001 -- one bad request must never take the listener down
            logger.exception("local read request failed")
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _serve_read(self, msg: dict[str, Any]) -> dict[str, Any]:
        target_id, probe, params = msg.get("target_id"), msg.get("probe"), msg.get("params")
        if not isinstance(target_id, str) or not isinstance(probe, str) or not isinstance(params, dict):
            return {"status": "refused", "reason": "malformed local read request"}
        if probe not in reads.READ_PROBES:
            return {"status": "unsupported", "reason": f"Kratos has no {probe!r} read"}
        try:
            params = reads.validate_params(probe, params)  # fail fast here; the agent re-checks
        except reads.ReadParamError as e:
            return {"status": "refused", "reason": str(e)}
        if not self.core.is_live(target_id):
            waited = await self._wait_for_agent(target_id)
            if not waited:
                return self.core.offline_result(target_id)
        return await self.core.read_probe(target_id, probe, params)

    async def _wait_for_agent(self, target_id: str) -> bool:
        if not self.core.expect_reconnect(target_id, self.started_monotonic):
            return False
        deadline = time.monotonic() + WAIT_FOR_AGENT_SECONDS
        while time.monotonic() < deadline:
            await asyncio.sleep(0.25)
            if self.core.is_live(target_id):
                return True
        return False


# ---------------------------------------------------------------------------
# Client (blocking; called from a tool running in a worker thread)
# ---------------------------------------------------------------------------
def _no_listener() -> LocalReadError:
    """Say which case it is: nothing running at all, or a listener that can't
    serve reads (an older build, or one started for a different data folder)."""
    from kratos.subagent.core_listener import listener_running

    if listener_running():
        return LocalReadError("no_listener", (
            "A Kratos listener is running, but it can't serve investigation reads -- it's an older build "
            "or was started for a different data folder. Restart it (systemctl restart kratos-core-listener, "
            "or the user service) so it picks up this version."))
    return LocalReadError("no_listener", NO_LISTENER_MESSAGE)


def _request(data_dir: Path, message: dict[str, Any], timeout: float) -> dict[str, Any]:
    path = socket_path(data_dir)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise _no_listener() from None
    if not stat.S_ISSOCK(st.st_mode):
        raise LocalReadError("protocol", f"{path} is not a socket")
    if st.st_uid not in (os.getuid(), 0):
        raise LocalReadError("refused", f"the listener socket {path} belongs to another user -- not using it")
    if st.st_mode & 0o077:
        raise LocalReadError("refused", f"the listener socket {path} is readable by other users -- not using it "
                                        "(restart the listener to recreate it)")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        try:
            s.connect(str(path))
        except (ConnectionRefusedError, FileNotFoundError):
            raise _no_listener() from None
        proto.send_frame_sync(s, message)
        reply = proto.recv_frame_sync(s)
    except socket.timeout:
        raise LocalReadError("timeout", f"the Kratos listener didn't answer within {int(timeout)}s") from None
    except EOFError:
        raise LocalReadError("protocol", "the Kratos listener closed the connection without answering "
                                         "(it may have just restarted -- try again)") from None
    except (proto.ProtocolError, OSError) as e:
        raise LocalReadError("protocol", f"talking to the Kratos listener failed: {e}") from None
    finally:
        s.close()
    if reply.get("type") == MSG_LOCAL_REFUSED:
        raise LocalReadError("refused", f"the Kratos listener refused the request: {reply.get('reason')}")
    return reply


def request_read(data_dir: Path, target_id: str, probe: str, params: dict[str, Any]) -> dict[str, Any]:
    """Ask the listener to run one named probe on a target's sub-agent.
    Returns {status, reason?, data?}; raises LocalReadError only when the
    listener itself can't be reached or misbehaves."""
    budget = reads.PROBE_TIMEOUT_SECONDS.get(probe, 30) + REPLY_MARGIN_SECONDS * 2 + WAIT_FOR_AGENT_SECONDS
    reply = _request(Path(data_dir), {"type": MSG_LOCAL_READ, "target_id": target_id, "probe": probe,
                                      "params": params}, timeout=budget)
    reply.pop("type", None)
    return reply


def listener_status(data_dir: Path, timeout: float = 3.0) -> dict[str, Any] | None:
    """What the running listener holds right now (None when none answers)."""
    try:
        reply = _request(Path(data_dir), {"type": MSG_LOCAL_STATUS}, timeout=timeout)
    except LocalReadError:
        return None
    reply.pop("type", None)
    return reply
