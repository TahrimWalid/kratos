"""Cooperative cancellation for the commands one piece of work starts.

Collection (kratos.collect) runs several checks in parallel under a time budget.
When the budget runs out, a check that is still waiting on an `ssh` or `nmap`
process must really stop -- not be left running on this machine or, through the
open connection, on the monitored one. A `CancelScope` is bound to a check's
thread (a ContextVar, so it follows `contextvars.copy_context()`); every command
started through `run()` while it is active is registered with it, and
`scope.cancel()` kills them all. With no scope active `run()` is exactly
`subprocess.run`, so code that is never collected behaves as before and tests
that patch `subprocess.run` keep working.
"""
from __future__ import annotations

import contextlib
import contextvars
import subprocess
import threading
from typing import Any, Iterator


class CancelScope:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._procs: set[subprocess.Popen] = set()
        self._cancelled = False

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def _register(self, proc: subprocess.Popen) -> bool:
        """False when the scope is already cancelled (the caller must not start work)."""
        with self._lock:
            if self._cancelled:
                return False
            self._procs.add(proc)
            return True

    def _forget(self, proc: subprocess.Popen) -> None:
        with self._lock:
            self._procs.discard(proc)

    def cancel(self) -> int:
        """Kill every command still running under this scope. Returns how many."""
        with self._lock:
            self._cancelled = True
            procs = list(self._procs)
        killed = 0
        for proc in procs:
            if proc.poll() is None:
                with contextlib.suppress(OSError):
                    proc.kill()
                    killed += 1
        return killed


_CURRENT: contextvars.ContextVar[CancelScope | None] = contextvars.ContextVar("kratos_cancel_scope", default=None)


def current() -> CancelScope | None:
    return _CURRENT.get()


@contextlib.contextmanager
def bound(scope: CancelScope) -> Iterator[CancelScope]:
    token = _CURRENT.set(scope)
    try:
        yield scope
    finally:
        _CURRENT.reset(token)


class Cancelled(Exception):
    """The work was cancelled (its time budget ran out) before the command started or while it ran."""


def run(argv: list[str], *, input: str | None = None, timeout: float | None = None,
        **kwargs: Any) -> subprocess.CompletedProcess:
    """`subprocess.run(argv, ...)`, killable through the active CancelScope.
    Accepts the keyword arguments the callers use (capture_output, text, errors,
    check)."""
    scope = _CURRENT.get()
    if scope is None:
        if input is not None:
            kwargs["input"] = input
        if timeout is not None:
            kwargs["timeout"] = timeout
        return subprocess.run(argv, **kwargs)
    check = kwargs.pop("check", False)
    capture = kwargs.pop("capture_output", False)
    if capture:
        kwargs.setdefault("stdout", subprocess.PIPE)
        kwargs.setdefault("stderr", subprocess.PIPE)
    if input is not None:
        kwargs.setdefault("stdin", subprocess.PIPE)
    with subprocess.Popen(argv, **kwargs) as proc:
        if not scope._register(proc):
            proc.kill()
            raise Cancelled("cancelled before the command started")
        try:
            try:
                stdout, stderr = proc.communicate(input, timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                raise
        finally:
            scope._forget(proc)
        if scope.cancelled and proc.returncode in (-9, -15):
            raise Cancelled("cancelled while the command was running")
        if check and proc.returncode:
            raise subprocess.CalledProcessError(proc.returncode, argv, output=stdout, stderr=stderr)
        return subprocess.CompletedProcess(argv, proc.returncode, stdout, stderr)
