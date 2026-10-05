"""Cancellation shared by command readers within one read-only audit."""

import os
import signal
import subprocess
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar


class AuditCancelled(BaseException):
    """Stop a worker without converting cancellation into a check finding."""


_session: ContextVar["AuditSession | None"] = ContextVar("audit_session", default=None)


def check_cancelled() -> None:
    session = _session.get()
    if session is not None and session.cancelled.is_set():
        raise AuditCancelled()


def current_session() -> "AuditSession | None":
    return _session.get()


class AuditSession:
    def __init__(self) -> None:
        self.cancelled = threading.Event()
        self._lock = threading.Lock()
        self._processes: set[subprocess.Popen[str]] = set()

    @contextmanager
    def bind(self) -> Iterator[None]:
        token = _session.set(self)
        try:
            check_cancelled()
            yield
        finally:
            _session.reset(token)

    @staticmethod
    def _signal(process: subprocess.Popen[str], sig: signal.Signals) -> None:
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass

    def cancel(self) -> None:
        self.cancelled.set()
        main_thread = threading.current_thread() is threading.main_thread()
        previous_handler = signal.getsignal(signal.SIGINT) if main_thread else None
        if main_thread:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
        try:
            self._cancel_processes()
        finally:
            if main_thread:
                signal.signal(
                    signal.SIGINT,
                    previous_handler if previous_handler is not None else signal.SIG_DFL,
                )

    def _cancel_processes(self) -> None:
        # Starting and registering a process is atomic with respect to cancellation.
        with self._lock:
            processes = tuple(self._processes)
        for process in processes:
            self._signal(process, signal.SIGTERM)
        if processes:
            time.sleep(0.15)
        # Retain the snapshot: a leader can exit while its descendants ignore TERM.
        for process in processes:
            self._signal(process, signal.SIGKILL)

    def capture(
        self,
        command: list[str],
        timeout: float,
        input_str: str | None = None,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        with self._lock:
            if self.cancelled.is_set():
                raise AuditCancelled()
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE if input_str is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                start_new_session=True,
            )
            self._processes.add(process)
        deadline = time.monotonic() + timeout
        first = True
        try:
            while True:
                if self.cancelled.is_set():
                    raise AuditCancelled()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                try:
                    stdout, stderr = process.communicate(
                        input=input_str if first else None, timeout=min(0.1, remaining)
                    )
                    if self.cancelled.is_set():
                        raise AuditCancelled()
                    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
                except subprocess.TimeoutExpired:
                    first = False
        finally:
            try:
                if process.poll() is None:
                    self._signal(process, signal.SIGTERM)
                    try:
                        process.wait(timeout=0.15)
                    except subprocess.TimeoutExpired:
                        pass
                # Also clean up descendants when the leader has already exited.
                self._signal(process, signal.SIGKILL)
                process.communicate()
            finally:
                with self._lock:
                    self._processes.discard(process)


def capture(
    command: list[str],
    timeout: float,
    input_str: str | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    session = current_session()
    if session is not None:
        return session.capture(command, timeout, input_str, env)
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
        input=input_str,
        stdin=subprocess.DEVNULL if input_str is None else None,
        env=env,
    )
