"""Bound HTTPS and DNS probes in a short-lived, cancellable process."""

import http.client
import json
import queue
import sys
import threading
import time
import urllib.error
import urllib.request

HTTPS_TARGETS = (
    "https://archlinux.org/",
    "https://aur.archlinux.org/",
    "https://flathub.org/",
)


def _reachable(url: str, timeout: float) -> bool:
    try:
        request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "DotDoctor"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.geturl().startswith("https://")
    except urllib.error.HTTPError as exc:
        # A verified HTTPS response proves reachability, even if this service
        # rejects HEAD or currently returns an application/server error.
        reachable = exc.geturl().startswith("https://")
        exc.close()
        return reachable
    except (OSError, ValueError, http.client.HTTPException):
        return False


def probe(targets: tuple[str, ...], timeout: float) -> bool:
    if not targets or timeout <= 0:
        return False
    answers: queue.Queue[bool] = queue.Queue()
    deadline = time.monotonic() + timeout
    reader = _reachable

    def check(url: str) -> None:
        answers.put(reader(url, timeout))

    # Daemon readers cannot delay worker exit when DNS ignores socket timeouts.
    # The parent also bounds and cancels this entire process.
    for target in targets:
        threading.Thread(target=check, args=(target,), daemon=True).start()
    for _ in targets:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        try:
            if answers.get(timeout=remaining):
                return True
        except queue.Empty:
            return False
    return False


if __name__ == "__main__":
    print(json.dumps(probe(tuple(json.loads(sys.argv[1])), float(sys.argv[2]))))
