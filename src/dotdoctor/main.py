import signal
import sys
from typing import Any


def _handle_sigterm(signum: int, frame: Any) -> None:
    # Restore cursor if hidden by terminal spinner and exit cleanly
    sys.stderr.write("\033[?25h\n")
    sys.exit(143)


def run() -> None:
    signal.signal(signal.SIGTERM, _handle_sigterm)
    try:
        from dotdoctor.cli.app import app

        app()
    except KeyboardInterrupt:
        # Restore cursor if hidden by terminal spinner and exit cleanly
        sys.stderr.write("\033[?25h\n")
        sys.exit(130)


if __name__ == "__main__":
    run()
