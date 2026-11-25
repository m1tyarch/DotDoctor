import os
import signal
import sys
from typing import Any


def _restore_terminal() -> None:
    if (
        sys.stderr.isatty()
        and not any(
            os.environ.get(flag) for flag in ("NO_COLOR", "NO_ANIMATION", "DOTDOCTOR_NO_ANIMATION")
        )
        and os.environ.get("TERM") != "dumb"
    ):
        sys.stderr.write("\x1b]9;4;0\x07")
    sys.stderr.write("\033[?25h\n")
    sys.stderr.flush()


def _handle_sigterm(signum: int, frame: Any) -> None:
    # Restore cursor if hidden by terminal spinner and exit cleanly
    _restore_terminal()
    sys.exit(143)


def run() -> None:
    if len(sys.argv) == 2 and sys.argv[1] in ("-V", "--version", "version"):
        from dotdoctor import __version__

        sys.stdout.write(f"dotdoctor {__version__}\n")
        sys.exit(0)

    signal.signal(signal.SIGTERM, _handle_sigterm)
    try:
        from dotdoctor.cli.app import app

        app()
    except KeyboardInterrupt:
        # Restore cursor if hidden by terminal spinner and exit cleanly
        _restore_terminal()
        sys.exit(130)


if __name__ == "__main__":
    run()
