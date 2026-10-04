import sys


def run() -> None:
    try:
        from dotdoctor.cli.app import app

        app()
    except KeyboardInterrupt:
        # Restore cursor if hidden by terminal spinner and exit cleanly
        sys.stderr.write("\033[?25h\n")
        sys.exit(130)


if __name__ == "__main__":
    run()
