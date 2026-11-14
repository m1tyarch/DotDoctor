"""Isolate HTTP/DNS blocking calls so an audit can cancel them with its readers."""

import json
import sys

from dotdoctor.infrastructure.maintenance import fetch_news

if __name__ == "__main__":
    try:
        print(json.dumps(fetch_news()))
    except Exception:
        # Output valid JSON array and exit non-zero on error
        print(json.dumps([]))
        sys.exit(1)
