"""Isolate HTTP/DNS blocking calls so an audit can cancel them with its readers."""

import json

from dotdoctor.infrastructure.maintenance import fetch_news

if __name__ == "__main__":
    print(json.dumps(fetch_news()))
