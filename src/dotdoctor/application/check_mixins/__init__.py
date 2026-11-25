"""Modular diagnostic check mixins grouped by category."""

from dotdoctor.application.check_mixins.hygiene import HygieneChecksMixin
from dotdoctor.application.check_mixins.runtime import RuntimeChecksMixin
from dotdoctor.application.check_mixins.updates import UpdatesChecksMixin

__all__ = [
    "HygieneChecksMixin",
    "RuntimeChecksMixin",
    "UpdatesChecksMixin",
]
