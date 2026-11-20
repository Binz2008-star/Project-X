"""Read-only IPA analysis engine.

Public surface: :func:`inspect_ipa` returns a versioned
:class:`~project_x.ipa.report.IpaInspectionReport`. Everything below it is
standard library only, so analysis runs identically on Windows, macOS and CI
without an Apple toolchain.
"""
from .bundle import AppIdentity, BundleError, EmbeddedBundle
from .inspector import inspect_ipa, sha256_of_file
from .report import SCHEMA_VERSION, Finding, IpaInspectionReport
from .safety import ArchiveLimits, ArchiveSafetyError, SafeArchive

__all__ = [
    "ArchiveLimits",
    "ArchiveSafetyError",
    "AppIdentity",
    "BundleError",
    "EmbeddedBundle",
    "Finding",
    "IpaInspectionReport",
    "SCHEMA_VERSION",
    "SafeArchive",
    "inspect_ipa",
    "sha256_of_file",
]
