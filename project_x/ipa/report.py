"""The stable JSON contract emitted by the IPA analysis engine.

The report is the only thing downstream systems (registries, build gates,
compatibility matrices) are allowed to depend on, so the shape is versioned and
every field is explicitly typed here rather than assembled ad hoc.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .bundle import AppIdentity, EmbeddedBundle
from .collisions import DependencyAnalysis
from .macho import MachOSlice
from .signing import SigningReport

SCHEMA_VERSION = "1.2"
ANALYZER_NAME = "project-x-ipa"
ANALYZER_VERSION = "0.3.0"

SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}

INTERPRETATION_NOTE = (
    "Static inspection describes structure only. A clean report is not evidence "
    "that a binary is free of malicious code, and a failed check is not by itself "
    "proof of tampering. Signature validity is never asserted without the Apple "
    "trust chain and a real signing identity."
)


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    detail: str
    context: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"unknown severity {self.severity!r}")

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "severity": self.severity,
            "detail": self.detail,
            "context": dict(self.context),
        }


@dataclass(frozen=True)
class ArtifactInfo:
    file_name: str
    size_bytes: int
    entry_count: int
    uncompressed_bytes: int
    sha256: str | None

    def to_dict(self) -> dict:
        return {
            "file_name": self.file_name,
            "size_bytes": self.size_bytes,
            "entry_count": self.entry_count,
            "uncompressed_bytes": self.uncompressed_bytes,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class IpaInspectionReport:
    artifact: ArtifactInfo
    limits: dict
    identity: AppIdentity
    macho_slices: tuple[MachOSlice, ...]
    bundles: dict[str, list[EmbeddedBundle]]
    signing: SigningReport
    dependencies: DependencyAnalysis
    findings: tuple[Finding, ...]
    generated_at: str

    def to_dict(self) -> dict:
        ordered = tuple(sorted(self.findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.code)))
        return {
            "schema_version": SCHEMA_VERSION,
            "generated_at": self.generated_at,
            "analyzer": {"name": ANALYZER_NAME, "version": ANALYZER_VERSION},
            "artifact": self.artifact.to_dict(),
            "limits": dict(self.limits),
            "identity": self.identity.to_dict(),
            "macho": {
                "slice_count": len(self.macho_slices),
                "is_universal": len(self.macho_slices) > 1,
                "architectures": sorted({s.arch for s in self.macho_slices}),
                "slices": [s.to_dict() for s in self.macho_slices],
            },
            "bundles": {
                "extensions": [b.to_dict() for b in self.bundles.get("extensions", [])],
                "frameworks": [b.to_dict() for b in self.bundles.get("frameworks", [])],
                "resource_bundles": [b.to_dict() for b in self.bundles.get("resource_bundles", [])],
                "counts": {key: len(value) for key, value in sorted(self.bundles.items())},
            },
            "signing": self.signing.to_dict(),
            "dependencies": self.dependencies.to_dict(),
            "findings": [f.to_dict() for f in ordered],
            "interpretation": {"note": INTERPRETATION_NOTE, "malware_verdict": None},
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
