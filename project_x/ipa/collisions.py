"""Framework and dependency reference analysis.

The rule this module exists to enforce came from a real failure mode: an app
that vendors a framework can break if a build injects another framework with
the same basename, because the loader resolves ``@rpath/<name>`` to whichever
copy is present. A colliding basename is therefore a build risk that must be
resolved before any injection is attempted; static basename analysis alone
does not prove that a collision-free injection will work.
"""
from __future__ import annotations

from dataclasses import dataclass

from .bundle import EmbeddedBundle
from .macho import DylibRef, MachOError, load_macho
from .safety import SafeArchive

_LINKING_KINDS = {"load", "weak", "reexport", "upward", "lazy"}


@dataclass(frozen=True)
class FrameworkRef:
    path: str
    basename: str
    install_name: str | None
    binary_present: bool

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "basename": self.basename,
            "install_name": self.install_name,
            "binary_present": self.binary_present,
        }


@dataclass(frozen=True)
class DependencyRef:
    name: str
    kind: str

    def to_dict(self) -> dict:
        return {"name": self.name, "kind": self.kind}


@dataclass(frozen=True)
class DependencyAnalysis:
    frameworks: tuple[FrameworkRef, ...]
    rpath_dependencies: tuple[str, ...]
    executable_path_dependencies: tuple[str, ...]
    unresolved_rpath_dependencies: tuple[str, ...]
    protected_frameworks: tuple[str, ...]
    duplicate_framework_basenames: tuple[str, ...]
    rpath_dependency_refs: tuple[DependencyRef, ...] = ()
    executable_path_dependency_refs: tuple[DependencyRef, ...] = ()
    unresolved_rpath_dependency_refs: tuple[DependencyRef, ...] = ()

    def to_dict(self) -> dict:
        return {
            "frameworks": [f.to_dict() for f in self.frameworks],
            "rpath_dependencies": list(self.rpath_dependencies),
            "executable_path_dependencies": list(self.executable_path_dependencies),
            "unresolved_rpath_dependencies": list(self.unresolved_rpath_dependencies),
            "protected_frameworks": list(self.protected_frameworks),
            "duplicate_framework_basenames": list(self.duplicate_framework_basenames),
            "rpath_dependency_refs": [r.to_dict() for r in self.rpath_dependency_refs],
            "executable_path_dependency_refs": [
                r.to_dict() for r in self.executable_path_dependency_refs
            ],
            "unresolved_rpath_dependency_refs": [
                r.to_dict() for r in self.unresolved_rpath_dependency_refs
            ],
        }


def framework_basename(reference: str) -> str:
    """``@rpath/Foo.framework/Foo`` -> ``Foo.framework``."""
    parts = [part for part in reference.split("/") if part]
    for part in parts:
        if part.endswith(".framework"):
            return part
    return parts[-1] if parts else reference


def _install_name(archive: SafeArchive, bundle: EmbeddedBundle) -> tuple[str | None, bool]:
    if not bundle.executable_present:
        return None, False
    try:
        slices = load_macho(archive, bundle.executable)
    except (MachOError, KeyError):
        return None, True
    for slc in slices:
        for ref in slc.dylibs:
            if ref.kind == "id":
                return ref.name, True
    return None, True


def analyse_dependencies(
    archive: SafeArchive,
    main_dylibs: tuple[DylibRef, ...],
    framework_bundles: list[EmbeddedBundle],
) -> DependencyAnalysis:
    frameworks: list[FrameworkRef] = []
    for bundle in framework_bundles:
        install_name, binary_present = _install_name(archive, bundle)
        frameworks.append(
            FrameworkRef(
                path=bundle.path,
                basename=bundle.path.rstrip("/").rsplit("/", 1)[-1],
                install_name=install_name,
                binary_present=binary_present,
            )
        )

    rpath_refs = tuple(
        sorted(
            {
                (d.name, d.kind)
                for d in main_dylibs
                if d.kind in _LINKING_KINDS and d.name.startswith("@rpath/")
            }
        )
    )
    executable_refs = tuple(
        sorted(
            {
                (d.name, d.kind)
                for d in main_dylibs
                if d.kind in _LINKING_KINDS and d.name.startswith("@executable_path/")
            }
        )
    )
    rpath_dependency_refs = tuple(DependencyRef(name, kind) for name, kind in rpath_refs)
    executable_path_dependency_refs = tuple(
        DependencyRef(name, kind) for name, kind in executable_refs
    )
    rpath_deps = tuple(sorted({ref.name for ref in rpath_dependency_refs}))
    executable_deps = tuple(sorted({ref.name for ref in executable_path_dependency_refs}))

    local = {f.basename for f in frameworks}
    unresolved_refs = tuple(
        ref for ref in rpath_dependency_refs if framework_basename(ref.name) not in local
    )
    unresolved = tuple(sorted({ref.name for ref in unresolved_refs}))
    protected = tuple(sorted({framework_basename(dep) for dep in rpath_deps} & local))

    seen: dict[str, int] = {}
    for framework in frameworks:
        seen[framework.basename] = seen.get(framework.basename, 0) + 1
    duplicates = tuple(sorted(name for name, count in seen.items() if count > 1))

    return DependencyAnalysis(
        frameworks=tuple(frameworks),
        rpath_dependencies=rpath_deps,
        executable_path_dependencies=executable_deps,
        unresolved_rpath_dependencies=unresolved,
        protected_frameworks=protected,
        duplicate_framework_basenames=duplicates,
        rpath_dependency_refs=rpath_dependency_refs,
        executable_path_dependency_refs=executable_path_dependency_refs,
        unresolved_rpath_dependency_refs=unresolved_refs,
    )
