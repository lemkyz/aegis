import json
import re
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

from aegis.schemas.dependencies import DependencyPackage


DependencyParser = Callable[[Path], list[DependencyPackage]]


class UnsupportedDependencyFileError(ValueError):
    pass


class InvalidDependencyFileError(ValueError):
    pass


_EXACT_REQUIREMENT_PATTERN = re.compile(
    r"""
    ^
    (?P<name>
        [A-Za-z0-9]
        [A-Za-z0-9._-]*
    )
    (?:\[[^\]]+\])?
    \s*==\s*
    (?P<version>
        [A-Za-z0-9]
        [A-Za-z0-9._+!-]*
    )
    $
    """,
    re.VERBOSE,
)


def parse_dependency_file(
    file_path: str | Path,
) -> list[DependencyPackage]:
    path = Path(file_path).resolve()

    parser = _resolve_parser(path)

    packages = parser(path)

    return _deduplicate_packages(packages)


def supported_dependency_file(
    file_path: str | Path,
) -> bool:
    try:
        _resolve_parser(Path(file_path))
    except UnsupportedDependencyFileError:
        return False

    return True


def _resolve_parser(
    path: Path,
) -> DependencyParser:
    name = path.name.lower()

    if name == "package-lock.json":
        return _parse_package_lock

    if name in {
        "pnpm-lock.yaml",
        "pnpm-lock.yml",
    }:
        return _parse_pnpm_lock

    if name == "yarn.lock":
        return _parse_yarn_lock

    if name == "poetry.lock":
        return _parse_poetry_lock

    if name == "pipfile.lock":
        return _parse_pipfile_lock

    if name == "cargo.lock":
        return _parse_cargo_lock

    if (
        name == "requirements.txt"
        or (
            name.startswith("requirements-")
            and name.endswith(".txt")
        )
        or (
            name.startswith("requirements.")
            and name.endswith(".txt")
        )
    ):
        return _parse_requirements

    raise UnsupportedDependencyFileError(
        f"Unsupported dependency file: {path.name}"
    )


def _parse_requirements(
    path: Path,
) -> list[DependencyPackage]:
    try:
        content = path.read_text(
            encoding="utf-8",
        )
    except OSError as exc:
        raise InvalidDependencyFileError(
            f"Could not read {path}: {exc}"
        ) from exc

    packages: list[DependencyPackage] = []

    for raw_line in content.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        line = _strip_inline_comment(line)

        if not line:
            continue

        if line.startswith(
            (
                "-r ",
                "--requirement ",
                "-c ",
                "--constraint ",
                "-e ",
                "--editable ",
                "--index-url ",
                "--extra-index-url ",
                "--find-links ",
                "--trusted-host ",
                "--hash ",
            )
        ):
            continue

        requirement_part = line.split(";", 1)[0].strip()

        if " --hash=" in requirement_part:
            requirement_part = requirement_part.split(
                " --hash=",
                1,
            )[0].strip()

        match = _EXACT_REQUIREMENT_PATTERN.fullmatch(
            requirement_part
        )

        if match is None:
            continue

        packages.append(
            DependencyPackage(
                name=_normalize_pypi_name(
                    match.group("name")
                ),
                version=match.group("version"),
                ecosystem="PyPI",
                manifest=str(path),
                direct=True,
            )
        )

    return packages


def _strip_inline_comment(
    line: str,
) -> str:
    for index, character in enumerate(line):
        if (
            character == "#"
            and index > 0
            and line[index - 1].isspace()
        ):
            return line[:index].strip()

    return line


def _normalize_pypi_name(
    name: str,
) -> str:
    return re.sub(
        r"[-_.]+",
        "-",
        name,
    ).lower()


def _parse_package_lock(
    path: Path,
) -> list[DependencyPackage]:
    try:
        payload = json.loads(
            path.read_text(
                encoding="utf-8",
            )
        )
    except OSError as exc:
        raise InvalidDependencyFileError(
            f"Could not read {path}: {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise InvalidDependencyFileError(
            f"Invalid JSON in {path}: {exc}"
        ) from exc

    if not isinstance(payload, dict):
        raise InvalidDependencyFileError(
            f"{path} must contain a JSON object."
        )

    packages_section = payload.get("packages")

    if isinstance(packages_section, dict):
        return _parse_modern_package_lock(
            path,
            packages_section,
        )

    dependencies_section = payload.get(
        "dependencies"
    )

    if isinstance(dependencies_section, dict):
        return _parse_legacy_package_lock(
            path,
            dependencies_section,
        )

    return []


def _parse_modern_package_lock(
    path: Path,
    packages_section: dict[str, Any],
) -> list[DependencyPackage]:
    root_metadata = packages_section.get("", {})

    direct_names: set[str] = set()

    if isinstance(root_metadata, dict):
        for field in (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ):
            values = root_metadata.get(field, {})

            if isinstance(values, dict):
                direct_names.update(
                    str(name)
                    for name in values
                )

    packages: list[DependencyPackage] = []

    for package_path, metadata in (
        packages_section.items()
    ):
        if (
            not package_path
            or not isinstance(metadata, dict)
        ):
            continue

        version = metadata.get("version")

        if not isinstance(version, str) or not version:
            continue

        name = metadata.get("name")

        if not isinstance(name, str) or not name:
            name = _npm_name_from_package_path(
                package_path
            )

        if not name:
            continue

        packages.append(
            DependencyPackage(
                name=name,
                version=version,
                ecosystem="npm",
                manifest=str(path),
                direct=(
                    name in direct_names
                    and _is_top_level_node_module(
                        package_path
                    )
                ),
            )
        )

    return packages


def _npm_name_from_package_path(
    package_path: str,
) -> str | None:
    marker = "node_modules/"

    if marker not in package_path:
        return None

    remainder = package_path.rsplit(
        marker,
        1,
    )[1]

    parts = [
        part
        for part in remainder.split("/")
        if part
    ]

    if not parts:
        return None

    if parts[0].startswith("@"):
        if len(parts) < 2:
            return None

        return f"{parts[0]}/{parts[1]}"

    return parts[0]


def _is_top_level_node_module(
    package_path: str,
) -> bool:
    normalized = package_path.strip("/")

    if not normalized.startswith("node_modules/"):
        return False

    remainder = normalized[len("node_modules/"):]

    if "/node_modules/" in remainder:
        return False

    parts = remainder.split("/")

    if remainder.startswith("@"):
        return len(parts) == 2

    return len(parts) == 1


def _parse_legacy_package_lock(
    path: Path,
    dependencies: dict[str, Any],
) -> list[DependencyPackage]:
    packages: list[DependencyPackage] = []

    def visit(
        values: dict[str, Any],
        *,
        direct: bool,
    ) -> None:
        for name, metadata in values.items():
            if not isinstance(metadata, dict):
                continue

            version = metadata.get("version")

            if isinstance(version, str) and version:
                packages.append(
                    DependencyPackage(
                        name=str(name),
                        version=version,
                        ecosystem="npm",
                        manifest=str(path),
                        direct=direct,
                    )
                )

            nested = metadata.get("dependencies")

            if isinstance(nested, dict):
                visit(
                    nested,
                    direct=False,
                )

    visit(
        dependencies,
        direct=True,
    )

    return packages



def _read_text(
    path: Path,
) -> str:
    try:
        return path.read_text(
            encoding="utf-8",
        )
    except OSError as exc:
        raise InvalidDependencyFileError(
            f"Could not read {path}: {exc}"
        ) from exc


def _parse_pipfile_lock(
    path: Path,
) -> list[DependencyPackage]:
    try:
        payload = json.loads(
            _read_text(path)
        )
    except json.JSONDecodeError as exc:
        raise InvalidDependencyFileError(
            f"Invalid JSON in {path}: {exc}"
        ) from exc

    if not isinstance(payload, dict):
        raise InvalidDependencyFileError(
            f"{path} must contain a JSON object."
        )

    packages: list[DependencyPackage] = []

    for category, entries in payload.items():
        if category == "_meta":
            continue

        if not isinstance(entries, dict):
            continue

        for name, metadata in entries.items():
            if not isinstance(metadata, dict):
                continue

            version = metadata.get("version")

            if not isinstance(version, str):
                continue

            version = version.strip()

            if version.startswith("=="):
                version = version[2:].strip()

            if not version:
                continue

            if any(
                key in metadata
                for key in (
                    "git",
                    "path",
                    "file",
                    "uri",
                )
            ):
                continue

            packages.append(
                DependencyPackage(
                    name=_normalize_pypi_name(
                        str(name)
                    ),
                    version=version,
                    ecosystem="PyPI",
                    manifest=str(path),
                    direct=False,
                )
            )

    return packages


def _parse_poetry_lock(
    path: Path,
) -> list[DependencyPackage]:
    try:
        payload = tomllib.loads(
            _read_text(path)
        )
    except tomllib.TOMLDecodeError as exc:
        raise InvalidDependencyFileError(
            f"Invalid TOML in {path}: {exc}"
        ) from exc

    entries = payload.get("package", [])

    if not isinstance(entries, list):
        raise InvalidDependencyFileError(
            f"{path} has an invalid package section."
        )

    packages: list[DependencyPackage] = []

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        name = entry.get("name")
        version = entry.get("version")

        if (
            not isinstance(name, str)
            or not isinstance(version, str)
            or not name.strip()
            or not version.strip()
        ):
            continue

        source = entry.get("source")

        if isinstance(source, dict):
            source_type = source.get("type")

            if source_type in {
                "git",
                "directory",
                "file",
                "url",
            }:
                continue

        packages.append(
            DependencyPackage(
                name=_normalize_pypi_name(name),
                version=version.strip(),
                ecosystem="PyPI",
                manifest=str(path),
                direct=False,
            )
        )

    return packages


def _parse_cargo_lock(
    path: Path,
) -> list[DependencyPackage]:
    try:
        payload = tomllib.loads(
            _read_text(path)
        )
    except tomllib.TOMLDecodeError as exc:
        raise InvalidDependencyFileError(
            f"Invalid TOML in {path}: {exc}"
        ) from exc

    entries = payload.get("package", [])

    if not isinstance(entries, list):
        raise InvalidDependencyFileError(
            f"{path} has an invalid package section."
        )

    packages: list[DependencyPackage] = []

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        name = entry.get("name")
        version = entry.get("version")
        source = entry.get("source", "")

        if (
            not isinstance(name, str)
            or not isinstance(version, str)
            or not name.strip()
            or not version.strip()
        ):
            continue

        if (
            isinstance(source, str)
            and source
            and not source.startswith(
                "registry+"
            )
        ):
            continue

        packages.append(
            DependencyPackage(
                name=name.strip(),
                version=version.strip(),
                ecosystem="crates.io",
                manifest=str(path),
                direct=False,
            )
        )

    return packages


def _parse_pnpm_lock(
    path: Path,
) -> list[DependencyPackage]:
    try:
        payload = yaml.safe_load(
            _read_text(path)
        )
    except yaml.YAMLError as exc:
        raise InvalidDependencyFileError(
            f"Invalid YAML in {path}: {exc}"
        ) from exc

    if not isinstance(payload, dict):
        raise InvalidDependencyFileError(
            f"{path} must contain a YAML mapping."
        )

    direct_names: set[str] = set()

    importers = payload.get("importers", {})

    if isinstance(importers, dict):
        for importer in importers.values():
            if not isinstance(importer, dict):
                continue

            for section in (
                "dependencies",
                "devDependencies",
                "optionalDependencies",
            ):
                dependencies = importer.get(
                    section,
                    {},
                )

                if isinstance(dependencies, dict):
                    direct_names.update(
                        str(name)
                        for name in dependencies
                    )

    packages: list[DependencyPackage] = []

    packages_section = payload.get(
        "packages",
        {},
    )

    if not isinstance(packages_section, dict):
        return packages

    for package_key, metadata in (
        packages_section.items()
    ):
        parsed = _parse_pnpm_package_key(
            str(package_key)
        )

        if parsed is None:
            continue

        name, version = parsed

        if isinstance(metadata, dict):
            resolution = metadata.get(
                "resolution",
                {},
            )

            if (
                isinstance(resolution, dict)
                and any(
                    key in resolution
                    for key in (
                        "directory",
                        "tarball",
                    )
                )
                and not resolution.get(
                    "integrity"
                )
            ):
                continue

        packages.append(
            DependencyPackage(
                name=name,
                version=version,
                ecosystem="npm",
                manifest=str(path),
                direct=name in direct_names,
            )
        )

    return packages


def _parse_pnpm_package_key(
    value: str,
) -> tuple[str, str] | None:
    key = value.strip().strip("'\"")

    if not key:
        return None

    if key.startswith("/"):
        key = key[1:]

    key = key.split("(", 1)[0]

    if key.startswith("@"):
        match = re.match(
            r"^(?P<name>@[^/]+/[^@/]+)"
            r"@(?P<version>[^/]+)$",
            key,
        )
    else:
        match = re.match(
            r"^(?P<name>[^/@]+)"
            r"@(?P<version>[^/]+)$",
            key,
        )

    if match is None:
        return None

    name = match.group("name")
    version = match.group("version")

    if not _looks_like_locked_version(
        version
    ):
        return None

    return name, version


def _parse_yarn_lock(
    path: Path,
) -> list[DependencyPackage]:
    content = _read_text(path)

    if "__metadata:" in content:
        return _parse_yarn_berry_lock(
            path,
            content,
        )

    return _parse_yarn_classic_lock(
        path,
        content,
    )


def _parse_yarn_classic_lock(
    path: Path,
    content: str,
) -> list[DependencyPackage]:
    packages: list[DependencyPackage] = []

    current_header: str | None = None

    for raw_line in content.splitlines():
        line = raw_line.rstrip()

        if (
            line
            and not line.startswith((" ", "\t", "#"))
            and line.endswith(":")
        ):
            current_header = line[:-1]
            continue

        if current_header is None:
            continue

        version_match = re.match(
            r'^\s+version\s+"([^"]+)"\s*$',
            line,
        )

        if version_match is None:
            continue

        name = _yarn_name_from_descriptor(
            current_header.split(",", 1)[0]
        )

        version = version_match.group(1)

        if (
            name
            and _looks_like_locked_version(version)
        ):
            packages.append(
                DependencyPackage(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    manifest=str(path),
                    direct=False,
                )
            )

        current_header = None

    return packages


def _parse_yarn_berry_lock(
    path: Path,
    content: str,
) -> list[DependencyPackage]:
    packages: list[DependencyPackage] = []

    current_header: str | None = None

    for raw_line in content.splitlines():
        line = raw_line.rstrip()

        if (
            line
            and not line.startswith((" ", "\t"))
            and line.endswith(":")
            and line != "__metadata:"
        ):
            current_header = line[:-1].strip(
                "'\""
            )
            continue

        if current_header is None:
            continue

        version_match = re.match(
            r'^\s+version:\s*"?([^"\s]+)"?\s*$',
            line,
        )

        if version_match is None:
            continue

        name = _yarn_name_from_descriptor(
            current_header.split(",", 1)[0]
        )

        version = version_match.group(1)

        if (
            name
            and _looks_like_locked_version(version)
        ):
            packages.append(
                DependencyPackage(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    manifest=str(path),
                    direct=False,
                )
            )

        current_header = None

    return packages


def _yarn_name_from_descriptor(
    descriptor: str,
) -> str | None:
    value = descriptor.strip().strip("'\"")

    if value.startswith("@"):
        match = re.match(
            r"^(?P<name>@[^/]+/[^@]+)@",
            value,
        )
    else:
        match = re.match(
            r"^(?P<name>[^@]+)@",
            value,
        )

    if match is None:
        return None

    return match.group("name")


def _looks_like_locked_version(
    value: str,
) -> bool:
    return bool(
        re.fullmatch(
            r"\d+(?:\.\d+){1,3}"
            r"(?:[-+][0-9A-Za-z.-]+)?",
            value,
        )
    )

def _deduplicate_packages(
    packages: list[DependencyPackage],
) -> list[DependencyPackage]:
    deduplicated: dict[
        tuple[str, str, str, str],
        DependencyPackage,
    ] = {}

    for package in packages:
        key = (
            package.ecosystem,
            package.name.lower(),
            package.version,
            package.manifest,
        )

        previous = deduplicated.get(key)

        if previous is None:
            deduplicated[key] = package
            continue

        if package.direct and not previous.direct:
            deduplicated[key] = previous.model_copy(
                update={
                    "direct": True,
                }
            )

    return sorted(
        deduplicated.values(),
        key=lambda package: (
            package.ecosystem,
            package.name.lower(),
            package.version,
        ),
    )
