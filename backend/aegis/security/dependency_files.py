import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

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
