import json
from pathlib import Path

import pytest

from aegis.security.dependency_files import (
    InvalidDependencyFileError,
    UnsupportedDependencyFileError,
    parse_dependency_file,
    supported_dependency_file,
)


def test_parse_requirements_exact_versions(
    tmp_path: Path,
) -> None:
    requirements = tmp_path / "requirements.txt"

    requirements.write_text(
        """
# production dependencies
Requests==2.32.3
Django[argon2]==5.1.1 ; python_version >= "3.12"
urllib3>=2.2
git+https://example.com/project.git
-r requirements-dev.txt
pytest==8.3.3  # test dependency
""".strip(),
        encoding="utf-8",
    )

    packages = parse_dependency_file(
        requirements
    )

    assert [
        (
            package.name,
            package.version,
            package.ecosystem,
            package.direct,
        )
        for package in packages
    ] == [
        (
            "django",
            "5.1.1",
            "PyPI",
            True,
        ),
        (
            "pytest",
            "8.3.3",
            "PyPI",
            True,
        ),
        (
            "requests",
            "2.32.3",
            "PyPI",
            True,
        ),
    ]


def test_parse_modern_package_lock(
    tmp_path: Path,
) -> None:
    lockfile = tmp_path / "package-lock.json"

    lockfile.write_text(
        json.dumps(
            {
                "name": "demo",
                "lockfileVersion": 3,
                "packages": {
                    "": {
                        "dependencies": {
                            "express": "^4.21.0",
                            "@scope/tool": "^2.0.0",
                        },
                    },
                    "node_modules/express": {
                        "version": "4.21.0",
                    },
                    "node_modules/@scope/tool": {
                        "version": "2.0.1",
                    },
                    "node_modules/body-parser": {
                        "version": "1.20.3",
                    },
                    (
                        "node_modules/express/"
                        "node_modules/debug"
                    ): {
                        "version": "2.6.9",
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    packages = parse_dependency_file(
        lockfile
    )

    by_name = {
        package.name: package
        for package in packages
    }

    assert by_name["express"].version == "4.21.0"
    assert by_name["express"].direct is True

    assert by_name["@scope/tool"].version == "2.0.1"
    assert by_name["@scope/tool"].direct is True

    assert by_name["body-parser"].direct is False
    assert by_name["debug"].direct is False

    assert all(
        package.ecosystem == "npm"
        for package in packages
    )


def test_parse_legacy_package_lock(
    tmp_path: Path,
) -> None:
    lockfile = tmp_path / "package-lock.json"

    lockfile.write_text(
        json.dumps(
            {
                "lockfileVersion": 1,
                "dependencies": {
                    "express": {
                        "version": "4.18.2",
                        "dependencies": {
                            "debug": {
                                "version": "2.6.9",
                            },
                        },
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    packages = parse_dependency_file(
        lockfile
    )

    assert [
        (
            package.name,
            package.version,
            package.direct,
        )
        for package in packages
    ] == [
        (
            "debug",
            "2.6.9",
            False,
        ),
        (
            "express",
            "4.18.2",
            True,
        ),
    ]


def test_invalid_package_lock_raises(
    tmp_path: Path,
) -> None:
    lockfile = tmp_path / "package-lock.json"

    lockfile.write_text(
        "{not valid json",
        encoding="utf-8",
    )

    with pytest.raises(
        InvalidDependencyFileError
    ):
        parse_dependency_file(lockfile)


def test_supported_dependency_files() -> None:
    assert supported_dependency_file(
        "requirements.txt"
    )
    assert supported_dependency_file(
        "requirements-dev.txt"
    )
    assert supported_dependency_file(
        "package-lock.json"
    )

    assert not supported_dependency_file(
        "poetry.lock"
    )


def test_unsupported_file_raises() -> None:
    with pytest.raises(
        UnsupportedDependencyFileError
    ):
        parse_dependency_file(
            "Cargo.lock"
        )
