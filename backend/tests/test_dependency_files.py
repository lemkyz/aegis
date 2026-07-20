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
    for filename in (
        "requirements.txt",
        "requirements-dev.txt",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "poetry.lock",
        "Pipfile.lock",
        "Cargo.lock",
    ):
        assert supported_dependency_file(
            filename
        )

    assert not supported_dependency_file(
        "Gemfile.lock"
    )


def test_unsupported_file_raises() -> None:
    with pytest.raises(
        UnsupportedDependencyFileError
    ):
        parse_dependency_file(
            "Gemfile.lock"
        )


def test_parse_pipfile_lock(
    tmp_path: Path,
) -> None:
    lockfile = tmp_path / "Pipfile.lock"

    lockfile.write_text(
        json.dumps(
            {
                "_meta": {
                    "pipfile-spec": 6,
                },
                "default": {
                    "requests": {
                        "version": "==2.32.3",
                    },
                    "local-package": {
                        "path": ".",
                        "version": "==1.0.0",
                    },
                },
                "develop": {
                    "pytest": {
                        "version": "==8.3.3",
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
            package.ecosystem,
        )
        for package in packages
    ] == [
        ("pytest", "8.3.3", "PyPI"),
        ("requests", "2.32.3", "PyPI"),
    ]


def test_parse_poetry_lock(
    tmp_path: Path,
) -> None:
    lockfile = tmp_path / "poetry.lock"

    lockfile.write_text(
        """
[[package]]
name = "requests"
version = "2.32.3"
description = ""
optional = false
python-versions = ">=3.9"

[[package]]
name = "local-package"
version = "1.0.0"

[package.source]
type = "directory"
url = "../local-package"
""".strip(),
        encoding="utf-8",
    )

    packages = parse_dependency_file(
        lockfile
    )

    assert [
        (
            package.name,
            package.version,
            package.ecosystem,
        )
        for package in packages
    ] == [
        ("requests", "2.32.3", "PyPI"),
    ]


def test_parse_cargo_lock(
    tmp_path: Path,
) -> None:
    lockfile = tmp_path / "Cargo.lock"

    lockfile.write_text(
        """
version = 4

[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "local-crate"
version = "0.1.0"
""".strip(),
        encoding="utf-8",
    )

    packages = parse_dependency_file(
        lockfile
    )

    assert [
        (
            package.name,
            package.version,
            package.ecosystem,
        )
        for package in packages
    ] == [
        ("local-crate", "0.1.0", "crates.io"),
        ("serde", "1.0.210", "crates.io"),
    ]


def test_parse_pnpm_lock(
    tmp_path: Path,
) -> None:
    lockfile = tmp_path / "pnpm-lock.yaml"

    lockfile.write_text(
        """
lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      express:
        specifier: ^4.21.0
        version: 4.21.0

packages:
  express@4.21.0:
    resolution:
      integrity: sha512-example

  debug@2.6.9:
    resolution:
      integrity: sha512-example
""".strip(),
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
    assert by_name["debug"].direct is False


def test_parse_yarn_classic_lock(
    tmp_path: Path,
) -> None:
    lockfile = tmp_path / "yarn.lock"

    lockfile.write_text(
        """
# yarn lockfile v1

express@^4.21.0:
  version "4.21.0"
  resolved "https://registry.yarnpkg.com/express/-/express-4.21.0.tgz"

"@scope/tool@^2.0.0":
  version "2.0.1"
  resolved "https://registry.yarnpkg.com/@scope/tool/-/tool-2.0.1.tgz"
""".strip(),
        encoding="utf-8",
    )

    packages = parse_dependency_file(
        lockfile
    )

    assert [
        (
            package.name,
            package.version,
            package.ecosystem,
        )
        for package in packages
    ] == [
        ("@scope/tool", "2.0.1", "npm"),
        ("express", "4.21.0", "npm"),
    ]


def test_all_new_lockfiles_are_supported() -> None:
    for filename in (
        "pnpm-lock.yaml",
        "yarn.lock",
        "poetry.lock",
        "Pipfile.lock",
        "Cargo.lock",
    ):
        assert supported_dependency_file(
            filename
        )
