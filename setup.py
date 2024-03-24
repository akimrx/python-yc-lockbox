#!/usr/bin/env python3

import sys

from os import path
from setuptools import find_packages, setup


try:
    from semantic_release import setup_hook

    setup_hook(sys.argv)
except ImportError:
    pass


cwd = path.abspath(path.dirname(__file__))


def build_description():
    with open("README.md", "r") as fh:
        long_description = fh.read()

    return long_description


def metadata():
    meta = {}
    with open(path.join(cwd, "yc_lockbox", "__init__.py"), "r") as fh:
        exec(fh.read(), meta)  # nosec
    return meta


def get_requirements(req_file: str | list[str] = "requirements.txt"):
    requirements_list = []

    def collect_requirements(f: str):
        nonlocal requirements_list

        with open(f) as requirements:
            for install in requirements:
                requirements_list.append(install.strip())

    if isinstance(req_file, list):
        for req in req_file:
            collect_requirements(req)
    else:
        collect_requirements(req_file)

    return requirements_list


def aio_requirements():
    return get_requirements("requirements.aio.txt")


meta = metadata()


def main() -> None:
    setup(
        name="yc-lockbox",
        keywords=["yandex", "cloud", "vault", "secrets", "lockbox"],
        platforms=["osx", "linux"],
        entry_points={},
        version=meta.get("__version__"),
        author=meta.get("__author__"),
        author_email=meta.get("__author_email__"),
        license=meta.get("__license__"),
        description="Yandex Lockbox client",
        long_description=build_description(),
        long_description_content_type="text/markdown",
        url=meta.get("__url__"),
        python_requires=">=3.10",
        packages=find_packages(),
        install_requires=get_requirements(),
        extras_require={
            "aio": aio_requirements(),
        },
        classifiers=[
            "License :: OSI Approved :: MIT License",
            "Intended Audience :: Information Technology",
            "Intended Audience :: System Administrators",
            "Intended Audience :: Developers",
            "Operating System :: OS Independent",
            "Topic :: Software Development :: Libraries :: Python Modules",
            "Topic :: Software Development :: Libraries",
            "Topic :: Software Development",
            "Programming Language :: Python :: 3.10",
            "Programming Language :: Python :: 3.11",
            "Programming Language :: Python :: 3.12",
            "Typing :: Typed",
        ],
    )


if __name__ == "__main__":
    main()
