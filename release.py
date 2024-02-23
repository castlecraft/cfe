#!/usr/bin/env ../../env/bin/python

import argparse
import os
import sys
from typing import Literal

import git
from packaging.version import Version

SemVerType = Literal["major", "minor", "micro"]


class ShellEscape:
    black = "\u001b[30m"
    red = "\u001b[31m"
    green = "\u001b[32m"
    yellow = "\u001b[33m"
    blue = "\u001b[34m"
    magenta = "\u001b[35m"
    cyan = "\u001b[36m"
    white = "\u001b[37m"
    reset = "\u001b[0m"
    bold = "\u001b[1m"
    underline = "\u001b[4m"
    endchar = "\033[0m"

    def rgb(r, g, b):
        return f"\u001b[38;2;{r};{g};{b}m"


def main():
    parser = get_args_parser()
    if len(sys.argv) == 1:
        parser.cprint_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    version = None
    app_name = "castlecraft"
    version = __import__(f"{app_name}").__version__
    release = None
    if args.major:
        release = increment_semver(version=version, incr_type="major")
    elif args.minor:
        release = increment_semver(version=version, incr_type="minor")
    elif args.patch:
        release = increment_semver(version=version, incr_type="micro")

    if release:
        cprint(f"Bumping from {version} to {release}")
        if not args.dry_run:
            cprint("Writing changes to __init__.py")
            with open(f"{app_name}/__init__.py", "w") as version_file:
                version_file.write(f'__version__ = "{release}"\n')

        repo = git.Repo(os.getcwd())
        git_commit_release_message(repo, release, args.dry_run)
        git_tag_repo(repo, release, args.dry_run)
        git_push_all(repo, remote=args.remote, dry_run=args.dry_run)


def increment_semver(version: str, incr_type: SemVerType):
    current_version = Version(version)
    if incr_type == "major":
        return f"{current_version.major + 1}.0.0"  # noqa: E501
    elif incr_type == "minor":
        return f"{current_version.major}.{current_version.minor + 1}.0"  # noqa: E501
    elif incr_type == "micro":
        return f"{current_version.major}.{current_version.minor}.{current_version.micro + 1}"  # noqa: E501


def get_args_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-d", "--dry-run", action="store_true", help="DO NOT make changes"
    )
    parser.add_argument(
        "-r",
        "--remote",
        action="store",
        help="Specify remote",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-j", "--major", action="store_true", help="Release Major Version"
    )
    group.add_argument(
        "-n", "--minor", action="store_true", help="Release Minor Version"
    )
    group.add_argument(
        "-p", "--patch", action="store_true", help="Release Patch Version"
    )
    return parser


def git_commit_release_message(repo, version, dry_run=False):
    cprint("Commit release to git")
    commit_message = f"Publish v{version}"
    if not dry_run:
        repo.git.add(all=True)
        repo.git.commit("-m", commit_message)


def git_tag_repo(repo, version, dry_run=False):
    if not dry_run:
        repo.create_tag(f"v{version}", message=f"Released v{version}")


def git_push_all(repo, remote=None, dry_run=False):
    if not remote:
        cprint("Available git remotes")
        index = 1
        for rem in repo.remotes:
            cprint(f"{index} - {rem.name}")
            index = index + 1

        remote = int(input("Select remote to push: "))

        try:
            remote = repo.remotes[remote - 1].name
        except Exception:
            cprint('Invalid Remote, setting remote to "upstream"')
            remote = "upstream"

    git_ssh_command = os.environ.get("GIT_SSH_COMMAND")
    if git_ssh_command:
        repo.git.update_environment(GIT_SSH_COMMAND=git_ssh_command)

    if not dry_run:
        repo.git.push(remote, "--follow-tags")


def cprint(string: str, color: str = ShellEscape.yellow):
    print(color + string + ShellEscape.endchar)  # noqa: T001


if __name__ == "__main__":
    main()
