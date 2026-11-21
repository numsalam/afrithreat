"""Git auto-commit for generated reports (the weekly cron path).

Only ever runs `git status`, `git add -- <report files>`,
`git commit -m <fixed message>` and a plain `git push` — never any
destructive or history-rewriting operation. All arguments are passed
as lists (no shell), every call is bounded by a timeout.
"""

import subprocess
from pathlib import Path

GIT_TIMEOUT = 60


class VcsError(Exception):
    """A git operation failed — surfaced to the operator, never retried."""


def _git(root, *args):
    try:
        return subprocess.run(["git", *args], cwd=root, capture_output=True,
                              text=True, timeout=GIT_TIMEOUT)
    except FileNotFoundError:
        raise VcsError("git is not installed") from None
    except subprocess.TimeoutExpired:
        raise VcsError(f"git {args[0]} timed out after {GIT_TIMEOUT}s") from None


def _why(result):
    return result.stderr.strip() or result.stdout.strip() or f"git exited {result.returncode}"


def repo_root(start):
    """The git repository root containing *start*, or None.

    *start* may be a file, a directory, or a not-yet-existing path —
    we walk up to the nearest existing directory to run git from.
    """
    cwd = Path(start).resolve()
    while not cwd.is_dir():
        if cwd.parent == cwd:
            return None  # reached the filesystem root, nothing exists
        cwd = cwd.parent
    result = _git(str(cwd), "rev-parse", "--show-toplevel")
    if result.returncode != 0:
        return None
    return Path(result.stdout.strip())


def commit_if_changed(paths, message):
    """Stage and commit *paths*; return the commit hash.

    Returns None when the files are unchanged (no empty commits).
    Raises VcsError for hard failures (not a repo, git misconfigured).
    """
    paths = [Path(p) for p in paths]
    root = repo_root(paths[0])
    if root is None:
        raise VcsError(f"{paths[0]} is not inside a git repository")

    status = _git(root, "status", "--porcelain", "--",
                  *[str(p) for p in paths])
    if status.returncode != 0:
        raise VcsError(_why(status))
    if not status.stdout.strip():
        return None  # report identical to last week — nothing to commit

    add = _git(root, "add", "--", *[str(p) for p in paths])
    if add.returncode != 0:
        raise VcsError(_why(add))
    commit = _git(root, "commit", "-m", message)
    if commit.returncode != 0:
        raise VcsError(_why(commit))
    return _git(root, "rev-parse", "HEAD").stdout.strip()


def push(root):
    """Plain `git push` of the current branch (never forced)."""
    result = _git(str(root), "push")
    if result.returncode != 0:
        raise VcsError(_why(result))
    return True
