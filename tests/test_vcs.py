"""Tests for the git auto-commit path (report --commit/--push)."""

import subprocess

import pytest

from afrithreat.vcs import VcsError, commit_if_changed, push, repo_root


def _git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, capture_output=True,
                          text=True, timeout=30)


@pytest.fixture
def repo(tmp_path):
    """A disposable git repository with a local identity."""
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "test@afrithreat.local")
    _git(tmp_path, "config", "user.name", "AFRITHREAT Test")
    return tmp_path


def test_commit_if_changed(repo):
    report = repo / "report.md"
    report.write_text("# week 1\n")
    commit_hash = commit_if_changed([report], "afrithreat: weekly report 1")
    assert commit_hash and len(commit_hash) == 40
    log = _git(repo, "log", "-1", "--format=%s").stdout.strip()
    assert log == "afrithreat: weekly report 1"


def test_unchanged_report_not_committed(repo):
    report = repo / "report.md"
    report.write_text("# same every week\n")
    assert commit_if_changed([report], "r1") is not None
    assert commit_if_changed([report], "r2") is None  # no empty commits
    log = _git(repo, "log", "--oneline").stdout
    assert log.count("\n") == 1          # only the first commit exists
    assert "r1" in log and "r2" not in log


def test_commit_stages_only_listed_paths(repo):
    report = repo / "report.md"
    secret = repo / "should_stay_untracked.txt"
    report.write_text("# report\n")
    secret.write_text("local only\n")
    commit_if_changed([report], "r1")
    status = _git(repo, "status", "--porcelain").stdout
    assert "should_stay_untracked.txt" in status  # never staged


def test_not_a_repository(tmp_path):
    report = tmp_path / "report.md"
    report.write_text("# report\n")
    with pytest.raises(VcsError):
        commit_if_changed([report], "r1")


def test_repo_root(repo, tmp_path):
    assert repo_root(repo / "reports" / "report.md") == repo.resolve()


def test_push_without_remote_fails_cleanly(repo):
    (repo / "report.md").write_text("# report\n")
    commit_if_changed([repo / "report.md"], "r1")
    with pytest.raises(VcsError):
        push(repo)
