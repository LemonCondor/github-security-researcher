from types import SimpleNamespace

from github_security import cli


def test_hunt_parser_and_dispatch(monkeypatch, tmp_path, capsys):
    seen = {}

    def fake_hunt(slug, repo, opts, *, out_dir):
        seen.update(slug=slug, repo=repo, files=opts.files, python=opts.toolchain.python)
        return [], tmp_path / "r.json"

    monkeypatch.setattr("github_security.hunt.run.hunt", fake_hunt)
    monkeypatch.setattr(cli.cfg, "load", lambda: SimpleNamespace(
        log_dir=tmp_path, policies=SimpleNamespace(llm_model=None)))
    monkeypatch.setattr(cli.obs, "configure", lambda *a, **k: None)
    rc = cli.main(["hunt", "a/b", "--path", str(tmp_path), "--files", "3", "--python", "/v/bin/python"])
    assert rc == 0 and seen == {"slug": "a/b", "repo": tmp_path, "files": 3, "python": "/v/bin/python"}
    assert "r.json" in capsys.readouterr().out
