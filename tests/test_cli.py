import json
from pathlib import Path

from loghunt.cli import main

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def test_sample_logs_produce_findings(capsys):
    code = main([str(SAMPLES / "auth.log"), str(SAMPLES / "access.log"), "--year", "2026"])
    out = capsys.readouterr().out
    assert code == 0
    assert "ssh-login-after-bruteforce" in out
    assert "web-attack-sql-injection" in out


def test_fail_on(capsys):
    args = [str(SAMPLES / "auth.log"), "--year", "2026"]
    assert main(args + ["--fail-on", "critical"]) == 1
    assert main(args + ["--fail-on", "critical", "--ignore-ip", "192.0.2.99"]) == 0


def test_json_output_is_valid(capsys):
    main([str(SAMPLES / "access.log"), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["stats"]["parsed"] > 0
    assert all({"rule", "severity", "ip", "mitre"} <= set(f) for f in data["findings"])


def test_markdown_output(capsys):
    main([str(SAMPLES / "access.log"), "--format", "markdown"])
    out = capsys.readouterr().out
    assert out.startswith("# Log analysis report")
    assert "| Severity | Rule |" in out


def test_output_file(tmp_path):
    target = tmp_path / "report.md"
    assert main([str(SAMPLES / "access.log"), "--format", "markdown", "-o", str(target)]) == 0
    assert target.read_text().startswith("# Log analysis report")


def test_missing_file(capsys):
    assert main(["/no/such/file.log"]) == 2
    assert "cannot read" in capsys.readouterr().err


def test_clean_log(tmp_path, capsys):
    log = tmp_path / "access.log"
    log.write_text('198.51.100.7 - - [18/Nov/2026:09:30:00 +0000] "GET / HTTP/1.1" 200 5 "-" "Mozilla/5.0"\n')
    assert main([str(log), "--fail-on", "low"]) == 0
    assert "nothing suspicious" in capsys.readouterr().out


def test_gzip_log(tmp_path, capsys):
    import gzip
    log = tmp_path / "access.log.1.gz"
    line = '203.0.113.15 - - [18/Nov/2026:10:10:00 +0000] "GET /b?id=1%20UNION%20SELECT%201 HTTP/1.1" 200 5 "-" "x"\n'
    with gzip.open(log, "wt") as fh:
        fh.write(line)
    main([str(log)])
    assert "web-attack-sql-injection" in capsys.readouterr().out


def test_stdin_and_journal_format(monkeypatch, capsys):
    import io
    lines = "".join(
        f"2026-11-22T18:55:{i:02d}+0200 arch sshd[900]: Failed password for invalid user user{i} from 127.0.0.1 port 5000{i} ssh2\n"
        for i in range(6))
    monkeypatch.setattr("sys.stdin", io.StringIO(lines))
    main(["-", "--type", "ssh"])
    out = capsys.readouterr().out
    assert "ssh-bruteforce" in out
    assert "ssh-user-enumeration" in out


def test_brief_output(capsys):
    main([str(SAMPLES / "auth.log"), "--year", "2026", "--format", "brief"])
    out = capsys.readouterr().out
    assert "LEVEL" in out
    assert "critical" in out and "192.0.2.99" in out
    assert len(out.splitlines()) < 15
