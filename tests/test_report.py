from afrithreat.config import load_config
from afrithreat.events import EventWriter
from afrithreat.report import generate_report


def test_report_generation(tmp_path):
    writer = EventWriter(tmp_path / "data")
    writer.write("telnet-1", "telnet", "auth", "41.203.1.1", 1000,
                 {"username": "root", "password": "toor"})
    writer.write("http-1", "http", "request", "197.210.5.5", 2000,
                 {"path": "/.env", "headers": {"User-Agent": "masscan"}})
    writer.write("ssh-1", "ssh", "auth", "197.210.5.5", 22,
                 {"username": "ubuntu", "method": "password",
                  "service": "ssh-connection", "password": "ubuntu123"})

    cfg = load_config(None)
    cfg["data_dir"] = str(tmp_path / "data")
    out = tmp_path / "reports"
    md_path = generate_report(cfg, out)

    text = md_path.read_text(encoding="utf-8")
    assert "AFRITHREAT" in text
    assert "41.203.1.1" in text
    assert "197.210.5.5" in text
    assert "/.env" in text
    assert "root" in text
    assert "Top SSH usernames tried" in text
    assert "ubuntu" in text
    assert "ubuntu123" in text
    assert "Events per sensor host" in text
    assert "sensor host(s) reporting" in text
    assert (out / "report.json").exists()


def test_report_with_enrichment(tmp_path):
    writer = EventWriter(tmp_path / "data")
    writer.write("http-1", "http", "request", "197.210.5.5", 2000,
                 {"path": "/x", "headers": {}})

    csv_path = tmp_path / "ranges.csv"
    csv_path.write_text(
        "network,country,asn,org\n197.210.0.0/16,NG,AS29465,NgREN\n",
        encoding="utf-8")

    cfg = load_config(None)
    cfg["data_dir"] = str(tmp_path / "data")
    cfg["enrich"] = {"csv_path": str(csv_path)}
    md_path = generate_report(cfg, tmp_path / "reports")

    text = md_path.read_text(encoding="utf-8")
    assert "NG" in text
    assert "Country" in text
