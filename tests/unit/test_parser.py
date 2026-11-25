"""hc22000 parsing and target filtering."""

from wicrack.capture.parser import (
    apply_filter,
    is_capture_file,
    list_capture_files,
    parse_22000_file,
    parse_22000_line,
)
from wicrack.selftest import make_test_22000


def test_pmkid_line_parse():
    line, password = make_test_22000()
    target = parse_22000_line(line)
    assert target is not None
    assert target["type"] == "PMKID"
    assert target["essid"] == "SelfTestNet"
    assert target["ap"] == "aabbccddeeff"
    assert password == "SelfTest123"  # fixture sanity


def test_eapol_line_parse():
    ap, sta = "aabbccddeeff", "112233445566"
    essid_hex = b"HomeNet".hex()
    line = f"WPA*02*{sta}*{ap}*{essid_hex}**"
    target = parse_22000_line(line)
    assert target is not None
    assert target["type"] == "EAPOL"
    assert target["essid"] == "HomeNet"
    assert target["ap"] == ap


def test_invalid_lines_return_none():
    for bad in ("", "NOTAHASH", "WPA*99*x*y", "WPA*01*onlyfew"):
        assert parse_22000_line(bad) is None


def test_parse_file(tmp_path):
    line, _ = make_test_22000()
    path = tmp_path / "h.22000"
    path.write_text(line + "\nJUNK\n" + line + "\n")
    targets = parse_22000_file(path)
    assert len(targets) == 2


def test_filter_include_mode(tmp_path):
    line, _ = make_test_22000()
    path = tmp_path / "h.22000"
    path.write_text(line + "\n")
    targets = parse_22000_file(path)
    out = apply_filter(path, targets, essids=["SelfTestNet"], bssids=[], mode="include")
    assert out == path  # all match -> original returned
    out = apply_filter(path, targets, essids=["OtherNet"], bssids=[], mode="include")
    assert out is None  # everything dropped


def test_filter_exclude_mode(tmp_path):
    line, _ = make_test_22000()
    path = tmp_path / "h.22000"
    path.write_text(line + "\n")
    targets = parse_22000_file(path)
    out = apply_filter(path, targets, essids=["OtherNet"], bssids=[], mode="exclude")
    assert out == path


def test_capture_listing(tmp_path):
    (tmp_path / "a.cap").write_bytes(b"x")
    (tmp_path / "b.PCAPNG").write_bytes(b"x")
    (tmp_path / "c.txt").write_bytes(b"x")
    assert is_capture_file("a.cap")
    assert not is_capture_file("c.txt")
    assert [p.name for p in list_capture_files(tmp_path)] == ["a.cap", "b.PCAPNG"]
