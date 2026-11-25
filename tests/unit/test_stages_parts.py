"""Seed extraction, keyboard walks, mangler generator, space rules."""

from wicrack.stages.kbwalks import build_walk_candidates
from wicrack.stages.mangler import builtin_mangler
from wicrack.stages.seeds import build_seed_list
from wicrack.stages.space import make_space_rules


def test_build_seed_list_filters(tmp_path):
    src = tmp_path / "wl.txt"
    src.write_text("password\nok\nhi\nwith space\n1337\ngoodpassword\nabcdefgh\n")
    out = build_seed_list(
        src, tmp_path / "seeds.txt", min_len=4, max_len=8, limit=100, alnum_only=True
    )
    words = out.read_text().splitlines()
    assert "password" in words
    assert "1337" in words
    assert "hi" not in words  # too short
    assert "with space" not in words  # non-alnum
    assert "goodpassword" not in words  # too long


def test_build_seed_list_limit(tmp_path):
    src = tmp_path / "wl.txt"
    src.write_text("\n".join(f"word{i:03d}" for i in range(50)))
    out = build_seed_list(
        src, tmp_path / "seeds.txt", min_len=4, max_len=10, limit=10, alnum_only=True
    )
    assert len(out.read_text().splitlines()) == 10


def test_keyboard_walk_candidates(tmp_path):
    path = build_walk_candidates(tmp_path / "kb.txt")
    lines = path.read_text().splitlines()
    assert "qwertyuiop" in lines
    assert "poiuytrewq" in lines  # reversed
    assert "QWERTYUIOP" in lines  # upper
    assert len(lines) == len(set(lines))  # no duplicates


def test_builtin_mangler_variants(tmp_path):
    seeds = tmp_path / "seeds.txt"
    seeds.write_text("admin\n")
    variants = list(builtin_mangler(seeds))
    assert "admin" in variants
    assert "Admin" in variants
    assert "ADMIN" in variants
    assert "@dm1n" in variants  # leet
    assert "admin123" in variants  # digit suffix
    assert "123admin" in variants  # digit prefix
    assert "admin!" in variants


def test_space_rules_content(tmp_path):
    path = make_space_rules(tmp_path / "space.rule", max_spaces=2)
    lines = path.read_text().splitlines()
    assert lines[0] == "$ "  # append one space
    assert "^ " in lines  # prepend
    assert len(lines) == 4  # 1,2 append + 1,2 prepend
