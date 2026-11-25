"""Mask math and the mask-learning engine."""

from wicrack.stages.learn import key_to_mask, learn_masks
from wicrack.stages.masks import charset_size, mask_keyspace


def test_charset_size():
    assert charset_size("?l?u?d ") == 63  # 26+26+10+1 literal space
    assert charset_size("?d") == 10
    assert charset_size("abc") == 3


def test_mask_keyspace():
    assert mask_keyspace("?d" * 8) == 100_000_000
    assert mask_keyspace("?d?d?d?d") == 10_000
    custom = mask_keyspace("?1" * 4, custom_charset="?l?u")
    assert custom == 52**4


def test_key_to_mask():
    assert key_to_mask("Pass word1") == "?u?l?l?l ?l?l?l?l?d"
    assert key_to_mask("12345678") == "?d" * 8
    assert key_to_mask("pass!word") == "?l?l?l?l?s?l?l?l?l"


def test_learn_masks_repeated_pattern():
    keys = ["Winter2024", "Summer2024", "Spring99", "short"]
    masks = learn_masks(keys, min_count=2)
    assert "?u?l?l?l?l?l?d?d?d?d" in masks  # Winter/Summer share structure


def test_learn_masks_needs_repeats():
    # structurally different keys -> no repeated pattern
    assert learn_masks(["unique1", "totallydifferent99"]) == []
