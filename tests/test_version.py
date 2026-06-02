from sentinel_brief.match.version import cmp, in_range


def test_cmp_basic():
    assert cmp("1.2.3", "1.2.4") < 0
    assert cmp("1.2.10", "1.2.2") > 0
    assert cmp("2.0.0", "2.0.0") == 0


def test_in_range_fixed_open():
    # Affected for [1.0.0, 2.0.0)
    assert in_range("1.5.0", "1.0.0", "2.0.0", None)
    assert not in_range("0.9.9", "1.0.0", "2.0.0", None)
    assert not in_range("2.0.0", "1.0.0", "2.0.0", None)


def test_in_range_last_affected():
    assert in_range("3.5.0", "3.0.0", None, "3.5.0")
    assert not in_range("3.5.1", "3.0.0", None, "3.5.0")


def test_in_range_no_introduced_means_zero():
    assert in_range("0.1.0", "0", "1.0.0", None)
