from pubtools.pulplib import ModulemdDefaultsUnit

from ubipop._matcher import UbiUnit
from ubipop._utils import batcher, flatten_md_defaults_name_profiles


def test_flatten_md_defaults_name_profiles():
    unit = UbiUnit(
        ModulemdDefaultsUnit(
            name="test",
            stream="foo",
            profiles={"rhel": ["common", "uncommon"], "fedora": ["super", "ultra"]},
            repo_id="foo-repo",
        ),
        "foo-repo",
    )

    out = flatten_md_defaults_name_profiles(unit)

    assert out == "test:[fedora:super,ultra]:[rhel:common,uncommon]"


def test_batcher():
    """Ensure batcher splits given units appropriately"""

    items = [1, 2, 3, 4, 5, 6, 7, 8, 9]
    assert list(batcher(items, 3)) == [[1, 2, 3], [4, 5, 6], [7, 8, 9]]
