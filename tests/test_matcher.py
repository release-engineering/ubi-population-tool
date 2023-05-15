import pytest

from pubtools.pulplib import (
    RpmUnit,
    Criteria,
    YumRepository,
    ModulemdUnit,
)
from ubiconfig import UbiConfig

from ubipop._matcher import (
    UbiUnit,
    Matcher,
    flatten_list_of_sets,
)


@pytest.fixture(name="ubi_config")
def fake_ubi_config():
    config_dict = {
        "arches": ["src"],
        "modules": {
            "include": [
                {
                    "name": "fake_name",
                    "stream": "fake_stream",
                    "profiles": ["test"],
                }
            ]
        },
        "packages": {
            "include": ["test.*", "test-debug.*", "something_else.src"],
            "exclude": [
                "excluded_with_globbing*",
                "excluded_package.*",
                "excluded_with_arch.src",
            ],
        },
        "content_sets": {},
    }
    yield UbiConfig.load_from_dict(config_dict, "fake/config.yaml")


def test_ubi_unit():
    """Test proper wrapping *Unit classes of pulplib and access of their attrs"""
    unit = RpmUnit(name="test", version="1.0", release="1", arch="x86_64")

    repo_id = "test_repo_id"
    ubi_unit = UbiUnit(unit, repo_id)

    # we can directly access attrs of RpmUnit
    assert ubi_unit.name == "test"
    assert ubi_unit.version == "1.0"
    assert ubi_unit.release == "1"
    assert ubi_unit.arch == "x86_64"
    assert ubi_unit.associate_source_repo_id == repo_id

    # non-existing attr will raise an error
    with pytest.raises(AttributeError):
        _ = ubi_unit.non_existing_attr


def test_run_raises_exception():
    """Matcher.run() method needs to implemented in subclasses"""
    matcher = Matcher(None, None)
    with pytest.raises(NotImplementedError):
        matcher.run()


def test_search_units(pulp):
    """Test simple search for units"""
    repo = YumRepository(
        id="test_repo",
    )
    repo.__dict__["_client"] = pulp.client

    unit_1 = RpmUnit(name="test", version="1.0", release="1", arch="x86_64")
    unit_2 = RpmUnit(name="test", version="1.0", release="1", arch="i386")
    pulp.insert_repository(repo)
    pulp.insert_units(repo, [unit_1, unit_2])

    matcher = Matcher(None, None)
    criteria = matcher.create_or_criteria(["name", "arch"], [("test", "x86_64")])
    # let Future return result
    search_result = matcher._search_units(repo, criteria, "rpm").result()

    # result should be set
    assert isinstance(search_result, set)
    # with only 1 item
    assert len(search_result) == 1
    unit = search_result.pop()
    # unit should be UbiUnit
    assert isinstance(unit, UbiUnit)
    # internally _unit attr should be RpmUnit
    assert isinstance(unit._unit, RpmUnit)
    # unit has name "test"
    assert unit.name == "test"
    # and proper associate_source_repo_id set
    assert unit.associate_source_repo_id == "test_repo"


def test_create_criteria():
    """Test creation of criteria list"""
    matcher = Matcher(None, None)

    fields = ["color", "size"]
    values = [("blue", "10"), ("white", "15")]

    criteria = matcher.create_or_criteria(fields, values)

    # there should be 2 criteria created
    assert len(criteria) == 2
    # both of instance of Criteria
    for crit in criteria:
        assert isinstance(crit, Criteria)
    # let's not test internal structure of criteria, that's responsibility of pulplib


def test_create_criteria_uneven_args():
    """Test wrong number of values in args"""
    matcher = Matcher(None, None)

    fields = ["color", "size"]
    values = [("blue", "10"), ("white")]
    # call to create_or_criteria raises ValueError because of uneven number of values of the second tuple
    # in value list
    with pytest.raises(ValueError):
        _ = matcher.create_or_criteria(fields, values)


def test_search_units_per_repos(pulp):
    """Test searching over multiple repositories"""
    repo_1 = YumRepository(
        id="test_repo_1",
    )
    repo_1.__dict__["_client"] = pulp.client

    repo_2 = YumRepository(
        id="test_repo_2",
    )
    repo_2.__dict__["_client"] = pulp.client

    unit_1 = RpmUnit(name="test", version="1.0", release="1", arch="x86_64")
    unit_2 = RpmUnit(name="test", version="1.0", release="1", arch="i386")

    pulp.insert_repository(repo_1)
    pulp.insert_repository(repo_2)
    pulp.insert_units(repo_1, [unit_1])
    pulp.insert_units(repo_2, [unit_2])

    expected_repo_ids = ["test_repo_1", "test_repo_2"]
    matcher = Matcher(None, None)

    criteria = matcher.create_or_criteria(
        ["name", "arch"], [("test", "x86_64"), ("test", "i386")]
    )

    # let Future return result
    search_result = matcher._search_units_per_repos(
        criteria, [repo_1, repo_2], "rpm"
    ).result()
    # result should be set
    assert isinstance(search_result, set)
    # with 2 items
    assert len(search_result) == 2
    # units are from both repos
    actual_repo_ids = []
    for unit in search_result:
        actual_repo_ids.append(unit.associate_source_repo_id)
        assert isinstance(unit, UbiUnit)
    assert sorted(actual_repo_ids) == expected_repo_ids


def test_search_rpms(pulp):
    """Test convenient method for searching rpms"""
    repo = YumRepository(
        id="test_repo_1",
    )
    repo.__dict__["_client"] = pulp.client
    unit_1 = RpmUnit(
        name="test",
        version="1.0",
        release="1",
        arch="x86_64",
        filename="test.x86_64.rpm",
    )
    unit_2 = RpmUnit(
        name="test", version="1.0", release="1", arch="i386", filename="test.i386.rpm"
    )

    pulp.insert_repository(repo)
    pulp.insert_units(repo, [unit_1, unit_2])

    matcher = Matcher(None, None)
    criteria = matcher.create_or_criteria(["filename"], [("test.x86_64.rpm",)])
    # let Future return result
    result = matcher.search_rpms(criteria, [repo]).result()
    # there should be be only one unit in the result set according to criteria
    assert len(result) == 1
    assert result.pop().filename == "test.x86_64.rpm"


def test_search_srpms(pulp):
    """Test convenient method for searching srpms"""
    repo = YumRepository(
        id="test_repo_1",
    )
    repo.__dict__["_client"] = pulp.client
    unit_1 = RpmUnit(
        name="test",
        version="1.0",
        release="1",
        arch="src",
        filename="test.src.rpm",
        content_type_id="srpm",
    )
    unit_2 = RpmUnit(
        name="test-devel",
        version="1.0",
        release="1",
        arch="src",
        filename="test-devel.src.rpm",
        content_type_id="srpm",
    )

    pulp.insert_repository(repo)
    pulp.insert_units(repo, [unit_1, unit_2])

    matcher = Matcher(None, None)
    criteria = matcher.create_or_criteria(["filename"], [("test.src.rpm",)])
    # let Future return result
    result = matcher.search_srpms(criteria, [repo]).result()
    # there should be be only one unit in the result set according to criteria
    assert len(result) == 1
    assert result.pop().filename == "test.src.rpm"


def test_search_moludemds(pulp):
    """Test convenient method for searching modulemds"""
    repo = YumRepository(
        id="test_repo_1",
    )
    repo.__dict__["_client"] = pulp.client
    unit_1 = ModulemdUnit(
        name="test",
        stream="10",
        version=100,
        context="abcdef",
        arch="x86_64",
    )
    unit_2 = ModulemdUnit(
        name="test",
        stream="20",
        version=100,
        context="abcdef",
        arch="x86_64",
    )

    pulp.insert_repository(repo)
    pulp.insert_units(repo, [unit_1, unit_2])

    matcher = Matcher(None, None)
    criteria = matcher.create_or_criteria(["name", "stream"], [("test", "10")])
    # let Future return result
    result = matcher.search_modulemds(criteria, [repo]).result()
    # there should be be only one unit in the result set according to criteria
    assert len(result) == 1
    assert result.pop().nsvca == "test:10:100:abcdef:x86_64"


def test_flatten_list_of_sets():
    """Test helper function that flattens list of sets into one set"""
    set_1 = set([1, 2, 3])
    set_2 = set([2, 3, 4])
    expected_set = set([1, 2, 3, 4])

    new_set = flatten_list_of_sets([set_1, set_2]).result()
    assert new_set == expected_set
