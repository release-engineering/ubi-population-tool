import pytest

from mock import MagicMock
from pubtools.pulplib import YumRepository, RpmUnit
from ubipop._utils import (
    AssociateAction,
    AssociateActionModuleDefaults,
    AssociateActionModules,
    AssociateActionRpms,
    PulpAction,
    UnassociateActionModuleDefaults,
    UnassociateActionModules,
    UnassociateActionRpms,
    vercmp_sort,
)
from ubipop._matcher import UbiUnit


def test_raise_not_implemented_pulp_action():
    units = ["unit1", "unit2"]
    repo = YumRepository(id="test")
    action = PulpAction(units, repo)
    pytest.raises(NotImplementedError, action.get_actions, None)


def test_raise_not_implemented_associate_action():
    units = ["unit1", "unit2"]
    repo = YumRepository(id="test")
    src_repo = YumRepository(id="test")
    action = AssociateAction(units, repo, src_repo)
    pytest.raises(NotImplementedError, action.get_actions, None)


@pytest.mark.parametrize(
    "klass, method",
    [
        (AssociateActionModules, "associate_modules"),
        (AssociateActionModuleDefaults, "associate_module_defaults"),
        (AssociateActionRpms, "associate_packages"),
    ],
)
def test_get_action_associate(klass, method):
    mocked_unit_1 = MagicMock()
    mocked_unit_1.associate_source_repo_id = "test_src_1"
    mocked_unit_2 = MagicMock()
    mocked_unit_2.associate_source_repo_id = "test_src_2"
    units = [mocked_unit_1, mocked_unit_2]
    dst_repo = YumRepository(id="test_dst")

    src_repos = [
        YumRepository(id="test_src_1"),
        YumRepository(id="test_src_2"),
    ]
    action = klass(units, dst_repo, src_repos)
    actions = action.get_actions(MagicMock())
    for action in actions:
        associate_action, src_repo_current, dst_repo_current, current_units = action
        assert "mock." + method in str(associate_action)
        assert len(current_units) == 1
        assert current_units == [
            u for u in units if u.associate_source_repo_id == src_repo_current.id
        ]
        assert dst_repo_current.id == dst_repo.id
        assert src_repo_current.id == current_units[0].associate_source_repo_id


@pytest.mark.parametrize(
    "klass, method",
    [
        (UnassociateActionModules, "unassociate_modules"),
        (UnassociateActionModuleDefaults, "unassociate_module_defaults"),
        (UnassociateActionRpms, "unassociate_packages"),
    ],
)
def test_get_action_unassociate(klass, method):
    units = ["unit1", "unit2"]
    dst_repo = YumRepository(id="test_dst")
    action = klass(units, dst_repo)
    associate_action, dst_repo_current, current_units = action.get_actions(MagicMock())[
        0
    ]

    assert "mock." + method in str(associate_action)
    assert current_units == units
    assert dst_repo_current.id == dst_repo.id


def test_vercmp_sort():
    """Tests all comparison methods for vercmp sort used for RPM packages comparison"""
    vercmp_klass = vercmp_sort()

    unit_1 = vercmp_klass(
        UbiUnit(
            RpmUnit(
                name="test",
                version="10",
                release="20",
                epoch="1",
                arch="x86_64",
            ),
            None,
        )
    )

    unit_2 = vercmp_klass(
        UbiUnit(
            RpmUnit(
                name="test",
                version="10",
                release="200",
                epoch="1",
                arch="x86_64",
            ),
            None,
        )
    )

    assert (unit_1 < unit_2) is True
    assert (unit_1 <= unit_2) is True
    assert (unit_1 == unit_2) is False
    assert (unit_1 >= unit_2) is False
    assert (unit_1 > unit_2) is False
    assert (unit_1 != unit_2) is True
