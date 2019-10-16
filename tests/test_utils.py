import pytest

from mock import MagicMock
from ubipop._utils import (
    AssociateAction,
    AssociateActionModuleDefaults,
    AssociateActionModules,
    AssociateActionRpms,
    PulpAction,
    UnassociateActionModuleDefaults,
    UnassociateActionModules,
    UnassociateActionRpms,
)
from ubipop._pulp_client import Repo


def test_raise_not_implemented_pulp_action():
    units = ["unit1", "unit2"]
    repo = Repo("test", "1", "test-rpms", "2", None, None, None)
    action = PulpAction(units, repo)
    pytest.raises(NotImplementedError, action.get_actions, None)


def test_raise_not_implemented_associate_action():
    units = ["unit1", "unit2"]
    repo = Repo("test", "1", "test-rpms", "2", None, None, None)
    src_repo = Repo("test", "1", "test-rpms", "2", None, None, None)
    action = AssociateAction(units, repo, src_repo)
    pytest.raises(NotImplementedError, action.get_actions, None)


@pytest.mark.parametrize("klass, method", [
    (AssociateActionModules, "associate_modules"),
    (AssociateActionModuleDefaults, "associate_module_defaults"),
    (AssociateActionRpms, "associate_packages"),
])
def test_get_action_associate(klass, method):
    mocked_unit_1 = MagicMock()
    mocked_unit_1.associate_source_repo_id = "test_src_1"
    mocked_unit_2 = MagicMock()
    mocked_unit_2.associate_source_repo_id = "test_src_2"
    units = [mocked_unit_1, mocked_unit_2]
    dst_repo = Repo("test_dst", "1", "test_dst-rpms", "2", None, None, None)
    src_repos = [Repo("test_src_1", "1", "test_src-rpms", "2", None, None, None),
                 Repo("test_src_2", "1", "test_src-rpms", "2", None, None, None)]
    action = klass(units, dst_repo, src_repos)
    actions = action.get_actions(MagicMock())

    for i, action in enumerate(actions):
        associate_action, src_repo_current, dst_repo_current, current_units = action
        assert "mock." + method in str(associate_action)
        assert current_units == [units[i]]
        assert dst_repo_current.repo_id == dst_repo.repo_id
        assert src_repo_current.repo_id == src_repos[i].repo_id


@pytest.mark.parametrize("klass, method", [
    (UnassociateActionModules, "unassociate_modules"),
    (UnassociateActionModuleDefaults, "unassociate_module_defaults"),
    (UnassociateActionRpms, "unassociate_packages"),
])
def test_get_action_unassociate(klass, method):
    units = ["unit1", "unit2"]
    dst_repo = Repo("test_dst", "1", "test_dst-rpms", "2", None, None, None)
    action = klass(units, dst_repo)
    associate_action, dst_repo_current, current_units = action.get_actions(MagicMock())[0]

    assert "mock." + method in str(associate_action)
    assert current_units == units
    assert dst_repo_current.repo_id == dst_repo.repo_id
