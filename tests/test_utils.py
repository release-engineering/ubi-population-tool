import pytest
from ubipop._utils import (PulpAction, AssociateAction, AssociateActionModules,
                           AssociateActionRpms, UnassociateActionRpms,
                           UnassociateActionModules)
from ubipop._pulp_client import Repo
from mock import MagicMock


def test_raise_not_implemented_pulp_action():
    units = ["unit1", "unit2"]
    repo = Repo("test", "1", "2", None)
    action = PulpAction(units, repo)
    pytest.raises(NotImplementedError, action.get_action, None)


def test_raise_not_implemented_associate_action():
    units = ["unit1", "unit2"]
    repo = Repo("test", "1", "2", None)
    src_repo = Repo("test", "1", "2", None)
    action = AssociateAction(units, repo, src_repo)
    pytest.raises(NotImplementedError, action.get_action, None)


@pytest.mark.parametrize("klass, method",
                         [(AssociateActionModules, "associate_modules"),
                          (AssociateActionRpms, "associate_packages")]
                         )
def test_get_action_associate(klass, method):
    units = ["unit1", "unit2"]
    dst_repo = Repo("test_dst", "1", "2", None)
    src_repo = Repo("test_src", "1", "2", None)
    action = klass(units, dst_repo, src_repo)
    associate_action, src_repo_current, dst_repo_current, current_units = \
        action.get_action(MagicMock())

    assert "mock." + method in str(associate_action)
    assert current_units == units
    assert dst_repo_current.repo_id == dst_repo.repo_id
    assert src_repo_current.repo_id == src_repo.repo_id


@pytest.mark.parametrize("klass, method",
                         [(UnassociateActionModules, "unassociate_modules"),
                          (UnassociateActionRpms, "unassociate_packages")]
                         )
def test_get_action_unassociate(klass, method):
    units = ["unit1", "unit2"]
    dst_repo = Repo("test_dst", "1", "2", None)
    action = klass(units, dst_repo)
    associate_action, dst_repo_current, current_units = action.get_action(MagicMock())

    assert "mock." + method in str(associate_action)
    assert current_units == units
    assert dst_repo_current.repo_id == dst_repo.repo_id
