import pytest

from pubtools.pulplib import RpmUnit, ModulemdUnit, ModulemdDefaultsUnit, FakeController
from ubipop._matcher import UbiUnit


def _get_test_unit(klass, **kwargs):
    repo_id = kwargs.pop("src_repo_id")
    return UbiUnit(klass(**kwargs), repo_id)


def get_rpm_unit(**kwargs):
    return _get_test_unit(RpmUnit, **kwargs)


def get_srpm_unit(**kwargs):
    kwargs["content_type_id"] = "srpm"
    kwargs["arch"] = "src"
    return _get_test_unit(RpmUnit, **kwargs)


def get_modulemd_unit(**kwargs):
    return _get_test_unit(ModulemdUnit, **kwargs)


def get_modulemd_defaults_unit(**kwargs):
    return _get_test_unit(ModulemdDefaultsUnit, **kwargs)


@pytest.fixture(name="pulp")
def fake_pulp():
    yield FakeController()
