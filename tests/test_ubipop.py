from datetime import datetime
from operator import attrgetter

import logging
import os
import shutil
import sys
import tempfile
import pytest
import ubiconfig

from pubtools.pulplib import (
    YumRepository,
    FakeController,
    Client,
    Distributor,
    ModulemdUnit,
    RpmUnit,
    ModulemdDefaultsUnit,
)
from mock import MagicMock, patch, call
from more_executors import Executors
from more_executors.futures import f_proxy, f_return
from ubipop import (
    UbiPopulateRunner,
    UbiRepoSet,
    RepoSet,
    UbiPopulate,
    ConfigMissing,
    RepoMissing,
    PopulationSourceMissing,
)
from ubipop._utils import (
    AssociateActionModules,
    UnassociateActionModules,
    AssociateActionModuleDefaults,
    UnassociateActionModuleDefaults,
)
from ubipop._matcher import UbiUnit


TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), "./data")


class FakeUbiPopulate(UbiPopulate):
    def __init__(self, *args, **kwargs):
        super(FakeUbiPopulate, self).__init__(*args, **kwargs)
        self.pulp_client_controller = FakeController()

    @property
    def pulp_client(self):
        # Super should give a Pulp client
        assert isinstance(super(FakeUbiPopulate, self).pulp_client, Client)
        # But we'll substitute our own
        return self.pulp_client_controller.client


@pytest.fixture(name="ubi_repo_set")
def fixture_ubi_repo_set():
    ubi_binary = get_test_repo(id="ubi-foo-rpms", ubi_config_version="7")
    ubi_source = get_test_repo(id="ubi-foo-source", ubi_config_version="7")
    ubi_debug = get_test_repo(id="ubi-foo-debug", ubi_config_version="7")

    ubi_binary.get_source_repository = MagicMock()
    ubi_binary.get_source_repository.return_value = ubi_source
    ubi_binary.get_debug_repository = MagicMock()
    ubi_binary.get_debug_repository.return_value = ubi_debug

    rhel_binary = get_test_repo(id="foo-rpms", ubi_config_version="7")
    rhel_source = get_test_repo(id="foo-source", ubi_config_version="7")
    rhel_debug = get_test_repo(id="foo-debug", ubi_config_version="7")

    rhel_binary.get_source_repository = MagicMock()
    rhel_binary.get_source_repository.return_value = rhel_source
    rhel_binary.get_debug_repository = MagicMock()
    rhel_binary.get_debug_repository.return_value = rhel_debug

    yield UbiRepoSet(
        RepoSet(
            [rhel_binary],
            [rhel_source],
            [rhel_debug],
        ),
        RepoSet(ubi_binary, ubi_source, ubi_debug),
    )


@pytest.fixture(name="ubi_repo_set_no_debug")
def fixture_ubi_repo_set_no_debug():
    ubi_binary = get_test_repo(id="ubi-foo-rpms", ubi_config_version="7")
    ubi_source = get_test_repo(id="ubi-foo-source", ubi_config_version="7")

    ubi_binary.get_source_repository = MagicMock()
    ubi_binary.get_source_repository.return_value = ubi_source
    ubi_binary.get_debug_repository = MagicMock()
    ubi_binary.get_debug_repository.return_value = f_proxy(f_return())

    rhel_binary = get_test_repo(id="foo-rpms", ubi_config_version="7")
    rhel_source = get_test_repo(id="foo-source", ubi_config_version="7")

    rhel_binary.get_source_repository = MagicMock()
    rhel_binary.get_source_repository.return_value = rhel_source
    rhel_binary.get_debug_repository = MagicMock()

    rhel_binary.get_debug_repository.return_value = f_proxy(f_return())

    yield UbiRepoSet(
        RepoSet(
            [rhel_binary],
            [rhel_source],
            f_proxy(f_return()),
        ),
        RepoSet(
            ubi_binary,
            ubi_source,
            f_proxy(f_return()),
        ),
    )


@pytest.fixture(name="test_ubiconfig")
def fixture_test_ubiconfig():
    yield ubiconfig.get_loader(TEST_DATA_DIR).load("ubi7/conf.yaml")


@pytest.fixture(name="executor")
def fixture_executor():
    yield Executors.thread_pool(max_workers=1).with_retry()


@pytest.fixture(name="mock_ubipop_runner")
def fixture_mock_ubipop_runner(ubi_repo_set, test_ubiconfig, executor):
    yield UbiPopulateRunner(
        MagicMock(), MagicMock(), ubi_repo_set, test_ubiconfig, False, executor
    )


def get_test_repo(**kwargs):
    return f_proxy(
        f_return(
            YumRepository(
                id=kwargs.get("id"),
                content_set=kwargs.get("content_set"),
                ubi_population=kwargs.get("ubi_population"),
                population_sources=kwargs.get("population_sources", []),
                ubi_config_version=kwargs.get("ubi_config_version"),
            )
        )
    )


def get_test_mod(**kwargs):
    # mozna se na toto vysrat
    unit = UbiUnit(
        ModulemdUnit(
            name=kwargs.get("name", ""),
            stream=kwargs.get("stream", ""),
            version=kwargs.get("version", 0),
            context=kwargs.get("context", ""),
            arch=kwargs.get("arch", ""),
            artifacts=kwargs.get("packages", []),
            profiles=kwargs.get("profiles", {}),
        ),
        kwargs.get("src_repo_id"),
    )

    return unit


def test_get_output_repo_ids(ubi_repo_set):
    repo_ids = ubi_repo_set.get_output_repo_ids()
    assert repo_ids == set(["ubi-foo-rpms", "ubi-foo-source", "ubi-foo-debug"])


def test_get_output_repo_ids_no_debug(ubi_repo_set_no_debug):
    repo_ids = ubi_repo_set_no_debug.get_output_repo_ids()
    assert repo_ids == set(["ubi-foo-rpms", "ubi-foo-source"])


def test_raise_config_missing(caplog):
    config_path = os.path.join(TEST_DATA_DIR, "ubi8")
    ubipopulate = UbiPopulate(
        "foo.pulp.com", ("foo", "foo"), False, ubiconfig_dir_or_url=config_path
    )

    for config in ubipopulate.ubiconfig_list:
        with pytest.raises(ConfigMissing):
            ubipopulate._get_config("9.8", config)

    assert (
        "Config file ubiconf_golang.yaml missing from 9.8 and default 9 branches"
        in caplog.text
    )


def test_publish_out_repos(mock_ubipop_runner):
    dt = datetime(2019, 9, 12, 0, 0, 0)

    d1 = Distributor(
        id="yum_distributor",
        type_id="yum_distributor",
        repo_id="repo",
        last_publish=dt,
        relative_url="content/unit/2/client",
    )
    repo = YumRepository(
        id="repo",
        eng_product_id=102,
        distributors=[d1],
        relative_url="content/unit/2/client",
    )
    fake_pulp = FakeController()
    repo.__dict__["_client"] = fake_pulp.client

    fake_pulp.insert_repository(repo)
    # Setup output repos, leave only binary repo as the actual one
    mock_ubipop_runner.repos.out_repos = RepoSet(
        f_proxy(f_return(repo)), f_proxy(f_return()), f_proxy(f_return())
    )

    fts = mock_ubipop_runner._publish_out_repos()

    # we should publish only one repository with one distributor
    assert len(fts) == 1
    assert [hist.repository.id for hist in fake_pulp.publish_history] == ["repo"]


def test_get_population_sources():
    repo = YumRepository(
        id="rhel-8-for-x86_64-appstream-rpms",
        content_set="rhel-8-for-x86_64-appstream-rpms",
        population_sources=["src_1", "src_2"],
    )

    fake_ubipopulate = FakeUbiPopulate(
        "foo.pulp.com", ("foo", "foo"), False, ubiconfig_dir_or_url=TEST_DATA_DIR
    )

    fake_pulp = fake_ubipopulate.pulp_client_controller

    repo_1 = YumRepository(
        id="src_1",
        content_set="src_1_cs",
    )

    repo_2 = YumRepository(
        id="src_2",
        content_set="src_2_cs",
    )
    fake_pulp.insert_repository(repo_1)
    fake_pulp.insert_repository(repo_2)

    repos = fake_ubipopulate._get_population_sources(
        repo
    )  # pylint: disable=protected-access

    assert len(repos) == 2
    assert ["src_1", "src_2"] == sorted([repo.id for repo in repos])


def test_get_population_sources_empty():
    repo = YumRepository(
        id="rhel-8-for-x86_64-appstream-rpms",
        content_set="rhel-8-for-x86_64-appstream-rpms",
    )

    fake_ubipopulate = FakeUbiPopulate(
        "foo.pulp.com", ("foo", "foo"), False, ubiconfig_dir_or_url=TEST_DATA_DIR
    )

    with pytest.raises(PopulationSourceMissing):
        fake_ubipopulate._get_population_sources(
            repo
        )  # pylint: disable=protected-access


@patch("pubtools.pulplib.YumRepository.get_debug_repository")
@patch("pubtools.pulplib.YumRepository.get_source_repository")
def test_get_ubi_repo_sets(get_debug_repository, get_source_repository):
    content_set = "rhel-8-for-x86_64-appstream-rpms"
    repo = YumRepository(
        id="ubi_binary",
        content_set="rhel-8-for-x86_64-appstream-rpms",
        population_sources=["input_binary"],
        ubi_population=True,
    )

    input_binary_repo = YumRepository(id="input_binary")
    input_source_repo = YumRepository(id="input_source")
    input_debug_repo = YumRepository(id="input_debug")

    debug_repo = get_test_repo(id="ubi_source", population_sources=["input_source"])
    source_repo = get_test_repo(id="ubi_debug", population_sources=["input_debug"])

    get_debug_repository.return_value = debug_repo
    get_source_repository.return_value = source_repo

    fake_ubipopulate = FakeUbiPopulate(
        "foo.pulp.com", ("foo", "foo"), False, ubiconfig_dir_or_url=TEST_DATA_DIR
    )

    fake_pulp = fake_ubipopulate.pulp_client_controller
    fake_pulp.insert_repository(repo)
    fake_pulp.insert_repository(input_binary_repo)
    fake_pulp.insert_repository(input_source_repo)
    fake_pulp.insert_repository(input_debug_repo)

    ubi_repo_sets = fake_ubipopulate._get_ubi_repo_sets(content_set)

    assert len(ubi_repo_sets) == 1
    ubi_repo_set = ubi_repo_sets[0]
    input_repos = ubi_repo_set.in_repos
    output_repos = ubi_repo_set.out_repos

    assert len(input_repos.rpm) == 1
    assert input_repos.rpm[0].id == "input_binary"
    assert len(input_repos.source) == 1
    assert input_repos.source[0].id == "input_source"
    assert len(input_repos.debug) == 1
    assert input_repos.debug[0].id == "input_debug"

    assert output_repos.rpm.id == "ubi_binary"
    assert output_repos.source.id == "ubi_source"
    assert output_repos.debug.id == "ubi_debug"


def test_diff_modules(mock_ubipop_runner):
    curr = [
        get_test_mod(name="1"),
        get_test_mod(name="2"),
        get_test_mod(name="3"),
    ]
    expected = [
        get_test_mod(name="2", pulplib=True),
        get_test_mod(name="3", pulplib=True),
        get_test_mod(name="4", pulplib=True),
    ]

    diff = mock_ubipop_runner._diff_modules_by_nsvca(
        curr, expected
    )  # pylint: disable=protected-access

    assert len(diff) == 1
    assert diff[0].name == "1"


@pytest.mark.parametrize(
    "rhel_repo_set, ubi_repo_set, fail",
    [
        (
            RepoSet(None, None, "foo-debug"),
            RepoSet(None, None, "ubi-foo-debug"),
            True,
        ),
        (
            RepoSet("foo-rpms", "foo-source", None),
            RepoSet("ubi-foo-rpms", "ubi-foo-source", None),
            False,
        ),
    ],
)
def test_ubi_repo_set(rhel_repo_set, ubi_repo_set, fail, caplog):
    if fail:
        with pytest.raises(RepoMissing):
            UbiRepoSet(rhel_repo_set, ubi_repo_set)

        assert "ERROR" in caplog.text
        assert "repo does not exist" in caplog.text
        assert "WARN" not in caplog.text

    else:
        UbiRepoSet(rhel_repo_set, ubi_repo_set)
        assert "WARN" in caplog.text
        assert "repo does not exist" in caplog.text
        assert "ERROR" not in caplog.text


@pytest.fixture(name="mocked_ubiconfig_load")
def fixture_mocked_ubiconfig_load():
    with patch("ubiconfig.get_loader") as get_loader:
        m = MagicMock()
        m.file_name = "test"
        m.version = "7.7"
        get_loader.return_value.load.return_value = m
        yield get_loader


def test_ubipopulate_load_ubiconfig(mocked_ubiconfig_load):
    # pylint: disable=unused-argument
    ubipop = UbiPopulate("foo.pulp.com", ("foo", "foo"), False, ["cfg.yaml"])
    assert len(ubipop.ubiconfig_list) == 1
    assert ubipop.ubiconfig_list[0].file_name == "test"


def test_load_ubiconfig_by_content_set_labels():
    """Ensure correct config is returned when given a content set label"""
    ubipop = UbiPopulate(
        "foo.pulp.com",
        ("foo", "foo"),
        False,
        ubiconfig_dir_or_url=TEST_DATA_DIR,
        content_sets=[
            "rhel-7-server-rpms",
        ],
    )
    assert len(ubipop.ubiconfig_list) == 1
    assert ubipop.ubiconfig_list[0].content_sets.rpm.output == "ubi-7-server-rpms"


def test_load_ubiconfig_by_repo_ids():
    """Ensure correct config is returned when given a repo ID"""
    repo = YumRepository(id="rhel-7-server", content_set="rhel-7-server-rpms")

    fake_ubipopulate = FakeUbiPopulate(
        "foo.pulp.com",
        ("foo", "foo"),
        False,
        ubiconfig_dir_or_url=TEST_DATA_DIR,
        repo_ids=[
            "rhel-7-server",
        ],
    )

    fake_pulp = fake_ubipopulate.pulp_client_controller
    fake_pulp.insert_repository(repo)

    assert len(fake_ubipopulate.ubiconfig_list) == 1
    assert (
        fake_ubipopulate.ubiconfig_list[0].content_sets.rpm.output
        == "ubi-7-server-rpms"
    )


@pytest.fixture(name="mocked_ubiconfig_load_all")
def fixture_mocked_ubiconfig_load_all():
    with patch("ubiconfig.get_loader") as get_loader:
        m = MagicMock()
        m.file_name = "test"
        m.version = "7"
        get_loader.return_value.load_all.return_value = [m]
        yield get_loader


def test_ubipopulate_load_all_ubiconfig(mocked_ubiconfig_load_all):
    # pylint: disable=unused-argument
    ubipop = UbiPopulate("foo.pulp.com", ("foo", "foo"), False)
    assert len(ubipop.ubiconfig_list) == 1
    assert ubipop.ubiconfig_list[0].file_name == "test"


@pytest.fixture(name="mock_get_repo_pairs")
def fixture_mock_get_repo_pairs(ubi_repo_set):
    with patch("ubipop.UbiPopulate._get_ubi_repo_sets") as get_ubi_repo_sets:
        get_ubi_repo_sets.return_value = [ubi_repo_set]
        yield get_ubi_repo_sets


@pytest.fixture(name="mock_run_ubi_population")
def fixture_mock_run_ubi_population():
    with patch("ubipop.UbiPopulateRunner.run_ubi_population") as run_ubi_population:
        yield run_ubi_population


def test_create_output_file_all_repos(
    mock_ubipop_runner,
    mock_get_repo_pairs,
    mocked_ubiconfig_load_all,
    mock_run_ubi_population,
):
    # pylint: disable=unused-argument
    path = tempfile.mkdtemp("ubipop")
    try:
        out_file_path = os.path.join(path, "output.txt")

        ubipop = UbiPopulate(
            "foo.pulp.com", ("foo", "foo"), False, output_repos=out_file_path
        )
        ubipop.populate_ubi_repos()

        with open(out_file_path) as f:
            content = f.readlines()

        assert sorted(content) == sorted(
            ["ubi-foo-rpms\n", "ubi-foo-source\n", "ubi-foo-debug\n"]
        )
    finally:
        shutil.rmtree(path)


@pytest.fixture(name="mock_current_content_ft")
def fixture_mock_current_content_ft():
    current_modules_ft = MagicMock()
    current_rpms_ft = MagicMock()
    current_srpms_ft = MagicMock()
    current_debug_rpms_ft = MagicMock()
    current_module_default_ft = MagicMock()

    current_modules_ft.result.return_value = [
        get_test_mod(name="md_current"),
    ]
    current_module_default_ft.result.return_value = [
        get_test_mod_defaults(
            name="mdd_current", stream="rhel", profiles={"2.5": "common"}
        ),
    ]
    current_rpms_ft.result.return_value = [
        get_test_pkg(name="rpm_current", filename="rpm_current.rpm"),
    ]
    current_srpms_ft.result.return_value = [
        get_test_pkg(name="srpm_current", filename="srpm_current.src.rpm"),
    ]
    current_debug_rpms_ft.result.return_value = [
        get_test_pkg(name="debug_rpm_current", filename="debug_rpm_current.rpm"),
    ]

    yield current_modules_ft, current_module_default_ft, current_rpms_ft, current_srpms_ft, current_debug_rpms_ft


def test_get_pulp_actions(mock_ubipop_runner, mock_current_content_ft):
    mock_ubipop_runner.repos.modules = f_proxy(
        f_return(set([get_test_mod(name="test_md", pulplib=True)]))
    )

    mock_ubipop_runner.repos.module_defaults = [
        UbiUnit(
            ModulemdDefaultsUnit(
                name="test_mdd",
                stream="rhel",
                profiles={"2.5": "uncommon"},
                repo_id="foo-rpms",
                content_type_id="modulemd_defaults",
            ),
            "foo-rpms",
        )
    ]

    binary_rpms = [
        UbiUnit(
            RpmUnit(
                name="test_rpm",
                version="1",
                release="2",
                arch="x86_64",
                filename="test_rpm.rpm",
            ),
            "foo-rpms",
        )
    ]
    debug_rpms = [
        UbiUnit(
            RpmUnit(
                name="test_debug_pkg",
                version="1",
                release="2",
                arch="x86_64",
                filename="test_rpm.rpm",
            ),
            "foo-debug",
        )
    ]
    source_rpms = [
        UbiUnit(
            RpmUnit(
                name="test_srpm",
                version="1",
                release="2",
                arch="x86_64",
                filename="test_srpm.src.rpm",
            ),
            "foo-source",
        )
    ]

    mock_ubipop_runner.repos.packages = f_proxy(f_return(binary_rpms))
    mock_ubipop_runner.repos.debug_rpms = f_proxy(f_return(debug_rpms))
    mock_ubipop_runner.repos.source_rpms = f_proxy(f_return(source_rpms))

    modular_binary = UbiUnit(
        RpmUnit(name="modular_binary", version="1.0", release="1", arch="x86_64"),
        "foo-rpms",
    )
    modular_debug = UbiUnit(
        RpmUnit(name="modular_debug", version="1.0", release="1", arch="x86_64"),
        "foo-debug",
    )
    modular_source = UbiUnit(
        RpmUnit(
            name="modular_source",
            version="1.0",
            release="1",
            arch="src",
            content_type_id="srpm",
        ),
        "foo-source",
    )

    # pylint: disable=protected-access
    (
        associations,
        unassociations,
        mdd_association,
        mdd_unassociation,
    ) = mock_ubipop_runner._get_pulp_actions(
        *mock_current_content_ft,
        modular_binary=f_proxy(f_return(set([modular_binary]))),
        modular_debug=f_proxy(f_return(set([modular_debug]))),
        modular_source=f_proxy(f_return(set([modular_source])))
    )

    # firstly, check correct associations, there should 1 unit of each type associated
    modules, rpms, srpms, debug_rpms = associations
    assert len(modules.units) == 1
    assert modules.units[0].name == "test_md"
    assert modules.dst_repo.id == "ubi-foo-rpms"
    assert len(modules.src_repos) == 1
    assert modules.src_repos[0].id == "foo-rpms"

    # there should be 2 rpms, one modular, one non-modular
    assert len(rpms.units) == 2
    rpms.units.sort(key=attrgetter("name"))
    assert rpms.units[0].name == "modular_binary"
    assert rpms.dst_repo.id == "ubi-foo-rpms"
    assert len(rpms.src_repos) == 1
    assert rpms.src_repos[0].id == "foo-rpms"

    assert rpms.units[1].name == "test_rpm"
    assert rpms.dst_repo.id == "ubi-foo-rpms"
    assert len(rpms.src_repos) == 1
    assert rpms.src_repos[0].id == "foo-rpms"

    srpms.units.sort(key=attrgetter("name"))
    assert len(srpms.units) == 2
    assert srpms.units[0].name == "modular_source"
    assert srpms.dst_repo.id == "ubi-foo-source"
    assert len(srpms.src_repos) == 1
    assert srpms.src_repos[0].id == "foo-source"

    assert srpms.units[1].name == "test_srpm"
    assert srpms.dst_repo.id == "ubi-foo-source"
    assert len(srpms.src_repos) == 1
    assert srpms.src_repos[0].id == "foo-source"

    debug_rpms.units.sort(key=attrgetter("name"))
    assert len(debug_rpms.units) == 2
    assert debug_rpms.units[0].name == "modular_debug"
    assert debug_rpms.dst_repo.id == "ubi-foo-debug"
    assert len(debug_rpms.src_repos) == 1
    assert debug_rpms.src_repos[0].id == "foo-debug"

    assert debug_rpms.units[1].name == "test_debug_pkg"
    assert debug_rpms.dst_repo.id == "ubi-foo-debug"
    assert len(debug_rpms.src_repos) == 1
    assert debug_rpms.src_repos[0].id == "foo-debug"

    # secondly, check correct unassociations, there should 1 unit of each type unassociated
    modules, rpms, srpms, debug_rpms = unassociations
    assert len(modules.units) == 1
    assert modules.units[0].name == "md_current"
    assert modules.dst_repo.id == "ubi-foo-rpms"

    assert len(rpms.units) == 1
    assert rpms.units[0].name == "rpm_current"
    assert rpms.dst_repo.id == "ubi-foo-rpms"

    assert len(srpms.units) == 1
    assert srpms.units[0].name == "srpm_current"
    assert srpms.dst_repo.id == "ubi-foo-source"

    assert len(debug_rpms.units) == 1
    assert debug_rpms.units[0].name == "debug_rpm_current"
    assert debug_rpms.dst_repo.id == "ubi-foo-debug"

    assert len(mdd_association.units) == 1
    assert mdd_association.dst_repo.id == "ubi-foo-rpms"
    assert len(mdd_association.src_repos) == 1
    assert mdd_association.src_repos[0].id == "foo-rpms"

    assert len(mdd_unassociation.units) == 1
    assert mdd_unassociation.units[0].name == "mdd_current"
    assert mdd_unassociation.dst_repo.id == "ubi-foo-rpms"


def test_get_pulp_actions_no_actions(mock_ubipop_runner, mock_current_content_ft):
    mock_ubipop_runner.repos.modules = f_proxy(
        f_return(set([get_test_mod(name="md_current", pulplib=True)]))
    )

    mock_ubipop_runner.repos.module_defaults = [
        UbiUnit(
            ModulemdDefaultsUnit(
                name="mdd_current",
                stream="rhel",
                profiles={"2.5": "common"},
                repo_id="foo-rpms",
                content_type_id="modulemd_defaults",
            ),
            "foo-rpms",
        )
    ]

    binary_rpms = [
        UbiUnit(
            RpmUnit(
                name="rpm_current",
                version="1",
                release="2",
                arch="x86_64",
                filename="rpm_current.rpm",
            ),
            "foo-rpms",
        )
    ]
    debug_rpms = [
        UbiUnit(
            RpmUnit(
                name="debug_rpm_current",
                version="1",
                release="2",
                arch="x86_64",
                filename="debug_rpm_current.rpm",
            ),
            "foo-debug",
        )
    ]
    source_rpms = [
        UbiUnit(
            RpmUnit(
                name="srpm_current",
                version="1",
                release="2",
                arch="x86_64",
                filename="srpm_current.src.rpm",
            ),
            "foo-source",
        )
    ]

    mock_ubipop_runner.repos.packages = f_proxy(f_return(binary_rpms))
    mock_ubipop_runner.repos.debug_rpms = f_proxy(f_return(debug_rpms))
    mock_ubipop_runner.repos.source_rpms = f_proxy(f_return(source_rpms))

    # pylint: disable=protected-access
    (
        associations,
        unassociations,
        mdd_association,
        mdd_unassociation,
    ) = mock_ubipop_runner._get_pulp_actions(
        *mock_current_content_ft, modular_binary=[], modular_debug=[], modular_source=[]
    )

    # firstly, check correct associations, there should 0 units associated
    modules, rpms, srpms, debug_rpms = associations
    assert len(modules.units) == 0
    assert len(mdd_association.units) == 0
    assert len(rpms.units) == 0
    assert len(srpms.units) == 0
    assert len(debug_rpms.units) == 0

    # secondly, check correct unassociations, there should 0 units unassociated
    modules, rpms, srpms, debug_rpms = unassociations
    assert len(modules.units) == 0
    assert len(mdd_unassociation.units) == 0
    assert len(rpms.units) == 0
    assert len(srpms.units) == 0
    assert len(debug_rpms.units) == 0


@pytest.fixture(name="set_logging")
def fixture_set_logging():
    logger = logging.getLogger("ubipop")
    logger.setLevel(logging.DEBUG)
    yield logger
    logger.handlers = []


def test_log_pulp_action(capsys, set_logging, mock_ubipop_runner):
    set_logging.addHandler(logging.StreamHandler(sys.stdout))
    src_repo = get_test_repo(id="test_src")
    dst_repo = get_test_repo(id="test_dst")
    associations = [
        AssociateActionModules(
            [get_test_mod(name="test_assoc", src_repo_id=src_repo.id, pulplib=True)],
            dst_repo,
            [src_repo],
        )
    ]
    unassociations = [
        UnassociateActionModules(
            [get_test_mod(name="test_unassoc", pulplib=True)], dst_repo
        )
    ]

    mock_ubipop_runner.log_pulp_actions(associations, unassociations)
    out, err = capsys.readouterr()
    assoc_line, unassoc_line = out.split("\n", 1)

    assert err == ""
    assert (
        assoc_line.strip()
        == "Would associate ModulemdUnit(name='test_assoc', stream='', version=0, context='', arch='', content_type_id='modulemd', repository_memberships=None, artifacts=[], profiles={}) from test_src to test_dst"
    )
    assert (
        unassoc_line.strip()
        == "Would unassociate ModulemdUnit(name='test_unassoc', stream='', version=0, context='', arch='', content_type_id='modulemd', repository_memberships=None, artifacts=[], profiles={}) from test_dst"
    )


def test_log_pulp_action_no_actions(capsys, set_logging, mock_ubipop_runner):
    set_logging.addHandler(logging.StreamHandler(sys.stdout))
    src_repo = get_test_repo(id="test_src")
    dst_repo = get_test_repo(id="test_dst")
    associations = [AssociateActionModules([], dst_repo, [src_repo])]
    unassociations = [UnassociateActionModules([], dst_repo)]

    mock_ubipop_runner.log_pulp_actions(associations, unassociations)
    out, err = capsys.readouterr()
    assoc_line, unassoc_line = out.split("\n", 1)

    assert err == ""
    assert (
        assoc_line.strip()
        == "No association expected for modules from ['test_src'] to test_dst"
    )
    assert unassoc_line.strip() == "No unassociation expected for modules from test_dst"


def test_get_pulp_no_duplicates(mock_ubipop_runner, mock_current_content_ft):

    mock_ubipop_runner.repos.modules = f_proxy(
        f_return(set([get_test_mod(name="md_current", pulplib=True)]))
    )

    mock_ubipop_runner.repos.module_defaults = [
        UbiUnit(
            ModulemdDefaultsUnit(
                name="mdd_current",
                stream="rhel",
                profiles={"2.5": "common"},
                repo_id="foo-rpms",
                content_type_id="modulemd_defaults",
            ),
            "foo-rpms",
        )
    ]

    binary_rpms = [
        UbiUnit(
            RpmUnit(
                name="rpm_current",
                version="1",
                release="2",
                arch="x86_64",
                filename="rpm_current.rpm",
            ),
            "foo-rpms",
        )
    ]
    debug_rpms = [
        UbiUnit(
            RpmUnit(
                name="debug_rpm_current",
                version="1",
                release="2",
                arch="x86_64",
                filename="debug_rpm_current.rpm",
            ),
            "foo-debug",
        )
    ]
    source_rpms = [
        UbiUnit(
            RpmUnit(
                name="test_srpm",
                version="1.0",
                release="1",
                arch="src",
                filename="test_srpm-1.0-1.src.rpm",
            ),
            "foo-source",
        ),
        UbiUnit(
            RpmUnit(
                name="test_srpm",
                version="1.0",
                release="2",
                arch="src",
                filename="test_srpm-1.0-2.src.rpm",
            ),
            "foo-source",
        ),
        UbiUnit(
            RpmUnit(
                name="test_srpm",
                version="1.0",
                release="2",
                arch="src",
                filename="test_srpm-1.1-1.src.rpm",
            ),
            "foo-source",
        ),
        UbiUnit(
            RpmUnit(
                name="test_pkg",
                version="1",
                release="2",
                arch="src",
                filename="srpm_new.src.rpm",
            ),
            "foo-source",
        ),
        UbiUnit(
            RpmUnit(
                name="foo_pkg",
                version="1",
                release="2",
                arch="src",
                filename="srpm_new.src.rpm",
            ),
            "foo-source",
        ),
        UbiUnit(
            RpmUnit(
                name="bar_pkg",
                version="1",
                release="2",
                arch="src",
                filename="srpm_new_next.src.rpm",
            ),
            "foo-source",
        ),
    ]

    mock_ubipop_runner.repos.packages = f_proxy(f_return(binary_rpms))
    mock_ubipop_runner.repos.debug_rpms = f_proxy(f_return(debug_rpms))
    mock_ubipop_runner.repos.source_rpms = f_proxy(f_return(source_rpms))

    # pylint: disable=protected-access
    associations, _, _, _ = mock_ubipop_runner._get_pulp_actions(
        *mock_current_content_ft, modular_binary=[], modular_debug=[], modular_source=[]
    )

    _, _, srpms, _ = associations
    # only 5 srpm associations, no duplicates
    assert len(srpms.units) == 5


def test_associate_units(mock_ubipop_runner):
    src_repo = get_test_repo(id="test_src")
    dst_repo = get_test_repo(id="test_dst")

    associations = [
        AssociateActionModules([get_test_mod(name="test_assoc")], dst_repo, [src_repo]),
    ]

    mock_ubipop_runner.pulp.associate_modules.return_value = ["task_id"]
    ret = mock_ubipop_runner._associate_unassociate_units(
        associations
    )  # pylint: disable=protected-access

    assert len(ret) == 1
    assert ret[0].result() == ["task_id"]


def test_associate_unassociate_md_defaults(mock_ubipop_runner):
    src_repo = get_test_repo(id="test_src")
    dst_repo = get_test_repo(id="tets_dst")

    associations = AssociateActionModuleDefaults(
        [
            get_test_mod_defaults(
                name="virt",
                stream="rhel",
                profiles={"2.5": ["common"]},
            ),
        ],
        dst_repo,
        [src_repo],
    )

    unassociations = UnassociateActionModuleDefaults(
        [
            get_test_mod_defaults(
                name="virt",
                stream="rhel",
                profiles={"2.5": ["unique"]},
            ),
        ],
        dst_repo,
    )

    mock_ubipop_runner.pulp.unassociate_module_defaults.return_value = ["task_id_0"]
    mock_ubipop_runner.pulp.associate_module_defaults.return_value = ["task_id_1"]

    # pylint: disable=protected-access
    mock_ubipop_runner._associate_unassociate_md_defaults(
        (associations,),
        (unassociations,),
    )

    # the calls has to be in order
    calls = [call(["task_id_0"]), call(["task_id_1"])]
    mock_ubipop_runner.pulp.wait_for_tasks.assert_has_calls(calls)
