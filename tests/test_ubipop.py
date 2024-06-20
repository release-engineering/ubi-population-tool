import logging
import os
import shutil
import sys
import tempfile
from concurrent.futures import wait
from datetime import datetime
from tempfile import NamedTemporaryFile

import pytest
import ubiconfig
from mock import MagicMock, patch
from more_executors import Executors
from more_executors.futures import f_proxy, f_return
from pubtools.pulplib import (
    Client,
    Distributor,
    FakeController,
    ModulemdDefaultsUnit,
    ModulemdUnit,
    RpmUnit,
    YumRepository,
)

from ubipop import (
    RepoContent,
    RepoMissing,
    RepoSet,
    UbiPopulate,
    UbiPopulateRunner,
    UbiRepoSet,
)
from ubipop._cdn import Publisher
from ubipop._utils import Association, Unassociation

from .conftest import (
    get_modulemd_defaults_unit,
    get_modulemd_unit,
    get_rpm_unit,
    get_srpm_unit,
)

# pylint: disable=protected-access


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
def fixture_mock_ubipop_runner(ubi_repo_set, executor):
    publisher_args = {"publish_options": {"clean": True}}

    yield UbiPopulateRunner(
        pulp_client=MagicMock(),
        repo_set=ubi_repo_set,
        dry_run=False,
        executor=executor,
        ubi_manifest_client=MagicMock(),
        publisher=Publisher(
            **publisher_args,
        ),
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
    mock_ubipop_runner.repo_set.out_repos = RepoSet(
        f_proxy(f_return(repo)), f_proxy(f_return()), f_proxy(f_return())
    )

    mock_ubipop_runner._publish_out_repos()

    # we should publish only one repository with one distributor
    assert len(mock_ubipop_runner._publisher._publish_queue) == 1
    wait(mock_ubipop_runner._publisher._publish_queue)
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

    assert (
        fake_ubipopulate._get_population_sources(repo) == []
    )  # pylint: disable=protected-access


def test_get_population_sources_none():
    fake_ubipopulate = FakeUbiPopulate(
        "foo.pulp.com", ("foo", "foo"), False, ubiconfig_dir_or_url=TEST_DATA_DIR
    )

    assert (
        fake_ubipopulate._get_population_sources(None) == []
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


@patch("pubtools.pulplib.YumRepository.get_debug_repository")
@patch("pubtools.pulplib.YumRepository.get_source_repository")
def test_get_ubi_repo_sets_repo_missing(
    get_debug_repository, get_source_repository, caplog
):
    content_set = "rhel-8-for-x86_64-appstream-rpms"
    repo = YumRepository(
        id="ubi_binary",
        content_set="rhel-8-for-x86_64-appstream-rpms",
        population_sources=["input_binary"],
        ubi_population=True,
    )

    input_binary_repo = YumRepository(id="input_binary")

    mock_in_repo = MagicMock()
    mock_in_repo.result.return_value = None
    get_source_repository.return_value = mock_in_repo
    get_debug_repository.return_value = mock_in_repo

    fake_ubipopulate = FakeUbiPopulate(
        "foo.pulp.com", ("foo", "foo"), False, ubiconfig_dir_or_url=TEST_DATA_DIR
    )

    fake_pulp = fake_ubipopulate.pulp_client_controller
    fake_pulp.insert_repository(repo)
    fake_pulp.insert_repository(input_binary_repo)

    with pytest.raises(RepoMissing):
        fake_ubipopulate._get_ubi_repo_sets(content_set)
    assert "Input Source repo does not exist" in caplog.text
    assert "Input Debug repo does not exist" in caplog.text


def test_diff_modules(mock_ubipop_runner):
    curr = [
        get_modulemd_unit(
            name="1",
            stream="foo",
            version=1,
            context="bar",
            arch="x86_64",
            src_repo_id="fake-repo",
        ),
        get_modulemd_unit(
            name="2",
            stream="foo",
            version=1,
            context="bar",
            arch="x86_64",
            src_repo_id="fake-repo",
        ),
        get_modulemd_unit(
            name="3",
            stream="foo",
            version=1,
            context="bar",
            arch="x86_64",
            src_repo_id="fake-repo",
        ),
    ]
    expected = [
        get_modulemd_unit(
            name="2",
            stream="foo",
            version=1,
            context="bar",
            arch="x86_64",
            src_repo_id="fake-repo",
        ),
        get_modulemd_unit(
            name="3",
            stream="foo",
            version=1,
            context="bar",
            arch="x86_64",
            src_repo_id="fake-repo",
        ),
        get_modulemd_unit(
            name="4",
            stream="foo",
            version=1,
            context="bar",
            arch="x86_64",
            src_repo_id="fake-repo",
        ),
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
            RepoSet(None, None, None),
            RepoSet(None, None, None),
            True,
        ),
        (
            RepoSet("foo-rpms", "foo-source", "foo-debug"),
            RepoSet("ubi-foo-rpms", "ubi-foo-source", "ubi-foo-debug"),
            False,
        ),
    ],
)
def test_ubi_repo_set(rhel_repo_set, ubi_repo_set, fail, caplog):
    if fail:
        with pytest.raises(RepoMissing):
            UbiRepoSet(rhel_repo_set, ubi_repo_set)

        assert "ERROR" in caplog.text
        assert "Rpm repo does not exist" in caplog.text
        assert "Source repo does not exist" in caplog.text
        assert "Debug repo does not exist" in caplog.text
    else:
        UbiRepoSet(rhel_repo_set, ubi_repo_set)
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


def test_load_ubiconfig_by_version():
    """Ensure correct config is returned when given a major version of ubi"""
    repo = YumRepository(id="rhel-7-server", content_set="rhel-7-server-rpms")

    fake_ubipopulate = FakeUbiPopulate(
        "foo.pulp.com",
        ("foo", "foo"),
        False,
        ubiconfig_dir_or_url=TEST_DATA_DIR,
        version="7",
    )

    fake_pulp = fake_ubipopulate.pulp_client_controller
    fake_pulp.insert_repository(repo)

    assert len(fake_ubipopulate.ubiconfig_list) == 1
    assert (
        fake_ubipopulate.ubiconfig_list[0].content_sets.rpm.output
        == "ubi-7-server-rpms"
    )


def test_load_ubiconfig_by_version_no_match():
    """Ensure no config is returned when given a major version of ubi that doesn't exist in data"""
    repo = YumRepository(id="rhel-7-server", content_set="rhel-7-server-rpms")

    fake_ubipopulate = FakeUbiPopulate(
        "foo.pulp.com",
        ("foo", "foo"),
        False,
        ubiconfig_dir_or_url=TEST_DATA_DIR,
        version="10",
    )

    fake_pulp = fake_ubipopulate.pulp_client_controller
    fake_pulp.insert_repository(repo)

    # no config should match
    assert len(fake_ubipopulate.ubiconfig_list) == 0


def test_load_ubiconfig_by_content_set_regex():
    """Ensure correct config is returned when given a content set regex"""
    repo = YumRepository(
        id="ubi-8-for-x86_64-appstream-rpms__8",
        content_set="ubi-8-for-x86_64-appstream-rpms",
    )

    fake_ubipopulate = FakeUbiPopulate(
        "foo.pulp.com",
        ("foo", "foo"),
        False,
        ubiconfig_dir_or_url=TEST_DATA_DIR,
        content_set_regex="ubi-8.*",
    )

    fake_pulp = fake_ubipopulate.pulp_client_controller
    fake_pulp.insert_repository(repo)

    # two config files are matched according to testdata
    assert len(fake_ubipopulate.ubiconfig_list) == 2

    fake_ubipopulate.ubiconfig_list.sort(key=lambda x: x.file_name)
    conf_1 = fake_ubipopulate.ubiconfig_list[0]
    conf_2 = fake_ubipopulate.ubiconfig_list[1]

    assert conf_1.file_name == "ubiconf_golang.yaml"
    assert conf_1.content_sets.rpm.output == "ubi-8-for-x86_64-appstream-rpms"

    assert conf_2.file_name == "ubiconf_golang2.yaml"
    assert conf_2.content_sets.rpm.output == "ubi-8-for-x86_64-appstream-rpms"


def test_load_ubiconfig_by_content_set_regex_and_version():
    """Ensure correct config is returned when given a content set regex and version"""
    repo = YumRepository(
        id="ubi-8-for-x86_64-appstream-rpms__8",
        content_set="ubi-8-for-x86_64-appstream-rpms",
    )

    fake_ubipopulate = FakeUbiPopulate(
        "foo.pulp.com",
        ("foo", "foo"),
        False,
        ubiconfig_dir_or_url=TEST_DATA_DIR,
        version="8",
        content_set_regex="x86_64",
    )

    fake_pulp = fake_ubipopulate.pulp_client_controller
    fake_pulp.insert_repository(repo)

    # two config files are matched according to testdata
    assert len(fake_ubipopulate.ubiconfig_list) == 2

    fake_ubipopulate.ubiconfig_list.sort(key=lambda x: x.file_name)
    conf_1 = fake_ubipopulate.ubiconfig_list[0]
    conf_2 = fake_ubipopulate.ubiconfig_list[1]

    assert conf_1.file_name == "ubiconf_golang.yaml"
    assert conf_1.content_sets.rpm.output == "ubi-8-for-x86_64-appstream-rpms"

    assert conf_2.file_name == "ubiconf_golang2.yaml"
    assert conf_2.content_sets.rpm.output == "ubi-8-for-x86_64-appstream-rpms"


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
    mock_get_repo_pairs, mocked_ubiconfig_load_all, mock_run_ubi_population
):
    # pylint: disable=unused-argument
    path = tempfile.mkdtemp("ubipop")
    try:
        out_file_path = os.path.join(path, "output.txt")
        with patch("ubipop.UbimClient"):
            with patch("ubipop.Publisher"):
                ubipop = UbiPopulate(
                    "foo.pulp.com",
                    ("foo", "foo"),
                    False,
                    output_repos_file=out_file_path,
                    ubi_manifest_url="https://ubi-manifest.com",
                )
                ubipop.populate_ubi_repos()

        with open(out_file_path) as f:
            content = f.readlines()

        assert sorted(content) == sorted(
            ["ubi-foo-rpms\n", "ubi-foo-source\n", "ubi-foo-debug\n"]
        )
    finally:
        shutil.rmtree(path)


@pytest.fixture(name="mock_current_content")
def fixture_mock_current_content():
    rpm = get_rpm_unit(
        name="rpm_current",
        filename="rpm_current.rpm",
        version="1",
        release="0",
        arch="x86_64",
        src_repo_id="ubi-foo-rpms",
    )

    srpm = get_srpm_unit(
        name="srpm_current",
        filename="srpm_current.src.rpm",
        version="1",
        release="0",
        arch="x86_64",
        src_repo_id="ubi-foo-source",
    )

    debug_rpm = get_rpm_unit(
        name="debug_rpm_current",
        filename="debug_rpm_current.rpm",
        version="1",
        release="0",
        arch="x86_64",
        src_repo_id="ubi-foo-debug",
    )

    modulemd_unit = get_modulemd_unit(
        name="md_current",
        stream="foo",
        version=1,
        context="bar",
        arch="x86_64",
        src_repo_id="ubi-foo-rpms",
    )
    modulemd_defaults_unit = get_modulemd_defaults_unit(
        name="mdd_current",
        stream="rhel",
        profiles={"2.5": ["common"]},
        repo_id="ubi-foo-rpms",
        src_repo_id="ubi-foo-rpms",
    )

    binary_rpms = f_proxy(f_return([rpm]))
    debug_rpms = f_proxy(f_return([srpm]))
    source_rpms = f_proxy(f_return([debug_rpm]))
    modulemds = f_proxy(f_return([modulemd_unit]))
    modulemd_defaults = f_proxy(f_return([modulemd_defaults_unit]))

    repo_content = RepoContent(
        binary_rpms, debug_rpms, source_rpms, modulemds, modulemd_defaults
    )

    yield repo_content


def test_get_pulp_actions(mock_ubipop_runner, mock_current_content):
    binary_rpm = get_rpm_unit(
        name="test_rpm",
        version="1",
        release="2",
        arch="x86_64",
        filename="test_rpm.rpm",
        src_repo_id="foo-rpms",
    )

    debug_rpm = get_rpm_unit(
        name="test_debug_pkg",
        version="1",
        release="2",
        arch="x86_64",
        filename="test_rpm.rpm",
        src_repo_id="foo-debug",
    )

    source_rpm = get_srpm_unit(
        name="test_srpm",
        version="1",
        release="2",
        filename="test_srpm.src.rpm",
        src_repo_id="foo-source",
    )
    modulemd = get_modulemd_unit(
        name="test_md",
        stream="foo",
        version=1,
        context="bar",
        arch="x86_64",
        src_repo_id="foo-rpms",
    )
    modulemd_defaults = get_modulemd_defaults_unit(
        name="test_mdd",
        stream="rhel",
        profiles={"2.5": ["uncommon"]},
        repo_id="foo-rpms",
        src_repo_id="foo-rpms",
    )

    mock_ubipop_runner.repo_set.packages = f_proxy(f_return([binary_rpm]))
    mock_ubipop_runner.repo_set.debug_rpms = f_proxy(f_return([debug_rpm]))
    mock_ubipop_runner.repo_set.source_rpms = f_proxy(f_return([source_rpm]))
    mock_ubipop_runner.repo_set.modules = f_proxy(f_return([modulemd]))
    mock_ubipop_runner.repo_set.module_defaults = f_proxy(f_return([modulemd_defaults]))

    # pylint: disable=protected-access
    (
        associations,
        unassociations,
        mdd_association,
        mdd_unassociation,
    ) = mock_ubipop_runner._get_pulp_actions(mock_current_content)

    # firstly, check correct associations, there should 1 unit of each type associated
    modules, rpms, srpms, debug_rpms = associations
    assert len(modules.units) == 1
    assert modules.units[0].name == "test_md"
    assert modules.dst_repo.id == "ubi-foo-rpms"
    assert len(modules.src_repos) == 1
    assert modules.src_repos[0].id == "foo-rpms"

    # there should be 1 rpm one modular, one non-modular
    assert len(rpms.units) == 1
    assert rpms.units[0].name == "test_rpm"
    assert rpms.dst_repo.id == "ubi-foo-rpms"
    assert len(rpms.src_repos) == 1
    assert rpms.src_repos[0].id == "foo-rpms"

    assert len(srpms.units) == 1
    assert srpms.units[0].name == "test_srpm"
    assert srpms.dst_repo.id == "ubi-foo-source"
    assert len(srpms.src_repos) == 1
    assert srpms.src_repos[0].id == "foo-source"

    assert len(debug_rpms.units) == 1
    assert debug_rpms.units[0].name == "test_debug_pkg"
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


def test_get_pulp_actions_no_actions(mock_ubipop_runner, mock_current_content):
    binary_rpm = get_rpm_unit(
        name="rpm_current",
        version="1",
        release="2",
        arch="x86_64",
        filename="rpm_current.rpm",
        src_repo_id="foo-rpms",
    )

    debug_rpm = get_rpm_unit(
        name="debug_rpm_current",
        version="1",
        release="2",
        arch="x86_64",
        filename="debug_rpm_current.rpm",
        src_repo_id="foo-debug",
    )

    source_rpm = get_srpm_unit(
        name="srpm_current",
        version="1",
        release="2",
        filename="srpm_current.src.rpm",
        src_repo_id="foo-source",
    )

    modulemd = get_modulemd_unit(
        name="md_current",
        stream="foo",
        version=1,
        context="bar",
        arch="x86_64",
        src_repo_id="ubi-foo-rpms",
    )

    modulemd_defaults = get_modulemd_defaults_unit(
        name="mdd_current",
        stream="rhel",
        profiles={"2.5": ["common"]},
        repo_id="foo-rpms",
        src_repo_id="foo-rpms",
    )

    mock_ubipop_runner.repo_set.packages = f_proxy(f_return([binary_rpm]))
    mock_ubipop_runner.repo_set.debug_rpms = f_proxy(f_return([debug_rpm]))
    mock_ubipop_runner.repo_set.source_rpms = f_proxy(f_return([source_rpm]))
    mock_ubipop_runner.repo_set.modules = f_proxy(f_return([modulemd]))
    mock_ubipop_runner.repo_set.module_defaults = f_proxy(f_return([modulemd_defaults]))

    # pylint: disable=protected-access
    (
        associations,
        unassociations,
        mdd_association,
        mdd_unassociation,
    ) = mock_ubipop_runner._get_pulp_actions(mock_current_content)

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

    unit_1 = get_modulemd_unit(
        name="test_assoc",
        stream="fake-stream",
        version=1,
        context="fake-context",
        arch="x86_64",
        src_repo_id=src_repo.id,
    )
    unit_2 = get_modulemd_unit(
        name="test_unassoc",
        stream="fake-stream",
        version=1,
        context="fake-context",
        arch="x86_64",
        src_repo_id=src_repo.id,
    )
    associations = [Association([unit_1], ModulemdUnit, dst_repo, [src_repo])]
    unassociations = [Unassociation([unit_2], ModulemdUnit, dst_repo)]

    mock_ubipop_runner.log_pulp_actions(associations, unassociations)
    out, err = capsys.readouterr()
    assoc_line, unassoc_line = out.split("\n", 1)

    assert err == ""
    assert (
        assoc_line.strip()
        == "Would associate ModulemdUnit(name='test_assoc', stream='fake-stream', version=1, context='fake-context', arch='x86_64') from test_src to test_dst"
    )
    assert (
        unassoc_line.strip()
        == "Would unassociate ModulemdUnit(name='test_unassoc', stream='fake-stream', version=1, context='fake-context', arch='x86_64') from test_dst"
    )


def test_log_pulp_action_no_actions(capsys, set_logging, mock_ubipop_runner):
    set_logging.addHandler(logging.StreamHandler(sys.stdout))
    src_repo = get_test_repo(id="test_src")
    dst_repo = get_test_repo(id="test_dst")
    associations = [Association([], ModulemdUnit, dst_repo, [src_repo])]
    unassociations = [Unassociation([], ModulemdUnit, dst_repo)]

    mock_ubipop_runner.log_pulp_actions(associations, unassociations)
    out, err = capsys.readouterr()
    assoc_line, unassoc_line = out.split("\n", 1)

    assert err == ""
    assert (
        assoc_line.strip()
        == "No association expected for ModulemdUnit from ['test_src'] to test_dst"
    )
    assert (
        unassoc_line.strip()
        == "No unassociation expected for ModulemdUnit from test_dst"
    )


@pytest.mark.parametrize(
    "skip_debug_repo",
    [True, False],
    ids=["skip_debug_repo_true", "skip_debug_repo_false"],
)
def test_get_current_content(mock_ubipop_runner, pulp, skip_debug_repo):
    """Tests getting current content from ubi repos, using Fake Client from pubtools-pulplib"""
    rpm_repo = YumRepository(
        id="rpm_repo",
    )
    rpm_repo.__dict__["_client"] = pulp.client

    debug_repo = YumRepository(
        id="debug_repo",
    )
    debug_repo.__dict__["_client"] = pulp.client

    source_repo = YumRepository(
        id="source_repo",
    )
    source_repo.__dict__["_client"] = pulp.client

    binary_rpm = RpmUnit(name="test", version="1.0", release="1", arch="x86_64")
    modulemd = ModulemdUnit(
        name="test_module_md",
        stream="fake-stream",
        version=1,
        context="fake-context",
        arch="x86_64",
    )

    modulemd_defaults = ModulemdDefaultsUnit(
        name="test_modulemd_defaults", stream="rhel", repo_id="rpm_repo"
    )

    debug_rpm = RpmUnit(
        name="test-debuginfo", version="1.0", release="1", arch="x86_64"
    )
    source_rpm = RpmUnit(
        name="test-srpm", version="1.0", release="1", arch="src", content_type_id="srpm"
    )

    pulp.insert_repository(rpm_repo)
    pulp.insert_units(rpm_repo, [binary_rpm, modulemd, modulemd_defaults])

    if not skip_debug_repo:
        pulp.insert_repository(debug_repo)
        pulp.insert_units(debug_repo, [debug_rpm])

    pulp.insert_repository(source_repo)
    pulp.insert_units(source_repo, [source_rpm])

    if skip_debug_repo:
        debug_repo = f_return(None)
    else:
        debug_repo = f_proxy(f_return(debug_repo))

    # overwrite out_repos with the testing ones
    mock_ubipop_runner.repo_set.out_repos = RepoSet(
        f_proxy(f_return(rpm_repo)), f_proxy(f_return(source_repo)), debug_repo
    )

    content = mock_ubipop_runner._get_current_content()

    binary_rpms = list(content.binary_rpms)
    assert len(binary_rpms) == 1
    assert binary_rpms[0].name == "test"

    modules = list(content.modules)
    assert len(modules) == 1
    assert modules[0].name == "test_module_md"

    modulemd_defaults = list(content.modulemd_defaults)
    assert len(modulemd_defaults) == 1
    assert modulemd_defaults[0].name == "test_modulemd_defaults"

    debug_rpms = list(content.debug_rpms)
    if skip_debug_repo:
        assert len(debug_rpms) == 0
    else:
        assert len(debug_rpms) == 1
        assert debug_rpms[0].name == "test-debuginfo"

    source_rpms = list(content.source_rpms)
    assert len(source_rpms) == 1
    assert source_rpms[0].name == "test-srpm"


@patch("pubtools.pulplib.YumRepository.get_debug_repository")
@patch("pubtools.pulplib.YumRepository.get_source_repository")
def test_populate_ubi_repos(get_debug_repository, get_source_repository, requests_mock):
    # pylint: disable=unused-argument
    """Test run of populate_ubi_repos that checks correct number of repo publication.
    It's simplified to contain only actions on RPM packages."""
    dt = datetime(2019, 9, 12, 0, 0, 0)

    d1 = Distributor(
        id="yum_distributor",
        type_id="yum_distributor",
        repo_id="ubi_binary",
        last_publish=dt,
        relative_url="content/unit/2/client",
    )

    d2 = Distributor(
        id="yum_distributor",
        type_id="yum_distributor",
        repo_id="ubi_source",
        last_publish=dt,
        relative_url="content/unit/3/client",
    )

    d3 = Distributor(
        id="yum_distributor",
        type_id="yum_distributor",
        repo_id="ubi_debug",
        last_publish=dt,
        relative_url="content/unit/4/client",
    )

    input_binary_repo = YumRepository(id="input_binary")
    input_source_repo = YumRepository(id="input_source")
    input_debug_repo = YumRepository(id="input_debug")

    output_binary_repo = YumRepository(
        id="ubi_binary",
        content_set="ubi-8-for-x86_64-appstream-rpms",
        population_sources=["input_binary"],
        ubi_population=True,
        ubi_config_version="8",
        eng_product_id=102,
        distributors=[d1],
        relative_url="content/unit/1/client",
    )
    output_source_repo = YumRepository(
        id="ubi_source",
        population_sources=["input_source"],
        eng_product_id=102,
        distributors=[d2],
        relative_url="content/unit/2/client",
    )
    output_debug_repo = YumRepository(
        id="ubi_debug",
        population_sources=["input_debug"],
        eng_product_id=102,
        distributors=[d3],
        relative_url="content/unit/3/client",
    )

    ubi_populate = FakeUbiPopulate(
        "foo.pulp.com",
        ("foo", "foo"),
        False,
        ubiconfig_dir_or_url=TEST_DATA_DIR,
        ubi_manifest_url="https://ubi-manifest.com",
    )

    fake_pulp = ubi_populate.pulp_client_controller
    fake_pulp.insert_repository(input_binary_repo)
    fake_pulp.insert_repository(input_source_repo)
    fake_pulp.insert_repository(input_debug_repo)

    fake_pulp.insert_repository(output_binary_repo)
    fake_pulp.insert_repository(output_source_repo)
    fake_pulp.insert_repository(output_debug_repo)

    get_debug_repository.return_value = fake_pulp.client.get_repository("ubi_debug")
    get_source_repository.return_value = fake_pulp.client.get_repository("ubi_source")

    old_rpm = RpmUnit(
        name="golang",
        version="1",
        release="a",
        arch="x86_64",
        filename="golang-1.a.x86_64.rpm",
        sourcerpm="golang-1.a.x86_64.src.rpm",
        signing_key="a1b2c3",
    )

    new_rpm = RpmUnit(
        name="golang",
        version="2",
        release="a",
        arch="x86_64",
        filename="golang-2.a.x86_64.rpm",
        sourcerpm="golang-2.a.x86_64.src.rpm",
        signing_key="a1b2c3",
    )

    old_modulemd = ModulemdUnit(
        name="test_md", stream="s", version="100", context="c", arch="x86_64"
    )
    new_modulemd = ModulemdUnit(
        name="test_md", stream="s", version="200", context="c", arch="x86_64"
    )

    old_modulemd_defaults = ModulemdDefaultsUnit(
        name="test_md_defaults",
        stream="stream",
        profiles={"minimal": ["name_1"]},
        repo_id="ubi_binary",
    )
    new_modulemd_defaults = ModulemdDefaultsUnit(
        name="test_md_defaults",
        stream="stream",
        profiles={"minimal": ["name_1", "name_2"]},
        repo_id="input_binary",
    )

    fake_pulp.insert_units(
        output_binary_repo, [old_rpm, old_modulemd, old_modulemd_defaults]
    )
    fake_pulp.insert_units(
        input_binary_repo, [new_rpm, new_modulemd, new_modulemd_defaults]
    )

    # mock calls to ubi-manifest service
    _create_ubi_manifest_mocks(requests_mock)

    # let's run actual population
    ubi_populate.populate_ubi_repos()
    history = fake_pulp.publish_history

    # there should be 3 repositories successfully published
    assert len(history) == 3
    expected_published_repo_ids = set(["ubi_binary", "ubi_debug", "ubi_source"])
    repo_ids_published = set()
    for publish in history:
        repo = publish.repository
        repo_ids_published.add(repo.id)

        assert repo.id in expected_published_repo_ids

        if repo.id == "ubi_binary":
            assert new_rpm.filename == repo.rpm_content[0].filename
            assert new_modulemd.nsvca == repo.modulemd_content[0].nsvca
            assert (
                new_modulemd_defaults.profiles
                == repo.modulemd_defaults_content[0].profiles
            )

    assert repo_ids_published == expected_published_repo_ids


@patch("ubipop._cdn.Publisher")
@patch("pubtools.pulplib.YumRepository.get_debug_repository")
@patch("pubtools.pulplib.YumRepository.get_source_repository")
def test_populate_ubi_repos_no_publish(
    get_debug_repository, get_source_repository, publisher, requests_mock, monkeypatch
):
    """Test run of populate_ubi_repos which checks that correct associations and
    unassociations were made in Pulp but no publish was performed. It's simplified to contain
    only actions on RPM packages."""
    monkeypatch.setenv("UBIPOP_SKIP_PUBLISH", "true")

    dt = datetime(2019, 9, 12, 0, 0, 0)

    d1 = Distributor(
        id="yum_distributor",
        type_id="yum_distributor",
        repo_id="ubi_binary",
        last_publish=dt,
        relative_url="content/unit/2/client",
    )

    d2 = Distributor(
        id="yum_distributor",
        type_id="yum_distributor",
        repo_id="ubi_source",
        last_publish=dt,
        relative_url="content/unit/3/client",
    )

    d3 = Distributor(
        id="yum_distributor",
        type_id="yum_distributor",
        repo_id="ubi_debug",
        last_publish=dt,
        relative_url="content/unit/4/client",
    )

    output_binary_repo = YumRepository(
        id="ubi_binary",
        content_set="ubi-8-for-x86_64-appstream-rpms",
        population_sources=["input_binary"],
        ubi_population=True,
        ubi_config_version="8",
        eng_product_id=102,
        distributors=[d1],
        relative_url="content/unit/1/client",
    )
    input_binary_repo = YumRepository(id="input_binary")
    input_source_repo = YumRepository(id="input_source")
    input_debug_repo = YumRepository(id="input_debug")

    output_source_repo = YumRepository(
        id="ubi_source",
        population_sources=["input_source"],
        eng_product_id=102,
        distributors=[d2],
        relative_url="content/unit/2/client",
    )
    output_debug_repo = YumRepository(
        id="ubi_debug",
        population_sources=["input_debug"],
        eng_product_id=102,
        distributors=[d3],
        relative_url="content/unit/3/client",
    )

    ubi_populate = FakeUbiPopulate(
        "foo.pulp.com",
        ("foo", "foo"),
        False,
        ubiconfig_dir_or_url=TEST_DATA_DIR,
        ubi_manifest_url="https://ubi-manifest.com",
    )

    fake_pulp = ubi_populate.pulp_client_controller
    fake_pulp.insert_repository(input_binary_repo)
    fake_pulp.insert_repository(input_source_repo)
    fake_pulp.insert_repository(input_debug_repo)

    fake_pulp.insert_repository(output_binary_repo)
    fake_pulp.insert_repository(output_source_repo)
    fake_pulp.insert_repository(output_debug_repo)

    get_debug_repository.return_value = fake_pulp.client.get_repository("ubi_debug")
    get_source_repository.return_value = fake_pulp.client.get_repository("ubi_source")

    old_rpm = RpmUnit(
        name="golang",
        version="1",
        release="a",
        arch="x86_64",
        filename="golang-1.a.x86_64.rpm",
        sourcerpm="golang-1.a.x86_64.src.rpm",
    )

    new_rpm = RpmUnit(
        name="golang",
        version="2",
        release="a",
        arch="x86_64",
        filename="golang-2.a.x86_64.rpm",
        sourcerpm="golang-2.a.x86_64.src.rpm",
    )

    old_modulemd = ModulemdUnit(
        name="test_md", stream="s", version="100", context="c", arch="x86_64"
    )
    new_modulemd = ModulemdUnit(
        name="test_md", stream="s", version="200", context="c", arch="x86_64"
    )

    old_modulemd_defaults = ModulemdDefaultsUnit(
        name="test_md_defaults",
        stream="stream",
        profiles={"minimal": ["name_1"]},
        repo_id="ubi_binary",
    )
    new_modulemd_defaults = ModulemdDefaultsUnit(
        name="test_md_defaults",
        stream="stream",
        profiles={"minimal": ["name_1", "name_2"]},
        repo_id="input_binary",
    )

    fake_pulp.insert_units(
        output_binary_repo, [old_rpm, old_modulemd, old_modulemd_defaults]
    )
    fake_pulp.insert_units(
        input_binary_repo, [new_rpm, new_modulemd, new_modulemd_defaults]
    )

    # mock calls to ubi-manifest service
    _create_ubi_manifest_mocks(requests_mock)

    # let's run actual population
    ubi_populate.populate_ubi_repos()

    publisher.assert_not_called()


@patch("ubipop._cdn.Publisher")
@patch("pubtools.pulplib.YumRepository.get_source_repository")
@patch("pubtools.pulplib.YumRepository.get_debug_repository")
def test_populate_ubi_repos_dry_run(
    get_debug_repository,
    get_source_repository,
    publisher,
    requests_mock,
    monkeypatch,
    caplog,
):
    """Test run of populate_ubi_repos with dry_run enabled."""
    monkeypatch.setenv("UBIPOP_SKIP_PUBLISH", "true")

    dt = datetime(2019, 9, 12, 0, 0, 0)

    d1 = Distributor(
        id="yum_distributor",
        type_id="yum_distributor",
        repo_id="ubi_binary",
        last_publish=dt,
        relative_url="content/unit/2/client",
    )

    d2 = Distributor(
        id="yum_distributor",
        type_id="yum_distributor",
        repo_id="ubi_source",
        last_publish=dt,
        relative_url="content/unit/3/client",
    )

    d3 = Distributor(
        id="yum_distributor",
        type_id="yum_distributor",
        repo_id="ubi_debug",
        last_publish=dt,
        relative_url="content/unit/4/client",
    )

    output_binary_repo = YumRepository(
        id="ubi_binary",
        content_set="ubi-8-for-x86_64-appstream-rpms",
        population_sources=["input_binary"],
        ubi_population=True,
        ubi_config_version="8",
        eng_product_id=102,
        distributors=[d1],
        relative_url="content/unit/1/client",
    )
    input_binary_repo = YumRepository(id="input_binary")
    input_source_repo = YumRepository(id="input_source")
    input_debug_repo = YumRepository(id="input_debug")

    output_source_repo = YumRepository(
        id="ubi_source",
        population_sources=["input_source"],
        eng_product_id=102,
        distributors=[d2],
        relative_url="content/unit/2/client",
    )
    output_debug_repo = YumRepository(
        id="ubi_debug",
        population_sources=["input_debug"],
        eng_product_id=102,
        distributors=[d3],
        relative_url="content/unit/3/client",
    )

    ubi_populate = FakeUbiPopulate(
        "foo.pulp.com",
        ("foo", "foo"),
        dry_run=True,
        ubiconfig_dir_or_url=TEST_DATA_DIR,
        ubi_manifest_url="https://ubi-manifest.com",
        publisher=publisher,
    )

    fake_pulp = ubi_populate.pulp_client_controller
    fake_pulp.insert_repository(input_binary_repo)
    fake_pulp.insert_repository(input_source_repo)
    fake_pulp.insert_repository(input_debug_repo)

    fake_pulp.insert_repository(output_binary_repo)
    fake_pulp.insert_repository(output_source_repo)
    fake_pulp.insert_repository(output_debug_repo)

    get_debug_repository.return_value = fake_pulp.client.get_repository("ubi_debug")
    get_source_repository.return_value = fake_pulp.client.get_repository("ubi_source")

    old_rpm = RpmUnit(
        name="golang",
        version="1",
        release="a",
        arch="x86_64",
        filename="golang-1.a.x86_64.rpm",
        sourcerpm="golang-1.a.x86_64.src.rpm",
    )

    new_rpm = RpmUnit(
        name="golang",
        version="2",
        release="a",
        arch="x86_64",
        filename="golang-2.a.x86_64.rpm",
        sourcerpm="golang-2.a.x86_64.src.rpm",
    )

    old_modulemd = ModulemdUnit(
        name="test_md", stream="s", version="100", context="c", arch="x86_64"
    )
    new_modulemd = ModulemdUnit(
        name="test_md", stream="s", version="200", context="c", arch="x86_64"
    )

    old_modulemd_defaults = ModulemdDefaultsUnit(
        name="test_md_defaults",
        stream="stream",
        profiles={"minimal": ["name_1"]},
        repo_id="ubi_binary",
    )
    new_modulemd_defaults = ModulemdDefaultsUnit(
        name="test_md_defaults",
        stream="stream",
        profiles={"minimal": ["name_1", "name_2"]},
        repo_id="input_binary",
    )

    fake_pulp.insert_units(
        output_binary_repo, [old_rpm, old_modulemd, old_modulemd_defaults]
    )
    fake_pulp.insert_units(
        input_binary_repo, [new_rpm, new_modulemd, new_modulemd_defaults]
    )

    # mock calls to ubi-manifest service
    _create_ubi_manifest_mocks(requests_mock)

    # let's run actual population
    ubi_populate.populate_ubi_repos()

    # should not have published
    publisher.assert_not_called()

    # should have logged content and actions
    for msg in (
        "Current rpms in repo:",
        "Current srpms in repo:",
        "Current module_defaults in repo:",
        "Current modules in repo:",
        "Would associate",
        "Would unassociate",
    ):
        assert msg in caplog.text


@patch("pubtools.pulplib.YumRepository.get_source_repository")
def test_populate_ubi_repos_missing_repos(get_source_repository, requests_mock, caplog):
    # pylint: disable=unused-argument
    """Test run of populate_ubi_repos with a missing repo."""
    dt = datetime(2019, 9, 12, 0, 0, 0)

    d1 = Distributor(
        id="yum_distributor",
        type_id="yum_distributor",
        repo_id="ubi_binary",
        last_publish=dt,
        relative_url="content/unit/2/client",
    )

    d2 = Distributor(
        id="yum_distributor",
        type_id="yum_distributor",
        repo_id="ubi_source",
        last_publish=dt,
        relative_url="content/unit/3/client",
    )

    output_binary_repo = YumRepository(
        id="ubi_binary",
        content_set="ubi-8-for-x86_64-appstream-rpms",
        population_sources=["input_binary"],
        ubi_population=True,
        ubi_config_version="8",
        eng_product_id=102,
        distributors=[d1],
        relative_url="content/unit/1/client",
    )
    input_binary_repo = YumRepository(id="input_binary")
    input_source_repo = YumRepository(id="input_source")
    input_debug_repo = YumRepository(id="input_debug")

    output_source_repo = YumRepository(
        id="ubi_source",
        population_sources=["input_source"],
        eng_product_id=102,
        distributors=[d2],
        relative_url="content/unit/2/client",
    )

    # Omitting debug repo.

    ubi_populate = FakeUbiPopulate(
        "foo.pulp.com",
        ("foo", "foo"),
        False,
        ubiconfig_dir_or_url=TEST_DATA_DIR,
        ubi_manifest_url="https://ubi-manifest.com",
    )

    fake_pulp = ubi_populate.pulp_client_controller
    fake_pulp.insert_repository(input_binary_repo)
    fake_pulp.insert_repository(input_source_repo)
    fake_pulp.insert_repository(input_debug_repo)

    fake_pulp.insert_repository(output_binary_repo)
    fake_pulp.insert_repository(output_source_repo)
    # No debug repo.

    get_source_repository.return_value = fake_pulp.client.get_repository("ubi_source")

    old_rpm = RpmUnit(
        name="golang",
        version="1",
        release="a",
        arch="x86_64",
        filename="golang-1.a.x86_64.rpm",
        sourcerpm="golang-1.a.x86_64.src.rpm",
    )

    new_rpm = RpmUnit(
        name="golang",
        version="2",
        release="a",
        arch="x86_64",
        filename="golang-2.a.x86_64.rpm",
        sourcerpm="golang-2.a.x86_64.src.rpm",
    )

    old_modulemd = ModulemdUnit(
        name="test_md", stream="s", version="100", context="c", arch="x86_64"
    )
    new_modulemd = ModulemdUnit(
        name="test_md", stream="s", version="200", context="c", arch="x86_64"
    )

    old_modulemd_defaults = ModulemdDefaultsUnit(
        name="test_md_defaults",
        stream="stream",
        profiles={"minimal": ["name_1"]},
        repo_id="ubi_binary",
    )
    new_modulemd_defaults = ModulemdDefaultsUnit(
        name="test_md_defaults",
        stream="stream",
        profiles={"minimal": ["name_1", "name_2"]},
        repo_id="input_binary",
    )

    fake_pulp.insert_units(
        output_binary_repo, [old_rpm, old_modulemd, old_modulemd_defaults]
    )
    fake_pulp.insert_units(
        input_binary_repo, [new_rpm, new_modulemd, new_modulemd_defaults]
    )

    # mock calls to ubi-manifest service
    _create_ubi_manifest_mocks(requests_mock)

    # let's run actual population
    ubi_populate.populate_ubi_repos()
    history = fake_pulp.publish_history

    # should have published no repositories
    assert len(history) == 0
    # should have logged an error and a warning
    assert "Input Debug repo does not exist" in caplog.text
    assert "Skipping current content triplet, some repos are missing" in caplog.text


def _create_ubi_manifest_mocks(requests_mock):
    # mock requesting manifest generation
    url = "api/v1/manifest"
    url = os.path.join("https://ubi-manifest.com", url)
    response = [{"task_id": "some-task-id"}]
    requests_mock.register_uri("POST", url, json=response)

    # mock getting task result
    url = "api/v1/task/some-task-id"
    url = os.path.join("https://ubi-manifest.com", url)
    requests_mock.register_uri(
        "GET",
        url,
        [{"json": {"task_id": "some-task-id", "state": "SUCCESS"}, "status_code": 200}],
    )

    # mock getting manifest for binary repo
    url = "api/v1/manifest/ubi_binary"
    url = os.path.join("https://ubi-manifest.com", url)
    response = {
        "repo_id": "ubi_binary",
        "content": [
            {
                "unit_type": "RpmUnit",
                "src_repo_id": "input_binary",
                "value": "golang-2.a.x86_64.rpm",
            },
            {
                "unit_type": "ModulemdUnit",
                "src_repo_id": "input_binary",
                "value": "test_md:s:200:c:x86_64",
            },
            {
                "unit_type": "ModulemdDefaultsUnit",
                "src_repo_id": "input_binary",
                "value": "test_md_defaults:stream",
            },
        ],
    }
    requests_mock.register_uri("GET", url, json=response)

    # mock getting from debug and source repos - just empty manifests
    url = "api/v1/manifest/ubi_debug"
    url = os.path.join("https://ubi-manifest.com", url)
    response = {"repo_id": "some-repo-id", "content": []}
    requests_mock.register_uri("GET", url, json=response)

    url = "api/v1/manifest/ubi_source"
    url = os.path.join("https://ubi-manifest.com", url)
    response = {"repo_id": "some-repo-id", "content": []}
    requests_mock.register_uri("GET", url, json=response)


@patch("ubipop.Client")
def test_make_pulp_client_cert(mocked_client):
    """Tests that pulp client can be created with cert/key used for auth"""
    with NamedTemporaryFile() as cert, NamedTemporaryFile() as key:
        cert_path = os.path.abspath(cert.name)
        key_path = os.path.abspath(key.name)
        auth = (cert_path, key_path)

        ubi_populate = UbiPopulate("example.pulp.com", auth, dry_run=False)
        _ = ubi_populate.pulp_client

        mocked_client.assert_called_once_with(
            "https://example.pulp.com", verify=True, cert=auth
        )


@patch("ubipop.Client")
def test_make_pulp_client_username(mocked_client):
    """Tests that pulp client can be created with username/password used for auth"""

    auth = ("username", "password")
    ubi_populate = UbiPopulate("example.pulp.com", auth, dry_run=False)
    _ = ubi_populate.pulp_client

    mocked_client.assert_called_once_with(
        "https://example.pulp.com", verify=True, auth=auth
    )
