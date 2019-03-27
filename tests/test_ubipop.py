import pytest
import ubiconfig
import tempfile
import os
import shutil
from ubipop import UbiPopulateRunner, UbiRepoSet, RepoSet, UbiPopulate
from ubipop._pulp_client import Module, Package
from mock import MagicMock
from mock import patch
from more_executors import Executors

TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), './data')


@pytest.fixture()
def ubi_repo_set():
    rhel_repo_set = RepoSet("foo-rpms", "foo-source", "foo-debug")
    ubi_repo_set = RepoSet("ubi-foo-rpms", "ubi-foo-source", "ubi-foo-debug")
    yield UbiRepoSet(rhel_repo_set, ubi_repo_set)


@pytest.fixture()
def test_ubiconfig():
    yield ubiconfig.get_loader(TEST_DATA_DIR).load("conf.yaml")


@pytest.fixture()
def executor():
    yield Executors.thread_pool(max_workers=1).with_retry()


@pytest.fixture()
def mock_ubipop_runner(ubi_repo_set, test_ubiconfig, executor):
    yield UbiPopulateRunner(MagicMock(), ubi_repo_set, test_ubiconfig, False, executor)


def get_test_pkg(**kwargs):
    return Package(kwargs.get('name'), kwargs.get('filename'))


def get_test_mod(**kwargs):
    return Module(kwargs.get('name', ''),
                  kwargs.get('stream', ''),
                  kwargs.get('version', ''),
                  kwargs.get('context', ''),
                  kwargs.get('arch', ''),
                  kwargs.get('packages', ''),
                  kwargs.get('profiles', ''))


def test_get_packages_from_module(mock_ubipop_runner):
    package_name = "postgresql"
    input_modules = \
        [get_test_mod(
            packages=["postgresql-0:9.6.10-1.module+el8+2470+d1bafa0e.src",
                      "postgresql-0:9.6.10-1.module+el8+2470+d1bafa0e.x86_64",
                      "postgresql-contrib-0:9.6.10-1.module+el8+2470+d1bafa0e.x86_64",
                      "postgresql-contrib-debuginfo-0:9.6.10-1.module+el8+2470+d1bafa0e.x86_64"]
                      )]

    pkgs_from_modules = mock_ubipop_runner.get_packages_from_module(package_name, input_modules)
    assert len(pkgs_from_modules) == 1
    pkg = pkgs_from_modules[0]
    assert pkg.name == "postgresql"
    # filename is without  epoch
    assert pkg.filename == "postgresql-9.6.10-1.module+el8+2470+d1bafa0e.x86_64.rpm"


def test_packages_names_by_profiles(mock_ubipop_runner):
    profiles_from_ubiconfig = ["prof2", "prof3"]
    profiles = {"prof1": ["pkg1", "pkg2"], 'prof2': ["pkg3"]}
    modules = [get_test_mod(profiles=profiles)]
    pkg_names = mock_ubipop_runner.get_packages_names_by_profiles(profiles_from_ubiconfig, modules)

    assert len(pkg_names) == 1
    assert pkg_names[0] == "pkg3"


def test_packages_names_by_profiles_all_profiles(mock_ubipop_runner):
    profiles = {"prof1": ["pkg1", "pkg2"], 'prof2': ["pkg3"]}
    modules = [get_test_mod(profiles=profiles)]
    pkg_names = mock_ubipop_runner.get_packages_names_by_profiles([], modules)

    assert len(pkg_names) == 3
    assert sorted(pkg_names) == sorted(profiles['prof1'] + profiles['prof2'])


def test_sort_packages(mock_ubipop_runner):
    packages = [
        get_test_pkg(filename="tomcatjss-7.3.6-1.el8+1944+b6c8e16f.noarch.rpm"),
        get_test_pkg(filename="tomcatjss-5.3.6-1.el8+1944+b6c8e16f.noarch.rpm"),
        get_test_pkg(filename="tomcatjss-9.3.6-1.el8+1944+b6c8e16f.noarch.rpm")]

    mock_ubipop_runner.sort_packages(packages)

    assert "5.3.6" in packages[0].filename
    assert "7.3.6" in packages[1].filename
    assert "9.3.6" in packages[2].filename


def test_keep_n_latest_modules(mock_ubipop_runner):
    sorted_modules = [get_test_mod(version=1), get_test_mod(version=2), get_test_mod(version=3)]

    mock_ubipop_runner.keep_n_latest_modules(sorted_modules)

    assert len(sorted_modules) == 1
    assert sorted_modules[0].version == 3


def test_sort_modules(mock_ubipop_runner):
    modules = [get_test_mod(version=2), get_test_mod(version=3), get_test_mod(version=1)]
    mock_ubipop_runner.sort_modules(modules)

    assert modules[0].version == 1
    assert modules[1].version == 2
    assert modules[2].version == 3


def test_get_blacklisted_packages(mock_ubipop_runner):
    pkg_name = "foo-pkg"
    test_pkg_list = [get_test_pkg(name=pkg_name,
                                  filename="{name}-3.0.6-4.el7.noarch.rpm".format(name=pkg_name))]

    blacklist = mock_ubipop_runner.get_blacklisted_packages(test_pkg_list)

    assert len(blacklist) == 1
    assert blacklist[0].name == pkg_name


def test_match_packages(mock_ubipop_runner):
    package_name = 'foo-pkg'

    mock_ubipop_runner.pulp.search_rpms.return_value = [get_test_pkg(name=package_name)]
    mock_ubipop_runner._match_packages()

    assert len(mock_ubipop_runner.out_repo_set.packages) == 1
    assert mock_ubipop_runner.out_repo_set.packages[package_name][0].name == package_name


def test_match_modules(mock_ubipop_runner):
    mock_ubipop_runner.pulp.search_modules.return_value = \
        [get_test_mod(name="m1",
                      profiles={'prof1': ["tomcatjss"]},
                      packages=["tomcatjss-0:7.3.6-1.el8+1944+b6c8e16f.noarch"])]

    mock_ubipop_runner._match_modules()

    assert len(mock_ubipop_runner.out_repo_set.modules) == 1
    assert len(mock_ubipop_runner.out_repo_set.modules["n1s1"]) == 1
    assert mock_ubipop_runner.out_repo_set.modules["n1s1"][0].name == 'm1'
    pkg = mock_ubipop_runner.out_repo_set.pkgs_from_modules["n1s1"][0]
    assert pkg.filename == "tomcatjss-7.3.6-1.el8+1944+b6c8e16f.noarch.rpm"
    assert pkg.filename == "tomcatjss-7.3.6-1.el8+1944+b6c8e16f.noarch.rpm"


def test_diff_modules(mock_ubipop_runner):
    curr = [get_test_mod(name='1'), get_test_mod(name='2'), get_test_mod(name='3')]
    expected = [get_test_mod(name='2'),
                get_test_mod(name='3'),
                get_test_mod(name='4')]
    diff = mock_ubipop_runner._diff_modules_by_nsvca(curr, expected)
    assert len(diff) == 1
    assert diff[0].name == '1'


def test_keep_n_newest_packages(mock_ubipop_runner):
    packages = [get_test_pkg(name="tomcatjss",
                             filename="tomcatjss-7.3.6-1.el8+1944+b6c8e16f.noarch.rpm"),
                get_test_pkg(name="tomcatjss",
                             filename="tomcatjss-7.3.7-1.el8+1944+b6c8e16f.noarch.rpm"),
                get_test_pkg(name="tomcatjss",
                             filename="tomcatjss-7.3.8-1.el8+1944+b6c8e16f.noarch.rpm")]

    mock_ubipop_runner.keep_n_newest_packages(packages)

    assert len(packages) == 1
    assert "7.3.8" in packages[0].filename


def test_keep_n_newest_packages_with_referenced_pkg_in_module(mock_ubipop_runner):
    packages = [
        get_test_pkg(name="tomcatjss", filename="tomcatjss-7.3.6-1.el8+1944+b6c8e16f.noarch.rpm"),
        get_test_pkg(name="tomcatjss", filename="tomcatjss-7.3.7-1.el8+1944+b6c8e16f.noarch.rpm"),
        get_test_pkg(name="tomcatjss", filename="tomcatjss-7.3.8-1.el8+1944+b6c8e16f.noarch.rpm")]

    mock_ubipop_runner.out_repo_set.modules["ns"] = []
    mock_ubipop_runner.out_repo_set.pkgs_from_modules["ns"] = \
        [get_test_pkg(name="tomcatjss", filename="tomcatjss-7.3.7-1.el8+1944+b6c8e16f.noarch.rpm")]

    mock_ubipop_runner.keep_n_newest_packages(packages)

    assert len(packages) == 2
    assert "7.3.8" in packages[0].filename
    assert "7.3.7" in packages[1].filename


@pytest.mark.parametrize("rhel_repo_set, ubi_repo_set, fail",
                         [(RepoSet(None, None, "foo-debug"),
                           RepoSet(None, None, "ubi-foo-debug"), True),
                          (RepoSet('foo-rpms', "foo-source", None),
                           RepoSet("ubi-foo-rpms", "ubi-foo-source", None), False),
                          ])
def test_ubi_repo_set(rhel_repo_set, ubi_repo_set, fail, caplog):
    from ubipop import RepoMissing

    if fail:
        with pytest.raises(RepoMissing):
            UbiRepoSet(rhel_repo_set, ubi_repo_set)

        assert 'ERROR' in caplog.text
        assert 'repo does not exist' in caplog.text
        assert 'WARN' not in caplog.text

    else:
        UbiRepoSet(rhel_repo_set, ubi_repo_set)
        assert 'WARN' in caplog.text
        assert 'repo does not exist' in caplog.text
        assert 'ERROR' not in caplog.text


@pytest.fixture()
def mocked_ubiconfig_load():
    with patch('ubiconfig.get_loader') as get_loader:
        get_loader.return_value.load.return_value = "test"
        yield get_loader


def test_ubipopulate_load_ubiconfig(mocked_ubiconfig_load):
    ubipop = UbiPopulate("foo.pulp.com", ('foo', 'foo'), False, ['cfg.yaml'])
    assert len(ubipop.ubiconfig_list) == 1
    assert ubipop.ubiconfig_list[0] == "test"


@pytest.fixture()
def mocked_ubiconfig_load_all():
    with patch('ubiconfig.get_loader') as get_loader:
        get_loader.return_value.load_all.return_value = ["test"]
        yield get_loader


def test_ubipopulate_load_all_ubiconfig(mocked_ubiconfig_load_all):
    ubipop = UbiPopulate("foo.pulp.com", ('foo', 'foo'), False)
    assert len(ubipop.ubiconfig_list) == 1
    assert ubipop.ubiconfig_list[0] == "test"


def test_create_srpms_output_set(mock_ubipop_runner):
    expected_src_rpm_filename = "tomcatjss-7.3.6-1.el8+1944+b6c8e16f.src.rpm"
    mock_ubipop_runner.out_repo_set.packages['foo'] = \
        [get_test_pkg(name="tomcatjss",
                      filename="tomcatjss-7.3.6-1.el8+1944+b6c8e16f.noarch.rpm"),
         get_test_pkg(name="kernel",
                      filename="kernel-7.3.6-1.el8+1944+b6c8e16f.noarch.rpm")
         ]

    mock_ubipop_runner._create_srpms_output_set()
    out_srpms = mock_ubipop_runner.out_repo_set.source_rpms
    assert len(out_srpms) == 1
    assert out_srpms[0].name == "tomcatjss"
    assert out_srpms[0].filename == expected_src_rpm_filename


def test_create_debug_output_set(mock_ubipop_runner):
    expected_debug_filename = "tomcatjss-debuginfo-7.3.6-1.el8+1944+b6c8e16f.noarch.rpm"
    mock_ubipop_runner.out_repo_set.packages['foo'] = \
        [get_test_pkg(name="tomcatjss",
                      filename="tomcatjss-7.3.6-1.el8+1944+b6c8e16f.noarch.rpm"),
         get_test_pkg(name="kernel",
                      filename="kernel-7.3.6-1.el8+1944+b6c8e16f.noarch.rpm")
         ]

    mock_ubipop_runner._create_debuginfo_output_set()
    out_debug_rpms = mock_ubipop_runner.out_repo_set.debug_rpms
    assert len(out_debug_rpms) == 1
    assert out_debug_rpms[0].name == "tomcatjss"
    assert out_debug_rpms[0].filename == expected_debug_filename


@pytest.fixture()
def mock_get_repo_pairs():
    with patch('ubipop.UbiPopulate._get_input_and_output_repo_pairs') as get_repo_pairs:
        get_repo_pairs.return_value = [ubi_repo_set]
        yield get_repo_pairs


@pytest.fixture()
def mock_run_ubi_population(ubi_repo_set):
    with patch('ubipop.UbiPopulateRunner.run_ubi_population') as run_ubi_population:
        run_ubi_population.return_value = set(['repo1', 'repo2'])
        yield run_ubi_population


def test_create_output_file(mock_ubipop_runner, mock_get_repo_pairs, mocked_ubiconfig_load_all,
                            mock_run_ubi_population):
    path = tempfile.mkdtemp("ubipop")
    try:
        out_file_path = os.path.join(path, 'output.txt')
        ubipop = UbiPopulate("foo.pulp.com", ('foo', 'foo'), False,
                             output_changed_repos=out_file_path)

        ubipop.populate_ubi_repos()

        with open(out_file_path) as f:
            content = f.readlines()

        assert len(content) == 2
        assert content == ['repo1\n', 'repo2\n']

    finally:
        shutil.rmtree(path)
