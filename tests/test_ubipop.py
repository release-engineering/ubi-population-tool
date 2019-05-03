import logging
import os
import shutil
import sys
import tempfile

from copy import deepcopy

import pytest
import ubiconfig

from mock import MagicMock, patch, call
from more_executors import Executors
from ubipop import UbiPopulateRunner, UbiRepoSet, RepoSet, UbiPopulate
from ubipop._pulp_client import Module, ModuleDefaults, Package, Repo
from ubipop._utils import (
    AssociateActionModules,
    UnassociateActionModules,
    AssociateActionModuleDefaults,
    UnassociateActionModuleDefaults,
    split_filename,
)

TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), './data')


@pytest.fixture()
def ubi_repo_set():
    yield UbiRepoSet(RepoSet(get_test_repo(repo_id="foo-rpms"),
                             get_test_repo(repo_id="foo-source"),
                             get_test_repo(repo_id="foo-debug")),
                     RepoSet(get_test_repo(repo_id="ubi-foo-rpms"),
                             get_test_repo(repo_id="ubi-foo-source"),
                             get_test_repo(repo_id="ubi-foo-debug")))


@pytest.fixture()
def ubi_repo_set_no_debug():
    yield UbiRepoSet(RepoSet(get_test_repo(repo_id="foo-rpms"),
                             get_test_repo(repo_id="foo-source"),
                             None),
                     RepoSet(get_test_repo(repo_id="ubi-foo-rpms"),
                             get_test_repo(repo_id="ubi-foo-source"),
                             None))


@pytest.fixture()
def test_ubiconfig():
    yield ubiconfig.get_loader(TEST_DATA_DIR).load("conf.yaml")


@pytest.fixture()
def executor():
    yield Executors.thread_pool(max_workers=1).with_retry()


@pytest.fixture()
def mock_ubipop_runner(ubi_repo_set, test_ubiconfig, executor):
    yield UbiPopulateRunner(MagicMock(), ubi_repo_set, test_ubiconfig, False, executor)


def get_test_repo(**kwargs):
    return Repo(
        kwargs.get('repo_id'),
        kwargs.get('arch'),
        kwargs.get('platform_full_version'),
        kwargs.get('distributors_ids_type_ids'),
    )


def get_test_pkg(**kwargs):
    return Package(
        kwargs.get('name'),
        kwargs.get('filename'),
        sourcerpm_filename=kwargs.get('sourcerpm_filename'),
        is_modular=kwargs.get('is_modular', False),
    )


def get_test_mod(**kwargs):
    return Module(
        kwargs.get('name', ''),
        kwargs.get('stream', ''),
        kwargs.get('version', ''),
        kwargs.get('context', ''),
        kwargs.get('arch', ''),
        kwargs.get('packages', ''),
        kwargs.get('profiles', ''),
    )


def get_test_mod_defaults(**kwargs):
    return ModuleDefaults(kwargs['name'], kwargs['stream'], kwargs['profiles'])


def test_get_output_repo_ids(ubi_repo_set):
    repo_ids = ubi_repo_set.get_output_repo_ids()
    assert repo_ids == set(["ubi-foo-rpms", "ubi-foo-source", "ubi-foo-debug"])


def test_get_output_repo_ids_no_debug(ubi_repo_set_no_debug):
    repo_ids = ubi_repo_set_no_debug.get_output_repo_ids()
    assert repo_ids == set(["ubi-foo-rpms", "ubi-foo-source"])


def test_get_packages_from_module_by_name(mock_ubipop_runner):
    package_name = "postgresql"
    input_modules = [
        get_test_mod(
            packages=[
                "postgresql-0:9.6.10-1.module+el8+2470+d1bafa0e.src",
                "postgresql-0:9.6.10-1.module+el8+2470+d1bafa0e.x86_64",
                "postgresql-contrib-0:9.6.10-1.module+el8+2470+d1bafa0e.x86_64",
            ],
        ),
    ]

    packages_fnames = [
        "postgresql-9.6.10-1.module+el8+2470+d1bafa0e.src.rpm",
        "postgresql-9.6.10-1.module+el8+2470+d1bafa0e.x86_64.rpm",
        "postgresql-contrib-9.6.10-1.module+el8+2470+d1bafa0e.x86_64.rpm",
    ]

    mock_ubipop_runner.pulp.search_rpms.side_effect = _get_search_rpms_side_effect(packages_fnames)
    rpms, debug_rpms = mock_ubipop_runner.get_packages_from_module(input_modules, package_name)
    assert len(rpms) == 1
    assert len(debug_rpms) == 0
    pkg = rpms[0]
    # filename is without  epoch
    assert pkg.filename == "postgresql-9.6.10-1.module+el8+2470+d1bafa0e.x86_64.rpm"


def test_get_packages_from_module(mock_ubipop_runner):
    input_modules = [
        get_test_mod(
            packages=[
                "postgresql-0:9.6.10-1.module+el8+2470+d1bafa0e.src",
                "postgresql-0:9.6.10-1.module+el8+2470+d1bafa0e.x86_64",
                "postgresql-contrib-0:9.6.10-1.module+el8+2470+d1bafa0e.x86_64",
            ],
        ),
    ]

    packages_fnames = [
        "postgresql-9.6.10-1.module+el8+2470+d1bafa0e.src.rpm",
        "postgresql-9.6.10-1.module+el8+2470+d1bafa0e.x86_64.rpm",
        "postgresql-contrib-9.6.10-1.module+el8+2470+d1bafa0e.x86_64.rpm",
    ]

    mock_ubipop_runner.pulp.search_rpms.side_effect = _get_search_rpms_side_effect(packages_fnames)

    rpms, debug_rpms = mock_ubipop_runner.get_packages_from_module(input_modules)
    assert len(rpms) == 2 # srpm is not included
    assert len(debug_rpms) == 0  # no debug rpm in this testcase


def test_get_packages_from_module_debuginfo(mock_ubipop_runner):
    input_modules = [
        get_test_mod(
            packages=[
                "postgresql-0:9.6.10-1.module+el8+2470+d1bafa0e.src",
                "postgresql-contrib-debuginfo-0:9.6.10-1.module+el8+2470+d1bafa0e.x86_64",
            ],
        ),
    ]

    packages_fnames = [
        "postgresql-9.6.10-1.module+el8+2470+d1bafa0e.src.rpm",
        "postgresql-9.6.10-1.module+el8+2470+d1bafa0e.x86_64.rpm",
        "postgresql-contrib-9.6.10-1.module+el8+2470+d1bafa0e.x86_64.rpm",
        "postgresql-contrib-debuginfo-9.6.10-1.module+el8+2470+d1bafa0e.x86_64.rpm",
    ]

    mock_ubipop_runner.pulp.search_rpms.side_effect = _get_search_rpms_side_effect(packages_fnames,
                                                                                   debug_only=True)

    rpms, debug_rpms = mock_ubipop_runner.get_packages_from_module(input_modules)
    assert len(rpms) == 0  # no srpm or binary rpm are included
    assert len(debug_rpms) == 1  # one debug rpm in this testcase
    assert debug_rpms[0].filename == \
           "postgresql-contrib-debuginfo-9.6.10-1.module+el8+2470+d1bafa0e.x86_64.rpm"


def test_packages_names_by_profiles(mock_ubipop_runner):
    profiles_from_ubiconfig = ["prof2", "prof3"]
    profiles = {"prof1": ["pkg1", "pkg2"], 'prof2': ["pkg3"], 'prof3': ["pkg3", "pkg4"]}
    modules = [get_test_mod(profiles=profiles)]
    pkg_names = mock_ubipop_runner.get_packages_names_by_profiles(profiles_from_ubiconfig, modules)

    assert sorted(pkg_names) == ["pkg3", "pkg4"]


def test_packages_names_by_profiles_all_profiles(mock_ubipop_runner):
    profiles = {"prof1": ["pkg1", "pkg2"], 'prof2': ["pkg3"]}
    modules = [get_test_mod(profiles=profiles)]
    pkg_names = mock_ubipop_runner.get_packages_names_by_profiles([], modules)

    assert len(pkg_names) == 3
    assert sorted(pkg_names) == sorted(profiles['prof1'] + profiles['prof2'])


def test_sort_packages(mock_ubipop_runner):
    packages = [
        get_test_pkg(filename="rubygems-2.0.14-26.el7_1.noarch.rpm"),
        get_test_pkg(filename="rubygems-2.0.14-25.el7_1.noarch.rpm"),
        get_test_pkg(filename="rubygems-2.0.14.1-33.el7_6.noarch.rpm"),
        get_test_pkg(filename="rubygems-2.0.14.1-34.el7_6.noarch.rpm"),
        get_test_pkg(filename="rubygems-2.0.13.1-34.el7_6.noarch.rpm"),
        get_test_pkg(filename="rubygems-2.0.13.2-34.el7_6.noarch.rpm"),
    ]

    mock_ubipop_runner.sort_packages(packages)

    assert "2.0.13.1-34" in packages[0].filename
    assert "2.0.13.2-34" in packages[1].filename
    assert "2.0.14-25" in packages[2].filename
    assert "2.0.14-26" in packages[3].filename
    assert "2.0.14.1-33" in packages[4].filename
    assert "2.0.14.1-34" in packages[5].filename


def test_keep_n_latest_modules(mock_ubipop_runner):
    sorted_modules = [
        get_test_mod(version=1),
        get_test_mod(version=2),
        get_test_mod(version=3),
    ]

    mock_ubipop_runner.keep_n_latest_modules(sorted_modules)

    assert len(sorted_modules) == 1
    assert sorted_modules[0].version == 3


def test_sort_modules(mock_ubipop_runner):
    modules = [
        get_test_mod(version=2),
        get_test_mod(version=3),
        get_test_mod(version=1),
    ]
    mock_ubipop_runner.sort_modules(modules)

    assert modules[0].version == 1
    assert modules[1].version == 2
    assert modules[2].version == 3


def test_get_blacklisted_packages_match_name_glob(mock_ubipop_runner):
    pkg_name = "foo-pkg"
    test_pkg_list = [
        get_test_pkg(
            name=pkg_name,
            filename="{name}-3.0.6-4.el7.noarch.rpm".format(name=pkg_name),
        ),
        get_test_pkg(
            name="no-match-foo-pkg",
            filename="no-match-foo-pkg-3.0.6-4.el7.noarch.rpm",
        ),
    ]

    blacklist = mock_ubipop_runner.get_blacklisted_packages(test_pkg_list)

    assert len(blacklist) == 1
    assert blacklist[0].name == pkg_name


def test_get_blacklisted_packages_match_arch(mock_ubipop_runner):
    pkg_name = "foo-arch-test"
    test_pkg_list = [
        get_test_pkg(
            name=pkg_name,
            filename="{name}-3.0.6-4.el7.noarch.rpm".format(name=pkg_name),
        ),
        get_test_pkg(
            name=pkg_name,
            filename="{name}-3.0.6-4.el7.x86_64.rpm".format(name=pkg_name),
        ),
    ]

    blacklist = mock_ubipop_runner.get_blacklisted_packages(test_pkg_list)

    assert len(blacklist) == 1
    assert blacklist[0].name == pkg_name
    assert "x86_64" in blacklist[0].filename


def _get_search_rpms_side_effect(package_name_or_filename_or_list, debug_only=False):
    def _f(*args, **kwargs):
        if debug_only and "debug" not in args[0].repo_id:
            return

        if len(args) > 1 and args[1] == package_name_or_filename_or_list:
            return [get_test_pkg(name=args[1])]

        if isinstance(package_name_or_filename_or_list, list):
            if kwargs['filename'] in package_name_or_filename_or_list:
                return [
                    get_test_pkg(
                        name=split_filename(kwargs['filename'])[0],
                        filename=kwargs['filename']),
                ]

        if 'filename' in kwargs and package_name_or_filename_or_list == kwargs['filename']:
            return [
                get_test_pkg(
                    name=split_filename(kwargs['filename'])[0],
                    filename=kwargs['filename']),
                ]

    return _f


def test_match_binary_rpms(mock_ubipop_runner):
    package_name = 'foo-pkg'
    mock_ubipop_runner.pulp.search_rpms.side_effect = _get_search_rpms_side_effect(package_name)
    mock_ubipop_runner._match_binary_rpms()

    assert len(mock_ubipop_runner.repos.packages) == 1
    assert mock_ubipop_runner.repos.packages[package_name][0].name == package_name


def test_match_debug_rpms(mock_ubipop_runner):
    package_name = 'foo-pkg-debuginfo'
    mock_ubipop_runner.pulp.search_rpms.side_effect = _get_search_rpms_side_effect(package_name)
    mock_ubipop_runner._match_debug_rpms()

    assert len(mock_ubipop_runner.repos.debug_rpms) == 1
    assert mock_ubipop_runner.repos.debug_rpms[package_name][0].name == package_name


def test_match_modules(mock_ubipop_runner):
    mock_ubipop_runner.pulp.search_modules.return_value = \
        [get_test_mod(name="m1",
                      profiles={'prof1': ["tomcatjss"]},
                      packages=["tomcatjss-0:7.3.6-1.el8+1944+b6c8e16f.noarch"])]
    pkg_filename = "tomcatjss-7.3.6-1.el8+1944+b6c8e16f.noarch.rpm"
    mock_ubipop_runner.pulp.search_rpms.side_effect = _get_search_rpms_side_effect(pkg_filename)
    mock_ubipop_runner._match_modules()

    assert len(mock_ubipop_runner.repos.modules) == 1
    assert len(mock_ubipop_runner.repos.modules["n1s1"]) == 1
    assert mock_ubipop_runner.repos.modules["n1s1"][0].name == 'm1'
    pkg = mock_ubipop_runner.repos.pkgs_from_modules["n1s1"][0]
    assert pkg.filename == "tomcatjss-7.3.6-1.el8+1944+b6c8e16f.noarch.rpm"
    assert pkg.filename == "tomcatjss-7.3.6-1.el8+1944+b6c8e16f.noarch.rpm"


def test_match_modules_without_profile(ubi_repo_set, executor):
    test_ubiconf = ubiconfig.get_loader(TEST_DATA_DIR).load('ubiconf_golang.yaml')
    mocked_ubipop_runner = UbiPopulateRunner(
        MagicMock(),
        ubi_repo_set,
        test_ubiconf,
        False,
        executor,
    )

    mocked_ubipop_runner.pulp.search_modules.return_value = [
        get_test_mod(
            name="go-toolset",
            profiles={"common": ["go-toolset"]},
            packages=[
                "go-toolset-0:1.11.5-1.module+el8+2774+11afa8b5.x86_64",
                "golang-0:1.11.5-1.module+el8+2774+11afa8b5.x86_64",
                "golang-bin-0:1.11.5-1.module+el8+2774+11afa8b5.x86_64",
                "golang-docs-0:1.11.5-1.module+el8+2774+11afa8b5.noarch",
                "golang-misc-0:1.11.5-1.module+el8+2774+11afa8b5.noarch",
                "golang-race-0:1.11.5-1.module+el8+2774+11afa8b5.x86_64",
                "golang-src-0:1.11.5-1.module+el8+2774+11afa8b5.noarch",
                "golang-tests-0:1.11.5-1.module+el8+2774+11afa8b5.noarch",
            ],
        ),
    ]

    packages_fnames = [
        "go-toolset-1.11.5-1.module+el8+2774+11afa8b5.x86_64.rpm",
        "golang-1.11.5-1.module+el8+2774+11afa8b5.x86_64.rpm",
        "golang-bin-1.11.5-1.module+el8+2774+11afa8b5.x86_64.rpm",
        "golang-docs-1.11.5-1.module+el8+2774+11afa8b5.noarch.rpm",
        "golang-misc-1.11.5-1.module+el8+2774+11afa8b5.noarch.rpm",
        "golang-race-1.11.5-1.module+el8+2774+11afa8b5.x86_64.rpm",
        "golang-src-1.11.5-1.module+el8+2774+11afa8b5.noarch.rpm",
        "golang-tests-1.11.5-1.module+el8+2774+11afa8b5.noarch.rpm",
    ]

    mocked_ubipop_runner.pulp.search_rpms.side_effect = _get_search_rpms_side_effect(packages_fnames)
    mocked_ubipop_runner._match_modules()

    assert len(mocked_ubipop_runner.repos.modules) == 1
    assert len(mocked_ubipop_runner.repos.modules['go-toolsetrhel8']) == 1
    assert mocked_ubipop_runner.repos.modules['go-toolsetrhel8'][0].name == 'go-toolset'
    assert len(mocked_ubipop_runner.repos.pkgs_from_modules['go-toolsetrhel8']) == 8
    assert len(mocked_ubipop_runner.repos.packages) == 8
    assert len(mocked_ubipop_runner.repos.debug_rpms) == 0


def test_match_module_defaults(mock_ubipop_runner):
    mock_ubipop_runner.repos.modules['n1s1'] = [
        get_test_mod(name="virt", profiles={'2.5': ["common"]}, stream='rhel'),
    ]
    mock_ubipop_runner.pulp.search_module_defaults.return_value = [
        get_test_mod_defaults(name='virt', stream='rhel', profiles={'2.5': ["common"]}),
    ]

    mock_ubipop_runner._match_module_defaults()

    assert len(mock_ubipop_runner.repos.module_defaults) == 1
    md_d = mock_ubipop_runner.repos.module_defaults['virtrhel']
    assert len(md_d) == 1
    assert md_d[0].name == 'virt'
    assert md_d[0].name_profiles == 'virt:[2.5:common]'

def test_diff_modules(mock_ubipop_runner):
    curr = [
        get_test_mod(name='1'),
        get_test_mod(name='2'),
        get_test_mod(name='3'),
    ]
    expected = [
        get_test_mod(name='2'),
        get_test_mod(name='3'),
        get_test_mod(name='4'),
    ]

    diff = mock_ubipop_runner._diff_modules_by_nsvca(curr, expected)

    assert len(diff) == 1
    assert diff[0].name == '1'


def test_keep_n_newest_packages(mock_ubipop_runner):
    packages = [
        get_test_pkg(
            name="tomcatjss",
            filename="tomcatjss-7.3.6-1.el8+1944+b6c8e16f.noarch.rpm",
        ),
        get_test_pkg(
            name="tomcatjss",
            filename="tomcatjss-7.3.8-1.el8+1944+b6c8e16f.noarch.rpm",
        ),
        get_test_pkg(
            name="tomcatjss",
            filename="tomcatjss-7.3.7-1.el8+1944+b6c8e16f.noarch.rpm",
        ),
    ]
    packages.sort()
    mock_ubipop_runner.keep_n_latest_packages(packages)

    assert len(packages) == 1
    assert "7.3.8" in packages[0].filename


def test_keep_n_newest_packages_multi_arch(mock_ubipop_runner):
    packages = [
        get_test_pkg(
            name="tomcatjss",
            filename="tomcatjss-7.3.6-1.noarch.rpm",
        ),
        get_test_pkg(
            name="tomcatjss",
            filename="tomcatjss-7.3.6-1.x86_64.rpm",
        ),
        get_test_pkg(
            name="tomcatjss",
            filename="tomcatjss-7.3.6-1.i686.rpm",
        ),
        get_test_pkg(
            name="tomcatjss",
            filename="tomcatjss-7.3.5-1.i686.rpm",
        ),
    ]

    packages.sort()
    mock_ubipop_runner.keep_n_latest_packages(packages)
    assert len(packages) == 3

    arches_expected = ['noarch', 'x86_64', 'i686']
    arches_current = []

    for pkg in packages:
        _, _, _, _, arch = split_filename(pkg.filename)
        arches_current.append(arch)

    assert sorted(arches_current) == sorted(arches_expected)


def test_keep_n_newest_packages_with_referenced_pkg_in_module(mock_ubipop_runner):
    packages = [
        get_test_pkg(
            name="tomcatjss",
            filename="tomcatjss-7.3.6-1.el8+1944+b6c8e16f.noarch.rpm",
            is_modular=True,
        ),
        get_test_pkg(
            name="tomcatjss",
            filename="tomcatjss-7.3.7-1.el8+1944+b6c8e16f.noarch.rpm",
            is_modular=True,
        ),
        get_test_pkg(
            name="tomcatjss",
            filename="tomcatjss-7.3.8-1.el8+1944+b6c8e16f.noarch.rpm",
            is_modular=True,
        ),
    ]

    mock_ubipop_runner.repos.modules["ns"] = []
    mock_ubipop_runner.repos.pkgs_from_modules["ns"] = [
        get_test_pkg(
            name="tomcatjss",
            filename="tomcatjss-7.3.7-1.el8+1944+b6c8e16f.noarch.rpm",
            is_modular=True,
        ),
    ]

    mock_ubipop_runner.keep_n_latest_packages(packages)

    assert len(packages) == 1
    assert "7.3.7" in packages[0].filename


@pytest.mark.parametrize("rhel_repo_set, ubi_repo_set, fail", [
    (
        RepoSet(None, None, "foo-debug"),
        RepoSet(None, None, "ubi-foo-debug"),
        True,
    ),
    (
        RepoSet('foo-rpms', "foo-source", None),
        RepoSet("ubi-foo-rpms", "ubi-foo-source", None),
        False,
    ),
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
    mock_ubipop_runner.repos.packages['foo'] = [
        get_test_pkg(
            name="tomcatjss",
            filename="tomcatjss-7.3.6-1.el8+1944+b6c8e16f.noarch.rpm",
            sourcerpm_filename=expected_src_rpm_filename,
        ),
        get_test_pkg(
            name="kernel",
            filename="kernel-7.3.6-1.el8+1944+b6c8e16f.noarch.rpm",
            sourcerpm_filename="kernel.src.rpm",
        ),
    ]

    mock_ubipop_runner._create_srpms_output_set()

    out_srpms = mock_ubipop_runner.repos.source_rpms
    assert len(out_srpms) == 1
    assert out_srpms['tomcatjss'][0].name == "tomcatjss"
    assert out_srpms['tomcatjss'][0].filename == expected_src_rpm_filename


def test_create_srpms_output_set_missings_srpm_reference(capsys, set_logging, mock_ubipop_runner):
    set_logging.addHandler(logging.StreamHandler(sys.stdout))
    mock_ubipop_runner.repos.packages['foo'] = [
        get_test_pkg(
            name="tomcatjss",
            filename="tomcatjss-7.3.6-1.el8+1944+b6c8e16f.noarch.rpm",
        ),
    ]

    mock_ubipop_runner._create_srpms_output_set()

    out_srpms = mock_ubipop_runner.repos.source_rpms
    assert len(out_srpms) == 0
    out, err = capsys.readouterr()

    assert err == ""
    assert out.strip() == "Package tomcatjss doesn't reference its source rpm"


@pytest.fixture()
def mock_get_repo_pairs(ubi_repo_set):
    with patch('ubipop.UbiPopulate._get_input_and_output_repo_pairs') as get_repo_pairs:
        get_repo_pairs.return_value = [ubi_repo_set]
        yield get_repo_pairs


@pytest.fixture()
def mock_run_ubi_population():
    with patch('ubipop.UbiPopulateRunner.run_ubi_population') as run_ubi_population:
        yield run_ubi_population


def test_create_output_file_all_repos(mock_ubipop_runner, mock_get_repo_pairs,
                                      mocked_ubiconfig_load_all, mock_run_ubi_population):
    path = tempfile.mkdtemp("ubipop")
    try:
        out_file_path = os.path.join(path, 'output.txt')

        ubipop = UbiPopulate("foo.pulp.com", ('foo', 'foo'), False, output_repos=out_file_path)
        ubipop.populate_ubi_repos()

        with open(out_file_path) as f:
            content = f.readlines()

        assert sorted(content) == sorted(["ubi-foo-rpms\n", "ubi-foo-source\n", "ubi-foo-debug\n"])
    finally:
        shutil.rmtree(path)


@pytest.fixture()
def mock_current_content_ft():
    current_modules_ft = MagicMock()
    current_rpms_ft = MagicMock()
    current_srpms_ft = MagicMock()
    current_debug_rpms_ft = MagicMock()
    current_module_default_ft = MagicMock()

    current_modules_ft.result.return_value = [
        get_test_mod(name="md_current"),
    ]
    current_module_default_ft.result.return_value = [
        get_test_mod_defaults(name='mdd_current', stream='rhel', profiles={'2.5': 'common'}),
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

    yield current_modules_ft, current_module_default_ft, current_rpms_ft, \
        current_srpms_ft, current_debug_rpms_ft


def test_get_pulp_actions(mock_ubipop_runner, mock_current_content_ft):
    mock_ubipop_runner.repos.modules = {
        "test": [
            get_test_mod(name="test_md"),
        ],
    }
    mock_ubipop_runner.repos.module_defaults = {
        'test': [
            get_test_mod_defaults(name='test_mdd', stream='rhel', profiles={'2.5': 'uncommon'}),
        ],
    }
    mock_ubipop_runner.repos.packages = {
        "test_rpm": [
            get_test_pkg(name="test_rpm", filename="test_rpm.rpm"),
        ],
    }
    mock_ubipop_runner.repos.debug_rpms = {
        "test_debug_pkg": [
            get_test_pkg(name="test_debug_pkg", filename="test_debug_pkg.rpm"),
        ],
    }
    mock_ubipop_runner.repos.source_rpms = {
        "test_srpm": [
            get_test_pkg(name="test_srpm", filename="test_srpm.src.rpm"),
        ],
    }

    associations, unassociations, mdd_association, mdd_unassociation = \
        mock_ubipop_runner._get_pulp_actions(*mock_current_content_ft)

    # firstly, check correct associations, there should 1 unit of each type associated
    modules, rpms, srpms, debug_rpms = associations
    assert len(modules.units) == 1
    assert modules.units[0].name == "test_md"
    assert modules.dst_repo.repo_id == "ubi-foo-rpms"
    assert modules.src_repo.repo_id == "foo-rpms"

    assert len(rpms.units) == 1
    assert rpms.units[0].name == "test_rpm"
    assert rpms.dst_repo.repo_id == "ubi-foo-rpms"
    assert rpms.src_repo.repo_id == "foo-rpms"

    assert len(srpms.units) == 1
    assert srpms.units[0].name == "test_srpm"
    assert srpms.dst_repo.repo_id == "ubi-foo-source"
    assert srpms.src_repo.repo_id == "foo-source"

    assert len(debug_rpms.units) == 1
    assert debug_rpms.units[0].name == "test_debug_pkg"
    assert debug_rpms.dst_repo.repo_id == "ubi-foo-debug"
    assert debug_rpms.src_repo.repo_id == "foo-debug"

    # secondly, check correct unassociations, there should 1 unit of each type unassociated
    modules, rpms, srpms, debug_rpms = unassociations
    assert len(modules.units) == 1
    assert modules.units[0].name == "md_current"
    assert modules.dst_repo.repo_id == "ubi-foo-rpms"

    assert len(rpms.units) == 1
    assert rpms.units[0].name == "rpm_current"
    assert rpms.dst_repo.repo_id == "ubi-foo-rpms"

    assert len(srpms.units) == 1
    assert srpms.units[0].name == "srpm_current"
    assert srpms.dst_repo.repo_id == "ubi-foo-source"

    assert len(debug_rpms.units) == 1
    assert debug_rpms.units[0].name == "debug_rpm_current"
    assert debug_rpms.dst_repo.repo_id == "ubi-foo-debug"

    assert len(mdd_association.units) == 1
    assert mdd_association.dst_repo.repo_id == 'ubi-foo-rpms'
    assert mdd_association.src_repo.repo_id == 'foo-rpms'

    assert len(mdd_unassociation.units) == 1
    assert mdd_unassociation.units[0].name == 'mdd_current'
    assert mdd_unassociation.dst_repo.repo_id == 'ubi-foo-rpms'



def test_get_pulp_actions_no_actions(mock_ubipop_runner, mock_current_content_ft):
    mock_ubipop_runner.repos.modules = {
        "test": [
            get_test_mod(name="md_current"),
        ],
    }
    mock_ubipop_runner.repos.module_defaults = {
        "test": [
            get_test_mod_defaults(name='mdd_current', stream='rhel', profiles={'2.5': 'common'}),
        ],
    }
    mock_ubipop_runner.repos.packages = {
        "test_rpm": [
            get_test_pkg(name="rpm_current", filename="rpm_current.rpm"),
        ],
    }
    mock_ubipop_runner.repos.debug_rpms = {
        "test_debug_pkg": [
            get_test_pkg(name="debug_rpm_current", filename="debug_rpm_current.rpm"),
        ],
    }
    mock_ubipop_runner.repos.source_rpms = {
        "test_srpm": [
            get_test_pkg(name="srpm_current", filename="srpm_current.src.rpm"),
        ],
    }

    associations, unassociations, mdd_association, mdd_unassociation = \
        mock_ubipop_runner._get_pulp_actions(*mock_current_content_ft)

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


@pytest.fixture()
def set_logging():
    logger = logging.getLogger("ubipop")
    logger.setLevel(logging.DEBUG)
    yield logger
    logger.handlers = []


def test_log_pulp_action(capsys, set_logging, mock_ubipop_runner):
    set_logging.addHandler(logging.StreamHandler(sys.stdout))
    src_repo = get_test_repo(repo_id='test_src')
    dst_repo = get_test_repo(repo_id='test_dst')
    associations = [AssociateActionModules([get_test_mod(name="test_assoc")], dst_repo, src_repo)]
    unassociations = [UnassociateActionModules([get_test_mod(name="test_unassoc")], dst_repo)]

    mock_ubipop_runner.log_pulp_actions(associations, unassociations)
    out, err = capsys.readouterr()
    assoc_line, unassoc_line = out.split('\n', 1)

    assert err == ""
    assert assoc_line.strip() == "Would associate test_assoc:::: from test_src to test_dst"
    assert unassoc_line.strip() == "Would unassociate test_unassoc:::: from test_dst"


def test_log_pulp_action_no_actions(capsys, set_logging, mock_ubipop_runner):
    set_logging.addHandler(logging.StreamHandler(sys.stdout))
    src_repo = get_test_repo(repo_id='test_src')
    dst_repo = get_test_repo(repo_id='test_dst')
    associations = [AssociateActionModules([], dst_repo, src_repo)]
    unassociations = [UnassociateActionModules([], dst_repo)]

    mock_ubipop_runner.log_pulp_actions(associations, unassociations)
    out, err = capsys.readouterr()
    assoc_line, unassoc_line = out.split('\n', 1)

    assert err == ""
    assert assoc_line.strip() == "No association expected for modules from test_src to test_dst"
    assert unassoc_line.strip() == "No unassociation expected for modules from test_dst"


def test_associate_units(mock_ubipop_runner):
    src_repo = get_test_repo(repo_id='test_src')
    dst_repo = get_test_repo(repo_id='test_dst')

    associations = [
        AssociateActionModules([get_test_mod(name="test_assoc")], dst_repo, src_repo),
    ]

    mock_ubipop_runner.pulp.associate_modules.return_value = ["task_id"]
    ret = mock_ubipop_runner._associate_unassociate_units(associations)

    assert len(ret) == 1
    assert ret[0].result() == ["task_id"]


def test_associate_unassociate_md_defaults(mock_ubipop_runner):
    src_repo = get_test_repo(repo_id='test_src')
    dst_repo = get_test_repo(repo_id='tets_dst')

    associations = AssociateActionModuleDefaults([
        get_test_mod_defaults(
            name='virt',
            stream='rhel',
            profiles={'2.5': ["common"]},
        ),
    ], dst_repo, src_repo)

    unassociations = UnassociateActionModuleDefaults([
        get_test_mod_defaults(
            name='virt',
            stream='rhel',
            profiles={'2.5': ["unique"]},
        ),
    ], dst_repo)

    mock_ubipop_runner.pulp.unassociate_module_defaults.return_value = ['task_id_0']
    mock_ubipop_runner.pulp.associate_module_defaults.return_value = ['task_id_1']

    mock_ubipop_runner._associate_unassociate_md_defaults((associations,), (unassociations,))

    # the calls has to be in order
    calls = [call(['task_id_0']), call(['task_id_1'])]
    mock_ubipop_runner.pulp.wait_for_tasks.assert_has_calls(calls)


def test_finalize_rpms_output_set(mock_ubipop_runner):
    expected_filename = "tomcatjss-7.3.6-1.el8+1944+b6c8e16f.noarch.rpm"
    mock_ubipop_runner.repos.packages['tomcatjss'] = [
        get_test_pkg(
            name="tomcatjss",
            filename=expected_filename,
        ),
        get_test_pkg(
            name="tomcatjss",
            filename="tomcatjss-7.3.5-1.el8+1944+b6c8e16f.noarch.rpm",
        ),
    ]

    mock_ubipop_runner._finalize_rpms_output_set()

    out_packages = mock_ubipop_runner.repos.packages['tomcatjss']
    assert len(out_packages) == 1
    assert out_packages[0].filename == expected_filename


def test_finalize_debug_output_set(mock_ubipop_runner):
    expected_filename = "tomcatjss-debuginfo-7.3.6-1.el8+1944+b6c8e16f.noarch.rpm"
    mock_ubipop_runner.repos.debug_rpms['tomcatjss-debuginfo'] = [
        get_test_pkg(
            name="tomcatjss-debuginfo",
            filename=expected_filename,
        ),
        get_test_pkg(
            name="tomcatjss-debuginfo",
            filename="tomcatjss-debuginfo-7.3.5-1.el8+1944+b6c8e16f.noarch.rpm",
        ),
    ]

    mock_ubipop_runner._finalize_debug_output_set()
    out_packages = mock_ubipop_runner.repos.debug_rpms['tomcatjss-debuginfo']
    assert len(out_packages) == 1
    assert out_packages[0].filename == expected_filename


def test_finalize_finalize_modules_output_set(mock_ubipop_runner):
    expected_nsvca = "::3::"
    mock_ubipop_runner.repos.modules['test:module'] = [
        get_test_mod(version=2),
        get_test_mod(version=3),
    ]

    mock_ubipop_runner._finalize_modules_output_set()

    out_modules = mock_ubipop_runner.repos.modules['test:module']
    assert len(out_modules) == 1
    assert out_modules[0].nsvca == expected_nsvca


def test_exclude_blacklisted_packages(mock_ubipop_runner):
    mock_ubipop_runner.repos.packages["kernel-blacklisted"] = [
        get_test_pkg(
            name="kernel-blacklisted",
            filename="kernel-blacklisted-7.3.5-1.el8+1944+b6c8e16f.noarch.rpm",
        ),
    ]

    mock_ubipop_runner.repos.pkgs_from_modules = deepcopy(mock_ubipop_runner.repos.packages)

    mock_ubipop_runner.repos.debug_rpms["kernel-blacklisted-debuginfo"] = [
        get_test_pkg(
            name="kernel-blacklisted-debuginfo",
            filename="kernel-blacklisted-debuginfo-7.3.5-1.el8+1944+b6c8e16f.noarch.rpm",
        ),
    ]

    mock_ubipop_runner._exclude_blacklisted_packages()

    assert len(mock_ubipop_runner.repos.packages) == 0
    # no blacklisting from pkgs from mds
    assert len(mock_ubipop_runner.repos.pkgs_from_modules) == 1
    assert len(mock_ubipop_runner.repos.debug_rpms) == 0
