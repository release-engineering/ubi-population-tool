import json
import logging
import os
import subprocess

import pytest
import requests
import ubiconfig
from pubtools.pulplib import (
    Client,
    Criteria,
    Matcher,
    ModulemdDefaultsUnit,
    ModulemdUnit,
    RpmUnit,
)

import ubipop

PULP_HOSTNAME = os.getenv("TEST_PULP_HOSTNAME")
PULP_USER = os.getenv("TEST_PULP_USER")
PULP_PWD = os.getenv("TEST_PULP_PWD")
PULP_CERT_PATH = os.getenv("TEST_PULP_CERT_PATH")
PULP_KEY_PATH = os.getenv("TEST_PULP_KEY_PATH")
PULP_SECURE = os.getenv("TEST_PULP_SECURE", "0").lower() in ["true", "yes", "1"]
MANIFEST_URL = os.getenv("TEST_MANIFEST_URL")
REQUESTS_CA_BUNDLE = os.getenv("REQUESTS_CA_BUNDLE")
GITLAB_CONFIG_URL = os.getenv("GITLAB_CONFIG_URL")
PULP_RPM_REPO_PREFIX = "/pulp/rpmrepos/"

TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), "./data")

INTEGRATION_NOT_SETUP = PULP_HOSTNAME is None


def load_ubiconfig(filename, version):
    loader = ubiconfig.get_loader(GITLAB_CONFIG_URL)
    return loader.load(filename, version)


@pytest.fixture(name="pulp_client")
def make_pulp_client():
    kwargs = {
        "verify": PULP_SECURE,
    }

    if PULP_CERT_PATH is not None and PULP_KEY_PATH is not None:
        kwargs["cert"] = (PULP_CERT_PATH, PULP_KEY_PATH)
    # if cert/key not present, use user/pass auth to pulp
    else:
        kwargs["auth"] = (PULP_USER, PULP_PWD)

    return Client("https://" + PULP_HOSTNAME + "/", **kwargs)


def run_ubipop_tool(content_set, workers=10, dry_run=False):
    if PULP_CERT_PATH is None:
        auth = (PULP_USER, PULP_PWD)
    else:
        auth = (PULP_CERT_PATH, PULP_KEY_PATH)

    up = ubipop.UbiPopulate(
        pulp_hostname=PULP_HOSTNAME,
        pulp_auth=auth,
        dry_run=dry_run,
        ubiconfig_dir_or_url=GITLAB_CONFIG_URL,
        verify=PULP_SECURE,
        workers_count=workers,
        ubi_manifest_url=MANIFEST_URL,
        content_sets=content_set,
    )

    logging.basicConfig()
    logger = logging.getLogger("ubipop")
    logger.setLevel(logging.INFO)
    up.populate_ubi_repos()


def get_repos_from_cs(cs, skip_dot_version=False):
    kwargs = {"verify": PULP_SECURE}
    if PULP_CERT_PATH is not None:
        kwargs["cert"] = (PULP_CERT_PATH, PULP_KEY_PATH)
    else:
        kwargs["auth"] = (PULP_USER, PULP_PWD)
    p = Client("https://" + PULP_HOSTNAME, **kwargs)

    repos = p.search_repository(Criteria.with_field("notes.content_set", cs))

    for repo in repos:
        if skip_dot_version and "." in repo.platform_full_version:
            continue

        yield {
            "id": repo.id,
            "url": repo.relative_url,
            "arch": repo.arch,
        }


def query_repo_rpms(query, repo_id, repo_url, force_refresh=True, arch_list=None):
    args = [
        "yum",
        "repoquery",
        "-q",
        "--envra",
        "--repoid={}".format(repo_id),
        "--repofrompath={},{}".format(repo_id, repo_url),
    ]

    if force_refresh:
        args.append("--refresh")

    if arch_list is not None:
        args.append(
            "--archlist={}".format(",".join(arch_list)),
        )

    if query is not None:
        args.append(query)
    out = subprocess.check_output(args, shell=False)

    if isinstance(out, bytes):
        out = out.decode()

    return [pkg.split(":")[1] + ".rpm" for pkg in out.split("\n") if pkg]


def query_repo_modules(
    query, repo_id, repo_url, force_refresh=True, arch_list=None, full_data=False
):
    args = [
        "yum",
        "module",
        "list",
        "-q",
        "--repoid={}".format(repo_id),
        "--repofrompath={},{}".format(repo_id, repo_url),
    ]
    if force_refresh:
        args.append("--refresh")

    if arch_list is not None:
        args.append(
            "--archlist={}".format(",".join(arch_list)),
        )

    if query is not None:
        args.append(query)

    out = subprocess.check_output(args, shell=False)

    if isinstance(out, bytes):
        out = out.decode()

    lines = out.split("\n")
    lines = lines[2:-3]
    if not full_data:
        return [md.split(" ")[0] for md in lines]
    else:
        return lines


def get_repo_url(relative_url):
    if PULP_SECURE:
        scheme = "https"
    else:
        scheme = "http"

    return "{scheme}://{host}{prefix}{relative_url}".format(
        scheme=scheme,
        host=PULP_HOSTNAME,
        prefix=PULP_RPM_REPO_PREFIX,
        relative_url=relative_url,
    )


def can_download_package(rpm, repo_url):
    repo_url = repo_url.replace("pulp/rpmrepos", "")
    url = "{}/Packages/{}/{}".format(repo_url, rpm[0].lower(), rpm)
    r = requests.head(url)
    return r.status_code == 200


def split_filename(filename):
    """
    Pass in a standard style rpm fullname

    Return a name, version, release, epoch, arch, e.g.::
        foo-1.0-1.i386.rpm returns foo, 1.0, 1, i386
        1:bar-9-123a.ia64.rpm returns bar, 9, 123a, 1, ia64
    """

    if filename[-4:] == ".rpm":
        filename = filename[:-4]

    arch_index = filename.rfind(".")
    arch = filename[arch_index + 1 :]

    rel_index = filename[:arch_index].rfind("-")
    rel = filename[rel_index + 1 : arch_index]

    ver_index = filename[:rel_index].rfind("-")
    ver = filename[ver_index + 1 : rel_index]

    epoch_index = filename.find(":")

    if epoch_index == -1:
        epoch = ""
    else:
        epoch = filename[:epoch_index]

    name = filename[epoch_index + 1 : ver_index]

    return name, ver, rel, epoch, arch


def clean_name(name):
    return split_filename(name)[0]


def separate_modules(module_list):
    """
    Create a tuple consisting of module name and additional module data.
    """
    return [
        (module[: module.find(" ")], module[module.find(" ") + 1 :])
        for module in module_list
    ]


def get_rpm_from_repo(client, repo, rpm_list, field):

    rpm = []
    if field == "name":
        repo_unit = get_rpm_by_name(client, repo, rpm_list)
    else:
        repo_unit = get_rpm_by_filename(client, repo, rpm_list)
    for item in repo_unit:
        rpm.append(item.filename)
    return rpm


def get_rpm_by_name(client, repo, package_name):
    repo = client.get_repository(repo)
    crit = Criteria.and_(
        Criteria.with_unit_type(RpmUnit),
        Criteria.with_field("name", Matcher.in_(package_name)),
    )
    repo_unit = repo.search_content(crit)
    return repo_unit


def get_rpm_by_filename(client, repo, filename):
    repo = client.get_repository(repo)
    crit = Criteria.and_(
        Criteria.with_unit_type(RpmUnit),
        Criteria.with_field("filename", Matcher.in_(filename)),
    )
    repo_unit = repo.search_content(crit)
    return repo_unit


def get_modulemd_from_repo(client, repo, modulemd_nsvca):
    modulemd = []
    n, s, v, c, a = modulemd_nsvca.split(":")
    v = int(v)
    repo = client.get_repository(repo)
    crit = Criteria.and_(
        Criteria.with_unit_type(ModulemdUnit),
        Criteria.with_field("name", n),
        Criteria.with_field("stream", s),
        Criteria.with_field("version", v),
        Criteria.with_field("context", c),
        Criteria.with_field("arch", a),
    )
    repo_unit = repo.search_content(crit)
    for item in repo_unit:
        modulemd.append(item.nsvca)
    return modulemd


def get_modulemd_default_from_repo(client, repo, module_ns):
    modulemd_default = []
    n, s = module_ns.split(":")
    repo = client.get_repository(repo)
    crit = Criteria.and_(
        Criteria.with_unit_type(ModulemdDefaultsUnit),
        Criteria.with_field("name", n),
        Criteria.with_field("stream", s),
    )
    repo_unit = repo.search_content(crit)
    for item in repo_unit:
        modulemd_default.append(item)
    return modulemd_default


def get_rpm_from_expected_json(filename):
    filename = TEST_DATA_DIR + "/" + filename
    # Opening JSON file

    with open(filename) as f:
        data = json.load(f)
        files = []
        modules = []
        modulemd_defaults = []
        for i in data["content"]:
            if i["unit_type"] == "RpmUnit":
                files.append(i["value"])
            if i["unit_type"] == "ModulemdUnit":
                modules.append(i["value"])
            if i["unit_type"] == "ModulemdDefaultsUnit":
                modulemd_defaults.append(i["value"])
    return files, modules, modulemd_defaults


def get_input_or_output_repo_from_config(config_file, version, in_repo=True):
    repo_dir = {}
    repo_url = {}
    cfg = load_ubiconfig(config_file, version)
    if in_repo:
        repos = {
            "rpm": get_repos_from_cs(cfg.content_sets.rpm.input, skip_dot_version=True),
            "srpm": get_repos_from_cs(
                cfg.content_sets.srpm.input, skip_dot_version=True
            ),
            "debug": get_repos_from_cs(
                cfg.content_sets.debuginfo.input, skip_dot_version=True
            ),
        }
    else:
        repos = {
            "rpm": get_repos_from_cs(
                cfg.content_sets.rpm.output, skip_dot_version=True
            ),
            "srpm": get_repos_from_cs(
                cfg.content_sets.srpm.output, skip_dot_version=True
            ),
            "debug": get_repos_from_cs(
                cfg.content_sets.debuginfo.output, skip_dot_version=True
            ),
        }
    for repo_type, repo_iter in repos.items():
        for repo in repo_iter:
            repo_url[repo_type] = repo["url"]
            repo_dir[repo_type] = repo["id"]

    return repo_dir, repo_url


def filter_debug_packages(type, cfg_packages_whitelist):
    if type == "debug":
        filter_debug = lambda pkg: pkg.name.endswith("debuginfo") or pkg.name.endswith(
            "debugsource"
        )

    else:
        filter_debug = lambda pkg: not pkg.name.endswith(
            "debuginfo"
        ) or not pkg.name.endswith("debugsource")

    pkgs_expected_exclude = [
        pkg.name for pkg in cfg_packages_whitelist if filter_debug(pkg)
    ]

    return pkgs_expected_exclude


def run_pub_client_publish(repo_ids, target):
    cmd = ["pub", "publish", "--target", target]
    for repo_id in repo_ids:
        cmd.extend(["--repo", repo_id])
    try:
        ret = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode("utf-8")
        if "CLOSED" not in ret:
            logging.info("The publish is not successful, so please check it first")
            raise Exception("The publish fails as some reason")
        else:
            logging.info("The publish is successful")
    except subprocess.CalledProcessError as ex:
        logging.error(
            "Command: %s returns with error %s: %s",
            ex.cmd,
            ex.returncode,
            ex.output,
        )
        raise ex


@pytest.mark.skipif(INTEGRATION_NOT_SETUP, reason="Integration test is not set up.")
def test_run_ubi_pop_for_rhel7(pulp_client):
    run_ubipop_tool(["rhel-7-server-rpms"])

    (
        content_set_output_repo,
        content_set_output_repo_url,
    ) = get_input_or_output_repo_from_config(
        "rhel-7-server.yaml", "ubi7.7", in_repo=False
    )
    (
        expected_rpm_list,
        expected_modulemd_list,
        expected_modulemd_default_list,
    ) = get_rpm_from_expected_json("ubi7/expected_rhel7_repo.json")
    rpm_repo = content_set_output_repo["rpm"]
    rpm_repo_url = get_repo_url(content_set_output_repo_url["rpm"])
    run_pub_client_publish([rpm_repo], "target_to_pulp2_ubi")
    for rpm in expected_rpm_list:
        # verify the rpm exist in the repo
        assert get_rpm_from_repo(
            pulp_client, rpm_repo, [rpm], "filename"
        ), "Can't find the rpm :{}".format(rpm)
        # verify the rpm exist in the cdn server
        assert can_download_package(
            rpm, rpm_repo_url
        ), "Can't download package: {}".format(rpm)

    # verify the modulemd exist in the repo
    for modulemd in expected_modulemd_list:
        assert get_modulemd_from_repo(
            pulp_client, rpm_repo, modulemd
        ), "Can't find the modulemd :{}".format(modulemd)

    # verify the modulemd_default exist in the repo
    for modulemd_defaults in expected_modulemd_default_list:
        assert get_modulemd_default_from_repo(
            pulp_client, rpm_repo, modulemd_defaults
        ), "Can't find the modulemd_default :{}".format(modulemd_defaults)

    # verify the modulemd exist and modulemd default in the cdn server
    modulemds = query_repo_modules(None, "ubi", rpm_repo_url)
    while "" in modulemds:
        modulemds.remove("")
    assert len(modulemds) == 3, "Unexpected repo modulemds found."
    # assert the module prefile
    modulemds = query_repo_modules(None, "ubi", rpm_repo_url, full_data=True)
    mod_name, mod_profile = separate_modules(modulemds)[0]
    assert mod_name == "httpd", "Expected modulemd: httpd, found modulemd: {}".format(
        mod_name
    )
    assert (
        "common" in mod_profile
    ), "Modulemd httpd should have common profile as default."


@pytest.mark.skipif(INTEGRATION_NOT_SETUP, reason="Integration test is not set up.")
def test_ubipop_does_not_associate_packages_in_exclude_list(pulp_client):
    """
    Test if ubipop does not associate packages in the repo.

    One package in whitelisted and blacklist at the same time
    will not be associated to repo.
    No modules are whitelisted or blacklisted.
    """
    publish_repos = []
    cfg = load_ubiconfig("rhel-8-for-x86_64-baseos.yaml", "ubi8.5")
    (
        content_set_output_repo,
        content_set_output_repo_url,
    ) = get_input_or_output_repo_from_config(
        "rhel-8-for-x86_64-baseos.yaml", "ubi8.5", in_repo=False
    )
    # the exclude packages are ["gettext","ncurses","gettext-debuginfo","ncurses-debuginfo"]
    for item in content_set_output_repo:
        pkg = filter_debug_packages(item, cfg.packages.blacklist)
        # verify before do the ubipop, one package.blacklist in the ubi repo, "ncurses" in rpm and source ubi repo
        # "ncurses-debuginfo" in debug ubi repo
        assert (
            len(
                get_rpm_from_repo(
                    pulp_client, content_set_output_repo[item], pkg, "name"
                )
            )
        ) == 1

    run_ubipop_tool(["rhel-8-for-x86_64-baseos-rpms"])
    for item in content_set_output_repo:
        publish_repos.append(content_set_output_repo[item])
    run_pub_client_publish(publish_repos, "target_to_pulp2_ubi")
    # #verify after ubipop, no exclude package rpm exist in the ubi repo, as it is unassoicated
    for item in content_set_output_repo:
        pkg = filter_debug_packages(item, cfg.packages.blacklist)
        assert not get_rpm_from_repo(
            pulp_client, content_set_output_repo[item], pkg, "name"
        ), "find the package which should be exclude:{} in {}".format(
            pkg, content_set_output_repo[item]
        )

    expected_module_rpm = [
        "perl-HTTP-Tiny-0.074-2.module+el8.1.0+2926+ce7246ad.noarch.rpm"
    ]

    (
        content_set_output_repo_appstream,
        content_set_output_repo_url_appstream,
    ) = get_input_or_output_repo_from_config(
        "rhel-8-for-x86_64-appstream.yaml", "ubi8.5", in_repo=False
    )

    # verify before do the ubipop, one module rpm in the ubi repo
    assert (
        len(
            get_rpm_from_repo(
                pulp_client,
                content_set_output_repo_appstream["rpm"],
                expected_module_rpm,
                "filename",
            )
        )
    ) == 1
    run_ubipop_tool(["rhel-8-for-x86_64-appstream-rpms"])
    run_pub_client_publish(
        [content_set_output_repo_appstream["rpm"]], "target_to_pulp2_ubi"
    )
    # verify after ubipop, the modulemd rpm still not be unassociated, though it's in blacklist
    assert (
        len(
            get_rpm_from_repo(
                pulp_client,
                content_set_output_repo_appstream["rpm"],
                expected_module_rpm,
                "filename",
            )
        )
    ) == 1


@pytest.mark.skipif(INTEGRATION_NOT_SETUP, reason="Integration test is not set up.")
def test_ubipop_not_filter_non_module_rpm_and_module_rpm_with_same_package(pulp_client):
    """
    Test if ubipop will not exclude non-module rpm in the repo.
    non-module rpm and module_rpm has the same package perl, which should be included after pop
    Module_rpm and non-module rpm will not be filter, so when module_rpm has less version than
    module_rpm, it will not be excluded also.
    """
    expected = [
        "perl-5.26.3-420.el8.s390x.rpm",
        "perl-5.32.1-471.module+el8.6.0+13324+628a2397.s390x.rpm",
    ]

    (
        content_set_output_repo,
        content_set_output_repo_url,
    ) = get_input_or_output_repo_from_config(
        "rhel-8-for-s390x-appstream.yaml", "ubi8.5", in_repo=False
    )

    (
        content_set_input_repo,
        content_set_input_repo_url,
    ) = get_input_or_output_repo_from_config(
        "rhel-8-for-s390x-appstream.yaml", "ubi8.5", in_repo=True
    )

    # verify the two packages do not be included in the ubi repo
    assert not get_rpm_from_repo(
        pulp_client, content_set_output_repo["rpm"], expected, "filename"
    )

    # verify the two packages is in the rhel input repo, so when afer ubipop, it will be associated
    for rpm in expected:
        # verify the rpm exist in the rhel input repo
        assert get_rpm_from_repo(
            pulp_client, content_set_input_repo["rpm"], [rpm], "filename"
        ), "Can't find the rpm in the rhel repo:{}".format(rpm)

    run_ubipop_tool(["rhel-8-for-s390x-appstream-rpms"])
    run_pub_client_publish([content_set_output_repo["rpm"]], "target_to_pulp2_ubi")
    rpm_repo_url = get_repo_url(content_set_output_repo_url["rpm"])

    # verify the two packages are associated
    for rpm in expected:
        # verify the rpm exist in the ubi repo
        assert get_rpm_from_repo(
            pulp_client, content_set_output_repo["rpm"], [rpm], "filename"
        ), "Can't find the rpm :{}".format(rpm)
        # verify the rpm exist in the cdn server
        assert can_download_package(
            rpm, rpm_repo_url
        ), "Can't download package: {}".format(rpm)


@pytest.mark.skipif(INTEGRATION_NOT_SETUP, reason="Integration test is not set up.")
def test_ubipop_not_filter_module_rpm_with_different_version(pulp_client):
    """
    Test if ubipop will not filter module rpm in the repo

    """
    (
        content_set_output_repo,
        content_set_output_repo_url,
    ) = get_input_or_output_repo_from_config(
        "rhel-8-for-ppc64le-appstream.yaml", "ubi8.5", in_repo=False
    )
    (
        expected_rpm_list,
        expected_modulemd_list,
        expected_modulemd_default_list,
    ) = get_rpm_from_expected_json("ubi8/expected_rhel8_ppc64le_repo.json")
    rpm_repo = content_set_output_repo["rpm"]
    rpm_repo_url = get_repo_url(content_set_output_repo_url["rpm"])

    # verify the ubi repo is empty, no rpm and no module before ubipop
    assert not get_rpm_from_repo(
        pulp_client, rpm_repo, expected_rpm_list, "filename"
    ), "rpm exist in the ubi repo"
    for modulemd in expected_modulemd_list:
        assert not get_modulemd_from_repo(
            pulp_client, rpm_repo, modulemd
        ), "modulemd exist in the ubi repo"
    for modulemd_default in expected_modulemd_default_list:
        assert not get_modulemd_default_from_repo(
            pulp_client, rpm_repo, modulemd_default
        ), "modulemd_default exist in the ubi repo"
    run_ubipop_tool(["rhel-8-for-ppc64le-appstream-rpms"], dry_run=True)

    # after dry run, no change, so the repo still is empty

    assert not get_rpm_from_repo(
        pulp_client, rpm_repo, expected_rpm_list, "filename"
    ), "rpm exist in the ubi repo"
    for modulemd in expected_modulemd_list:
        assert not get_modulemd_from_repo(
            pulp_client, rpm_repo, modulemd
        ), "modulemd exist in the ubi repo"
    for modulemd_default in expected_modulemd_default_list:
        assert not get_modulemd_default_from_repo(
            pulp_client, rpm_repo, modulemd_default
        ), "modulemd_default exist in the ubi repo"

    run_ubipop_tool(["rhel-8-for-ppc64le-appstream-rpms"])
    run_pub_client_publish([rpm_repo], "target_to_pulp2_ubi")
    for rpm in expected_rpm_list:
        if "containers-common" in rpm:
            # verify the containers-common rpm exist in the repo
            assert get_rpm_from_repo(
                pulp_client, rpm_repo, [rpm], "filename"
            ), "Can't find the rpm :{}".format(rpm)
            # verify the rpm exist in the cdn server
            assert can_download_package(
                rpm, rpm_repo_url
            ), "Can't download package: {}".format(rpm)

    # verify the modulemd exist in the repo
    for modulemd in expected_modulemd_list:
        assert get_modulemd_from_repo(
            pulp_client, rpm_repo, modulemd
        ), "Can't find the modulemd :{}".format(modulemd)

    # verify the modulemd_default exist in the repo
    for modulemd_defaults in expected_modulemd_default_list:
        assert get_modulemd_default_from_repo(
            pulp_client, rpm_repo, modulemd_defaults
        ), "Can't find the modulemd_default :{}".format(modulemd_defaults)

    # verify the modulemd exist and modulemd default in the cdn server
    modulemds = query_repo_modules(None, "ubi", rpm_repo_url, full_data=True)
    assert len(modulemds) == 6, "Unexpected repo modulemds found."
    mod_name, mod_profile = separate_modules(modulemds)[1]
    assert (
        mod_name == "container-tools"
    ), "Expected modulemd: container-tools, found modulemd: {}".format(mod_name)
    assert (
        "common" in mod_profile
    ), "Modulemd container-tools should have common profile as default."


@pytest.mark.skipif(INTEGRATION_NOT_SETUP, reason="Integration test is not set up.")
def test_ubipop_get_dependencies_module_rpm(pulp_client):
    """
    Test if ubipop get the dependencies of module
    ubipop can get the dependencies of rpm

    """

    expected_module = ["perl:5.24:8010020190529084201:3af8e029:aarch64"]
    expected_packages = ["ncurses", "ncurses-base", "ncurses-libs"]

    cfg = load_ubiconfig("rhel-8-for-aarch64-appstream.yaml", "ubi8.5")
    (
        content_set_output_repo,
        content_set_output_repo_url,
    ) = get_input_or_output_repo_from_config(
        "rhel-8-for-aarch64-appstream.yaml", "ubi8.5", in_repo=False
    )

    # verify the ubiconfig_include doesn't have the perl:5.24
    mds_stream = []
    for md in cfg.modules.whitelist:
        if md.name == "perl":
            mds_stream.append(md.stream)
    assert md.stream[0] != expected_module[0].split(":")[1]
    # verify before ubipop, not perl:5.24 in ubi repo
    for modulemd in expected_module:
        assert not get_modulemd_from_repo(
            pulp_client, content_set_output_repo["rpm"], modulemd
        ), "Can find the modulemd :{}".format(modulemd)

    run_ubipop_tool("rhel-8-for-aarch64-appstream-rpms")
    run_pub_client_publish([content_set_output_repo["rpm"]], "target_to_pulp2_ubi")
    # verify the perl:5.24 is in the ubi repo, though the config only include perl:5.32.

    for modulemd in expected_module:
        assert get_modulemd_from_repo(
            pulp_client, content_set_output_repo["rpm"], modulemd
        ), "Can't find the modulemd :{}".format(modulemd)

    # verity before ubipop, there is no expected_rpm exist in ubi-8-for-aarch64-base-rpms
    # and there is no such package in config
    cfg_base = load_ubiconfig("rhel-8-for-aarch64-baseos.yaml", "ubi8.5")
    (
        content_set_output_repo_base,
        content_set_output_repo_url_base,
    ) = get_input_or_output_repo_from_config(
        "rhel-8-for-aarch64-baseos.yaml", "ubi8.5", in_repo=False
    )
    pkgs_included = [pkg.name for pkg in cfg_base.packages.whitelist]
    for package in expected_packages:
        assert package not in pkgs_included
        assert (
            len(
                get_rpm_from_repo(
                    pulp_client, content_set_output_repo_base["rpm"], [package], "name"
                )
            )
            == 0
        ), "packages should not exist in ubi repo :{}".format(package)

    run_ubipop_tool("rhel-8-for-aarch64-baseos-rpms")
    run_pub_client_publish([content_set_output_repo_base["rpm"]], "target_to_pulp2_ubi")
    # verify after ubipop, the package exist as depencidies rpm, though no config
    # here also verify the set of repo ubi-8-for-aarch64-base-rpms be published
    for package in expected_packages:
        assert (
            len(
                get_rpm_from_repo(
                    pulp_client, content_set_output_repo_base["rpm"], [package], "name"
                )
            )
            != 0
        ), "packages should not exist in ubi repo :{}".format(package)
