import os
import subprocess
import io
import logging
import pytest
import requests
import ubiconfig
import ubipop

from ubipop._pulp_client import Pulp
from ubipop._utils import split_filename
from ubipop.ubi_manifest_client.client import Client
from pubtools.pulplib import (
    Repository,
    RpmUnit,
    Matcher,
)

from pubtools.pulplib import Client, Criteria
from rpm import labelCompare as label_compare  # pylint: disable=no-name-in-module
from ubipop._matcher import (
        UbiUnit,
        ModularMatcher,
        RpmMatcher,
    )

PULP_HOSTNAME = os.getenv("TEST_PULP_HOSTNAME")
PULP_USER = os.getenv("TEST_PULP_USER")
PULP_PWD = os.getenv("TEST_PULP_PWD")
PULP_CERT_PATH = os.getenv("TEST_PULP_CERT_PATH")
PULP_SECURE = os.getenv("TEST_PULP_SECURE", "0").lower() in ["true", "yes", "1"]
MANIFEST_URL = os.getenv("TEST_MANIFEST_URL")
REQUESTS_CA_BUNDLE = os.getenv("REQUESTS_CA_BUNDLE")
PULP_RPM_REPO_PREFIX = "/pulp/rpmrepos/"

TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), "./data")

INTEGRATION_NOT_SETUP = PULP_HOSTNAME is None


def load_ubiconfig(filename):
    loader = ubiconfig.get_loader(TEST_DATA_DIR)
    print (loader.load(filename))
    return loader.load(filename)


def make_pulp_client(url, auth, insecure):
    return Client(url=url, auth=auth, verify=not insecure)


def run_ubipop_tool(config_file, workers=10, dry_run=False, capture_log=False):
    if PULP_CERT_PATH is None:
        auth = (PULP_USER, PULP_PWD)
    else:
        auth = (PULP_CERT_PATH,)

    up = ubipop.UbiPopulate(
        pulp_hostname=PULP_HOSTNAME,
        pulp_auth=auth,
        dry_run=dry_run,
        ubiconfig_filename_list=[config_file],
        ubiconfig_dir_or_url=TEST_DATA_DIR,
        insecure=not PULP_SECURE,
        ubi_manifest_url="http://10.0.151.225:8000",
        workers_count=workers,
    )
    if capture_log:
        logger = logging.getLogger("ubipop")
        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        handler.setLevel(logging.WARNING)
        logger.addHandler(handler)

    up.populate_ubi_repos()

    if capture_log:
        captured = log_capture.getvalue()
        log_capture.close()
        return captured


def get_repos_from_cs(cs, skip_dot_version=False):
    p = Pulp(PULP_HOSTNAME, (PULP_USER, PULP_PWD), not PULP_SECURE)

    ret = p.do_request(
        "post",
        "repositories/search/",
        {
            "criteria": {
                "filters": {"notes.content_set": cs},
            },
            "distributors": False,
        },
    )

    ret.raise_for_status()

    for item in ret.json():
        notes = item["notes"]

        if skip_dot_version and "." in notes["platform_full_version"]:
            continue

        yield {
            "id": item["id"],
            "name": item["display_name"],
            "url": notes["relative_url"],
            "arch": notes["arch"],
        }


def query_pulp_rpms(repo_id, name=None, arch=None):
    p = Pulp(PULP_HOSTNAME, (PULP_USER, PULP_PWD), not PULP_SECURE)

    url = "repositories/{REPO_ID}/search/units/".format(REPO_ID=repo_id)

    criteria = {"type_ids": ["rpm", "srpm"]}
    filters = {"filters": {"unit": {}}}

    if name:
        filters["filters"]["unit"]["name"] = name
        criteria.update(filters)

    if arch:
        filters["filters"]["unit"]["arch"] = arch
        criteria.update(filters)

    res = p.do_request("post", url, {"criteria": criteria})
    res.raise_for_status()
    rpms = []

    for item in res.json():
        metadata = item["metadata"]
        rpms.append(
            {
                "name": metadata["name"],
                "arch": metadata["arch"],
                "filename": metadata["filename"],
            }
        )

    return rpms


def query_pulp_modules(repo_id, name=None, stream=None):
    p = Pulp(PULP_HOSTNAME, (PULP_USER, PULP_PWD), not PULP_SECURE)

    url = "repositories/{REPO_ID}/search/units/".format(REPO_ID=repo_id)

    criteria = {"type_ids": ["modulemd"]}

    if name and stream:
        criteria.update({"filters": {"unit": {"name": name, "stream": stream}}})

    res = p.do_request("post", url, {"criteria": criteria})
    res.raise_for_status()
    modules = []

    for item in res.json():
        metadata = item["metadata"]
        modules.append(
            {
                "name": metadata["name"],
                "arch": metadata["arch"],
                "stream": metadata["stream"],
                "artifacts": metadata["artifacts"],
                "profiles": metadata["profiles"],
            }
        )

    return modules


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
    print (args)
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
    repo_url=repo_url.replace("pulp/rpmrepos","")
    print (repo_url)
    url = "{}/Packages/{}/{}".format(repo_url, rpm[0].lower(), rpm)
    print (url)
    r = requests.head(url)
    return r.status_code == 200


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


def get_rpm_from_repo(repo, rpm_list):
    client = make_pulp_client(url="https://"+PULP_HOSTNAME+"/",auth=(PULP_USER,PULP_PWD),insecure=False)
    file_name = []
    repo = Repository(id=repo)
    repo.__dict__["_client"] = client
    crit = Criteria.and_(
        Criteria.with_field_in("content_type_id", ["rpm"]),
        Criteria.with_field_in("name", rpm_list),

    )
    repo_unit = repo.search_content(crit)
    for item in repo_unit:
        file_name.append(item.filename)
    return file_name


@pytest.mark.skipif(INTEGRATION_NOT_SETUP, reason="Integration test is not set up.")
def test_run_ubi_pop_for_rhel7():
    run_ubipop_tool("ubi7/rhel-7-server.yaml")


@pytest.mark.skipif(INTEGRATION_NOT_SETUP, reason="Integration test is not set up.")
def test_ubipop_can_associate_packages():
    """
    Test if ubipop can associate packages in the repo.

    One or more packages will be published to RPM, SRPM and debug repos.
    No packages are blacklisted.
    """

    def assert_pkgs(pkgs_included, pkgs_found):
        for pkg in pkgs_included:
            assert (
                pkg in pkgs_found
            ), '"{}" is whitelisted but not in the repository.'.format(pkg)

    cfg = load_ubiconfig("ubi7/rhel-7-server.yaml")

    repos = {
        "rpm": get_repos_from_cs(cfg.content_sets.rpm.output, skip_dot_version=True),
        "srpm": get_repos_from_cs(cfg.content_sets.srpm.output, skip_dot_version=True),
        "debug": get_repos_from_cs(
            cfg.content_sets.debuginfo.output, skip_dot_version=True
        ),
    }
    for item in repos:
        print (item)
    for repo_type, repo_iter in repos.items():
        if repo_type == "debug":
            filter_debug = (
                lambda pkg: "debuginfo" in pkg.name or "debugsource" in pkg.name
            )
        else:
            filter_debug = (
                lambda pkg: "debuginfo" not in pkg.name
                and "debugsource" not in pkg.name
            )

        pkgs_included = [
            pkg.name for pkg in cfg.packages.whitelist if filter_debug(pkg)
        ]
        for repo in repo_iter:
            repo_id = repo["id"]
            print (repo_id)
            repo_url = get_repo_url(repo["url"])

            pulp_rpms = query_pulp_rpms(repo_id)
            pkgs_found = [rpm["name"] for rpm in pulp_rpms]
            if "source" in repo_id:
                pkgs_included.remove("perl-FCGI")
                pkgs_included.remove("httpd-tools")
                pkgs_included.remove("kernel-headers")
            if "debug" in repo_id:
                pkgs_included.remove("ethtool-debuginfo")
                pkgs_included.remove("MySQL-python-debuginfo")
            assert_pkgs(pkgs_included, pkgs_found)

            repo_rpms = query_repo_rpms(None, "ubi", repo_url)
            pkgs_found = [clean_name(rpm) for rpm in repo_rpms]
            assert_pkgs(pkgs_included, pkgs_found)


@pytest.mark.skipif(INTEGRATION_NOT_SETUP, reason="Integration test is not set up.")
def test_ubipop_does_not_associate_packages_in_exclude_list():
    """
    Test if ubipop does not associate packages in blacklist in the repo.

    One package is whitelisted and will be associated to RPM and SRPM repo.
    The same package will not be included or blacklisted from debug repo.
    Additional packages are also blacklisted from all repos.
    No modules are whitelisted or blacklisted.
    """

    def assert_pkgs(pkgs_included, pkgs_found):
        for pkg in pkgs_included:
            assert (
                pkg not in pkgs_found
            ), '"{}" is blacklisted and should not in the repository.'.format(pkg)
    cfg = load_ubiconfig("ubi7/rhel-7-server.yaml")

    debug_repos = get_repos_from_cs(
        cfg.content_sets.debuginfo.output, skip_dot_version=True
    )
    for repo in debug_repos:
        repo_id = repo["id"]
        repo_url = get_repo_url(repo["url"])
        pulp_rpms = query_pulp_rpms(repo_id)
        repo_rpms = query_repo_rpms(None, "ubi", repo_url)
        pulp_pkgs_found = [rpm["name"] for rpm in pulp_rpms]
        repo_pkgs_found = [clean_name(rpm) for rpm in repo_rpms]
        pkgs_included = [pkg.name for pkg in cfg.packages.blacklist]
        assert len(pulp_pkgs_found) == len(repo_pkgs_found)
        assert_pkgs(pkgs_included, pulp_pkgs_found)


def get_last_version_rpms(filenames):
    rpms = []
    for f in filenames:
        print ("fff"+f)
        rpm = filename_convert_to_rpm(f)
        rpms.append(rpm)
    rpms.sort(key=vercmp_sort())
    matcher = RpmMatcher(None, None)
    matcher._keep_n_latest_rpms(rpms)
    return rpms[0]


def filename_convert_to_rpm(filename):
    """
    Pass in a standard style rpm fullname

    Return a name, version, release, epoch, arch, e.g.::
        foo-1.0-1.i386.rpm returns foo, 1.0, 1, i386
        1:bar-9-123a.ia64.rpm returns bar, 9, 123a, 1, ia64
    """

    if filename[-4:] == ".rpm":
        filename = filename[:-4]

    arch_index = filename.rfind(".")
    arch = filename[arch_index + 1:]

    rel_index = filename[:arch_index].rfind("-")
    rel = filename[rel_index + 1: arch_index]

    ver_index = filename[:rel_index].rfind("-")
    ver = filename[ver_index + 1: rel_index]

    epoch_index = filename.find(":")

    if epoch_index == -1:
        epoch = ""
    else:
        epoch = filename[:epoch_index]

    name = filename[epoch_index + 1: ver_index]

    return UbiUnit(
        RpmUnit(
            name=name,
            version=ver,
            release=rel,
            epoch=epoch,
            arch=arch,
        ),
        None,
    )


def vercmp_sort():
    class Klass(object):
        def __init__(self, package):
            self.evr_tuple = (package.epoch, package.version, package.release)

        def __lt__(self, other):
            return label_compare(self.evr_tuple, other.evr_tuple) < 0

        def __gt__(self, other):
            return label_compare(self.evr_tuple, other.evr_tuple) > 0

        def __eq__(self, other):
            return label_compare(self.evr_tuple, other.evr_tuple) == 0

        def __le__(self, other):
            return label_compare(self.evr_tuple, other.evr_tuple) <= 0

        def __ge__(self, other):
            return label_compare(self.evr_tuple, other.evr_tuple) >= 0

        def __ne__(self, other):
            return label_compare(self.evr_tuple, other.evr_tuple) != 0

    return Klass


def get_in_repo_from_config(config_file):
    repo_dir = {}
    repo_url = {}
    cfg = load_ubiconfig(config_file)
    repos = {
        "rpm": get_repos_from_cs(cfg.content_sets.rpm.input, skip_dot_version=True),
        "srpm": get_repos_from_cs(cfg.content_sets.srpm.input, skip_dot_version=True),
        "debug": get_repos_from_cs(
            cfg.content_sets.debuginfo.input, skip_dot_version=True
        ),
    }
    for repo_type, repo_iter in repos.items():
        print (repo_type, repo_iter)
        for repo in repo_iter:
            repo_url[repo_type] = repo["url"]
            repo_dir[repo_type] = repo["id"]

    return repo_dir, repo_url


def get_out_repo_from_config(config_file):
    repo_dir = {}
    repo_url = {}
    cfg = load_ubiconfig(config_file)
    repos = {
        "rpm": get_repos_from_cs(cfg.content_sets.rpm.output, skip_dot_version=True),
        "srpm": get_repos_from_cs(cfg.content_sets.srpm.output, skip_dot_version=True),
        "debug": get_repos_from_cs(
            cfg.content_sets.debuginfo.output, skip_dot_version=True
        ),
    }
    for repo_type, repo_iter in repos.items():
        print (repo_type, repo_iter)
        for repo in repo_iter:
            repo_dir[repo_type] = repo["id"]
            repo_url[repo_type] = repo["url"]

    return repo_dir, repo_url


@pytest.mark.skipif(INTEGRATION_NOT_SETUP, reason="Integration test is not set up.")
def test_ubipop_only_associate_higher_version_rpm():
    """
    Test if ubipop associate the latest packages in the repo.
    """
    expected_name = ["MySQL-python"]
    rpm_repo, _ = get_in_repo_from_config("ubi7/rhel-7-server.yaml")
    rpm_out_repo, rpm_out_repo_url=get_out_repo_from_config("ubi7/rhel-7-server.yaml")

    expected_rpms = get_rpm_from_repo(rpm_repo["rpm"], expected_name)
    expected_latst_rpm = get_last_version_rpms(expected_rpms)
    actual_rpms = get_rpm_from_repo(rpm_out_repo["rpm"], expected_name)
    actual_rpm = filename_convert_to_rpm(actual_rpms[0])
    assert vars(expected_latst_rpm) == vars(actual_rpm)
    repo_url = get_repo_url(rpm_out_repo_url["rpm"])
    repo_rpms = query_repo_rpms(None, "ubi", repo_url)
    assert actual_rpms[0] in repo_rpms, "pulp repo doesn't have the rpm"
    for rpm in actual_rpms:
        assert can_download_package(
            rpm, repo_url
        ), "Can't download package: {}".format(rpm)


def get_module_from_repo(repo, module_name):
    client = make_pulp_client(url="https://"+PULP_HOSTNAME+"/",auth=(PULP_USER,PULP_PWD),insecure=False)
    module = []
    repo = Repository(id=repo)
    repo.__dict__["_client"] = client
    crit = Criteria.and_(
        Criteria.with_field_in("content_type_id", ["modulemd"]),
        Criteria.with_field_in("name", module_name),

    )
    repo_unit = repo.search_content(crit)
    for item in repo_unit:
        module.append(item)
    return module


def get_module_default_from_repo(repo, module_name):
    client = make_pulp_client(url="https://"+PULP_HOSTNAME+"/", auth=(PULP_USER,PULP_PWD), insecure=False)
    module_default = []
    repo = Repository(id=repo)
    repo.__dict__["_client"] = client
    crit = Criteria.and_(
        Criteria.with_field_in("content_type_id", ["modulemd_defaults"]),
        Criteria.with_field_in("name", module_name),

    )
    repo_unit = repo.search_content(crit)
    for item in repo_unit:
        module_default.append(item)
    return module_default


@pytest.mark.skipif(INTEGRATION_NOT_SETUP, reason="Integration test is not set up.")
def test_ubipop_can_associate_dependencies_rpm():
    """
    Test if ubipop associate the rpm which is required by
    the whitelist rpms.
    """
    expected_name = ['glibc']
    rpm_out_repos, _ = get_out_repo_from_config("ubi7/rhel-7-server.yaml")
    rpm_in_repos, _ = get_out_repo_from_config("ubi7/rhel-7-server.yaml")
    expected_rpm = get_rpm_from_repo(rpm_in_repos["rpm"], expected_name)
    actual_rpm = get_rpm_from_repo(rpm_out_repos["rpm"], expected_name)
    assert expected_rpm == actual_rpm, "actual rpm doesn't the same"


@pytest.mark.skipif(INTEGRATION_NOT_SETUP, reason="Integration test is not set up.")
def test_ubipop_can_associate_module_unit():
    """
    Test if ubipop associate the module which is defined in the module.
    """

    cfg = load_ubiconfig("ubi7/rhel-7-server.yaml")
    mds_included = {}
    for md in cfg.modules.whitelist:
        mds_included[md.name] = md.stream
    rpm_out_repos, _ = get_out_repo_from_config("ubi7/rhel-7-server.yaml")
    rpm_in_repos, in_repo_url = get_in_repo_from_config("ubi7/rhel-7-server.yaml")
    expected_module = get_module_from_repo(rpm_in_repos["rpm"], mds_included.keys())
    actual_module = get_module_from_repo(rpm_out_repos["rpm"], mds_included.keys())
    repo_url = get_repo_url(in_repo_url["rpm"])
    assert len(expected_module) == len(actual_module), "the module_unit is not associated"


@pytest.mark.skipif(INTEGRATION_NOT_SETUP, reason="Integration test is not set up.")
def test_ubipop_can_associate_module_default_unit():
    """
    Test if ubipop associate the module default which is defined in the module.
    """
    cfg = load_ubiconfig("ubi7/rhel-7-server.yaml")
    mds_included = {}
    for md in cfg.modules.whitelist:
        mds_included[md.name] = md.stream
    rpm_out_repos, _ = get_out_repo_from_config("ubi7/rhel-7-server.yaml")
    rpm_in_repos, _ = get_in_repo_from_config("ubi7/rhel-7-server.yaml")
    expected_module_default = get_module_default_from_repo(rpm_in_repos["rpm"], mds_included.keys())

    actual_module_default = get_module_default_from_repo(rpm_out_repos["rpm"], mds_included.keys())
    assert len(expected_module_default) == len(actual_module_default), "the module_default is not associated"


def get_module_of_rpm_from_repo(repo, module_name):
    moduleunit = get_module_from_repo(repo, module_name)
    filenames = set()
    for module in moduleunit:
        pkgs_names = []
        for filename in module.artifacts_filenames:
            # skip source rpms
            if filename.endswith(".src.rpm"):
                continue

            # if need to take only some packages from profiles
            if pkgs_names:
                name, _, _, _, _ = split_filename(filename)
                if name not in pkgs_names:
                    continue

            filenames.add(filename)

    return filenames


@pytest.mark.skipif(INTEGRATION_NOT_SETUP, reason="Integration test is not set up.")
def test_run_ubi_pop_for_rhel8():
    run_ubipop_tool("ubi8/rhel-8-server.yaml")


def get_last_version_module(modules):
    matcher = ModularMatcher(None, None)
    name_stream_modules_map = {}
    for modulemd in modules:
        key = modulemd.name + modulemd.stream
        name_stream_modules_map.setdefault(key, []).append(modulemd)

    out = []
    for module_list in name_stream_modules_map.values():
        module_list.sort(key=lambda module: module.version)
        matcher._keep_n_latest_modules(module_list)
        out.extend(module_list)

    return out


@pytest.mark.skipif(INTEGRATION_NOT_SETUP, reason="Integration test is not set up.")
def test_ubipop_can_associate_module_rpm():
    """
    Test if ubipop associate the rpm which list under whitelist's module of artificatrs.
    """
    rpm_out_repos, _ = get_out_repo_from_config("ubi8/rhel-8-server.yaml")
    rpm_in_repos, _ = get_in_repo_from_config("ubi8/rhel-8-server.yaml")
    expected = ["perl"]
    expected_rpm = ["perl-5.24.4-404.module+el8.1.0+2926+ce7246ad.x86_64.rpm"]
    actual_module_of_rpm = get_module_of_rpm_from_repo(rpm_out_repos["rpm"], expected)
    assert expected_rpm[0] in actual_module_of_rpm, "the module_rpm is not associated"
