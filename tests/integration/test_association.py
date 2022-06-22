import os
import subprocess
import logging
import pytest
import requests
import ubiconfig
import ubipop
import json

from ubipop._pulp_client import Pulp
from ubipop._utils import split_filename
from ubipop.ubi_manifest_client.client import Client

from pubtools.pulplib import (
    Client,
    Criteria,
    Matcher,
    ModulemdUnit,
    RpmUnit,
    ModulemdDefaultsUnit,
)

PULP_HOSTNAME = os.getenv("TEST_PULP_HOSTNAME")
PULP_USER = os.getenv("TEST_PULP_USER")
PULP_PWD = os.getenv("TEST_PULP_PWD")
PULP_CERT_PATH = os.getenv("TEST_PULP_CERT_PATH")
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
    with Client(
        url="https://" + PULP_HOSTNAME + "/", auth=(PULP_USER, PULP_PWD), verify=True
    ) as client:
        yield client


def run_ubipop_tool(content_set, workers=10, dry_run=False):
    if PULP_CERT_PATH is None:
        auth = (PULP_USER, PULP_PWD)
    else:
        auth = (PULP_CERT_PATH,)

    up = ubipop.UbiPopulate(
        pulp_hostname=PULP_HOSTNAME,
        pulp_auth=auth,
        dry_run=dry_run,
        ubiconfig_dir_or_url=GITLAB_CONFIG_URL,
        insecure=not PULP_SECURE,
        workers_count=workers,
        ubi_manifest_url=MANIFEST_URL,
        content_sets=content_set,
    )

    logging.basicConfig()
    logger = logging.getLogger("ubipop")
    logger.setLevel(logging.INFO)
    up.populate_ubi_repos()


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
    modulemds = query_repo_modules(None, "ubi", rpm_repo_url, full_data=True)
    assert len(modulemds) == 3, "Unexpected repo modulemds found."
    mod_name, mod_profile = separate_modules(modulemds)[0]
    assert mod_name == "httpd", "Expected modulemd: httpd, found modulemd: {}".format(
        mod_name
    )
    assert (
        "common [d]" in mod_profile
    ), "Modulemd httpd should have common profile as default."
