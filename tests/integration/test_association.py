import os
import subprocess
import io
import logging

from itertools import chain

import pytest
import requests
import ubiconfig
import ubipop

from ubipop._pulp_client import Pulp
from ubipop._utils import split_filename

PULP_HOSTNAME = os.getenv('TEST_PULP_HOSTNAME')
PULP_USER = os.getenv('TEST_PULP_USER')
PULP_PWD = os.getenv('TEST_PULP_PWD')
PULP_CERT_PATH = os.getenv('TEST_PULP_CERT_PATH')
PULP_SECURE = os.getenv('TEST_PULP_SECURE', '0').lower() in ['true', 'yes', '1']
PULP_RPM_REPO_PREFIX = '/pulp/rpmrepos/'

TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), './data/ubi7')

INTEGRATION_NOT_SETUP = PULP_HOSTNAME is None


def load_ubiconfig(filename):
    loader = ubiconfig.get_loader(TEST_DATA_DIR)
    return loader.load(filename)


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
        workers_count=workers,
    )
    if capture_log:
        logger = logging.getLogger('ubipop')
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

    ret = p.do_request('post', 'repositories/search/', {
        'criteria': {
            'filters': {'notes.content_set': cs},
        },
        'distributors': False,
    })

    ret.raise_for_status()

    for item in ret.json():
        notes = item['notes']

        if skip_dot_version and '.' in notes['platform_full_version']:
            continue

        yield {
            'id': item['id'],
            'name': item['display_name'],
            'url': notes['relative_url'],
            'arch': notes['arch']
        }


def query_pulp_rpms(repo_id, name=None, arch=None):
    p = Pulp(PULP_HOSTNAME, (PULP_USER, PULP_PWD), not PULP_SECURE)

    url = 'repositories/{REPO_ID}/search/units/'.format(REPO_ID=repo_id)

    criteria = {'type_ids': ['rpm', 'srpm']}
    filters = {'filters': {'unit': {}}}

    if name:
        filters['filters']['unit']['name'] = name
        criteria.update(filters)

    if arch:
        filters['filters']['unit']['arch'] = arch
        criteria.update(filters)

    res = p.do_request('post', url, {'criteria': criteria})
    res.raise_for_status()
    rpms = []

    for item in res.json():
        metadata = item['metadata']
        rpms.append({
            'name': metadata['name'],
            'arch': metadata['arch'],
            'filename': metadata['filename'],
        })

    return rpms


def query_pulp_modules(repo_id, name=None, stream=None):
    p = Pulp(PULP_HOSTNAME, (PULP_USER, PULP_PWD), not PULP_SECURE)

    url = 'repositories/{REPO_ID}/search/units/'.format(REPO_ID=repo_id)

    criteria = {'type_ids': ['modulemd']}

    if name and stream:
        criteria.update({'filters': {'unit': {'name': name, 'stream': stream}}})

    res = p.do_request('post', url, {'criteria': criteria})
    res.raise_for_status()
    modules = []

    for item in res.json():
        metadata = item['metadata']
        modules.append({
            'name': metadata['name'],
            'arch': metadata['arch'],
            'stream': metadata['stream'],
            'artifacts': metadata['artifacts'],
            'profiles': metadata['profiles'],
        })

    return modules


def query_repo_rpms(query, repo_id, repo_url, force_refresh=True, arch_list=None):
    args = [
        'yum',
        'repoquery',
        '-q',
        '--envra',
        '--repoid={}'.format(repo_id),
        '--repofrompath={},{}'.format(repo_id, repo_url),
    ]

    if force_refresh:
        args.append('--refresh')

    if arch_list is not None:
        args.append('--archlist={}'.format(','.join(arch_list)),)

    if query is not None:
        args.append(query)

    out = subprocess.check_output(args, shell=False)

    if isinstance(out, bytes):
        out = out.decode()

    return [pkg.split(':')[1] + '.rpm' for pkg in out.split('\n') if pkg]


def query_repo_modules(query, repo_id, repo_url, force_refresh=True, arch_list=None,
                       full_data=False):
    args = [
        'yum',
        'module',
        'list',
        '-q',
        '--repoid={}'.format(repo_id),
        '--repofrompath={},{}'.format(repo_id, repo_url),
    ]

    if force_refresh:
        args.append('--refresh')

    if arch_list is not None:
        args.append('--archlist={}'.format(','.join(arch_list)),)

    if query is not None:
        args.append(query)

    out = subprocess.check_output(args, shell=False)

    if isinstance(out, bytes):
        out = out.decode()

    lines = out.split('\n')
    lines = lines[2:-3]
    if not full_data:
        return [md.split(' ')[0] for md in lines]
    else:
        return lines

def get_repo_url(relative_url):
    if PULP_SECURE:
        scheme = 'https'
    else:
        scheme = 'http'

    return '{scheme}://{host}{prefix}{relative_url}'.format(
        scheme=scheme,
        host=PULP_HOSTNAME,
        prefix=PULP_RPM_REPO_PREFIX,
        relative_url=relative_url,
    )


def can_download_package(rpm, repo_url):
    url = '{}/Packages/{}/{}'.format(repo_url, rpm[0].lower(), rpm)
    r = requests.head(url)
    return r.status_code == 200


def clean_name(name):
    return split_filename(name)[0]

def separate_modules(module_list):
    '''
    Create a tuple consisting of module name and additional module data.
    '''
    return [(module[:module.find(' ')], module[module.find(' ') + 1:])
            for module in module_list]

def assert_empty_repo(repo):
    repo_id = repo['id']
    repo_url = get_repo_url(repo['url'])

    rpms = query_pulp_rpms(repo_id)
    assert not rpms, 'Repository "{}" is not empty.'.format(repo_id)

    rpms = query_repo_rpms(None, 'ubi', repo_url)
    assert not rpms, 'Repository "{}" is not empty.'.format(repo_url)

    mds = query_pulp_modules(repo_id)
    assert not mds, 'Repository is not empty: {}'.format(repo_id)

    mds = query_repo_modules(None, 'ubi', repo_url)
    assert not mds, 'Repository is not empty: {}'.format(repo_url)


def assert_empty_repos(cfg):
    rpm_repos = get_repos_from_cs(cfg.content_sets.rpm.output)
    srpm_repos = get_repos_from_cs(cfg.content_sets.srpm.output)
    debug_repos = get_repos_from_cs(cfg.content_sets.debuginfo.output)

    repos = chain(rpm_repos, srpm_repos, debug_repos)

    for repo in repos:
        assert_empty_repo(repo)


@pytest.mark.skipif(INTEGRATION_NOT_SETUP, reason='Integration test is not set up.')
def test_modulemd_defaults_unit_copy():
    '''
    Test if modulemd_defaults are copied to ubi repository.
    '''
    cfg = load_ubiconfig('associate-md.yaml')
    rpm_repos = get_repos_from_cs(cfg.content_sets.rpm.output, skip_dot_version=True)
    for repo in rpm_repos:
        repo_url = repo_url = get_repo_url(repo['url'])
        break
    modules = query_repo_modules(None, 'ubi', repo_url, full_data=True)

    assert len(modules) == 2, 'Unexpected repo modules found.'
    separated_modules = separate_modules(modules)
    
    for module in separated_modules:
        if module[0] == 'httpd':
            assert '[d]' not in module[1], 'Module httpd shouldn\'t have defaults.'
        elif module[0] == 'perl-FCGI':
            assert 'common [d]' in module[1], \
                   'Module perl-FCGI should have common profile as default.'
        else:
            raise AssertionError('Unknown module in repo.')
    
    run_ubipop_tool('associate-md.yaml')

    modules = query_repo_modules(None, 'ubi', repo_url, full_data=True)
    assert len(modules) == 1, 'Unexpected repo modules found.'
    separated_module = separate_modules(modules)[0]
    assert separated_module[0] == 'httpd', 'Unknown module in repo.'
    assert 'common [d]' in separated_module[1], \
           'Module httpd should have common profile as default.'


@pytest.mark.skipif(INTEGRATION_NOT_SETUP, reason='Integration test is not set up.')
def test_ubipop_can_clean_repos():
    '''
    Test if an empty (no packages and modules) config file
    cleans up all packages and modules in the repo.

    Running this should not associate any packages or modules,
    and also unassociate all packages and modules if any available.
    '''
    run_ubipop_tool('clean-repos.yaml')
    cfg = load_ubiconfig('clean-repos.yaml')
    assert_empty_repos(cfg)


@pytest.mark.skipif(INTEGRATION_NOT_SETUP, reason='Integration test is not set up.')
def test_dry_run_mode():
    '''
    Test if ubipop dry run-mode does not do execute actions.

    Repositories will be cleaned to ensure nothing is published.
    Than it will run in dry-run mode with packages and modules.
    No packages and modules should be associated.
    '''
    run_ubipop_tool('clean-repos.yaml')
    cfg = load_ubiconfig('clean-repos.yaml')
    assert_empty_repos(cfg)

    run_ubipop_tool('associate-pkg.yaml', dry_run=True)
    cfg = load_ubiconfig('associate-pkg.yaml')
    assert_empty_repos(cfg)

    run_ubipop_tool('associate-md.yaml', dry_run=True)
    cfg = load_ubiconfig('associate-md.yaml')
    assert_empty_repos(cfg)


@pytest.mark.skipif(INTEGRATION_NOT_SETUP, reason='Integration test is not set up.')
def test_ubipop_can_associate_packages():
    '''
    Test if ubipop can associate packages in the repo.

    One or more packages will be published to RPM, SRPM and debug repos.
    No packages are blacklisted.
    No modules are whitelisted or blacklisted.
    '''
    def assert_pkgs(pkgs_included, pkgs_found):
        assert len(pkgs_found) == len(pkgs_included)

        for pkg in pkgs_found:
            assert pkg in pkgs_included, '"{}" is on repository but not in whitelist.'.format(pkg)

        for pkg in pkgs_included:
            assert pkg in pkgs_found, '"{}" is whitelisted but not in the repository.'.format(pkg)

    run_ubipop_tool('associate-pkg.yaml')

    cfg = load_ubiconfig('associate-pkg.yaml')

    repos = {
        'rpm': get_repos_from_cs(cfg.content_sets.rpm.output, skip_dot_version=True),
        'srpm': get_repos_from_cs(cfg.content_sets.srpm.output, skip_dot_version=True),
        'debug': get_repos_from_cs(cfg.content_sets.debuginfo.output, skip_dot_version=True),
    }

    for repo_type, repo_iter in repos.items():
        if repo_type == 'debug':
            filter_debug = lambda pkg: 'debuginfo' in pkg.name or 'debugsource' in pkg.name
        else:
            filter_debug = lambda pkg: 'debuginfo' not in pkg.name and 'debugsource' not in pkg.name

        pkgs_included = [pkg.name for pkg in cfg.packages.whitelist if filter_debug(pkg)]

        for repo in repo_iter:
            repo_id = repo['id']
            repo_url = get_repo_url(repo['url'])

            pulp_rpms = query_pulp_rpms(repo_id)
            pkgs_found = [rpm['name'] for rpm in pulp_rpms]
            assert_pkgs(pkgs_included, pkgs_found)

            repo_rpms = query_repo_rpms(None, 'ubi', repo_url)
            pkgs_found = [clean_name(rpm) for rpm in repo_rpms]
            assert_pkgs(pkgs_included, pkgs_found)

            mds = query_pulp_modules(repo_id)
            assert not mds, 'Repository is not empty: {}'.format(repo_id)

            mds = query_repo_modules(None, 'ubi', repo_url)
            assert not mds, 'Repository is not empty: {}'.format(repo_url)

            for rpm in repo_rpms:
                assert can_download_package(rpm, repo_url), "Can't download package: {}".format(rpm)


@pytest.mark.skipif(INTEGRATION_NOT_SETUP, reason='Integration test is not set up.')
@pytest.mark.parametrize('cfg_file', [
    'do-not-associate-excluded-pkg.yaml',
    'do-not-associate-pkg-if-in-exclude.yaml',
    'do-not-associate-pkg-if-not-in-include.yaml',
])
def test_ubipop_does_not_associate_packages(cfg_file):
    '''
    Test if ubipop does not associate packages in the repo.

    One package is whitelisted and will be associated to RPM and SRPM repo.
    The same package will not be included or blacklisted from debug repo.
    Additional packages are also blacklisted from all repos.
    No modules are whitelisted or blacklisted.
    '''
    run_ubipop_tool(cfg_file)

    cfg = load_ubiconfig(cfg_file)

    rpm_repos = get_repos_from_cs(cfg.content_sets.rpm.output, skip_dot_version=True)
    srpm_repos = get_repos_from_cs(cfg.content_sets.srpm.output, skip_dot_version=True)
    debug_repos = get_repos_from_cs(cfg.content_sets.debuginfo.output, skip_dot_version=True)

    repos = chain(rpm_repos, srpm_repos)

    for repo in repos:
        repo_id = repo['id']
        repo_url = get_repo_url(repo['url'])

        pulp_rpms = query_pulp_rpms(repo_id)
        assert len(pulp_rpms) == 1, 'Wrong packages on repository: {}'.format(repo_id)

        repo_rpms = query_repo_rpms(None, 'ubi', repo_url)
        assert len(repo_rpms) == 1, 'Wrong packages on repository: {}'.format(repo_url)

        pulp_pkgs_found = [rpm['name'] for rpm in pulp_rpms]
        repo_pkgs_found = [clean_name(rpm) for rpm in repo_rpms]
        pkgs_included = [pkg.name for pkg in cfg.packages.whitelist]

        assert pulp_pkgs_found[0] == repo_pkgs_found[0] == pkgs_included[0]

        mds = query_pulp_modules(repo_id)
        assert not mds, 'Repository is not empty: {}'.format(repo_id)

        mds = query_repo_modules(None, 'ubi', repo_url)
        assert not mds, 'Repository is not empty: {}'.format(repo_url)

    for repo in debug_repos:
        assert_empty_repo(repo)


@pytest.mark.skipif(INTEGRATION_NOT_SETUP, reason='Integration test is not set up.')
def test_ubipop_can_associate_modules():
    '''
    Test if ubipop can associate modules and it's packages by profiles.

    One or more modules are going to be associated.
    Packages in the profiles of modules should be associated.

    No packages are explicit whitelisted or blacklisted, this means
    that all packages associated belong to a profile of a module.
    '''
    def assert_mds(mds_included, mds_found):
        assert len(mds_found) == len(mds_included)

        for md in mds_found:
            assert md in mds_included, '"{}" is on repository but not in whitelist.'.format(md)

        for md in mds_included:
            assert md in mds_found, '"{}" is whitelisted but not in the repository.'.format(md)

    run_ubipop_tool('associate-md.yaml')

    cfg = load_ubiconfig('associate-md.yaml')
    mds_included = [md.name for md in cfg.modules.whitelist]

    rpm_repos = get_repos_from_cs(cfg.content_sets.rpm.output, skip_dot_version=True)

    for repo in rpm_repos:
        repo_id = repo['id']
        repo_url = get_repo_url(repo['url'])

        # Check if whitelisted modules are in pulp
        pulp_mds = query_pulp_modules(repo_id)
        mds_found = [md['name'] for md in pulp_mds]
        assert_mds(mds_included, mds_found)

        # Check if whitelisted modules are in repository
        mds_found = query_repo_modules(None, 'ubi', repo_url)
        assert_mds(mds_included, mds_found)

        # Check if packages of profiles of whitelisted modules are in pulp
        pulp_rpms = query_pulp_rpms(repo_id)
        pkgs_found = [rpm['name'] for rpm in pulp_rpms]

        for md_name in mds_included:
            module = [md for md in pulp_mds if md['name'] == md_name][0]
            profiles = [md.profiles for md in cfg.modules.whitelist if md.name == md_name][0]

            for profile in profiles:
                pkgs_profile = module['profiles'].get(profile, [])

                for pkg in pkgs_profile:
                    assert pkg in pkgs_found, '"{}" not in the repository.'.format(pkg)

        # Check if packages of profiles of whitelisted modules are in repository
        repo_rpms = query_repo_rpms(None, 'ubi', repo_url)
        pkgs_found = [clean_name(rpm) for rpm in repo_rpms]

        for md_name in mds_included:
            module = [md for md in pulp_mds if md['name'] == md_name][0]
            profiles = [md.profiles for md in cfg.modules.whitelist if md.name == md_name][0]

            for profile in profiles:
                pkgs_profile = module['profiles'].get(profile, [])

                for pkg in pkgs_profile:
                    assert pkg in pkgs_found, '"{}" not in the repository.'.format(pkg)


@pytest.mark.skipif(INTEGRATION_NOT_SETUP, reason='Integration test is not set up.')
def test_add_packages_multiple_arch():
    '''
    Test if latest packages of all architectures are added to the output repo.
    '''
    cfg = load_ubiconfig('associate-pkg-multi-arch.yaml')
    rpm_repos = get_repos_from_cs(cfg.content_sets.rpm.output, skip_dot_version=True)
    for repo in rpm_repos:
        repo_url = get_repo_url(repo['url'])
        break
    repo_rpms = query_repo_rpms(None, 'ubi', repo_url)
    assert all('glibc' not in rpm for rpm in repo_rpms), \
           'No glibc rpms should be in the output repo.'

    run_ubipop_tool('associate-pkg-multi-arch.yaml')

    repo_rpms = query_repo_rpms(None, 'ubi', repo_url)
    found_archs = []
    for rpm in repo_rpms:
        if 'glibc' in rpm:
            found_archs.append(rpm.split('.')[-2])
    assert all(arch in found_archs for arch in ['i686', 'x86_64']), \
           'Not all archs of glibs are present in the output repo.'
    assert len(found_archs) == 2, 'Unexpected archs found in the output repo.'


@pytest.mark.skipif(INTEGRATION_NOT_SETUP, reason='Integration test is not set up.')
def test_artifact_copy_if_profiles_not_speficied():
    '''
    Test if packages defined in a module profile and artifacts have been added to ubi repo.
    '''
    cfg = load_ubiconfig('associate-md-pkg.yaml')
    rpm_repos = get_repos_from_cs(cfg.content_sets.rpm.output, skip_dot_version=True)
    for repo in rpm_repos:
        repo_url = get_repo_url(repo['url'])
        break
    repo_rpms = query_repo_rpms(None, 'ubi', repo_url)
    expected1 = ['httpd-2.4.6-88.el7.x86_64.rpm', 'httpd-tools-2.4.6-88.el7.x86_64.rpm',
                 'jss-4.4.4-3.el7.x86_64.rpm', 'nuxwdog-1.0.3-8.el7.x86_64.rpm']
    for rpm in repo_rpms:
        assert all(new_rpm != rpm for new_rpm in expected1), \
               'Unexpected rpm in the rpm content set.'

    debug_repos = get_repos_from_cs(cfg.content_sets.debuginfo.output, skip_dot_version=True)
    for repo in debug_repos:
        repo_url = get_repo_url(repo['url'])
        break
    repo_rpms = query_repo_rpms(None, 'ubi', repo_url)
    expected2 = 'nuxwdog-debuginfo-1.0.3-8.el7.x86_64.rpm'
    assert all(expected2 != rpm for repo in repo_rpms), \
           'Unexpected rpm in srpm content set.'
    unexpected = 'jss-debuginfo-4.5.0-1.module+el8+2656+97b10827.x86_64.rpm'
    assert all(unexpected != rpm for repo in repo_rpms), \
           'Unexpected rpm in srpm content set.'

    srpm_rpm_repos = get_repos_from_cs(cfg.content_sets.srpm.output, skip_dot_version=True)
    for repo in srpm_rpm_repos:
        repo_url = get_repo_url(repo['url'])
        break
    repo_rpms = query_repo_rpms(None, 'ubi', repo_url)
    expected3 = ['httpd-2.4.6-88.el7.src.rpm',
                 'jss-4.4.4-3.el7.src.rpm',
                 'nuxwdog-1.0.3-8.el7.src.rpm']
    for rpm in repo_rpms:
        assert all(new_rpm != rpm for new_rpm in expected3), \
               'Unexpected rpm in the debuginfo content set.'

    logs = run_ubipop_tool('associate-md-pkg.yaml', capture_log=True)

    rpm_repos = get_repos_from_cs(cfg.content_sets.rpm.output, skip_dot_version=True)
    for repo in rpm_repos:
        repo_url = get_repo_url(repo['url'])
        break
    repo_rpms = query_repo_rpms(None, 'ubi', repo_url)
    assert expected1[0] in repo_rpms and expected1[1] in repo_rpms, \
           'Package in module profile has not been added to ubi repo.'
    assert expected1[2] in repo_rpms, \
           'Package in module artifacts has not been added to ubi repo.'
    assert expected1[3] in repo_rpms, \
           'Package in module artifacts, which is also excluded has not been added to ubi repo.'

    debug_repos = get_repos_from_cs(cfg.content_sets.debuginfo.output, skip_dot_version=True)
    for repo in debug_repos:
        repo_url = get_repo_url(repo['url'])
        break
    repo_rpms = query_repo_rpms(None, 'ubi', repo_url)
    assert expected2 in repo_rpms, \
           'Package in module artifacts, which is also excluded has not been added to ubi repo.'
    assert unexpected not in repo_rpms, \
           'Package in module artifacts, which isn\'t in source repo has been added to ubi repo.'
    assert 'RPM {} is unavailable in input repos'.format(unexpected) in logs, \
           'LOG warning notifying about the RPM unavailability has not been captured.'

    srpm_repos = get_repos_from_cs(cfg.content_sets.srpm.output, skip_dot_version=True)
    for repo in srpm_repos:
        repo_url = get_repo_url(repo['url'])
        break
    repo_rpms = query_repo_rpms(None, 'ubi', repo_url)
    assert expected3[0] in repo_rpms, \
           'Package in module profile has not been added to ubi repo.'
    assert expected3[1] in repo_rpms, \
           'Package in module artifacts has not been added to ubi repo.'
    assert expected3[2] in repo_rpms, \
           'Package in module artifacts, which is also excluded has not been added to ubi repo.'
