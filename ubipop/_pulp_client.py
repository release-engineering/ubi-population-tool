import logging
import os
import threading
import time

from urllib3.util.retry import Retry

try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin

import requests

from cmp_version import cmp_version

_LOG = logging.getLogger("ubipop")

HTTP_TOTAL_RETRIES = int(os.environ.get("UBIPOP_HTTP_TOTAL_RETRIES", 10))
HTTP_RETRY_BACKOFF = float(os.environ.get("UBIPOP_HTTP_RETRY_BACKOFF", 1))


class UnsupportedTypeId(Exception):
    pass


class PulpRetryAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, *args, **kwargs):
        kwargs['max_retries'] = Retry(
            total=kwargs.get('total_retries', HTTP_TOTAL_RETRIES),
            status_forcelist=[500, 502, 503, 504],
            method_whitelist=["HEAD", "TRACE", "GET", "POST", "PUT", "OPTIONS", "DELETE"],
            backoff_factor=kwargs.get('backoff_factor', HTTP_RETRY_BACKOFF)
        )
        super(PulpRetryAdapter, self).__init__(*args, **kwargs)


class Pulp(object):
    PULP_API = "/pulp/api/v2/"

    def __init__(self, hostname, auth, insecure=False):
        self.hostname = hostname
        self.auth = auth
        self.scheme = "https://"
        self.base_url = urljoin(self.scheme + hostname, self.PULP_API)
        self.insecure = insecure
        self.local = threading.local()

    def _make_session(self):
        adapter = PulpRetryAdapter()
        session = requests.Session()
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        if len(self.auth) == 1:
            session.cert = self.auth[0]
        else:
            session.auth = self.auth

        self.local.session = session

    def do_request(self, req_type, url, data=None):
        if not hasattr(self.local, 'session'):
            self._make_session()

        req_url = urljoin(self.base_url, url)

        if req_type == "post":
            ret = self.local.session.post(req_url, json=data, verify=not self.insecure)
        elif req_type == "get":
            ret = self.local.session.get(req_url, verify=not self.insecure)
        else:
            ret = None

        return ret

    def search_repo_by_cs(self, content_set):
        url = "repositories/search/"
        payload = {"criteria": {"filters": {"notes.content_set": content_set}},
                   "distributors": True}

        ret = self.do_request("post", url, payload)
        ret.raise_for_status()
        repos = []
        for item in ret.json():
            notes = item['notes']
            repos.append(Repo(item['id'], notes['arch'], notes['platform_full_version'],
                              [(distributor['id'], distributor['distributor_type_id'])
                               for distributor in item['distributors']]))

        return repos

    def search_rpms(self, repo, name=None, arch=None, name_globbing=False, filename=None):
        url = "repositories/{REPO_ID}/search/units/".format(REPO_ID=repo.repo_id)
        criteria = {"type_ids": ["rpm", "srpm"]}

        filters = {"filters": {"unit": {}}}
        if name:
            if name_globbing:
                filters["filters"]["unit"]["name"] = {"$regex": name + ".*"}
            else:
                filters["filters"]["unit"]["name"] = name

        if arch:
            filters["filters"]["unit"]["arch"] = arch

        if filename:
            filters["filters"]["unit"]["filename"] = filename

        criteria.update(filters)
        payload = {"criteria": criteria}
        ret = self.do_request("post", url, payload)
        rpms = []
        ret.raise_for_status()
        for item in ret.json():
            metadata = item['metadata']
            rpms.append(Package(metadata['name'], metadata['filename'],
                                sourcerpm_filename=metadata.get('sourcerpm'),
                                is_modular=metadata.get('is_modular', False)))
        return rpms

    def search_modules(self, repo, name=None, stream=None):
        url = "repositories/{REPO_ID}/search/units/".format(REPO_ID=repo.repo_id)
        criteria = {"type_ids": ["modulemd"]}
        if name and stream:
            criteria.update({"filters": {"unit": {"name": name, "stream": stream}}})
        payload = {"criteria": criteria}

        ret = self.do_request("post", url, payload)
        modules = []
        ret.raise_for_status()
        for item in ret.json():

            metadata = item['metadata']
            modules.append(Module(metadata['name'], metadata['stream'],
                                  metadata['version'], metadata['context'],
                                  metadata['arch'], metadata['artifacts'], metadata['profiles']))
        return modules

    def search_module_defaults(self, repo, name=None, stream=None):
        url = "repositories/{REPO_ID}/search/units/".format(REPO_ID=repo.repo_id)
        criteria = {"type_ids": ["modulemd_defaults"]}
        if name and stream:
            criteria.update({"filters": {"unit": {"name": name, "stream": stream}}})
        payload = {"criteria": criteria}

        ret = self.do_request("post", url, payload)
        ret.raise_for_status()
        module_defaults = []
        for item in ret.json():
            metadata = item['metadata']
            module_defaults.append(ModuleDefaults(metadata['name'], metadata['stream'],
                                                  metadata['profiles']))
        return module_defaults

    def wait_for_tasks(self, task_id_list, delay=5.0):
        results = {}

        _tasks = set(task_id_list)
        while _tasks:
            statuses = self.search_tasks(_tasks)
            for status in statuses:
                if status["state"] in ("finished", "error", "cancelled"):
                    _tasks -= set([status["task_id"]])
                results[status["task_id"]] = status
            if _tasks:
                time.sleep(delay)
        return results

    def search_tasks(self, task_ids):
        url = "tasks/{task_id}/"
        statuses = []
        for task_id in task_ids:
            ret = self.do_request('get', url.format(task_id=task_id))
            statuses.append(ret.json())
        return statuses

    def _modules_query(self, modules):
        query_list = []
        for module in modules:
            query_list.append({'$and': [{'name': module.name},
                                        {'context': module.context},
                                        {'version': module.version},
                                        {'stream': module.stream},
                                        {'arch': module.arch}
                                       ]})

        return query_list

    def _module_defaults_query(self, module_defaults):
        query_list = []
        for md_d in module_defaults:
            query_list.append({'$and': [
                {'name': md_d.name},
                {'stream': md_d.stream}
            ]})
        return query_list

    def _rpms_query(self, rpms):
        return [{"filename": rpm.filename} for rpm in rpms]

    def unassociate_units(self, repo, units, type_ids):
        url = "repositories/{dst_repo}/actions/unassociate/".format(dst_repo=repo.repo_id)
        data = {
            'criteria': {
                'type_ids': list(type_ids),
                'filters': {
                    'unit': {
                        "$or": self._get_query_list(type_ids, units)
                    }
                }
            },
        }
        log_msg = "Unassociating %s from %s"
        for unit in units:
            _LOG.info(log_msg, str(unit), repo.repo_id)

        ret = self.do_request('post', url, data).json()
        return [task['task_id'] for task in ret['spawned_tasks']]

    def associate_units(self, src_repo, dest_repo, units, type_ids):
        url = "repositories/{dst_repo}/actions/associate/".format(dst_repo=dest_repo.repo_id)
        data = {
            'source_repo_id': src_repo.repo_id,
            'criteria': {
                'type_ids': list(type_ids),
                'filters': {
                    'unit': {
                        '$or': self._get_query_list(type_ids, units),
                    },
                },
            },
        }
        log_msg = "Associating %s from %s to %s"
        for unit in units:
            _LOG.info(log_msg, str(unit), src_repo.repo_id, dest_repo.repo_id)
        ret = self.do_request('post', url, data)
        ret.raise_for_status()
        ret_json = ret.json()
        return [task['task_id'] for task in ret_json['spawned_tasks']]

    def _get_query_list(self, type_ids, units):
        if "modulemd" in type_ids:
            query_list = self._modules_query(units)
        elif "modulemd_defaults" in type_ids:
            query_list = self._module_defaults_query(units)
        elif "rpm" in type_ids or "srpm" in type_ids:
            query_list = self._rpms_query(units)
        else:
            raise UnsupportedTypeId

        return query_list

    def associate_modules(self, src_repo, dst_repo, modules):
        return self.associate_units(src_repo, dst_repo, modules, ("modulemd", ))

    def associate_module_defaults(self, src_repo, dst_repo, module_defaults):
        return self.associate_units(src_repo, dst_repo, module_defaults, ("modulemd_defaults", ))

    def associate_packages(self, src_repo, dst_repo, rpms):
        return self.associate_units(src_repo, dst_repo, rpms, ("rpm", "srpm"))

    def unassociate_modules(self, repo, modules):
        return self.unassociate_units(repo, modules, ("modulemd", ))

    def unassociate_module_defaults(self, repo, module_defaults):
        return self.unassociate_units(repo, module_defaults, ("modulemd_defaults", ))

    def unassociate_packages(self, repo, rpms):
        return self.unassociate_units(repo, rpms, ("rpm", "srpm"))

    def publish_repo(self, repo):
        url = "repositories/{repo_id}/actions/publish/".format(repo_id=repo.repo_id)
        task_ids = []
        for dist_id, dist_type_id in repo.distributors_ids_type_ids_tuples:
            _LOG.info("Publishing %s in %s", repo.repo_id, dist_id)
            data = {"id": dist_id}
            if dist_type_id in ("rpm_rsync_distributor", "cdn_distributor"):
                data["override_config"] = {"delete": True}
            ret = self.do_request('post', url, data).json()
            task_ids.extend(task['task_id'] for task in ret['spawned_tasks'])

        return task_ids


class Repo(object):
    def __init__(self, repo_id, arch, platform_full_version, distributors_ids_type_ids):
        self.repo_id = repo_id
        self.arch = arch
        self.platform_full_version = platform_full_version
        self.distributors_ids_type_ids_tuples = distributors_ids_type_ids


class Package(object):
    def __init__(self, name, filename, sourcerpm_filename=None, is_modular=False):
        self.name = name
        self.filename = filename
        self.sourcerpm_filename = sourcerpm_filename
        self.is_modular = is_modular

    def __lt__(self, other):
        return cmp_version(self.filename, other.filename) < 0

    def __gt__(self, other):
        return cmp_version(self.filename, other.filename) > 0

    def __eq__(self, other):
        return cmp_version(self.filename, other.filename) == 0

    def __le__(self, other):
        return cmp_version(self.filename, other.filename) <= 0

    def __ge__(self, other):
        return cmp_version(self.filename, other.filename) >= 0

    def __ne__(self, other):
        return cmp_version(self.filename, other.filename) != 0

    def __str__(self):
        return self.filename


class Module(object):
    def __init__(self, name, stream, version, context, arch, packages, profiles):
        self.name = name
        self.stream = stream
        self.version = version
        self.context = context
        self.arch = arch
        self.packages = packages
        self.profiles = profiles

    @property
    def nsvca(self):
        return ':'.join((self.name, self.stream, str(self.version), self.context, self.arch))

    def __str__(self):
        return self.nsvca


class ModuleDefaults(object):
    """
    module_defaults unit, defines which profiles are enabled by default when activating
    a module. For example:
    {...,
     "name": "ruby",
     "profiles": {
        "2.5": [
            "common"]
        },
    ...
    }
    if someone asks to enable 'ruby:2.5' for some repo without specifing profiles, will
    get 'common' profile by defualt
    """
    def __init__(self, name, stream, profiles):
        self.name = name
        self.stream = stream
        self.profiles = profiles  # a dict such as {'4.046':['common']}

    def __str__(self):
        return self.name

    @property
    def name_profiles(self):
        """
        flatten the profles and prepend name
        format: name:[key:profile,profile]:[key:profile]
        'ruby:[2.5:common,unique]'
        """
        result = self.name
        for key in sorted(self.profiles):
            result += ':[%s:%s]' % (key, ','.join(sorted(self.profiles[key])))
        return result
