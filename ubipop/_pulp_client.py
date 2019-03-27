import requests
import time
import logging
from rpm_vercmp import vercmp
try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin

_LOG = logging.getLogger("ubipop")


class UnsupportedTypeId(Exception):
    pass


class Pulp(object):
    PULP_API = "/pulp/api/v2/"

    def __init__(self, hostname, auth, insecure=False):
        self.hostname = hostname
        self.auth = auth
        self.scheme = "https://"
        self.base_url = urljoin(self.scheme + hostname, self.PULP_API)
        self.session = None
        self.insecure = insecure

    def do_request(self, req_type, url, data=None):
        if self.session is None:
            self.session = requests.Session()

            if len(self.auth) == 1:
                self.session.cert = self.auth[0]
            else:
                self.session.auth = self.auth

        req_url = urljoin(self.base_url, url)
        ret = None
        if req_type == "post":
            ret = self.session.post(req_url, json=data, verify=not self.insecure)
        elif req_type == "get":
            ret = self.session.get(req_url, verify=not self.insecure)

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

    def search_rpms(self, repo, name=None, arch=None, name_globbing=False):
        url = "repositories/{REPO_ID}/search/units/".format(REPO_ID=repo.repo_id)
        criteria = {"type_ids": ["rpm", "srpm"]}

        filters = {"filters": {"unit": {}}}
        if name:
            if name_globbing:
                filters["filters"]["unit"]["name"] = {"$regex": name + ".*"}
            else:
                filters["filters"]["unit"]["name"] = name

            criteria.update(filters)
        if arch:
            filters["filters"]["unit"]["arch"] = arch
            criteria.update(filters)

        payload = {"criteria": criteria}
        ret = self.do_request("post", url, payload)
        rpms = []
        ret.raise_for_status()
        for item in ret.json():
            metadata = item['metadata']
            rpms.append(Package(metadata['name'], metadata['filename'], metadata.get('sourcerpm')))
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

    def wait_for_tasks(self, task_id_list,  delay=5.0):
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
                '$or':  self._get_query_list(type_ids, units)
              }
            }
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

        elif "rpm" in type_ids or "srpm" in type_ids:
            query_list = self._rpms_query(units)
        else:
            raise UnsupportedTypeId

        return query_list

    def associate_modules(self, src_repo, dst_repo, modules):
        return self.associate_units(src_repo, dst_repo, modules, "modulemd")

    def associate_packages(self, rpms, src_repo, dst_repo):
        return self.associate_units(src_repo, dst_repo, rpms, ("rpm", "srpm"))

    def unassociate_modules(self, modules, repo):
        return self.unassociate_units(repo, modules, ("modulemd", ))

    def unassociate_packages(self, rpms, repo):
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
    def __init__(self, name, filename, sourcerpm_filename=None):
        self.name = name
        self.filename = filename
        self.sourcerpm_filename = sourcerpm_filename

    def __lt__(self, other):
        return vercmp(self.filename, other.filename) < 0

    def __gt__(self, other):
        return vercmp(self.filename, other.filename) > 0

    def __eq__(self, other):
        return vercmp(self.filename, other.filename) == 0

    def __le__(self, other):
        return vercmp(self.filename, other.filename) <= 0

    def __ge__(self, other):
        return vercmp(self.filename, other.filename) >= 0

    def __ne__(self, other):
        return vercmp(self.filename, other.filename) != 0

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
