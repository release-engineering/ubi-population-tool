import requests
import urlparse
import time
import logging

_LOG = logging.getLogger("ubipop")


class Pulp(object):
    PULP_API = "/pulp/api/v2/"

    def __init__(self, hostname, auth, insecure=False):
        self.hostname = hostname
        self.auth = auth
        self.scheme = "https://"
        self.base_url = urlparse.urljoin(self.scheme + hostname, self.PULP_API)
        self.session = None
        self.insecure = insecure

    def do_request(self, req_type, url, data=None):
        if self.session is None:
            self.session = requests.Session()

            if len(self.auth) == 1:
                self.session.cert = self.auth[0]
            else:
                self.session.auth = self.auth

        req_url = urlparse.urljoin(self.base_url, url)
        ret = None
        if req_type == "post":
            ret = self.session.post(req_url, json=data, verify=not self.insecure)
        elif req_type == "get":
            ret = self.session.get(req_url, verify=not self.insecure)

        return ret

    def search_repo_by_cs(self, content_set):
        url = "repositories/search/"
        payload = {"criteria": {"filters": {"notes.content_set": content_set}}, "distributors": True}

        ret = self.do_request("post", url, payload)
        ret.raise_for_status()
        repos = []
        for item in ret.json():
            notes = item['notes']
            repos.append(Repo(item['id'], notes['arch'], notes['platform_full_version'],
                              [distributor['id'] for distributor in item['distributors']]))

        return repos

    def search_rpms(self, repo, name=None, arch=None, name_globbing=False):
        url = "repositories/{REPO_ID}/search/units/".format(REPO_ID=repo.repo_id)
        criteria = {"type_ids": ["rpm", "srpm"]}

        filters = {"filters": {"unit": {}}}
        if name:
            if name_globbing:
                filters["filters"]["unit"]["name"] = {"$regex": name + "*"}
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
            rpms.append(Package(metadata['name'], metadata['filename'], metadata['sourcerpm']))
        return rpms

    def search_modules(self, repo, name=None, stream=None):
        url ="repositories/{REPO_ID}/search/units/".format(REPO_ID=repo.repo_id)
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

    def associate_units(self, src_repo, dest_repo, units, type_id):
        url = "repositories/{dst_repo}/actions/associate/".format(dst_repo=dest_repo.repo_id)
        if type_id == "modulemd":
            query_list = self._modules_query(units)

        elif type_id in ("rpm", "srpm"):
            query_list = self._rpms_query(units)
        else:
            raise Exception

        data = {
          'source_repo_id': src_repo.repo_id,
          'criteria': {
            'type_ids': [type_id],
            'filters': {
              'unit': {
                '$or':  query_list
              }
            }
          },
        }

        ret = self.do_request('post', url, data).json()
        return [task['task_id'] for task in ret['spawned_tasks']]

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
            statuses.append(self.do_request('get', url.format(task_id=task_id)).json())
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

    def unassociate_units(self, repo, units, type_id):
        url = "repositories/{dst_repo}/actions/unassociate/".format(dst_repo=repo.repo_id)
        if type_id == "modulemd":
            query_list = self._modules_query(units)

        elif type_id in ("rpm", "srpm"):
            query_list = self._rpms_query(units)
        else:
            raise Exception

        data = {
            'criteria': {
                'type_ids': [type_id],
                'filters': {
                    'unit': {
                        "$or": query_list
                    }
                }
            },
        }

        ret = self.do_request('post', url, data).json()
        return [task['task_id'] for task in ret['spawned_tasks']]

    def associate_modules(self, src_repo, dst_repo, modules):
        return self.associate_units(src_repo, dst_repo, modules, "modulemd")

    def associate_rpms(self, rpms, src_repo, dst_repo):
        return self.associate_units(src_repo, dst_repo, rpms, "rpm")

    def associate_srpms(self,rpms, src_repo, dst_repo):
        return self.associate_units(src_repo, dst_repo, rpms, "srpm")

    def unassociate_modules(self, modules, repo):
        return self.unassociate_units(repo, modules, "modulemd")

    def unassociate_rpms(self, rpms, repo):
        return self.unassociate_units(repo, rpms, "rpm")

    def unassociate_srpms(self, srpms, repo):
        return self.unassociate_units(repo, srpms, "srpm")

    def publish_repo(self, repo):
        url = "repositories/{repo_id}/actions/publish/".format(repo_id=repo.repo_id)
        task_ids = []
        for dist in repo.distributors_ids:
            _LOG.debug("Publishing {repo} in {dist_id}".format(repo=repo.repo_id, dist_id=dist))
            data = {"id": dist}
            ret = self.do_request('post', url, data).json()
            task_ids.extend(task['task_id'] for task in ret['spawned_tasks'])

        return task_ids


class Repo(object):
    def __init__(self, repo_id, arch, platform_full_version, distributors_ids):
        self.repo_id = repo_id
        self.arch = arch
        self.platform_full_version = platform_full_version
        self.distributors_ids = distributors_ids


class Package(object):
    def __init__(self, name, filename, sourcerpm_filename=None):
        self.name = name
        self.filename = filename
        self.sourcerpm_filename = sourcerpm_filename


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
