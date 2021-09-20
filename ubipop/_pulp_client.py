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

_LOG = logging.getLogger("ubipop")

HTTP_TOTAL_RETRIES = int(os.environ.get("UBIPOP_HTTP_TOTAL_RETRIES", 10))
HTTP_RETRY_BACKOFF = float(os.environ.get("UBIPOP_HTTP_RETRY_BACKOFF", 1))
HTTP_TIMEOUT = int(os.environ.get("UBIPOP_HTTP_TIMEOUT", 120))


class UnsupportedTypeId(Exception):
    pass


class PulpRetryAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, *args, **kwargs):
        kwargs["max_retries"] = Retry(
            total=kwargs.get("total_retries", HTTP_TOTAL_RETRIES),
            status_forcelist=[500, 502, 503, 504],
            method_whitelist=[
                "HEAD",
                "TRACE",
                "GET",
                "POST",
                "PUT",
                "OPTIONS",
                "DELETE",
            ],
            backoff_factor=kwargs.get("backoff_factor", HTTP_RETRY_BACKOFF),
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
        if insecure:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _make_session(self):
        adapter = PulpRetryAdapter()
        session = requests.Session()
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        if len(self.auth) == 1:
            session.cert = self.auth[0]
        else:
            session.auth = self.auth

        self.local.session = session

    def do_request(self, req_type, url, data=None):
        if not hasattr(self.local, "session"):
            self._make_session()

        req_url = urljoin(self.base_url, url)

        if req_type == "post":
            ret = self.local.session.post(
                req_url, json=data, verify=not self.insecure, timeout=HTTP_TIMEOUT
            )
        elif req_type == "get":
            ret = self.local.session.get(
                req_url, verify=not self.insecure, timeout=HTTP_TIMEOUT
            )
        else:
            ret = None

        return ret

    def wait_for_tasks(self, task_id_list, delay=5.0):
        results = {}

        _tasks = set(task_id_list)
        while _tasks:
            statuses = self.search_tasks(_tasks)
            for status in statuses:
                if status["state"] in ("finished", "error", "canceled"):
                    _tasks -= set([status["task_id"]])
                results[status["task_id"]] = status
            if _tasks:
                time.sleep(delay)
        return results

    def search_tasks(self, task_ids):
        url = "tasks/{task_id}/"
        statuses = []
        for task_id in task_ids:
            ret = self.do_request("get", url.format(task_id=task_id))
            statuses.append(ret.json())
        return statuses

    def _modules_query(self, modules):
        query_list = []
        for module in modules:
            query_list.append(
                {
                    "$and": [
                        {"name": module.name},
                        {"context": module.context},
                        {"version": module.version},
                        {"stream": module.stream},
                        {"arch": module.arch},
                    ]
                }
            )

        return query_list

    def _module_defaults_query(self, module_defaults):
        query_list = []
        for md_d in module_defaults:
            query_list.append({"$and": [{"name": md_d.name}, {"stream": md_d.stream}]})
        return query_list

    def _rpms_query(self, rpms):
        return [{"filename": rpm.filename} for rpm in rpms]

    def unassociate_units(self, repo, units, type_ids):
        url = "repositories/{dst_repo}/actions/unassociate/".format(dst_repo=repo.id)
        data = {
            "criteria": {
                "type_ids": list(type_ids),
                "filters": {"unit": {"$or": self._get_query_list(type_ids, units)}},
            },
        }
        log_msg = "Unassociating %s from %s"
        for unit in units:
            _LOG.info(log_msg, str(unit), repo.id)

        ret = self.do_request("post", url, data).json()
        return [task["task_id"] for task in ret["spawned_tasks"]]

    def associate_units(self, src_repo, dest_repo, units, type_ids):
        url = "repositories/{dst_repo}/actions/associate/".format(dst_repo=dest_repo.id)
        data = {
            "source_repo_id": src_repo.id,
            "criteria": {
                "type_ids": list(type_ids),
                "filters": {
                    "unit": {
                        "$or": self._get_query_list(type_ids, units),
                    },
                },
            },
        }
        log_msg = "Associating %s from %s to %s"
        for unit in units:
            _LOG.info(log_msg, str(unit), src_repo.id, dest_repo.id)
        ret = self.do_request("post", url, data)
        ret.raise_for_status()
        ret_json = ret.json()
        return [task["task_id"] for task in ret_json["spawned_tasks"]]

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
        return self.associate_units(src_repo, dst_repo, modules, ("modulemd",))

    def associate_module_defaults(self, src_repo, dst_repo, module_defaults):
        return self.associate_units(
            src_repo, dst_repo, module_defaults, ("modulemd_defaults",)
        )

    def associate_packages(self, src_repo, dst_repo, rpms):
        return self.associate_units(src_repo, dst_repo, rpms, ("rpm", "srpm"))

    def unassociate_modules(self, repo, modules):
        return self.unassociate_units(repo, modules, ("modulemd",))

    def unassociate_module_defaults(self, repo, module_defaults):
        return self.unassociate_units(repo, module_defaults, ("modulemd_defaults",))

    def unassociate_packages(self, repo, rpms):
        return self.unassociate_units(repo, rpms, ("rpm", "srpm"))
