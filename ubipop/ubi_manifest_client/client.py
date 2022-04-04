import logging
import os
import threading
from concurrent.futures import as_completed

import requests
from more_executors import Executors, f_map, f_proxy

from .models import UbiManifest

LOG = logging.getLogger(__name__)

API = "api/v1"


REQUESTS_MAX_WORKERS = int(os.getenv("UBIPOP_REQUESTS_MAX_WORKERS", "4"))


class UbiManifestTaskFailure(Exception):
    pass


class Client(object):
    def __init__(self, url):
        self._url = os.path.join(url, API)
        self._tls = threading.local()
        self._executor = (
            Executors.thread_pool(max_workers=REQUESTS_MAX_WORKERS)
            .with_map(self._unpack_response)
            .with_retry()
        )
        self._task_executor = (
            Executors.thread_pool(max_workers=REQUESTS_MAX_WORKERS)
            .with_map(self._unpack_response)
            .with_map(self._log_spawned_tasks)
            .with_poll(self._poll_tasks)
            .with_retry()
        )

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs):
        self._executor.__exit__(*args, **kwargs)
        self._task_executor.__exit__(*args, **kwargs)

    def _unpack_response(self, response):
        try:
            out = response.json()
        except Exception:
            response.raise_for_status()
            raise

        response.raise_for_status()
        return out

    @property
    def _session(self):
        if not hasattr(self._tls, "session"):
            self._tls.session = requests.Session()
        return self._tls.session

    def _do_request(self, **kwargs):
        return self._session.request(**kwargs)

    def get_manifest(self, repo_id):
        endpoint = "manifest"
        url = os.path.join(self._url, endpoint, repo_id)
        LOG.debug("Getting manifest for %s", repo_id)
        manifest_ft = self._executor.submit(self._do_request, method="GET", url=url)

        return f_proxy(f_map(manifest_ft, lambda data: UbiManifest.from_data(data)))

    def _get_task(self, task_id):
        endpoint = "task"
        url = os.path.join(self._url, endpoint, task_id)
        LOG.debug("Getting state of task: %s", task_id)
        return self._executor.submit(self._do_request, method="GET", url=url)

    def generate_manifest(self, repo_ids):
        endpoint = "manifest"
        url = os.path.join(self._url, endpoint)

        request_body = {"repo_ids": repo_ids}
        LOG.debug("Requesting generation of manifest for %s", repo_ids)
        return self._task_executor.submit(
            self._do_request, method="POST", url=url, json=request_body
        )

    def _poll_tasks(self, poll_descriptors):
        task_ids = []

        for d in poll_descriptors:
            for task in d.result:
                task_ids.append(task.get("task_id"))

        fts = []

        for task_id in task_ids:
            fts.append(self._get_task(task_id))

        tasks = {}
        for ft in as_completed(fts):
            task = ft.result()
            tasks[task["task_id"]] = task["state"]

        for d in poll_descriptors:
            succesfull_tasks = []
            for task in d.result:
                state = tasks.get(task["task_id"])
                if state == "FAILURE":
                    d.yield_exception(UbiManifestTaskFailure())
                elif state == "SUCCESS":
                    succesfull_tasks.append(task)

            if len(succesfull_tasks) == len(d.result):
                d.yield_result(succesfull_tasks)

    def _log_spawned_tasks(self, task_data):
        for item in task_data:
            task_id = item.get("task_id")
            if task_id:
                LOG.info("Created ubi-manifest task: %s", task_id)

        return task_data
