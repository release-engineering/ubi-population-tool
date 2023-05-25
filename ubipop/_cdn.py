# inspired by CDN client and cache purge implementation
# in https://github.com/release-engineering/pubtools-pulp/
import logging
import os
import re
import threading
from collections import namedtuple
from concurrent.futures import as_completed

import requests
from fastpurge import FastPurgeClient
from more_executors import Executors
from more_executors.futures import f_map, f_return, f_sequence
from pubtools.pulplib import PublishOptions

LOG = logging.getLogger("ubipop")


HeaderPair = namedtuple("HeaderPair", ["request", "response"])
TtlConfig = namedtuple("TtlConfig", ["regex", "ttl"])


class Publisher:
    def __init__(self, publish_options=None, edgerc=None, cdn_root=None, **kwargs):
        """Create a new Publisher object.
        Which can be used to enqueuing repository published with CDN cache purge.

        Arguments:
            publish_options (dict)
                supported args for PublishOptions class

            edgerc (str|dict)
                path to edgerc config or dict with config

            cdn_root (str)
                root url of CDN service (e.g. https://cdn.example.com)

            kwargs:
                other args used for CdnClient (e.g. arl_templates, cert, verify)

        """
        self._cdn_client = None
        self._cdn_cache_purger = None

        self._publish_queue = set()

        publish_options = publish_options if publish_options else {}
        self._publish_options = PublishOptions(**publish_options)

        self._edgerc = edgerc
        self._cdn_client_args = {
            "url": cdn_root,
        }
        for arg in ("cert", "verify", "arl_templates"):
            self._cdn_client_args[arg] = kwargs.get(arg)

        self._cdn_root = cdn_root

    def __enter__(self):
        return self

    def __exit__(self, *exc_details):
        if self._cdn_client:
            self._cdn_client.__exit__(*exc_details)
        if self._cdn_cache_purger:
            self._cdn_cache_purger.__exit__(*exc_details)

    @property
    def cdn_client(self):
        if not all(
            [self._cdn_client_args["url"], self._cdn_client_args["arl_templates"]]
        ):
            return None

        if not self._cdn_client:
            self._cdn_client = CdnClient(**self._cdn_client_args)
        return self._cdn_client

    @property
    def cdn_cache_purger(self):
        if not self._cdn_root:
            return None

        if not self._cdn_cache_purger:
            self._cdn_cache_purger = CdnCachePurger(self._edgerc)

        return self._cdn_cache_purger

    def enqueue(self, *repos):
        def _enqueue(repo):
            ft = repo.publish(self._publish_options)
            ft = f_map(ft, lambda _: repo)
            self._publish_queue.add(ft)

        _ = [_enqueue(r) for r in repos if r.result() is not None]

    def wait_publish_and_purge_cache(self):
        f_sequence(self._publish_queue).result()
        LOG.info("Publish finished")
        if self.cdn_cache_purger:
            LOG.info("CDN cache purge started")
            self._purge_cache().result()
            LOG.info("CDN cache purge finished")
        else:
            LOG.info("CDN cache purge disabled.")

    def _purge_cache(self):
        purges = []

        for repo in as_completed(self._publish_queue):
            _repo = repo.result()
            if _repo.relative_url:
                for mutable_url in _repo.mutable_urls:
                    relative_mutable_url = os.path.join(_repo.relative_url, mutable_url)

                    url = os.path.join(self._cdn_root, relative_mutable_url)
                    purges.append(f_return(url))
                    if self.cdn_client:
                        arls_ft = self.cdn_client.get_arl_for_path(relative_mutable_url)
                        purges.extend(arls_ft)

        return f_map(f_sequence(purges), self.cdn_cache_purger.purge_by_url)


class CdnCachePurger:
    def __init__(self, edgerc):
        """Create a new CDN cache purger client.

        Arguments:
            edgerc (str|dict)
                Path to edgerc config or dict containing the config.
        """
        self._edgerc = edgerc
        self._fastpurge_client = None

    def __enter__(self):
        return self

    def __exit__(self, *exc_details):
        if self._fastpurge_client:
            self._fastpurge_client.__exit__(*exc_details)

    @property
    def fastpurge_client(self):
        if not self._fastpurge_client:
            self._fastpurge_client = FastPurgeClient(auth=self._edgerc)

        return self._fastpurge_client

    def purge_by_url(self, urls):
        return self.fastpurge_client.purge_by_url(urls)


class CdnClient:
    # Client for requesting special headers from CDN service.

    # Default number of request thread modifiable by an env variable.
    # This is not a documented/supported feature of the library.
    _REQUEST_THREADS = int(os.environ.get("CDN_REQUEST_THREADS", "4"))
    _ATTEMPTS = int(os.environ.get("CDN_RETRY_ATTEMPTS", "9"))
    _SLEEP = float(os.environ.get("CDN_RETRY_SLEEP", "1.0"))
    _EXPONENT = float(os.environ.get("CDN_RETRY_EXPONENT", "3.0"))
    _MAX_SLEEP = float(os.environ.get("CDN_RETRY_MAX_SLEEP", "120.0"))

    TTL_REGEX = re.compile(r".*/(\d+[smhd])/.*")
    CACHE_KEY_HEADER = HeaderPair("akamai-x-get-cache-key", "X-Cache-Key")

    def __init__(self, url, arl_templates=None, max_retry_sleep=_MAX_SLEEP, **kwargs):
        """Create a new CDN client.

        Arguments:
            url (str)
                Base URL of CDN
            arl_templates List[str]
                Templates used for ARL generation
            max_retry_sleep (float)
                Max number of seconds to sleep between retries.
                Mainly provided so that tests can reduce the time needed to retry.
            kwargs
                Remaining arguments are used to initialize the requests.Session()
                used within this class (e.g. "verify", "cert").
        """
        self._url = url
        self._arl_templates = arl_templates
        self._tls = threading.local()

        retry_args = {
            "max_sleep": max_retry_sleep,
            "max_attempts": CdnClient._ATTEMPTS,
            "sleep": CdnClient._SLEEP,
            "exponent": CdnClient._EXPONENT,
        }
        self._session_attrs = kwargs
        self._executor = (
            Executors.thread_pool(name="cdn-client", max_workers=self._REQUEST_THREADS)
            .with_map(self._check_http_response)
            .with_retry(**retry_args)
        )

    def __enter__(self):
        return self

    def __exit__(self, *exc_details):
        self._executor.__exit__(*exc_details)

    @staticmethod
    def _check_http_response(response):
        response.raise_for_status()
        return response

    @property
    def _session(self):
        if not hasattr(self._tls, "session"):
            self._tls.session = requests.Session()
            for key, value in self._session_attrs.items():
                setattr(self._tls.session, key, value)
        return self._tls.session

    def _head(self, *args, **kwargs):
        return self._session.head(*args, **kwargs)

    def _on_failure(self, header, exception):
        LOG.error("Requesting header %s failed: %s", header, exception)
        raise exception

    def _get_headers_for_path(self, path, headers):
        url = os.path.join(self._url, path)

        LOG.info("Getting headers %s for %s", list(headers.values()), url)

        out = self._executor.submit(self._head, url, headers=headers)
        out = f_map(
            out,
            fn=lambda resp: resp.headers,
            error_fn=lambda ex: self._on_failure(list(headers.values()), ex),
        )

        return out

    def _get_ttl(self, path):
        headers = {"Pragma": self.CACHE_KEY_HEADER.request}

        out = self._get_headers_for_path(path, headers)

        def _parse_ttl(value):
            parsed = re.match(
                self.TTL_REGEX, value.get(self.CACHE_KEY_HEADER.response) or ""
            )
            return parsed.group(1) if parsed else None

        return f_map(out, _parse_ttl)

    def _is_valid_template(self, template):
        return all(["{ttl}" in template, "{path}" in template])

    def get_arl_for_path(self, path):
        """Get ARL for particular path using provided templates.
        This method generates ARLs for given path according to
        provided ARL templates. TTL value is requested from CDN
        special headers.

        If value of TTL cannot be fetched from CDN service,
        we fallback to hardcoded values.

        Arguments:
            path (str)
                Relative path/URL (e.g. content/foo/bar/repomd.xml).
        Returns:
            List[Future]
                A list of futures holding formatted ARLs.
        """

        def _format_template(ttl, template, path):
            ttl = f_map(ttl, fn=lambda x: x, error_fn=lambda _: ttl_for_path(path))
            return f_map(ttl, lambda x: template.format(ttl=x, path=path))

        out = []
        ttl_ft = self._get_ttl(path)

        for item in self._arl_templates or []:
            if self._is_valid_template(item):
                out.append(_format_template(ttl_ft, item, path))
        return out


# ordering of items matters as it's used as priority
CDN_TTL_CONFIG = (
    TtlConfig(re.compile(r"/repodata/.*\.xml$"), "4h"),
    TtlConfig(re.compile(r".*/ostree/repo/refs/heads/.*/(base|standard)$"), "10m"),
    TtlConfig(re.compile(r"(/PULP_MANIFEST$|/listing$|/repodata/)"), "10m"),
    TtlConfig(re.compile(r"/$"), "4h"),
)

DEFAULT_TTL = "30d"


def ttl_for_path(path):
    out = DEFAULT_TTL
    for regex, ttl in CDN_TTL_CONFIG:
        if regex.search(path):
            out = ttl
            break

    return out
