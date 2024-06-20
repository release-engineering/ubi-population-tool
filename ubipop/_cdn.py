import logging

from more_executors.futures import f_map, f_sequence
from pubtools.pulplib import PublishOptions

LOG = logging.getLogger("ubipop")


class Publisher:
    def __init__(self, publish_options=None):
        """Create a new Publisher object.
        Which can be used to enqueuing repository published with CDN cache purge.

        Arguments:
            publish_options (dict)
                supported args for PublishOptions class
        """
        self._publish_queue = set()

        publish_options = publish_options if publish_options else {}
        self._publish_options = PublishOptions(**publish_options)

    def __enter__(self):
        return self

    def __exit__(self, *exec_details):
        return

    def enqueue(self, *repos):
        def _enqueue(repo):
            ft = repo.publish(self._publish_options)
            ft = f_map(ft, lambda _: repo)
            self._publish_queue.add(ft)

        _ = [_enqueue(r) for r in repos if r.result() is not None]

    def wait_publish_and_purge_cache(self):
        f_sequence(self._publish_queue).result()
        LOG.info("Publish finished")
