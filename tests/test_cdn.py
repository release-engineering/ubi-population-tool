from concurrent.futures import as_completed
from datetime import datetime

import pytest
from pubtools.pulplib import Distributor, FakeController, YumRepository

from ubipop._cdn import CdnClient, Publisher

EDGERC_FAKE_CONF = {
    "client_secret": "some-secret",
    "host": "some-host",
    "access_token": "some-access-token",
    "client_token": "some-client-token",
}


@pytest.fixture(name="pulp")
def fake_pulp():
    yield FakeController()


def create_and_insert_repo(pulp, repos):
    out = []
    for repo in repos:
        pulp.insert_repository(repo)
        out.append(pulp.client.get_repository(repo.id))

    return out


def setup_fastpurge_mock(requests_mock):
    url = "https://some-host/ccu/v3/delete/url/production"
    seconds = 0.1
    response = {"some": ["return", "value"], "estimatedSeconds": seconds}
    requests_mock.register_uri("POST", url, status_code=201, json=response)


def test_publisher_without_cache_purge(pulp, requests_mock):
    """
    Tests a basic scenario of repository publish without cache purge.
    """
    dt = datetime(2019, 9, 12, 0, 0, 0)
    repos_to_insert = []
    for i in range(1, 100):
        repo_id = f"repo-{i}"
        distributor = Distributor(
            id="yum_distributor",
            type_id="yum_distributor",
            repo_id=repo_id,
            last_publish=dt,
            relative_url=f"content/unit/{i}/client",
        )
        repo = YumRepository(
            id=repo_id,
            eng_product_id=102,
            distributors=[distributor],
            relative_url=f"content/unit/{i}/client",
        )
        repos_to_insert.append(repo)

    repos = create_and_insert_repo(pulp, repos_to_insert)
    # enqueue repos for publish and wait for publish to finish
    with Publisher(**{}) as publisher:
        publisher.enqueue(*repos)
        publisher.wait_publish_and_purge_cache()

    # all repos are properly published
    assert [hist.repository.id for hist in pulp.publish_history] == [
        repo.id for repo in repos
    ]

    hist = requests_mock.request_history

    assert len(hist) == 0  # no requests expected as CDN cache purge is disabled


def test_publisher_with_cache_purge(pulp, requests_mock):
    """
    Tests a scenario of repository publish with cache purge by URL and ARLs generated with
    data from CDN service.
    """
    dt = datetime(2019, 9, 12, 0, 0, 0)
    repos_to_insert = []
    repo_id = "repo-1"
    distributor = Distributor(
        id="yum_distributor",
        type_id="yum_distributor",
        repo_id=repo_id,
        last_publish=dt,
        relative_url="content/unit/1/client",
    )
    repo = YumRepository(
        id=repo_id,
        eng_product_id=102,
        distributors=[distributor],
        relative_url="content/unit/1/client",
        mutable_urls=["repomd.xml"],
    )
    repos_to_insert.append(repo)

    repos = create_and_insert_repo(pulp, repos_to_insert)
    publisher_args = {
        "edgerc": EDGERC_FAKE_CONF,
        "publish_options": {
            "clean": True,
        },
        "cdn_root": "https://cdn.example.com",
        "arl_templates": ["/arl/1/test/{ttl}/{path}", "/arl/2/test/{ttl}/{path}"],
        "max_retry_sleep": 0.001,
    }
    setup_fastpurge_mock(requests_mock)

    url_ttl = ("https://cdn.example.com/content/unit/1/client/repomd.xml", "33s")
    # ARLs are generated from the template using the {ttl} placeholder, which is replaced with
    # the real TTL value. The real TTL value is extracted from the cache key header of the real
    # request for the given path using '/(\d+[smhd])/' regex.
    # The /1h/foo in the mocked header here is to test that if the path contains a component
    # that also matches the TTL regex ('/1h/'), it will still find the correct value ('/33s/').
    headers = {"X-Cache-Key": f"/fake/cache-key/{url_ttl[1]}/something/1h/foo"}
    requests_mock.register_uri("HEAD", url_ttl[0], headers=headers)

    # enqueue repos to publish and wait for publish and purge to finish
    with Publisher(**publisher_args) as publisher:
        publisher.enqueue(*repos)
        publisher.wait_publish_and_purge_cache()

    assert [hist.repository.id for hist in pulp.publish_history] == [
        repo.id for repo in repos
    ]

    hist = requests_mock.request_history

    assert len(hist) == 2  # 1 request to cdn service for headers and 1 purge request

    assert hist[0].url == "https://cdn.example.com/content/unit/1/client/repomd.xml"
    assert hist[1].json()["objects"] == [
        "https://cdn.example.com/content/unit/1/client/repomd.xml",
        "/arl/1/test/33s/content/unit/1/client/repomd.xml",
        "/arl/2/test/33s/content/unit/1/client/repomd.xml",
    ]


def test_cdn_client_retries(pulp, requests_mock):
    """
    Tests a scenario when some request to CDN service for TTL fails but
    it's retried with success.
    """
    dt = datetime(2019, 9, 12, 0, 0, 0)
    repos_to_insert = []
    repo_id = "repo-1"
    distributor = Distributor(
        id="yum_distributor",
        type_id="yum_distributor",
        repo_id=repo_id,
        last_publish=dt,
        relative_url="content/unit/1/client",
    )
    repo = YumRepository(
        id=repo_id,
        eng_product_id=102,
        distributors=[distributor],
        relative_url="content/unit/1/client",
        mutable_urls=["repomd.xml"],
    )
    repos_to_insert.append(repo)

    repos = create_and_insert_repo(pulp, repos_to_insert)

    url = "https://cdn.example.com/content/unit/1/client/repomd.xml"
    publisher_args = {
        "edgerc": EDGERC_FAKE_CONF,
        "publish_options": {
            "clean": True,
        },
        "cdn_root": "https://cdn.example.com",
        "arl_templates": ["/arl/1/test/{ttl}/{path}", "/arl/2/test/{ttl}/{path}"],
        "max_retry_sleep": 0.001,
    }
    setup_fastpurge_mock(requests_mock)
    requests_mock.register_uri(
        "HEAD",
        url,
        [
            # Fails on first try
            {"status_code": 500},
            # Then succeeds
            {
                "status_code": 200,
                "headers": {"X-Cache-Key": "/fake/cache-key/10h/something"},
            },
        ],
    )

    # enqueue repos for publish and wait to finish
    with Publisher(**publisher_args) as publisher:
        publisher.enqueue(*repos)
        publisher.wait_publish_and_purge_cache()

    # all published repos should be recorded in history
    assert [hist.repository.id for hist in pulp.publish_history] == [
        repo.id for repo in repos
    ]

    hist = requests_mock.request_history

    # there should be 2 requests to cdn service (failure and success) for headers and 1 CDN cache purge request
    assert len(hist) == 3

    for i in range(2):
        assert hist[i].url == "https://cdn.example.com/content/unit/1/client/repomd.xml"

    assert hist[-1].json()["objects"] == [
        "https://cdn.example.com/content/unit/1/client/repomd.xml",
        "/arl/1/test/10h/content/unit/1/client/repomd.xml",
        "/arl/2/test/10h/content/unit/1/client/repomd.xml",
    ]


@pytest.mark.parametrize(
    "path, expected_ttl",
    [
        ("content/test/repodata/repomd.xml", "4h"),
        ("content/test/repodata/", "10m"),
        ("/ostree/repo/refs/heads/test-path/base", "10m"),
        ("content/test/PULP_MANIFEST", "10m"),
        ("content/test/", "4h"),
        ("content/test/some-file", "30d"),
    ],
)
def test_arl_fallback(requests_mock, path, expected_ttl):
    """
    Tests fallback to default TTL values when TTL cannot be
    fetched from CDN service.
    """
    templates = [
        "/fake/template-1/{ttl}/{path}",
    ]
    with CdnClient(
        "https://cdn.example.com/", arl_templates=templates, max_retry_sleep=0.001
    ) as client:
        url = "https://cdn.example.com/content/foo/test-path-1/some-file"

        requests_mock.register_uri("HEAD", url, status_code=500)

        # Request ARLs
        arls_ft = client.get_arl_for_path(path)

        # It should be successful
        arl = [item.result() for item in as_completed(arls_ft)][0]

    # It should fallback to default ttl value
    assert arl == "/fake/template-1/{ttl}/{path}".format(ttl=expected_ttl, path=path)
