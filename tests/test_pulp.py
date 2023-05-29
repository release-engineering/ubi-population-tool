import threading

try:
    from http.client import HTTPResponse
except ImportError:
    from httplib import HTTPResponse

from io import BytesIO

import logging
import sys
import pytest
import requests

from mock import MagicMock, patch
from requests.exceptions import HTTPError

from pubtools.pulplib import YumRepository
from ubipop import _pulp_client as pulp_client
from ubipop._pulp_client import Pulp, PulpRetryAdapter

from .conftest import (
    get_rpm_unit,
    get_modulemd_defaults_unit,
)

ORIG_HTTP_TOTAL_RETRIES = pulp_client.HTTP_TOTAL_RETRIES
ORIG_HTTP_RETRY_BACKOFF = pulp_client.HTTP_RETRY_BACKOFF


@pytest.fixture(name="mock_pulp")
def fixture_mock_pulp():
    yield Pulp("foo.pulp.com")


@pytest.fixture(name="mock_repo")
def fixture_mock_repo():
    yield YumRepository(
        id="test_repo",
        content_set="test_repo-source-rpms",
        ubi_config_version="7.9",
        ubi_population=True,
        population_sources=["a", "b"],
    )


@pytest.fixture(name="mock_package")
def fixture_mock_package():
    yield get_rpm_unit(
        name="foo-pkg",
        version="10",
        release="1",
        arch="x86_64",
        filename="foo-pkg.rpm",
        src_repo_id="src_repo_id",
    )


@pytest.fixture(name="mock_mdd")
def fixture_mock_mdd():
    yield get_modulemd_defaults_unit(
        name="virt",
        stream="rhel",
        profiles={"2.6": ["common"]},
        repo_id="src_repo_id",
        src_repo_id="src_repo_id",
    )


@pytest.fixture(name="mock_response_for_async_req")
def fixture_mock_response_for_async_req():
    yield {"spawned_tasks": [{"task_id": "foo_task_id"}]}


@pytest.fixture(name="mock_associate")
def fixture_mock_associate(requests_mock, mock_repo, mock_response_for_async_req):
    url = "/pulp/api/v2/repositories/{dst_repo}/actions/associate/".format(
        dst_repo=mock_repo.id
    )
    yield requests_mock.register_uri("POST", url, json=mock_response_for_async_req)


@pytest.fixture(name="mock_unassociate")
def fixture_mock_unassociate(requests_mock, mock_repo, mock_response_for_async_req):
    url = "/pulp/api/v2/repositories/{dst_repo}/actions/unassociate/".format(
        dst_repo=mock_repo.id
    )
    requests_mock.register_uri("POST", url, json=mock_response_for_async_req)


@pytest.fixture(name="set_logging")
def fixture_set_logging():
    logger = logging.getLogger("ubipop")
    logger.setLevel(logging.INFO)
    yield logger
    logger.handlers = []


def test_associate_packages(mock_pulp, mock_associate, mock_repo, mock_package):
    # pylint: disable=unused-argument
    task_ids = mock_pulp.associate_packages(mock_repo, mock_repo, [mock_package])
    assert len(task_ids[0])
    assert task_ids[0] == "foo_task_id"


def test_associate_packages_log(
    capsys, mock_pulp, mock_associate, set_logging, mock_repo, mock_package
):
    # pylint: disable=unused-argument
    set_logging.addHandler(logging.StreamHandler(sys.stdout))
    mock_pulp.associate_packages(mock_repo, mock_repo, [mock_package])
    out, _ = capsys.readouterr()
    assert (
        out.strip() == "Associating rpm,srpm(foo-pkg.rpm) from test_repo to test_repo"
    )


def test_unassociate_packages(mock_pulp, mock_unassociate, mock_repo, mock_package):
    # pylint: disable=unused-argument
    task_ids = mock_pulp.unassociate_packages(mock_repo, [mock_package])
    assert len(task_ids[0])
    assert task_ids[0] == "foo_task_id"


def test_associate_module_defaults(mock_pulp, mock_associate, mock_repo, mock_mdd):
    # pylint: disable=unused-argument
    task_ids = mock_pulp.associate_module_defaults(mock_repo, mock_repo, [mock_mdd])
    assert task_ids
    assert task_ids[0] == "foo_task_id"


def test_unassociate_module_defaults(mock_pulp, mock_unassociate, mock_repo, mock_mdd):
    # pylint: disable=unused-argument
    task_ids = mock_pulp.unassociate_module_defaults(mock_repo, [mock_mdd])
    assert task_ids
    assert task_ids[0] == "foo_task_id"


def test_unassociate_module_defaults_log(
    capsys, mock_pulp, mock_unassociate, set_logging, mock_repo, mock_mdd
):
    # pylint: disable=unused-argument
    set_logging.addHandler(logging.StreamHandler(sys.stdout))
    mock_pulp.unassociate_module_defaults(mock_repo, [mock_mdd])
    out, _ = capsys.readouterr()
    assert out.strip() == "Unassociating modulemd_defaults(virt:rhel) from test_repo"


@pytest.fixture(name="search_task_response")
def fixture_search_task_response():
    yield {"state": "finished", "task_id": "test_task"}


@pytest.fixture(name="mock_search_task")
def fixture_mock_search_task(requests_mock, search_task_response):
    url = "/pulp/api/v2/tasks/{task_id}/".format(task_id="test_task")
    requests_mock.register_uri("GET", url, json=search_task_response)


def test_wait_for_tasks(mock_pulp, mock_search_task):
    # pylint: disable=unused-argument
    results = mock_pulp.wait_for_tasks(["test_task"])
    assert len(results) == 1
    assert results["test_task"]["state"] == "finished"


@pytest.fixture(name="mocked_getresponse")
def fixture_mocked_getresponse():
    with patch(
        "urllib3.connectionpool.HTTPConnectionPool._get_conn"
    ) as mocked_get_conn:
        yield mocked_get_conn.return_value.getresponse


def make_mock_response(status, text):
    response_string = (
        "HTTP/1.1 {0} Reason\r\n" "Content-Type: application/json\r\n" "\r\n" "{1}"
    ).format(status, text)

    mocked_sock = MagicMock()
    mocked_sock.makefile.return_value = BytesIO(response_string.encode())

    http_response = HTTPResponse(mocked_sock)
    http_response.begin()

    return http_response


@pytest.mark.parametrize(
    "should_retry,err_status_code,env_retries,retry_call,retry_args,ok_response,expected_retries",
    [
        # test everything is retryable
        (
            True,
            500,
            None,
            "wait_for_tasks",
            (["fake-tid"],),
            '{"state":"finished","task_id":"fake-tid"}',
            pulp_client.HTTP_TOTAL_RETRIES,
        ),
        (
            True,
            500,
            None,
            "search_tasks",
            ([MagicMock()],),
            "[]",
            pulp_client.HTTP_TOTAL_RETRIES,
        ),
        (
            True,
            500,
            None,
            "unassociate_units",
            ((2 * (MagicMock(),)) + (["rpm"],)),
            '{"spawned_tasks":[]}',
            pulp_client.HTTP_TOTAL_RETRIES,
        ),
        (
            True,
            500,
            None,
            "associate_units",
            (
                MagicMock(id="fake_id"),
                MagicMock(id="fake_id"),
                MagicMock(),
                ["rpm"],
            ),
            '{"spawned_tasks":[]}',
            pulp_client.HTTP_TOTAL_RETRIES,
        ),
        # test custom number of retries
        (
            True,
            500,
            3,
            "associate_units",
            (
                MagicMock(id="fake_id"),
                MagicMock(id="fake_id"),
                MagicMock(),
                ["rpm"],
            ),
            '{"spawned_tasks":[]}',
            3,
        ),
        # test 400 status is not retryable
        (
            False,
            400,
            3,
            "associate_units",
            (
                MagicMock(id="fake_id"),
                MagicMock(id="fake_id"),
                MagicMock(),
                ["rpm"],
            ),
            '{"spawned_tasks":[]}',
            3,
        ),
    ],
)
def test_retries(
    mocked_getresponse,
    mock_pulp,
    should_retry,
    err_status_code,
    env_retries,
    retry_call,
    retry_args,
    ok_response,
    expected_retries,
):
    pulp_client.HTTP_RETRY_BACKOFF = 0

    try:
        if env_retries:
            pulp_client.HTTP_TOTAL_RETRIES = env_retries

        retries = [
            make_mock_response(err_status_code, "Fake Http error")
            for _ in range(pulp_client.HTTP_TOTAL_RETRIES - 1)
        ]
        retries.extend([make_mock_response(200, ok_response)])
        mocked_getresponse.side_effect = retries

        if should_retry:
            getattr(mock_pulp, retry_call)(*retry_args)
            assert len(mocked_getresponse.mock_calls) == expected_retries
        else:
            with pytest.raises(HTTPError):
                getattr(mock_pulp, retry_call)(*retry_args)
    finally:
        pulp_client.HTTP_TOTAL_RETRIES = ORIG_HTTP_TOTAL_RETRIES
        pulp_client.HTTP_RETRY_BACKOFF = ORIG_HTTP_RETRY_BACKOFF


@pytest.mark.parametrize(
    "method,called",
    [
        ("get", True),
        ("post", True),
        ("put", False),
        ("delete", False),
    ],
)
def test_do_request(mock_pulp, method, called):
    mock_pulp.local.session = MagicMock()

    response = mock_pulp.do_request(method, "/foo/bar")

    handler = getattr(mock_pulp.local.session, method)

    if called:
        handler.assert_called_once()
        assert response is not None
    else:
        handler.assert_not_called()
        assert response is None


@pytest.mark.parametrize(
    "auth",
    [
        (["/path/file.crt"]),
        (["user", "pwd"]),
    ],
)
def test_make_session(mock_pulp, auth):
    mock_pulp.auth = auth
    mock_pulp._make_session()  # pylint: disable=protected-access

    assert hasattr(mock_pulp.local, "session")

    session = mock_pulp.local.session

    assert isinstance(session, requests.Session)
    assert isinstance(session.get_adapter("http://"), PulpRetryAdapter)
    assert isinstance(session.get_adapter("https://"), PulpRetryAdapter)


@pytest.mark.parametrize(
    "count",
    [
        (2),
        (5),
        (10),
    ],
)
def test_session_is_not_shared(mock_pulp, count):
    def make_session(sessions):
        mock_pulp._make_session()  # pylint: disable=protected-access
        sessions.append(mock_pulp.local.session)

    threads = []
    sessions = []

    for _ in range(count):
        t = threading.Thread(target=make_session, args=(sessions,))
        threads.append(t)

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    assert len(sessions) == len(threads) == count
    assert len(set(sessions)) == len(threads)

    for session in sessions:
        assert isinstance(session, requests.Session)
        assert isinstance(session.get_adapter("http://"), PulpRetryAdapter)
        assert isinstance(session.get_adapter("https://"), PulpRetryAdapter)


def test_insecure():
    with patch("urllib3.disable_warnings") as patched_warnings:
        kwargs = {
            "auth": ("fake", "user"),
            "verify": False,
        }
        Pulp("foo.host", **kwargs)
        patched_warnings.assert_called_once()
