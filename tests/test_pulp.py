import mock
import os
import sys
import re
import httplib
from requests.exceptions import HTTPError

from ubipop._pulp_client import Repo, Package, Pulp, PulpRetryAdapter, HTTP_TOTAL_RETRIES

import pytest

import requests_mock

if sys.version_info <= (2, 7,):
    import requests_mock as rm

    @pytest.fixture()
    def requests_mock():
        with rm.Mocker() as m:
            yield m


@pytest.fixture()
def mock_pulp():
    yield Pulp("foo.pulp.com", (None, ))


@pytest.fixture()
def search_repo_response():
    yield [{"id": "test_repo",
            "notes":
                {"arch": "x86_64",
                 "platform_full_version": "7"},
            "distributors": [{"id": "dist_id", "distributor_type_id": "d_type_id"}]}]


@pytest.fixture()
def mock_repo():
    yield Repo("test_repo", "x86_64", "7", [("dist_id_1", "dist_type_id_1"),
                                            ("dist_id_2", "dist_type_id_2")])


@pytest.fixture()
def mock_package():
    yield Package("foo-pkg", "foo-pkg.rpm")


@pytest.fixture()
def mock_response_for_async_req():
    yield {"spawned_tasks": [{"task_id": "foo_task_id"}]}


@pytest.fixture()
def search_rpms_response():
    yield [{"metadata": {"name": "foo-pkg", "filename": "foo-pkg.rpm",
                         "sourcerpm": "foo-pkg.src.rpm"}}]


@pytest.fixture()
def search_modules_response():
    yield [{"metadata": {"name": "foo-module", "stream": "9.6", "version": 1111,
                         "context": "foo-context",
                         "arch": "x86_64",  'artifacts': ["foo-pkg"],
                         'profiles': {"foo-prof": ["pkg-name"]}}}]


@pytest.fixture()
def mock_search_rpms(requests_mock, mock_repo, search_rpms_response):
    url = "/pulp/api/v2/repositories/{REPO_ID}/search/units/".format(REPO_ID=mock_repo.repo_id)
    requests_mock.register_uri('POST', url, json=search_rpms_response)


@pytest.fixture()
def mock_search_modules(requests_mock, mock_repo, search_modules_response):
    url = "/pulp/api/v2/repositories/{REPO_ID}/search/units/".format(REPO_ID=mock_repo.repo_id)
    requests_mock.register_uri('POST', url, json=search_modules_response)


@pytest.fixture()
def mock_search_repos(requests_mock, search_repo_response):
    url = '/pulp/api/v2/repositories/search/'
    requests_mock.register_uri('POST', url, json=search_repo_response)


@pytest.fixture()
def mock_publish(requests_mock, mock_repo, mock_response_for_async_req):
    url = "/pulp/api/v2/repositories/{repo_id}/actions/publish/"\
        .format(repo_id=mock_repo.repo_id)
    requests_mock.register_uri('POST', url, json=mock_response_for_async_req)


@pytest.fixture()
def mock_associate(requests_mock, mock_repo, mock_response_for_async_req):
    url = "/pulp/api/v2/repositories/{dst_repo}/actions/associate/"\
        .format(dst_repo=mock_repo.repo_id)
    yield requests_mock.register_uri('POST', url, json=mock_response_for_async_req)


@pytest.fixture()
def mock_unassociate(requests_mock, mock_repo, mock_response_for_async_req):
    url = "/pulp/api/v2/repositories/{dst_repo}/actions/unassociate/"\
        .format(dst_repo=mock_repo.repo_id)
    requests_mock.register_uri('POST', url, json=mock_response_for_async_req)


def test_search_repo_by_cs(mock_pulp, mock_search_repos):
    repos = mock_pulp.search_repo_by_cs("foo")

    assert len(repos) == 1
    repo = repos[0]
    assert repo.repo_id == "test_repo"
    assert repo.arch == "x86_64"
    assert repo.platform_full_version == "7"
    assert repo.distributors_ids_type_ids_tuples[0] == ("dist_id", "d_type_id")


def test_publish_repo(mock_pulp, mock_publish, mock_repo):
    task_ids = mock_pulp.publish_repo(mock_repo)

    assert len(task_ids[0])
    assert task_ids[0] == "foo_task_id"


def test_associate_packages(mock_pulp, mock_associate, mock_repo, mock_package):
    task_ids = mock_pulp.associate_packages(mock_repo, mock_repo, [mock_package])
    assert len(task_ids[0])
    assert task_ids[0] == "foo_task_id"


def test_unassociate_packages(mock_pulp, mock_unassociate, mock_repo, mock_package):
    task_ids = mock_pulp.unassociate_packages(mock_repo, [mock_package])
    assert len(task_ids[0])
    assert task_ids[0] == "foo_task_id"


def test_search_rpms(mock_pulp, mock_search_rpms, mock_repo):
    found_rpms = mock_pulp.search_rpms(mock_repo)
    assert len(found_rpms) == 1
    assert found_rpms[0].name == "foo-pkg"
    assert found_rpms[0].filename == "foo-pkg.rpm"
    assert found_rpms[0].sourcerpm_filename == "foo-pkg.src.rpm"


def test_search_modules(mock_pulp, mock_search_modules, mock_repo):
    found_modules = mock_pulp.search_modules(mock_repo)
    assert len(found_modules) == 1

    assert found_modules[0].nsvca == "foo-module:9.6:1111:foo-context:x86_64"
    assert found_modules[0].packages == ["foo-pkg"]
    assert found_modules[0].profiles == {"foo-prof": ["pkg-name"]}


@pytest.fixture()
def search_task_response():
    yield {"state": "finished", "task_id": "test_task"}


@pytest.fixture()
def mock_search_task(requests_mock, search_task_response):
    url = "/pulp/api/v2/tasks/{task_id}/".format(task_id='test_task')
    requests_mock.register_uri('GET', url, json=search_task_response)


def test_wait_for_tasks(mock_pulp, mock_search_task):
    results = mock_pulp.wait_for_tasks(["test_task"])
    assert len(results) == 1
    assert results["test_task"]['state'] == 'finished'


@pytest.fixture()
def mocked_getresponse():
    with mock.patch("urllib3.connectionpool.HTTPConnectionPool._get_conn") as mocked_get_conn:
        yield mocked_get_conn.return_value.getresponse


@pytest.fixture()
def set_backoff_to_zero_fixture(mock_pulp):
    patcher = mock.patch("ubipop._pulp_client.Pulp._make_session")
    orig = mock_pulp._make_session
    patched = patcher.start()
    patched.side_effect = lambda: [
        orig(),
        setattr(mock_pulp.adapter.max_retries, "backoff_factor", 0)
    ]
    yield patched
    patcher.stop()


def make_mock_response(status, text=None):
    m = mock.MagicMock(name='MockResponse', status=status)
    m.isclosed.side_effect = [False, True]
    m.msg = mock.MagicMock(spec=httplib.HTTPMessage, headers=[], status=status)
    m.read.return_value = text
    return m


@pytest.mark.parametrize(
    "should_retry,err_status_code,env_retries,retry_call,retry_args,ok_response,expected_retries",
    [
        (True, 500, None, "search_repo_by_cs", (mock.MagicMock(),), '{}', HTTP_TOTAL_RETRIES),
        (True, 500, None, "search_rpms", (mock.MagicMock(),), '[]', HTTP_TOTAL_RETRIES),
        (True, 500, None, "search_modules", (mock.MagicMock(),), '[]', HTTP_TOTAL_RETRIES),
        (True, 500, None, "wait_for_tasks", (['fake-tid'],),
         '{"state":"finished","task_id":"fake-tid"}', HTTP_TOTAL_RETRIES),
        (True, 500, None, "search_tasks", ([mock.MagicMock()],), '[]', HTTP_TOTAL_RETRIES),
        (True, 500, None, "unassociate_units", ((2 * (mock.MagicMock(), )) + (['rpm'], )),
         '{"spawned_tasks":[]}', HTTP_TOTAL_RETRIES),
        (True, 500, None, "associate_units", ((3 * (mock.MagicMock(), )) + (['rpm'], )),
         '{"spawned_tasks":[]}', HTTP_TOTAL_RETRIES),
        (True, 500, None, "publish_repo", (
            mock.MagicMock(distributors_ids_type_ids_tuples=[('a', 'b')]), ),
         '{"spawned_tasks":[]}', HTTP_TOTAL_RETRIES),

        (True, 500, 3, "search_repo_by_cs", (mock.MagicMock(),), '{}', 3),
        (False, 400, 3, "search_repo_by_cs", (mock.MagicMock(),), '{}', 3),
    ]
)
def test_retries(set_backoff_to_zero_fixture, mocked_getresponse, mock_pulp, should_retry, err_status_code,
                 env_retries, retry_call, retry_args, ok_response, expected_retries):
    global HTTP_TOTAL_RETRIES
    if env_retries:
        HTTP_TOTAL_RETRIES = env_retries

    retries = [make_mock_response(err_status_code, 'x')
               for _ in range(HTTP_TOTAL_RETRIES)[:-1]] + [make_mock_response(200, ok_response)]
    mocked_getresponse.side_effect = retries

    if should_retry:
        getattr(mock_pulp, retry_call)(*retry_args)
        assert len(mocked_getresponse.mock_calls) == expected_retries
    else:
        with pytest.raises(HTTPError):
            getattr(mock_pulp, retry_call)(*retry_args)
