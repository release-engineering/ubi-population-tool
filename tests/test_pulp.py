import sys

try:
    from http.client import HTTPMessage
except ImportError:
    from httplib import HTTPMessage

import pytest
import requests
import six

from mock import MagicMock, patch
from requests.exceptions import HTTPError

from ubipop import _pulp_client as pulp_client
from ubipop._pulp_client import Repo, Package, ModuleDefaults, Pulp, PulpRetryAdapter

ORIG_HTTP_TOTAL_RETRIES = pulp_client.HTTP_TOTAL_RETRIES
ORIG_HTTP_RETRY_BACKOFF = pulp_client.HTTP_RETRY_BACKOFF

if sys.version_info <= (2, 7,):
    import requests_mock as rm

    @pytest.fixture(name='requests_mock')
    def fixture_requests_mock():
        with rm.Mocker() as m:
            yield m


@pytest.fixture(name='mock_pulp')
def fixture_mock_pulp():
    yield Pulp("foo.pulp.com", (None, ))


@pytest.fixture(name='search_repo_response')
def fixture_search_repo_response():
    yield [{
        "id": "test_repo",
        "notes": {
            "arch": "x86_64",
            "platform_full_version": "7",
        },
        "distributors": [{
            "id": "dist_id",
            "distributor_type_id": "d_type_id",
        }],
    }]


@pytest.fixture(name='mock_repo')
def fixture_mock_repo():
    yield Repo(
        "test_repo", "x86_64", "7", [
            ("dist_id_1", "dist_type_id_1"),
            ("dist_id_2", "dist_type_id_2"),
        ],
    )


@pytest.fixture(name='mock_package')
def fixture_mock_package():
    yield Package("foo-pkg", "foo-pkg.rpm")


@pytest.fixture(name='mock_mdd')
def fixture_mock_mdd():
    yield ModuleDefaults("virt", "rhel", {"2.6": ["common"]})


@pytest.fixture(name='mock_response_for_async_req')
def fixture_mock_response_for_async_req():
    yield {"spawned_tasks": [{"task_id": "foo_task_id"}]}


@pytest.fixture(name='search_rpms_response')
def fixture_search_rpms_response(request):
    try:
        pkg_number = request.param
    except AttributeError:
        pkg_number = 1

    yield [{
        "metadata": {
            "name": "foo-pkg",
            "filename": "foo-pkg.rpm",
            "sourcerpm": "foo-pkg.src.rpm",
            "is_modular": False,
        }
    } for _ in range(pkg_number)]


@pytest.fixture(name='search_modules_response')
def fixture_search_modules_response():
    yield [{
        "metadata": {
            "name": "foo-module",
            "stream": "9.6",
            "version": 1111,
            "context": "foo-context",
            "arch": "x86_64",
            'artifacts': ["foo-pkg"],
            'profiles': {
                "foo-prof": ["pkg-name"]
            },
        },
    }]


@pytest.fixture(name='search_module_defaults_response')
def fixture_search_module_defaults_response():
    yield [{
        "metadata": {
            "name": "virt",
            "stream": "rhel",
            "profiles": {
                "rhel": ["default", "common"]
            },
        },
    }]


@pytest.fixture(name='mock_search_rpms')
def fixture_mock_search_rpms(requests_mock, mock_repo, search_rpms_response):
    url = "/pulp/api/v2/repositories/{REPO_ID}/search/units/".format(REPO_ID=mock_repo.repo_id)
    requests_mock.register_uri('POST', url, json=search_rpms_response)


@pytest.fixture(name='mock_search_modules')
def fixture_mock_search_modules(requests_mock, mock_repo, search_modules_response):
    url = "/pulp/api/v2/repositories/{REPO_ID}/search/units/".format(REPO_ID=mock_repo.repo_id)
    requests_mock.register_uri('POST', url, json=search_modules_response)


@pytest.fixture(name='mock_search_module_defaults')
def fixture_mock_search_module_defaults(requests_mock, mock_repo, search_module_defaults_response):
    url = "/pulp/api/v2/repositories/{REPO_ID}/search/units/".format(REPO_ID=mock_repo.repo_id)
    requests_mock.register_uri('POST', url, json=search_module_defaults_response)


@pytest.fixture(name='mock_search_repos')
def fixture_mock_search_repos(requests_mock, search_repo_response):
    url = '/pulp/api/v2/repositories/search/'
    requests_mock.register_uri('POST', url, json=search_repo_response)


@pytest.fixture(name='mock_publish')
def fixture_mock_publish(requests_mock, mock_repo, mock_response_for_async_req):
    url = "/pulp/api/v2/repositories/{repo_id}/actions/publish/"\
        .format(repo_id=mock_repo.repo_id)
    requests_mock.register_uri('POST', url, json=mock_response_for_async_req)


@pytest.fixture(name='mock_associate')
def fixture_mock_associate(requests_mock, mock_repo, mock_response_for_async_req):
    url = "/pulp/api/v2/repositories/{dst_repo}/actions/associate/"\
        .format(dst_repo=mock_repo.repo_id)
    yield requests_mock.register_uri('POST', url, json=mock_response_for_async_req)


@pytest.fixture(name='mock_unassociate')
def fixture_mock_unassociate(requests_mock, mock_repo, mock_response_for_async_req):
    url = "/pulp/api/v2/repositories/{dst_repo}/actions/unassociate/"\
        .format(dst_repo=mock_repo.repo_id)
    requests_mock.register_uri('POST', url, json=mock_response_for_async_req)


def test_search_repo_by_cs(mock_pulp, mock_search_repos):
    # pylint: disable=unused-argument
    repos = mock_pulp.search_repo_by_cs("foo")

    assert len(repos) == 1
    repo = repos[0]
    assert repo.repo_id == "test_repo"
    assert repo.arch == "x86_64"
    assert repo.platform_full_version == "7"
    assert repo.distributors_ids_type_ids_tuples[0] == ("dist_id", "d_type_id")


def test_publish_repo(mock_pulp, mock_publish, mock_repo):
    # pylint: disable=unused-argument
    task_ids = mock_pulp.publish_repo(mock_repo)

    assert len(task_ids[0])
    assert task_ids[0] == "foo_task_id"


def test_associate_packages(mock_pulp, mock_associate, mock_repo, mock_package):
    # pylint: disable=unused-argument
    task_ids = mock_pulp.associate_packages(mock_repo, mock_repo, [mock_package])
    assert len(task_ids[0])
    assert task_ids[0] == "foo_task_id"


def test_unassociate_packages(mock_pulp, mock_unassociate, mock_repo, mock_package):
    # pylint: disable=unused-argument
    task_ids = mock_pulp.unassociate_packages(mock_repo, [mock_package])
    assert len(task_ids[0])
    assert task_ids[0] == "foo_task_id"


def test_associate_module_defaults(mock_pulp, mock_associate, mock_repo, mock_mdd):
    # pylint: disable=unused-argument
    task_ids = mock_pulp.associate_module_defaults(mock_repo, mock_repo, [mock_mdd])
    assert task_ids
    assert task_ids[0] == 'foo_task_id'


def test_unassociate_module_defaults(mock_pulp, mock_unassociate, mock_repo, mock_mdd):
    # pylint: disable=unused-argument
    task_ids = mock_pulp.unassociate_module_defaults(mock_repo, [mock_mdd])
    assert task_ids
    assert task_ids[0] == 'foo_task_id'


def test_search_rpms(mock_pulp, mock_search_rpms, mock_repo):
    # pylint: disable=unused-argument
    found_rpms = mock_pulp.search_rpms(mock_repo)
    assert len(found_rpms) == 1
    assert found_rpms[0].name == "foo-pkg"
    assert found_rpms[0].filename == "foo-pkg.rpm"
    assert found_rpms[0].sourcerpm_filename == "foo-pkg.src.rpm"
    assert found_rpms[0].is_modular is False


@pytest.mark.parametrize('search_rpms_response', [0, 1, 2], indirect=True)
def test_search_rpms_by_filename(mock_pulp, mock_search_rpms, mock_repo, search_rpms_response):
    # pylint: disable=unused-argument
    found_rpms = mock_pulp.search_rpms(mock_repo, filename="foo-pkg.rpm")
    assert len(search_rpms_response) == len(found_rpms)


def test_search_modules(mock_pulp, mock_search_modules, mock_repo):
    # pylint: disable=unused-argument
    found_modules = mock_pulp.search_modules(mock_repo)
    assert len(found_modules) == 1

    assert found_modules[0].nsvca == "foo-module:9.6:1111:foo-context:x86_64"
    assert found_modules[0].packages == ["foo-pkg"]
    assert found_modules[0].profiles == {"foo-prof": ["pkg-name"]}


def test_search_module_defaults(mock_pulp, mock_search_module_defaults, mock_repo):
    # pylint: disable=unused-argument
    found_module_defaults = mock_pulp.search_module_defaults(mock_repo, name='virt', stream='rhel')
    assert len(found_module_defaults) == 1
    assert found_module_defaults[0].name == 'virt'
    assert found_module_defaults[0].stream == 'rhel'
    assert found_module_defaults[0].name_profiles == 'virt:[rhel:common,default]'


@pytest.fixture(name='search_task_response')
def fixture_search_task_response():
    yield {"state": "finished", "task_id": "test_task"}


@pytest.fixture(name='mock_search_task')
def fixture_mock_search_task(requests_mock, search_task_response):
    url = "/pulp/api/v2/tasks/{task_id}/".format(task_id='test_task')
    requests_mock.register_uri('GET', url, json=search_task_response)


def test_wait_for_tasks(mock_pulp, mock_search_task):
    # pylint: disable=unused-argument
    results = mock_pulp.wait_for_tasks(["test_task"])
    assert len(results) == 1
    assert results["test_task"]['state'] == 'finished'


@pytest.fixture(name='mocked_getresponse')
def fixture_mocked_getresponse():
    with patch("urllib3.connectionpool.HTTPConnectionPool._get_conn") as mocked_get_conn:
        yield mocked_get_conn.return_value.getresponse


def make_mock_response(status, text=None):
    m = MagicMock(name='MockResponse', status=status)
    m.isclosed.side_effect = [False, True]
    m.msg = MagicMock(spec=HTTPMessage, headers=[], status=status)
    m.read.return_value = six.b(text)
    return m


@pytest.mark.parametrize(
    "should_retry,err_status_code,env_retries,retry_call,retry_args,ok_response,expected_retries",
    [
        # test everything is retryable
        (True, 500, None, "search_repo_by_cs", ("",), '{}', pulp_client.HTTP_TOTAL_RETRIES),
        (True, 500, None, "search_rpms",
         (MagicMock(repo_id='fake_id'),), '[]', pulp_client.HTTP_TOTAL_RETRIES),
        (True, 500, None, "search_modules",
         (MagicMock(repo_id='fake_id'),), '[]', pulp_client.HTTP_TOTAL_RETRIES),
        (True, 500, None, "wait_for_tasks", (['fake-tid'],),
         '{"state":"finished","task_id":"fake-tid"}', pulp_client.HTTP_TOTAL_RETRIES),
        (True, 500, None, "search_tasks", ([MagicMock()],), '[]', pulp_client.HTTP_TOTAL_RETRIES),
        (True, 500, None, "unassociate_units", ((2 * (MagicMock(), )) + (['rpm'], )),
         '{"spawned_tasks":[]}', pulp_client.HTTP_TOTAL_RETRIES),
        (True, 500, None, "associate_units", (MagicMock(repo_id='fake_id'),
                                              MagicMock(repo_id='fake_id'),
                                              MagicMock(), ['rpm'], ),
         '{"spawned_tasks":[]}', pulp_client.HTTP_TOTAL_RETRIES),
        (True, 500, None, "publish_repo", (
            MagicMock(distributors_ids_type_ids_tuples=[('a', 'b')]), ),
         '{"spawned_tasks":[]}', pulp_client.HTTP_TOTAL_RETRIES),

        # test custom number of retries
        (True, 500, 3, "search_repo_by_cs", ("",), '{}', 3),

        # test 400 status is not retryable
        (False, 400, 3, "search_repo_by_cs", ("",), '{}', 3),
    ]
)
def test_retries(mocked_getresponse, mock_pulp, should_retry,
                 err_status_code, env_retries, retry_call,
                 retry_args, ok_response, expected_retries):
    pulp_client.HTTP_RETRY_BACKOFF = 0

    try:
        if env_retries:
            pulp_client.HTTP_TOTAL_RETRIES = env_retries

        retries = [make_mock_response(err_status_code, 'Fake Http error')
                   for _ in range(pulp_client.HTTP_TOTAL_RETRIES-1)]
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


@pytest.mark.parametrize('method,called', [
    ('get', True),
    ('post', True),
    ('put', False),
    ('delete', False),
])
def test_do_request(mock_pulp, method, called):
    mock_pulp.local.session = MagicMock()

    response = mock_pulp.do_request(method, '/foo/bar')

    handler = getattr(mock_pulp.local.session, method)

    if called:
        handler.assert_called_once()
        assert response is not None
    else:
        handler.assert_not_called()
        assert response is None


@pytest.mark.parametrize('auth', [
    (['/path/file.crt']),
    (['user', 'pwd']),
])
def test_make_session(mock_pulp, auth):
    mock_pulp.auth = auth
    mock_pulp._make_session() # pylint: disable=protected-access

    assert hasattr(mock_pulp.local, 'session')

    session = mock_pulp.local.session

    assert isinstance(session, requests.Session)
    assert isinstance(session.get_adapter('http://'), PulpRetryAdapter)
    assert isinstance(session.get_adapter('https://'), PulpRetryAdapter)
