from ubipop._pulp_client import Repo, Package, Pulp
import pytest
import sys


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
