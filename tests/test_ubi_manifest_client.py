import os

import pytest
import requests
from mock import MagicMock, patch

from ubipop.ubi_manifest_client.client import Client, UbiManifestTaskFailure
from ubipop.ubi_manifest_client.models import (
    ModulemdDefaultsUnit,
    ModulemdUnit,
    RpmUnit,
    UbiManifest,
)

# pylint: disable=protected-access


def test_generate_manifest(requests_mock):
    url = "api/v1/manifest"
    url = os.path.join("https://foo-bar.com", url)

    response = [{"task_id": "some-task-id"}]
    requests_mock.register_uri("POST", url, json=response)

    url = "api/v1/task/some-task-id"

    url = os.path.join("https://foo-bar.com", url)
    requests_mock.register_uri(
        "GET",
        url,
        [
            {
                "json": {"task_id": "some-task-id", "state": "PENDING"},
                "status_code": 200,
            },
            {
                "json": {"task_id": "some-task-id", "state": "SUCCESS"},
                "status_code": 200,
            },
        ],
    )

    with Client("https://foo-bar.com") as client:

        tasks = client.generate_manifest(["repo_id_1", "repo_id_2"])
        tasks.result()


def test_generate_manifest_failure(requests_mock):
    url = "api/v1/manifest"
    url = os.path.join("https://foo-bar.com", url)

    response = [{"task_id": "some-task-id"}]
    requests_mock.register_uri("POST", url, json=response)

    url = "api/v1/task/some-task-id"

    url = os.path.join("https://foo-bar.com", url)
    requests_mock.register_uri(
        "GET",
        url,
        [
            {
                "json": {"task_id": "some-task-id", "state": "PENDING"},
                "status_code": 200,
            },
            {
                "json": {"task_id": "some-task-id", "state": "FAILURE"},
                "status_code": 200,
            },
        ],
    )

    with Client("https://foo-bar.com") as client:
        tasks = client.generate_manifest(["repo_id_1", "repo_id_2"])
        with pytest.raises(UbiManifestTaskFailure):
            tasks.result()


def test_generate_manifest_task_not_found(requests_mock):
    """
    Tests that a task unknown to ubi-manifest makes depsolving of the manifest
    be requested again, and that the tasks of the new request are awaited.
    """
    manifest_url = os.path.join("https://foo-bar.com", "api/v1/manifest")
    requests_mock.register_uri(
        "POST",
        manifest_url,
        [
            {"json": [{"task_id": "missing-task-id"}], "status_code": 200},
            {"json": [{"task_id": "new-task-id"}], "status_code": 200},
        ],
    )

    requests_mock.register_uri(
        "GET",
        os.path.join("https://foo-bar.com", "api/v1/task/missing-task-id"),
        json={"detail": "Task missing-task-id not found"},
        status_code=404,
    )
    requests_mock.register_uri(
        "GET",
        os.path.join("https://foo-bar.com", "api/v1/task/new-task-id"),
        json={"task_id": "new-task-id", "state": "SUCCESS"},
    )

    with Client("https://foo-bar.com") as client:
        tasks = client.generate_manifest(["repo_id_1", "repo_id_2"])
        assert tasks.result() == [{"task_id": "new-task-id"}]

    post_requests = [
        r
        for r in requests_mock.request_history
        if r.method == "POST" and r.url == manifest_url
    ]
    assert len(post_requests) == 2


def test_generate_manifest_task_not_found_gives_up(requests_mock):
    """
    Tests that a task missing from ubi-manifest on every attempt fails the
    manifest generation instead of being requested forever.

    The error is raised as is, a missing task is a problem of the service
    rather than a failure of the task itself.
    """
    manifest_url = os.path.join("https://foo-bar.com", "api/v1/manifest")
    requests_mock.register_uri(
        "POST", manifest_url, json=[{"task_id": "missing-task-id"}]
    )
    requests_mock.register_uri(
        "GET",
        os.path.join("https://foo-bar.com", "api/v1/task/missing-task-id"),
        json={"detail": "Task missing-task-id not found"},
        status_code=404,
    )

    with Client("https://foo-bar.com") as client:
        tasks = client.generate_manifest(["repo_id_1", "repo_id_2"])
        with pytest.raises(requests.HTTPError) as exc_info:
            tasks.result()

        assert exc_info.value.response.status_code == 404

    post_requests = [
        r
        for r in requests_mock.request_history
        if r.method == "POST" and r.url == manifest_url
    ]
    assert len(post_requests) == 3


def test_unpack_failure():
    with Client("https://foo-bar.com") as client:
        response = MagicMock()
        response.json.side_effect = Exception()
        with pytest.raises(Exception):
            client._unpack_response(response)


def test_get_manifest(requests_mock):
    url = "api/v1/manifest/some-repo-id"
    url = os.path.join("https://foo-bar.com", url)

    response = {
        "repo_id": "some-repo-id",
        "content": [
            {
                "unit_type": "RpmUnit",
                "src_repo_id": "another-repo-id",
                "value": "some_package.rpm",
            },
            {
                "unit_type": "ModulemdUnit",
                "src_repo_id": "another-repo-id",
                "value": "name:stream:1234567890:context:arch",
            },
            {
                "unit_type": "ModulemdDefaultsUnit",
                "src_repo_id": "another-repo-id",
                "value": "name:stream",
            },
        ],
    }

    requests_mock.register_uri("GET", url, json=response)

    with Client("https://foo-bar.com") as client:
        manifest = client.get_manifest("some-repo-id").result()

        assert isinstance(manifest, UbiManifest)
        assert manifest.repo_id == "some-repo-id"

        # there should 3 units in the manifest
        assert len(manifest.manifest) == 3

        sorted_units = sorted(manifest.manifest, key=lambda x: x.src_repo_id)

        # each unit has proper type and fields set
        unit = sorted_units[0]
        assert isinstance(unit, RpmUnit)
        assert unit.src_repo_id == "another-repo-id"
        assert unit.associate_source_repo_id == unit.src_repo_id

        assert unit.dst_repo_id == "some-repo-id"
        assert unit.filename == "some_package.rpm"

        unit = sorted_units[1]
        assert isinstance(unit, ModulemdUnit)
        assert unit.src_repo_id == "another-repo-id"
        assert unit.associate_source_repo_id == unit.src_repo_id
        assert unit.dst_repo_id == "some-repo-id"
        assert unit.name == "name"
        assert unit.stream == "stream"
        assert unit.version == 1234567890
        assert unit.context == "context"
        assert unit.arch == "arch"

        unit = sorted_units[2]
        assert isinstance(unit, ModulemdDefaultsUnit)
        assert unit.src_repo_id == "another-repo-id"
        assert unit.associate_source_repo_id == unit.src_repo_id
        assert unit.dst_repo_id == "some-repo-id"
        assert unit.name == "name"
        assert unit.stream == "stream"


def test_no_auth(requests_mock):
    """
    Tests usage of no authentication to ubi-manifest service.
    """
    url = "api/v1/manifest"
    url = os.path.join("https://foo-bar.com", url)
    requests_mock.register_uri("GET", url)
    with Client("https://foo-bar.com") as client:
        _ = client._do_request(method="GET", url=url)
        assert client._tls.session.auth is None


def test_kerberos_auth_no_principal(requests_mock):
    """
    Tests failure when providing empty principal when kerberos auth. is enabled.
    """
    url = "api/v1/manifest"
    url = os.path.join("https://foo-bar.com", url)
    requests_mock.register_uri("GET", url)

    with patch.dict(
        os.environ,
        {
            "UBIPOP_KERBEROS_ENABLED_UBI_MANIFEST": "true",
        },
    ):

        with Client("https://foo-bar.com") as client:
            with pytest.raises(ValueError):
                _ = client._do_request(method="GET", url=url)


@patch("ubipop.ubi_manifest_client.client.HTTPSPNEGOAuth")
@patch("gssapi.Credentials", autospec=True)
def test_kerberos_auth(credentials_mock, kerb_mock, requests_mock):
    """
    Tests basic flow with kerberos auth. enabled.
    """
    mocked_credentials = MagicMock()
    credentials_mock.return_value = mocked_credentials

    url = "api/v1/manifest"
    url = os.path.join("https://foo-bar.com", url)
    requests_mock.register_uri("GET", url)

    with patch.dict(
        os.environ,
        {
            "UBIPOP_KERBEROS_ENABLED_UBI_MANIFEST": "true",
            "UBIPOP_KERBEROS_PRINCIPAL_UBI_MANIFEST": "principal@REALM.COM",
        },
    ):

        with Client("https://foo-bar.com") as client:
            _ = client._do_request(method="GET", url=url)
            kerb_mock.assert_called_once_with(
                mutual_authentication=2,
                opportunistic_auth=True,
                creds=mocked_credentials,
            )
            assert client._tls.session.auth is not None
