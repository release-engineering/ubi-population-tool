import os
from mock import MagicMock, patch

import pytest

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


@patch("ubipop.ubi_manifest_client.client.HTTPKerberosAuth")
def test_kerberos_auth(kerb_mock, requests_mock):
    """
    Tests basic flow with kerberos auth. enabled.
    """
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
                force_preemptive=True,
                principal="principal@REALM.COM",
            )
            assert client._tls.session.auth is not None
