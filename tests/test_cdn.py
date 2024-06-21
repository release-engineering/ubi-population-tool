from datetime import datetime

import pytest
from pubtools.pulplib import Distributor, FakeController, YumRepository

from ubipop._cdn import Publisher


@pytest.fixture(name="pulp")
def fake_pulp():
    yield FakeController()


def create_and_insert_repo(pulp, repos):
    out = []
    for repo in repos:
        pulp.insert_repository(repo)
        out.append(pulp.client.get_repository(repo.id))

    return out


def test_publisher(pulp):
    """
    Tests a basic scenario of repository publish.
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
        publisher.wait_publish()

    # all repos are properly published
    assert [hist.repository.id for hist in pulp.publish_history] == [
        repo.id for repo in repos
    ]
