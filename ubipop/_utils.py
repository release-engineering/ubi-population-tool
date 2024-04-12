class Association:
    def __init__(self, units, unit_type, dst_repo, src_repos):
        self.units = units
        self.unit_type = unit_type
        self.dst_repo = dst_repo
        self.src_repos = src_repos
        self._src_repo_id_to_unit_map = None

    @property
    def src_repo_id_to_unit_map(self):
        if self._src_repo_id_to_unit_map is None:
            mapping = {}
            for unit in self.units:
                mapping.setdefault(unit.associate_source_repo_id, []).append(unit)
            self._src_repo_id_to_unit_map = mapping
        return self._src_repo_id_to_unit_map

    def get_repo(self, repo_id):
        for repo in self.src_repos:
            if repo_id == repo.id:
                return repo


class Unassociation:
    def __init__(self, units, unit_type, dst_repo):
        self.units = units
        self.unit_type = unit_type
        self.dst_repo = dst_repo


def flatten_md_defaults_name_profiles(obj):
    """
    flatten the profiles of md_defaults unit and prepend name
    format: name:[key:profile,profile]:[key:profile]
    'ruby:[2.5:common,unique]'
    """
    result = obj.name
    for key in sorted(obj.profiles):
        result += ":[%s:%s]" % (key, ",".join(sorted(obj.profiles[key])))
    return result


def batcher(items: list, n: int):
    """Batches a list of items to lists of size n."""
    for i in range(0, len(items), n):
        yield items[i : i + n]
