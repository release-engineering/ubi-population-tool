class PulpAction(object):
    def __init__(self, units, dst_repo):
        self.units = units
        self.dst_repo = dst_repo

    def get_actions(self, pulp_client_inst):
        raise NotImplementedError


class AssociateAction(PulpAction):
    def __init__(self, units, dst_repo, src_repos):
        super(AssociateAction, self).__init__(units, dst_repo)
        self.src_repos = src_repos

    def _map_src_repo_to_unit(self):
        src_repo_unit_map = {}
        for unit in self.units:
            src_repo_unit_map.setdefault(unit.associate_source_repo_id, []).append(unit)

        return src_repo_unit_map

    def _get_repo_obj(self, repo_id):
        for repo in self.src_repos:
            if repo_id == repo.id:
                return repo

    def get_actions(self, pulp_client_inst):
        raise NotImplementedError


class AssociateActionModules(AssociateAction):
    TYPE = "modules"

    def get_actions(self, pulp_client_inst):
        actions = []
        for src_repo_id, units in self._map_src_repo_to_unit().items():
            actions.append(
                (
                    pulp_client_inst.associate_modules,
                    self._get_repo_obj(src_repo_id),
                    self.dst_repo,
                    units,
                )
            )

        return actions


class UnassociateActionModules(PulpAction):
    TYPE = "modules"

    def get_actions(self, pulp_client_inst):
        return [(pulp_client_inst.unassociate_modules, self.dst_repo, self.units)]


class AssociateActionModuleDefaults(AssociateAction):
    TYPE = "module_defaults"

    def get_actions(self, pulp_client_inst):
        actions = []
        for src_repo_id, units in self._map_src_repo_to_unit().items():
            actions.append(
                (
                    pulp_client_inst.associate_module_defaults,
                    self._get_repo_obj(src_repo_id),
                    self.dst_repo,
                    units,
                )
            )

        return actions


class UnassociateActionModuleDefaults(PulpAction):
    TYPE = "module_defaults"

    def get_actions(self, pulp_client_inst):
        return [
            (pulp_client_inst.unassociate_module_defaults, self.dst_repo, self.units)
        ]


class AssociateActionRpms(AssociateAction):
    TYPE = "packages"

    def get_actions(self, pulp_client_inst):
        actions = []
        for src_repo_id, units in self._map_src_repo_to_unit().items():
            actions.append(
                (
                    pulp_client_inst.associate_packages,
                    self._get_repo_obj(src_repo_id),
                    self.dst_repo,
                    units,
                )
            )

        return actions


class UnassociateActionRpms(PulpAction):
    TYPE = "packages"

    def get_actions(self, pulp_client_inst):
        return [(pulp_client_inst.unassociate_packages, self.dst_repo, self.units)]


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
