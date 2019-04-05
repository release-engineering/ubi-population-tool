# borrowed from https://github.com/rpm-software-management/yum
def splitFilename(filename):
    """
    Pass in a standard style rpm fullname

    Return a name, version, release, epoch, arch, e.g.::
        foo-1.0-1.i386.rpm returns foo, 1.0, 1, i386
        1:bar-9-123a.ia64.rpm returns bar, 9, 123a, 1, ia64
    """

    if filename[-4:] == '.rpm':
        filename = filename[:-4]

    archIndex = filename.rfind('.')
    arch = filename[archIndex + 1:]

    relIndex = filename[:archIndex].rfind('-')
    rel = filename[relIndex + 1:archIndex]

    verIndex = filename[:relIndex].rfind('-')
    ver = filename[verIndex + 1:relIndex]

    epochIndex = filename.find(':')
    if epochIndex == -1:
        epoch = ''
    else:
        epoch = filename[:epochIndex]

    name = filename[epochIndex + 1:verIndex]
    return name, ver, rel, epoch, arch


class PulpAction(object):
    def __init__(self, units,  dst_repo):
        self.units = units
        self.dst_repo = dst_repo

    def get_action(self, pulp_client_inst):
        raise NotImplementedError


class AssociateAction(PulpAction):
    def __init__(self, units, dst_repo, src_repo):
        super(AssociateAction, self).__init__(units, dst_repo)
        self.src_repo = src_repo

    def get_action(self, pulp_client_inst):
        raise NotImplementedError


class AssociateActionModules(AssociateAction):
    TYPE = "modules"

    def get_action(self, pulp_client_inst):
        return pulp_client_inst.associate_modules, self.src_repo, self.dst_repo, self.units


class UnassociateActionModules(PulpAction):
    TYPE = "modules"

    def get_action(self, pulp_client_inst):
        return pulp_client_inst.unassociate_modules, self.dst_repo,  self.units


class AssociateActionRpms(AssociateAction):
    TYPE = "packages"

    def get_action(self, pulp_client_inst):
        return pulp_client_inst.associate_packages, self.src_repo, self.dst_repo,  self.units


class UnassociateActionRpms(PulpAction):
    TYPE = "packages"

    def get_action(self, pulp_client_inst):
        return pulp_client_inst.unassociate_packages, self.dst_repo, self.units
