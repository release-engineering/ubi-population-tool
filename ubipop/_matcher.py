import os
import logging

from itertools import chain
from collections import defaultdict, deque
from concurrent.futures import as_completed
from pubtools.pulplib import Criteria
from pubtools.pulplib import Matcher as PulpLibMatcher
from more_executors.futures import f_flat_map, f_return, f_sequence, f_proxy
from more_executors import Executors
from ubipop._utils import split_filename, vercmp_sort

BATCH_SIZE = int(os.getenv("UBIPOP_BATCH_SIZE", "250"))
# need to set significantly lower batches for general rpm search
# otherwise db may very likely hit OOM error.
BATCH_SIZE_RPM = int(os.getenv("UBIPOP_BATCH_SIZE_RPM", "15"))

_LOG = logging.getLogger("ubipop.matcher")


class UbiUnit(object):
    """
    Wrapping class of model classes (*Unit) of pubtools.pulplib.
    """

    def __init__(self, unit, src_repo_id):
        self._unit = unit
        self.associate_source_repo_id = src_repo_id

    def __getattr__(self, name):
        return getattr(self._unit, name)

    def __str__(self):
        return str(self._unit)

    # TODO make this return hash of self._unit if possible in future
    # it should help us with not adding the same units into sets
    # that differ with associate_source_repo_id attr only
    # currently some *Unit classes from pulplib are not hashable
    # def __hash__(self):
    #    return hash(self._unit)


class Matcher(object):
    """
    Generic class can be used for matching units in pulp required for ubipop.
    This class should be subclasses and run() method needs to be implemented.
    """

    def __init__(self, input_repos, ubi_config, workers=8):
        self._input_repos = input_repos
        self._ubi_config = ubi_config
        # executor for this class, not adding retries because for pulp
        # we use executor from pulplib
        self._executor = Executors.thread_pool(max_workers=workers)

        self.binary_rpms = None
        self.debug_rpms = None
        self.source_rpms = None

    def run(self):
        """
        This method needs to be implemented in subclasses and should
        include only async calls that will set public attributes of the class
        and immediately return self.
        """
        raise NotImplementedError

    @classmethod
    def _search_units(
        cls, repo, criteria_list, content_type_id, batch_size_override=None
    ):
        """
        Search for units of one content type associated with given repository by criteria.
        """
        units = set()
        batch_size = batch_size_override or BATCH_SIZE

        def handle_results(page):
            for unit in page.data:
                unit = UbiUnit(unit, repo.id)
                units.add(unit)
            if page.next:
                return f_flat_map(page.next, handle_results)
            return f_return(units)

        criteria_split = []

        for start in range(0, len(criteria_list), batch_size):
            criteria_split.append(criteria_list[start : start + batch_size])
        fts = []

        for criteria_batch in criteria_split:
            _criteria = Criteria.and_(
                Criteria.with_field("content_type_id", content_type_id),
                Criteria.or_(*criteria_batch),
            )

            page_f = repo.search_content(_criteria)
            handled_f = f_flat_map(page_f, handle_results)

            fts.append(handled_f)

        return f_flat_map(f_sequence(fts), flatten_list_of_sets)

    @classmethod
    def create_or_criteria(cls, fields, values):
        # fields - list/tuple of fields [field1, field2]
        # values - list of tuples [(field1 value, field2 value), ...]
        # creates criteria for pulp query in a following way
        # one tuple in values uses AND logic
        # each criteria for one tuple are agregated by to or_criteria list
        or_criteria = []

        for val_tuple in values:
            inner_and_criteria = []
            if len(val_tuple) != len(fields):
                raise ValueError
            for index, field in enumerate(fields):

                inner_and_criteria.append(Criteria.with_field(field, val_tuple[index]))

            or_criteria.append(Criteria.and_(*inner_and_criteria))

        return or_criteria

    @classmethod
    def _search_units_per_repos(
        cls, or_criteria, repos, content_type, batch_size_override=None
    ):
        units = []
        for repo in repos:
            units.append(
                cls._search_units(
                    repo,
                    or_criteria,
                    content_type,
                    batch_size_override=batch_size_override,
                )
            )

        return f_proxy(f_flat_map(f_sequence(units), flatten_list_of_sets))

    @classmethod
    def search_rpms(cls, or_criteria, repos, batch_size_override=None):
        return cls._search_units_per_repos(
            or_criteria,
            repos,
            content_type="rpm",
            batch_size_override=batch_size_override,
        )

    @classmethod
    def search_srpms(cls, or_criteria, repos, batch_size_override=None):
        return cls._search_units_per_repos(
            or_criteria,
            repos,
            content_type="srpm",
            batch_size_override=batch_size_override,
        )

    @classmethod
    def search_modulemds(cls, or_criteria, repos):
        return cls._search_units_per_repos(or_criteria, repos, content_type="modulemd")

    @classmethod
    def search_modulemd_defaults(cls, or_criteria, repos):
        return cls._search_units_per_repos(
            or_criteria, repos, content_type="modulemd_defaults"
        )

    def _search_modulemd_defaults(self, or_criteria, repos):
        return self._search_units_per_repos(
            or_criteria, repos, content_type="modulemd_defaults"
        )

    def _get_srpms_criteria(self):
        filenames = []
        for rpms_list in as_completed([self.binary_rpms, self.debug_rpms]):
            for pkg in rpms_list:
                if pkg.sourcerpm is None:
                    _LOG.warning(
                        "Package %s doesn't reference its source rpm", pkg.name
                    )
                    continue
                filenames.append((pkg.sourcerpm,))

        pkgs_or_criteria = self.create_or_criteria(("filename",), filenames)
        return pkgs_or_criteria


class ModularMatcher(Matcher):
    def __init__(self, input_repos, ubi_config):
        super(ModularMatcher, self).__init__(input_repos, ubi_config)
        self.modules = None
        self.modulemd_defaults = None

    def run(self):
        """Asynchronously creates criteria for pulp queries and
        calls non-blocking search queries to pulp for ModularMatcher.
        Method immediately returns self, results of queries are
        stored as futures in public attributes of this class. Those
        can be accessed when they're needed.
        """
        modulemds_criteria = f_proxy(
            self._executor.submit(self._get_modulemds_criteria)
        )
        modules = f_proxy(
            self._executor.submit(
                self.search_modulemds, modulemds_criteria, self._input_repos.rpm
            )
        )
        self.modules = f_proxy(
            self._executor.submit(self._get_modulemd_output_set, modules)
        )
        rpms_criteria = f_proxy(self._executor.submit(self._get_modular_rpms_criteria))
        self.binary_rpms = f_proxy(
            self._executor.submit(
                self.search_rpms, rpms_criteria, self._input_repos.rpm
            )
        )
        self.debug_rpms = f_proxy(
            self._executor.submit(
                self.search_rpms, rpms_criteria, self._input_repos.debug
            )
        )
        srpms_criteria = f_proxy(self._executor.submit(self._get_srpms_criteria))
        self.source_rpms = f_proxy(
            self._executor.submit(
                self.search_srpms, srpms_criteria, self._input_repos.source
            )
        )
        modulemd_defaults_criteria = f_proxy(
            self._executor.submit(self._get_modulemd_defaults_criteria)
        )
        self.modulemd_defaults = f_proxy(
            self._executor.submit(
                self.search_modulemd_defaults,
                modulemd_defaults_criteria,
                self._input_repos.rpm,
            )
        )
        modulemd_defaults_criteria = f_proxy(
            self._executor.submit(self._get_modulemd_defaults_criteria)
        )
        self.modulemd_defaults = f_proxy(
            self._executor.submit(
                self._search_modulemd_defaults,
                modulemd_defaults_criteria,
                self._input_repos.rpm,
            )
        )
        return self

    def _get_modular_rpms_criteria(self):
        filenames_to_search = self._modular_rpms_filenames(self.modules)
        filenames_to_search = [(filename,) for filename in filenames_to_search]
        pkgs_or_criteria = self.create_or_criteria(("filename",), filenames_to_search)
        return pkgs_or_criteria

    def _get_modulemds_criteria(self):
        return self._get_criteria_for_modules(self._ubi_config)

    def _get_modulemd_defaults_criteria(self):
        return self._get_criteria_for_modules(self.modules)

    def _get_criteria_for_modules(self, modules):
        criteria_values = []
        for module in modules:
            criteria_values.append(
                (
                    module.name,
                    module.stream,
                )
            )

        fields = ("name", "stream")
        or_criteria = self.create_or_criteria(fields, criteria_values)
        return or_criteria

    def _get_modulemd_output_set(self, modules):
        name_stream_modules_map = {}
        # create internal dict structure for easier sorting
        # mapping "name + stream": list of modules
        for modulemd in modules:
            key = modulemd.name + modulemd.stream
            name_stream_modules_map.setdefault(key, []).append(modulemd)

        out = []
        # sort rpms and keep N latest versions of them
        for module_list in name_stream_modules_map.values():
            module_list.sort(key=lambda module: module.version)
            self._keep_n_latest_modules(module_list)
            out.extend(module_list)

        return out

    def _keep_n_latest_modules(self, modules, n=1):
        """
        Keeps n latest modules in modules sorted list
        """
        modules_to_keep = []
        versions_to_keep = sorted(set([m.version for m in modules]))[-n:]

        for module in modules:
            if module.version in versions_to_keep:
                modules_to_keep.append(module)

        modules[:] = modules_to_keep

    def _modular_rpms_filenames(self, modules):
        config_map = {}

        for module_config in self._ubi_config:
            key = module_config.name + module_config.stream
            config_map[key] = module_config.profiles

        filenames = set()
        for module in modules:
            key = module.name + module.stream
            pkgs_names = []
            # get rpm names from the modulemd profiles
            for profile in config_map.get(key) or []:
                if module.profiles:
                    pkgs_names.extend(module.profiles.get(profile) or [])

            for filename in module.artifacts_filenames:
                # skip source rpms
                if filename.endswith(".src.rpm"):
                    continue

                # if need to take only some packages from profiles
                if pkgs_names:
                    name, _, _, _, _ = split_filename(filename)
                    if name not in pkgs_names:
                        continue

                filenames.add(filename)

        return filenames


class RpmMatcher(Matcher):
    def __init__(self, input_repos, ubi_config):
        super(RpmMatcher, self).__init__(input_repos, ubi_config)

    def run(self):
        """Asynchronously creates criteria for pulp queries and
        calls non-blocking search queries to pulp for RpmMatcher.
        Method immediately returns self, results of queries are
        stored as futures in public attributes of this class. Those
        can be accessed when they're needed.
        """
        # overriding the normal batch size for queries
        # general queries for RPMs have extreme consumtion of RAM
        # and can easily cause OOM on production-size databases
        batch_size_override = BATCH_SIZE_RPM

        modular_rpm_filenames = f_proxy(self._get_pkgs_from_all_modules())
        rpms_criteria = f_proxy(self._executor.submit(self._get_rpms_criteria))

        binary_rpms = f_proxy(
            self._executor.submit(
                self.search_rpms,
                rpms_criteria,
                self._input_repos.rpm,
                batch_size_override,
            )
        )

        debug_rpms = f_proxy(
            self._executor.submit(
                self.search_rpms,
                rpms_criteria,
                self._input_repos.debug,
                batch_size_override,
            )
        )

        self.binary_rpms = f_proxy(
            self._executor.submit(
                self._get_rpm_output_set, binary_rpms, modular_rpm_filenames
            )
        )
        self.debug_rpms = f_proxy(
            self._executor.submit(
                self._get_rpm_output_set, debug_rpms, modular_rpm_filenames
            )
        )

        srpms_criteria = f_proxy(self._executor.submit(self._get_srpms_criteria))
        source_rpms = f_proxy(
            self._executor.submit(
                self.search_srpms,
                srpms_criteria,
                self._input_repos.source,
                batch_size_override,
            )
        )

        # the output set of source rpms is almost ready at this point
        # because it was created from final output set of binary and debug rpm
        # so just need to apply blacklist and nothing else
        self.source_rpms = f_proxy(
            self._executor.submit(
                self._get_rpm_output_set,
                source_rpms,
                modular_rpm_filenames=None,
                keep_all_versions=True,
            )
        )

        return self

    def _get_rpms_criteria(self):
        criteria_values = []

        for package_pattern in self._ubi_config.packages.whitelist:
            # skip src packages, they are searched seprately
            if package_pattern.arch == "src":
                continue
            arch = (
                PulpLibMatcher.exists()
                if package_pattern.arch in ("*", None)
                else package_pattern.arch
            )
            criteria_values.append((package_pattern.name, arch))

        fields = ("name", "arch")
        or_criteria = self.create_or_criteria(fields, criteria_values)
        return or_criteria

    def _get_pkgs_from_all_modules(self):
        # search for modulesmds in all input repos
        # and extract filenames only
        def extract_modular_filenames():
            modular_rpm_filenames = set()
            for module in modules:
                modular_rpm_filenames |= set(module.artifacts_filenames)

            return modular_rpm_filenames

        modules = self.search_modulemds([Criteria.true()], self._input_repos.rpm)
        return self._executor.submit(extract_modular_filenames)

    def _get_rpm_output_set(
        self, rpms, modular_rpm_filenames=None, keep_all_versions=False
    ):
        blacklist_parsed = self._parse_blacklist_config()
        name_rpms_maps = {}

        def is_blacklisted(rpm):
            for name, globbing, arch in blacklist_parsed:
                blacklisted = False
                if globbing:
                    if rpm.name.startswith(name):
                        blacklisted = True
                else:
                    if rpm.name == name:
                        blacklisted = True
                if arch:
                    if rpm.arch != arch:
                        blacklisted = False

                if blacklisted:
                    return blacklisted

        for rpm in rpms:
            if modular_rpm_filenames:
                # skip modular rpms
                if rpm.filename in modular_rpm_filenames:
                    continue
            # skip blacklisted rpms
            if is_blacklisted(rpm):
                continue

            name_rpms_maps.setdefault(rpm.name, []).append(rpm)

        out = []
        # sort rpms and keep N latest versions of them
        for rpm_list in name_rpms_maps.values():
            if not keep_all_versions:
                rpm_list.sort(key=vercmp_sort())
                self._keep_n_latest_rpms(rpm_list)
            out.extend(rpm_list)

        return out

    def _keep_n_latest_rpms(self, rpms, n=1):
        """
        Keep n latest non-modular rpms.

        Arguments:
            rpms (List[Rpm]): Sorted, oldest goes first

        Keyword arguments:
            n (int): Number of non-modular package versions to keep

        Returns:
            None. The packages list is changed in-place
        """
        # Use a queue of n elements per arch
        pkgs_per_arch = defaultdict(lambda: deque(maxlen=n))

        for rpm in rpms:
            pkgs_per_arch[rpm.arch].append(rpm)

        latest_pkgs_per_arch = [
            pkg for pkg in chain.from_iterable(pkgs_per_arch.values())
        ]

        rpms[:] = latest_pkgs_per_arch

    def _parse_blacklist_config(self):
        packages_to_exclude = []
        for package_pattern in self._ubi_config.packages.blacklist:
            globbing = package_pattern.name.endswith("*")
            if globbing:
                name = package_pattern.name[:-1]
            else:
                name = package_pattern.name
            arch = None if package_pattern.arch in ("*", None) else package_pattern.arch

            packages_to_exclude.append((name, globbing, arch))

        return packages_to_exclude


def flatten_list_of_sets(list_of_sets):
    out = set()
    for one_set in list_of_sets:
        out |= one_set

    return f_return(out)
