import os

from pubtools.pulplib import Criteria
from more_executors.futures import f_flat_map, f_return, f_sequence, f_proxy
from more_executors import Executors
from ubipop._utils import split_filename


BATCH_SIZE = int(os.getenv("UBIPOP_BATCH_SIZE", "250"))


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

    def run(self):
        """
        This method needs to be implemented in subclasses and should
        include only async calls that will set public attributes of the class
        and immediately return self.
        """
        raise NotImplementedError

    def _search_units(self, repo, criteria_list, content_type_id):
        """
        Search for units of one content type associated with given repository by criteria.
        """
        units = set()

        def handle_results(page):
            for unit in page.data:
                unit = UbiUnit(unit, repo.id)
                units.add(unit)
            if page.next:
                return f_flat_map(page.next, handle_results)
            return f_return(units)

        criteria_split = []

        for start in range(0, len(criteria_list), BATCH_SIZE):
            criteria_split.append(criteria_list[start : start + BATCH_SIZE])
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

    def _create_or_criteria(self, fields, values):
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

    def _search_units_per_repos(self, or_criteria, repos, content_type):
        units = []
        for repo in repos:
            units.append(self._search_units(repo, or_criteria, content_type))

        return f_proxy(f_flat_map(f_sequence(units), flatten_list_of_sets))

    def _search_rpms(self, or_criteria, repos):
        return self._search_units_per_repos(or_criteria, repos, content_type="rpm")

    def _search_srpms(self, or_criteria, repos):
        return self._search_units_per_repos(or_criteria, repos, content_type="srpm")

    def _search_moludemds(self, or_criteria, repos):
        return self._search_units_per_repos(or_criteria, repos, content_type="modulemd")


class ModularMatcher(Matcher):
    def __init__(self, input_repos, ubi_config):
        super(ModularMatcher, self).__init__(input_repos, ubi_config)
        self.modules = None
        self.binary_rpms = None
        self.debug_rpms = None
        self.source_rpms = None

    def run(self):
        """Asynchronously creates criteria for pulp queries and
        calls non-blocking search queries to pulp.
        Method immediately returns self, results of queries are
        stored as futures in public attributes of this class. Those
        can be accessed when they're needed.
        """
        modulemds_criteria = f_proxy(
            self._executor.submit(self._get_modulemds_criteria)
        )
        modules = f_proxy(
            self._executor.submit(
                self._search_moludemds, modulemds_criteria, self._input_repos.rpm
            )
        )
        self.modules = f_proxy(
            self._executor.submit(self._get_modulemd_output_set, modules)
        )
        rpms_criteria = f_proxy(self._executor.submit(self._get_modular_rpms_criteria))
        self.binary_rpms = f_proxy(
            self._executor.submit(
                self._search_rpms, rpms_criteria, self._input_repos.rpm
            )
        )
        self.debug_rpms = f_proxy(
            self._executor.submit(
                self._search_rpms, rpms_criteria, self._input_repos.debug
            )
        )
        srpms_criteria = f_proxy(
            self._executor.submit(self._get_modular_srpms_criteria)
        )
        self.source_rpms = f_proxy(
            self._executor.submit(
                self._search_srpms, srpms_criteria, self._input_repos.source
            )
        )
        return self

    def _get_modular_rpms_criteria(self):
        filenames_to_search = self._modular_rpms_filenames(self.modules)
        filenames_to_search = [(filename,) for filename in filenames_to_search]
        pkgs_or_criteria = self._create_or_criteria(("filename",), filenames_to_search)
        return pkgs_or_criteria

    def _get_modular_srpms_criteria(self):
        non_source_pkg = list(self.binary_rpms) + list(self.debug_rpms)
        filenames = [(pkg.sourcerpm,) for pkg in non_source_pkg]
        pkgs_or_criteria = self._create_or_criteria(("filename",), filenames)
        return pkgs_or_criteria

    def _get_modulemds_criteria(self):
        criteria_values = []
        for module in self._ubi_config:
            criteria_values.append(
                (
                    module.name,
                    module.stream,
                )
            )

        fields = ("name", "stream")
        or_criteria = self._create_or_criteria(fields, criteria_values)
        return or_criteria

    def _get_modulemd_output_set(self, modules):
        name_stream_modules_map = {}
        # create internal dict structure for easier sorting
        # mapping "name + stream": list of modules
        for modulemd in modules:
            key = modulemd.name + modulemd.stream
            name_stream_modules_map.setdefault(key, []).append(modulemd)

        out = []
        # sort modulemds and keep N latest versions of them
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


def flatten_list_of_sets(list_of_sets):
    out = set()
    for one_set in list_of_sets:
        out |= one_set

    return f_return(out)
