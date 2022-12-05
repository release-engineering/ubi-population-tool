import os
import logging

from pubtools.pulplib import Criteria
from more_executors.futures import f_flat_map, f_return, f_sequence, f_proxy
from more_executors import Executors

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


def flatten_list_of_sets(list_of_sets):
    out = set()
    for one_set in list_of_sets:
        out |= one_set

    return f_return(out)
