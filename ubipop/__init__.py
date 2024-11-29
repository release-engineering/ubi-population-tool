import logging
import os
import re
from collections import defaultdict, namedtuple

import attr
import ubiconfig
from more_executors import Executors
from more_executors.futures import f_proxy, f_return
from pubtools.pulplib import (
    Client,
    Criteria,
    ModulemdDefaultsUnit,
    ModulemdUnit,
    RpmUnit,
)

from ubipop._utils import (
    Association,
    Unassociation,
    batcher,
    flatten_md_defaults_name_profiles,
)

from ._matcher import Matcher
from .ubi_manifest_client.client import Client as UbimClient

_LOG = logging.getLogger("ubipop")


class RepoMissing(Exception):
    pass


RepoSet = namedtuple("RepoSet", ["rpm", "source", "debug"])


@attr.s
class RepoContent:
    binary_rpms = attr.ib()
    source_rpms = attr.ib()
    debug_rpms = attr.ib()
    modules = attr.ib()
    modulemd_defaults = attr.ib()


class UbiRepoSet:
    def __init__(self, input_repos, output_repos):
        self.in_repos = input_repos
        self.out_repos = output_repos

        self.packages = defaultdict(list)
        self.debug_rpms = defaultdict(list)
        self.modules = None
        self.module_defaults = defaultdict(list)
        self.source_rpms = defaultdict(list)

        self._ensure_repos_existence()

    def get_output_repos(self):
        repos = set([self.out_repos.rpm, self.out_repos.source])
        if self.out_repos.debug.result():
            repos.add(self.out_repos.debug)

        return repos

    def _ensure_repos_existence(self):
        fatal = False
        if not self.in_repos.rpm:
            fatal = True
            _LOG.error("Input Rpm repo does not exist")

        if not self.in_repos.source:
            fatal = True
            _LOG.error("Input Source repo does not exist")

        if not self.in_repos.debug:
            fatal = True
            _LOG.error("Input Debug repo does not exist")

        if not self.out_repos.rpm:
            fatal = True
            _LOG.error("Output Rpm repo does not exist")

        if not self.out_repos.source:
            fatal = True
            _LOG.error("Output Source repo does not exist")

        if not self.out_repos.debug:
            fatal = True
            _LOG.error("Output Debug repo does not exist")

        if fatal:
            raise RepoMissing()


class UbiPopulate:
    def __init__(
        self,
        pulp_hostname,
        pulp_auth,
        dry_run,
        ubiconfig_filename_list=None,
        ubiconfig_dir_or_url=None,
        verify=True,
        workers_count=4,
        output_repos_file=None,
        **kwargs
    ):
        self._pulp_hostname = pulp_hostname
        self._pulp_auth = pulp_auth
        self._verify = verify
        self._pulp_client = None
        self.dry_run = dry_run
        self.output_repos_file = output_repos_file
        self._executor = Executors.thread_pool(max_workers=workers_count).with_retry()
        self._ubiconfig_list = None
        self._ubiconfig_filename_list = ubiconfig_filename_list
        self._ubiconfig_dir_or_url = ubiconfig_dir_or_url
        self._content_sets = kwargs.get("content_sets", None)
        self._repo_ids = kwargs.get("repo_ids", None)
        self._version = kwargs.get("version", None)
        self._content_set_regex = kwargs.get("content_set_regex", None)
        self._ubi_manifest_url = kwargs.get("ubi_manifest_url") or None
        self._action_batch_size = kwargs.get("action_batch_size", 100)

    @property
    def pulp_client(self):
        if self._pulp_client is None:
            kwargs = {"verify": self._verify}
            if os.path.isfile(self._pulp_auth[0]) and os.path.isfile(
                self._pulp_auth[1]
            ):
                kwargs["cert"] = self._pulp_auth
            else:
                kwargs["auth"] = self._pulp_auth
            self._pulp_client = Client("https://" + self._pulp_hostname, **kwargs)
        return self._pulp_client

    @property
    def ubiconfig_list(self):
        if self._ubiconfig_list is None:
            self._ubiconfig_list = self._load_ubiconfig()
        return self._ubiconfig_list

    def _load_ubiconfig(self):
        ubiconfig_dir_or_url = self._ubiconfig_dir_or_url
        filenames = self._ubiconfig_filename_list
        loader = ubiconfig.get_loader(ubiconfig_dir_or_url)
        ubi_conf_list = []

        if filenames:
            ubi_conf_list.extend(loader.load(filename) for filename in filenames)
        else:
            ubi_conf_list.extend(loader.load_all())

        return self._filter_ubi_conf_list(ubi_conf_list)

    def _filter_ubi_conf_list(self, config_list):
        """
        Reduces the list of UBI configurations to only those matching
        provided content sets and/or repo IDs. Config can be further filter
        by major version of or content_set_regex.
        """

        content_sets = self._content_sets
        repo_ids = self._repo_ids
        version = self._version
        content_set_regex = self._content_set_regex

        filtered_conf_list = []

        content_sets = content_sets or []
        repo_ids = repo_ids or []

        if not any([content_sets, repo_ids, version, content_set_regex]):
            # no filtering requested, return complete list of ubi config
            return config_list

        if content_set_regex:
            content_set_regex = re.compile(content_set_regex)

        if repo_ids:
            repos = [self.pulp_client.get_repository(repo_id) for repo_id in repo_ids]

            for repo in repos:
                content_sets.append(repo.content_set)

        for conf in config_list:
            # if requested, filter config by major version
            if version and not conf.version.startswith(version):
                continue

            for label in [
                conf.content_sets.rpm.input,
                conf.content_sets.rpm.output,
                conf.content_sets.srpm.input,
                conf.content_sets.srpm.output,
                conf.content_sets.debuginfo.input,
                conf.content_sets.debuginfo.output,
            ]:
                # matching by specific content sets takes precedence
                # or if empty content_set, content_set_regex - take the config immediately
                # we don't have any other filter to use
                if (
                    not any([content_sets, content_set_regex])
                    or label in content_sets
                    or (content_set_regex and re.search(content_set_regex, label))
                ):
                    filtered_conf_list.append(conf)
                    break

        return filtered_conf_list

    def populate_ubi_repos(self):
        repo_sets_list = []
        out_repos = set()  # list of all affected repositories
        ubi_binary_repos = []  # binary repos used for generating manifest

        # since repos are searched by content sets, same repo could be searched and populated
        # multiple times, to avoid that, cache the content sets already used and skip the config
        # whose content sets are all in the cache
        used_content_sets = set()
        for config in sorted(self.ubiconfig_list, key=str):
            content_sets = [
                config.content_sets.rpm.output,
                config.content_sets.srpm.output,
                config.content_sets.debuginfo.output,
            ]

            to_use = [cs for cs in content_sets if cs not in used_content_sets]
            if to_use:
                for cs in to_use:
                    used_content_sets.add(cs)
            else:
                _LOG.debug(
                    "Skipping %s, since it's been used already",
                    config.file_name,
                )
                continue
            try:
                repo_sets = self._get_ubi_repo_sets(config.content_sets.rpm.output)

            except RepoMissing:
                _LOG.warning("Skipping current content triplet, some repos are missing")
                continue

            repo_sets_list.append(repo_sets)
            ubi_binary_repos.extend(
                [repo_set.out_repos.rpm.id for repo_set in repo_sets]
            )

        with UbimClient(self._ubi_manifest_url) as ubim_client:
            tasks = ubim_client.generate_manifest(ubi_binary_repos)
            tasks.result()
            self._run_ubi_population(repo_sets_list, out_repos, ubim_client)

        if self.output_repos_file:
            with open(self.output_repos_file, "w") as f:
                for repo in out_repos:
                    f.write(repo.id.strip() + "\n")

    def _get_ubi_repo_sets(self, ubi_binary_cs):
        """
        Searches for ubi repository triplet (binary rpm, srpm, debug) for
        one ubi config item and tries to determine their population sources
        (input repositories). Returns list UbiRepoSet objects that provides
        input and output repositories that are used for population process.
        """
        rpm_repos = self.pulp_client.search_repository(
            Criteria.and_(
                Criteria.with_field("notes.content_set", ubi_binary_cs),
                Criteria.with_field("ubi_population", True),
            )
        )

        ubi_repo_sets = []
        for out_rpm_repo in rpm_repos:
            out_source_repo = out_rpm_repo.get_source_repository()
            out_debug_repo = out_rpm_repo.get_debug_repository()

            in_rpm_repos = self._get_population_sources(out_rpm_repo)
            in_source_repos = self._get_population_sources(out_source_repo)
            in_debug_repos = self._get_population_sources(out_debug_repo)

            # we need to apply f_proxy(f_return()) for out_rpm_repo for keeping consistency
            # that all objects in out|in_repos are futures
            out_repos = (
                f_proxy(f_return(out_rpm_repo)),
                out_source_repo,
                out_debug_repo,
            )
            in_repos = (in_rpm_repos, in_source_repos, in_debug_repos)

            ubi_repo_sets.append(UbiRepoSet(RepoSet(*in_repos), RepoSet(*out_repos)))

        return ubi_repo_sets

    def _get_population_sources(self, out_repo):
        if (
            not hasattr(out_repo, "population_sources")
            or not out_repo.population_sources
        ):
            return []

        repos = [
            self.pulp_client.get_repository(repo_id)
            for repo_id in out_repo.population_sources
        ]

        return repos

    def _run_ubi_population(self, repo_sets_list, out_repos, ubim_client=None):
        for repo_sets in repo_sets_list:
            for repo_set in repo_sets:
                UbiPopulateRunner(
                    self.pulp_client,
                    repo_set,
                    self.dry_run,
                    self._executor,
                    ubim_client,
                    self._action_batch_size,
                ).run_ubi_population()

                out_repos.update(repo_set.get_output_repos())


class UbiPopulateRunner:
    def __init__(
        self,
        pulp_client,
        repo_set,
        dry_run,
        executor,
        ubi_manifest_client=None,
        action_batch_size=100,
    ):
        self.pulp_client = pulp_client
        self.ubim_client = ubi_manifest_client
        self.repo_set = repo_set
        self.dry_run = dry_run
        self._executor = executor
        self._action_batch_size = action_batch_size

    def run_ubi_population(self):
        current_content = self._get_current_content()

        # start async querying for modulemds and modular and non-modular packages
        binary_manifest = self.ubim_client.get_manifest(self.repo_set.out_repos.rpm.id)
        debug_manifest = self.ubim_client.get_manifest(self.repo_set.out_repos.debug.id)
        source_manifest = self.ubim_client.get_manifest(
            self.repo_set.out_repos.source.id
        )

        self.repo_set.modules = binary_manifest.modules
        self.repo_set.module_defaults = self._search_expected_modulemd_defaults(
            binary_manifest.modulemd_defaults
        )
        self.repo_set.packages = binary_manifest.packages
        self.repo_set.debug_rpms = debug_manifest.packages
        self.repo_set.source_rpms = source_manifest.packages

        (
            associations,
            unassociations,
            mdd_association,
            mdd_unassociation,
        ) = self._get_pulp_actions(current_content)

        if self.dry_run:
            self.log_curent_content(current_content)
            self.log_pulp_actions(
                associations + (mdd_association,),
                unassociations + (mdd_unassociation,),
            )
        else:
            fts = []
            fts.extend(self._do_copy(associations))
            fts.extend(self._do_remove(unassociations))
            for ft in fts:
                ft.result()

            # Completely remove modulemd_defaults before copying.
            self._do_remove([mdd_unassociation])
            for ft in fts:
                ft.result()
            self._do_copy([mdd_association])
            for ft in fts:
                ft.result()

    def _get_current_content(self):
        """
        Gather current content of output repos
        """
        criteria = [Criteria.true()]
        current_modulemds = f_proxy(
            self._executor.submit(
                Matcher.search_modulemds,
                criteria,
                [self.repo_set.out_repos.rpm],
            )
        )
        current_modulemd_defaults = f_proxy(
            self._executor.submit(
                Matcher.search_modulemd_defaults,
                criteria,
                [self.repo_set.out_repos.rpm],
            )
        )
        current_rpms = f_proxy(
            self._executor.submit(
                Matcher.search_rpms, criteria, [self.repo_set.out_repos.rpm]
            )
        )
        current_srpms = f_proxy(
            self._executor.submit(
                Matcher.search_srpms, criteria, [self.repo_set.out_repos.source]
            )
        )

        if self.repo_set.out_repos.debug.result():
            current_debug_rpms = f_proxy(
                self._executor.submit(
                    Matcher.search_rpms,
                    criteria,
                    [self.repo_set.out_repos.debug],
                )
            )
        else:
            current_debug_rpms = f_proxy(f_return([]))

        current_content = RepoContent(
            current_rpms,
            current_srpms,
            current_debug_rpms,
            current_modulemds,
            current_modulemd_defaults,
        )
        return current_content

    def _search_expected_modulemd_defaults(self, modulemd_defaults):
        criteria_values = [(unit.name,) for unit in modulemd_defaults]
        fields = ("name",)
        or_criteria = Matcher.create_or_criteria(fields, criteria_values)
        return f_proxy(
            self._executor.submit(
                Matcher.search_modulemd_defaults,
                or_criteria,
                self.repo_set.in_repos.rpm,
            )
        )

    def _get_pulp_actions(self, current_content):
        """
        Determines expected pulp actions by comparing current content of output repos and
        expected content.

        Content that needs association: unit is in expected but not in current
        Content that needs unassociation: unit is in current but not in expected
        No action: unit is in current and in expected
        """

        modules_assoc, modules_unassoc = self._get_pulp_actions_mds(
            self.repo_set.modules, current_content.modules
        )
        md_defaults_assoc, md_defaults_unassoc = self._get_pulp_actions_md_defaults(
            self.repo_set.module_defaults, current_content.modulemd_defaults
        )

        rpms_assoc, rpms_unassoc = self._get_pulp_actions_pkgs(
            self.repo_set.packages, current_content.binary_rpms
        )
        srpms_assoc, srpms_unassoc = self._get_pulp_actions_pkgs(
            self.repo_set.source_rpms, current_content.source_rpms
        )

        debug_assoc = None
        debug_unassoc = None
        if current_content.debug_rpms:
            debug_assoc, debug_unassoc = self._get_pulp_actions_pkgs(
                self.repo_set.debug_rpms, current_content.debug_rpms
            )

        associations = (
            Association(
                modules_assoc,
                ModulemdUnit,
                self.repo_set.out_repos.rpm,
                self.repo_set.in_repos.rpm,
            ),
            Association(
                rpms_assoc,
                RpmUnit,
                self.repo_set.out_repos.rpm,
                self.repo_set.in_repos.rpm,
            ),
            Association(
                srpms_assoc,
                RpmUnit,
                self.repo_set.out_repos.source,
                self.repo_set.in_repos.source,
            ),
            Association(
                debug_assoc,
                RpmUnit,
                self.repo_set.out_repos.debug,
                self.repo_set.in_repos.debug,
            ),
        )

        unassociations = (
            Unassociation(modules_unassoc, ModulemdUnit, self.repo_set.out_repos.rpm),
            Unassociation(rpms_unassoc, RpmUnit, self.repo_set.out_repos.rpm),
            Unassociation(srpms_unassoc, RpmUnit, self.repo_set.out_repos.source),
            Unassociation(debug_unassoc, RpmUnit, self.repo_set.out_repos.debug),
        )

        mdd_association = Association(
            md_defaults_assoc,
            ModulemdDefaultsUnit,
            self.repo_set.out_repos.rpm,
            self.repo_set.in_repos.rpm,
        )
        mdd_unassociation = Unassociation(
            md_defaults_unassoc,
            ModulemdDefaultsUnit,
            self.repo_set.out_repos.rpm,
        )

        return associations, unassociations, mdd_association, mdd_unassociation

    def _get_pulp_actions_mds(self, modules, current):
        return self._determine_pulp_actions(
            modules, current, self._diff_modules_by_nsvca
        )

    def _get_pulp_actions_md_defaults(self, module_defaults, current):
        return self._determine_pulp_actions(
            module_defaults,
            current,
            self._diff_md_defaults_by_profiles,
        )

    def _get_pulp_actions_pkgs(self, pkgs, current):
        return self._determine_pulp_actions(
            pkgs, current, self._diff_packages_by_filename
        )

    def _determine_pulp_actions(self, units, current, diff_f):
        expected = list(units)
        to_associate = diff_f(expected, current)
        to_unassociate = diff_f(current, expected)
        return to_associate, to_unassociate

    def _diff_modules_by_nsvca(self, modules_1, modules_2):
        return self._diff_lists_by_attr(modules_1, modules_2, "nsvca")

    def _diff_md_defaults_by_profiles(self, module_defaults_1, module_defaults_2):
        return self._diff_lists_by_attr(
            module_defaults_1,
            module_defaults_2,
            flatten_md_defaults_name_profiles,
        )

    def _diff_packages_by_filename(self, packages_1, packages_2):
        return self._diff_lists_by_attr(packages_1, packages_2, "filename")

    def _diff_lists_by_attr(self, list_1, list_2, attr_or_func):
        def diff_attr(obj):
            if callable(attr_or_func):
                return attr_or_func(obj)
            return getattr(obj, attr_or_func)

        attrs_list_2 = [diff_attr(obj) for obj in list_2]
        diff = [obj for obj in list_1 if diff_attr(obj) not in attrs_list_2]

        return diff

    def log_curent_content(self, current_content):
        _LOG.info("Current modules in repo: %s", self.repo_set.out_repos.rpm.id)
        for module in current_content.modules:
            _LOG.info(module.nsvca)

        _LOG.info(
            "Current module_defaults in repo: %s",
            self.repo_set.out_repos.rpm.id,
        )
        for md_d in current_content.modulemd_defaults:
            _LOG.info("module_defaults: %s, profiles: %s", md_d.name, md_d.profiles)

        _LOG.info("Current rpms in repo: %s", self.repo_set.out_repos.rpm.id)
        for rpm in current_content.binary_rpms:
            _LOG.info(rpm.filename)

        _LOG.info("Current srpms in repo: %s", self.repo_set.out_repos.source.id)
        for rpm in current_content.source_rpms:
            _LOG.info(rpm.filename)

        if self.repo_set.out_repos.debug:
            _LOG.info("Current rpms in repo: %s", self.repo_set.out_repos.debug.id)
            for rpm in current_content.debug_rpms:
                _LOG.info(rpm.filename)

    def log_pulp_actions(self, associations, unassociations):
        for item in associations:
            if item.units:
                for unit in item.units:
                    _LOG.info(
                        "Would associate %s from %s to %s",
                        unit,
                        unit.associate_source_repo_id,
                        item.dst_repo.id,
                    )

            else:
                _LOG.info(
                    "No association expected for %s from %s to %s",
                    item.unit_type.__name__,
                    [r.id for r in item.src_repos],
                    item.dst_repo.id,
                )

        for item in unassociations:
            if item.units:
                for unit in item.units:
                    _LOG.info("Would unassociate %s from %s", unit, item.dst_repo.id)
            else:
                _LOG.info(
                    "No unassociation expected for %s from %s",
                    item.unit_type.__name__,
                    item.dst_repo.id,
                )

    def _do_copy(self, associations):
        association_fts = []
        for a in associations:
            for src_repo_id, units in a.src_repo_id_to_unit_map.items():
                if units:
                    src_repo = self.pulp_client.get_repository(src_repo_id)
                    dst_repo = self.pulp_client.get_repository(a.dst_repo.id)
                    for chunk in list(batcher(units, self._action_batch_size)):
                        criteria = self._criteria_for_units(chunk, a.unit_type)
                        association_fts.append(
                            self.pulp_client.copy_content(src_repo, dst_repo, criteria)
                        )
        return association_fts

    def _do_remove(self, unassociations):
        unassociation_fts = []
        for u in unassociations:
            if u.units:
                dst_repo = self.pulp_client.get_repository(u.dst_repo.id)
                for chunk in list(batcher(u.units, self._action_batch_size)):
                    criteria = self._criteria_for_units(chunk, u.unit_type)
                    unassociation_fts.append(dst_repo.remove_content(criteria))
        return unassociation_fts

    def _criteria_for_units(self, units, unit_type):
        partial_crit = []
        for unit in units:
            if unit_type is RpmUnit:
                partial_crit.append(Criteria.with_field("filename", unit.filename))
            elif unit_type is ModulemdUnit:
                md_crit = []
                nsvca_dict = {
                    "name": unit.name,
                    "stream": unit.stream,
                    "version": unit.version,
                    "context": unit.context,
                    "arch": unit.arch,
                }
                for md_part, value in nsvca_dict.items():
                    md_crit.append(Criteria.with_field(md_part, value))
                partial_crit.append(Criteria.and_(*md_crit))
            elif unit_type is ModulemdDefaultsUnit:
                partial_crit.append(
                    Criteria.and_(
                        Criteria.with_field("name", unit.name),
                        Criteria.with_field("stream", unit.stream),
                    )
                )

        if partial_crit:
            return Criteria.and_(
                Criteria.with_unit_type(unit_type), Criteria.or_(*partial_crit)
            )
