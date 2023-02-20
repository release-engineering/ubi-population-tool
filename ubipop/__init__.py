from datetime import date
import logging
import re
import os

from collections import defaultdict, deque, namedtuple
from concurrent.futures import as_completed
from itertools import chain
from pubtools.pulplib import Client, Criteria, PublishOptions
from fastpurge import FastPurgeClient

import attr
import ubiconfig

from more_executors import Executors
from more_executors.futures import f_sequence, f_proxy, f_return
from ubipop._pulp_client import Pulp
from ubipop._utils import (
    AssociateActionModules,
    AssociateActionModuleDefaults,
    AssociateActionRpms,
    UnassociateActionModules,
    UnassociateActionModuleDefaults,
    UnassociateActionRpms,
    flatten_md_defaults_name_profiles,
)
from ._matcher import Matcher
from .ubi_manifest_client.client import Client as UbimClient


_LOG = logging.getLogger("ubipop")


class RepoMissing(Exception):
    pass


class ConfigMissing(Exception):
    pass


class PopulationSourceMissing(Exception):
    pass


RepoSet = namedtuple("RepoSet", ["rpm", "source", "debug"])


@attr.s
class RepoContent(object):
    binary_rpms = attr.ib()
    source_rpms = attr.ib()
    debug_rpms = attr.ib()
    modules = attr.ib()
    modulemd_defaults = attr.ib()


class UbiRepoSet(object):
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


class UbiPopulate(object):
    def __init__(
        self,
        pulp_hostname,
        pulp_auth,
        dry_run,
        ubiconfig_filename_list=None,
        ubiconfig_dir_or_url=None,
        insecure=False,
        workers_count=4,
        output_repos=None,
        **kwargs
    ):
        # legacy client implemeted in this repo, it's expected to be replaced by pubtools.pulplib.Client
        self.pulp = Pulp(pulp_hostname, pulp_auth, insecure)
        self._pulp_hostname = pulp_hostname
        self._pulp_auth = pulp_auth
        self._insecure = insecure
        self._pulp_client = None
        self.dry_run = dry_run
        self.output_repos = output_repos
        self._executor = Executors.thread_pool(max_workers=workers_count).with_retry()
        self._ubiconfig_list = None
        self._ubiconfig_filename_list = ubiconfig_filename_list
        self._ubiconfig_dir_or_url = ubiconfig_dir_or_url
        self._content_sets = kwargs.get("content_sets", None)
        self._repo_ids = kwargs.get("repo_ids", None)
        self._version = kwargs.get("version", None)
        self._content_set_regex = kwargs.get("content_set_regex", None)
        self._ubiconfig_map = None

        self._ubi_manifest_url = kwargs.get("ubi_manifest_url") or None

        self._EDGERC_CFG = os.getenv("UBIPOP_EDGERC_CFG", "/etc/.edgerc")
        self._FASTPURGE_ROOT_URL = os.getenv("UBIPOP_FASTPURGE_ROOT_URL", "")

    @property
    def pulp_client(self):
        if self._pulp_client is None:
            self._pulp_client = self._make_pulp_client(
                self._pulp_hostname, self._pulp_auth, self._insecure
            )
        return self._pulp_client

    def _make_pulp_client(self, url, auth, insecure):
        return Client("https://" + url, auth=auth, verify=not insecure)

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

    @property
    def ubiconfig_map(self):
        if self._ubiconfig_map is None:
            self._ubiconfig_map = self._create_config_map()
        return self._ubiconfig_map

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

    def _create_config_map(self):
        """Create a config map from self.ubiconfig_list, it has the form in:
        {
            "7.7":
                {
                    "config_filename1": config1,
                    "config_filename2": config2,
                    ...,
                },
            "8.1":
                {
                    "config_filename1": config1,
                    ...,
                },
            ....
        }
        """

        config_map = {}
        for config in self.ubiconfig_list:
            config_map.setdefault(config.version, {}).setdefault(
                config.file_name, config
            )

        return config_map

    def _get_config(self, repo, config):
        # get the right config file by ubi_config_version attr of a repository
        # if not found, try to fallback to the default version (major version)
        if not repo.ubi_config_version:
            raise ValueError("Repo: %s does not have ubi_config_version" % repo.id)

        _ubi_config_version = repo.ubi_config_version
        if _ubi_config_version not in self.ubiconfig_map:
            # if the config is missing, we need to use the default config branch
            _ubi_config_version = _ubi_config_version.split(".")[0]
        try:
            right_config = self.ubiconfig_map[_ubi_config_version][config.file_name]
        except KeyError:
            _LOG.error(
                "Config file %s missing from %s and default %s branches",
                config.file_name,
                repo.ubi_config_version,
                repo.ubi_config_version.split(".")[0],
            )
            raise ConfigMissing()

        return right_config

    def populate_ubi_repos(self):
        out_repos = set()
        used_content_sets = set()
        # since repos are searched by content sets, same repo could be searched and populated
        # multiple times, to avoid that, cache the content sets already used and skip the config
        # whose content sets are all in the cache
        repo_pairs_list = []
        ubi_binary_repos = []
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
                    "Skipping %s, since it's been used already", config.file_name
                )
                continue

            try:
                repo_pairs = self._get_ubi_repo_sets(config.content_sets.rpm.output)

            except RepoMissing:
                _LOG.warning("Skipping current content triplet, some repos are missing")
                continue

            repo_pairs_list.append((repo_pairs, config))
            ubi_binary_repos.extend(
                [repo_set.out_repos.rpm.id for repo_set in repo_pairs]
            )
        with UbimClient(self._ubi_manifest_url) as ubim_client:
            tasks = ubim_client.generate_manifest(ubi_binary_repos)
            tasks.result()
            awaited_repos_publishes = self._run_ubi_population(
                repo_pairs_list, out_repos, ubim_client
            )

        # wait until publication of all repos is finished
        if awaited_repos_publishes:
            f_sequence(awaited_repos_publishes).result()

        self._purge_cache(out_repos)

        if self.output_repos:
            with open(self.output_repos, "w") as f:
                for repo in out_repos:
                    f.write(repo.id.strip() + "\n")

    def _purge_cache(self, repos):
        if not self.dry_run and self._FASTPURGE_ROOT_URL:
            with FastPurgeClient(auth=self._EDGERC_CFG) as fp_client:
                urls_to_purge = []
                for repo in repos:
                    for url in repo.mutable_urls:
                        flush_url = os.path.join(
                            self._FASTPURGE_ROOT_URL, repo.relative_url, url
                        )
                        urls_to_purge.append(flush_url)
                _LOG.info("Purging cache started.")
                fp_client.purge_by_url(urls_to_purge).result()
                _LOG.info("Purging cache finished.")
        else:
            _LOG.warning("Cache purge disabled.")

    def _run_ubi_population(self, repo_pairs_list, out_repos, ubim_client=None):
        awaited_repos_publishes = []
        for repo_pairs, config in repo_pairs_list:
            for repo_set in repo_pairs:
                right_config = self._get_config(repo_set.out_repos.rpm, config)

                repos_publishes = UbiPopulateRunner(
                    self.pulp,
                    self.pulp_client,
                    repo_set,
                    right_config,
                    self.dry_run,
                    self._executor,
                    ubim_client,
                ).run_ubi_population()

                out_repos.update(repo_set.get_output_repos())
                # in case of dry-run there are no publications expected
                if repos_publishes:
                    awaited_repos_publishes.extend(repos_publishes)

        return awaited_repos_publishes

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


class UbiPopulateRunner(object):
    def __init__(
        self,
        legacy_client,
        pulp_client,
        output_repo_set,
        ubiconfig_item,
        dry_run,
        executor,
        ubi_manifest_client=None,
    ):
        self.pulp = legacy_client
        self.pulp_client = pulp_client
        self.ubim_client = ubi_manifest_client

        self.repos = output_repo_set
        self.ubiconfig = ubiconfig_item
        self.dry_run = dry_run
        self._executor = executor

    def _determine_pulp_actions(self, units, current, diff_f, extra_units=None):
        expected = list(units)
        if extra_units:
            expected += list(extra_units)
        to_associate = diff_f(expected, current)
        to_unassociate = diff_f(current, expected)
        return to_associate, to_unassociate

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

    def _get_pulp_actions_pkgs(self, pkgs, current, modular_pkgs):
        return self._determine_pulp_actions(
            pkgs, current, self._diff_packages_by_filename, modular_pkgs
        )

    def _get_pulp_actions_src_pkgs(self, pkgs, current, modular):
        """
        Get required pulp actions to make sure existing and desired source packages are in
        match.
        """
        uniq_srpms = {}

        all_pkgs = list(pkgs) + list(modular)

        # filter out packages that share same source rpm
        for pkg in all_pkgs:
            fn = pkg.filename or pkg.sourcerpm
            uniq_srpms[fn] = pkg

        src_pkgs = list(uniq_srpms.values())
        return self._determine_pulp_actions(
            src_pkgs, current, self._diff_packages_by_filename
        )

    def _get_pulp_actions(
        self,
        current_content,
        modular_binary,
        modular_debug,
        modular_source,
    ):
        """
        Determines expected pulp actions by comparing current content of output repos and
        expected content.

        Content that needs association: unit is in expected but not in current
        Content that needs unassociation: unit is in current but not in expected
        No action: unit is in current and in expected
        """

        modules_assoc, modules_unassoc = self._get_pulp_actions_mds(
            self.repos.modules, current_content.modules
        )
        md_defaults_assoc, md_defaults_unassoc = self._get_pulp_actions_md_defaults(
            self.repos.module_defaults, current_content.modulemd_defaults
        )

        rpms_assoc, rpms_unassoc = self._get_pulp_actions_pkgs(
            self.repos.packages, current_content.binary_rpms, modular_binary
        )
        srpms_assoc, srpms_unassoc = self._get_pulp_actions_src_pkgs(
            self.repos.source_rpms, current_content.source_rpms, modular_source
        )

        debug_assoc = None
        debug_unassoc = None
        if current_content.debug_rpms:
            debug_assoc, debug_unassoc = self._get_pulp_actions_pkgs(
                self.repos.debug_rpms, current_content.debug_rpms, modular_debug
            )

        associations = (
            AssociateActionModules(
                modules_assoc, self.repos.out_repos.rpm, self.repos.in_repos.rpm
            ),
            AssociateActionRpms(
                rpms_assoc, self.repos.out_repos.rpm, self.repos.in_repos.rpm
            ),
            AssociateActionRpms(
                srpms_assoc, self.repos.out_repos.source, self.repos.in_repos.source
            ),
            AssociateActionRpms(
                debug_assoc, self.repos.out_repos.debug, self.repos.in_repos.debug
            ),
        )

        unassociations = (
            UnassociateActionModules(modules_unassoc, self.repos.out_repos.rpm),
            UnassociateActionRpms(rpms_unassoc, self.repos.out_repos.rpm),
            UnassociateActionRpms(srpms_unassoc, self.repos.out_repos.source),
            UnassociateActionRpms(debug_unassoc, self.repos.out_repos.debug),
        )

        mdd_association = AssociateActionModuleDefaults(
            md_defaults_assoc, self.repos.out_repos.rpm, self.repos.in_repos.rpm
        )

        mdd_unassociation = UnassociateActionModuleDefaults(
            md_defaults_unassoc, self.repos.out_repos.rpm
        )

        return associations, unassociations, mdd_association, mdd_unassociation

    def _diff_modules_by_nsvca(self, modules_1, modules_2):
        return self._diff_lists_by_attr(modules_1, modules_2, "nsvca")

    def _diff_md_defaults_by_profiles(self, module_defaults_1, module_defaults_2):
        return self._diff_lists_by_attr(
            module_defaults_1, module_defaults_2, flatten_md_defaults_name_profiles
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

    def _search_expected_modulemd_defaults(self, modulemd_defaults):
        criteria_values = [(unit.name,) for unit in modulemd_defaults]
        fields = ("name",)
        or_criteria = Matcher.create_or_criteria(fields, criteria_values)
        return f_proxy(
            self._executor.submit(
                Matcher.search_modulemd_defaults, or_criteria, self.repos.in_repos.rpm
            )
        )

    def run_ubi_population(self):
        current_content = self._get_current_content()

        modular_rpms = []
        modular_debug_rpms = []
        modular_source_rpms = []

        # start async querying for modulemds and modular and non-modular packages
        binary_manifest = self.ubim_client.get_manifest(self.repos.out_repos.rpm.id)
        debug_manifest = self.ubim_client.get_manifest(self.repos.out_repos.debug.id)
        source_manifest = self.ubim_client.get_manifest(self.repos.out_repos.source.id)
        self.repos.modules = binary_manifest.modules
        self.repos.module_defaults = self._search_expected_modulemd_defaults(
            binary_manifest.modulemd_defaults
        )
        self.repos.packages = binary_manifest.packages
        self.repos.debug_rpms = debug_manifest.packages
        self.repos.source_rpms = source_manifest.packages

        (
            associations,
            unassociations,
            mdd_association,
            mdd_unassociation,
        ) = self._get_pulp_actions(
            current_content,
            modular_rpms,
            modular_debug_rpms,
            modular_source_rpms,
        )

        if self.dry_run:
            self.log_curent_content(current_content)
            self.log_pulp_actions(
                associations + (mdd_association,),
                unassociations + (mdd_unassociation,),
            )
        else:
            fts = []
            fts.extend(self._associate_unassociate_units(associations + unassociations))
            # wait for associate/unassociate tasks
            self._wait_pulp(fts)

            self._associate_unassociate_md_defaults(
                (mdd_association,), (mdd_unassociation,)
            )

            # return list of futures with repo publishes
            return self._publish_out_repos()

    def _associate_unassociate_units(self, action_list):
        fts = []
        for action in action_list:
            if action.units:
                fts.extend(
                    [self._executor.submit(*a) for a in action.get_actions(self.pulp)]
                )

        return fts

    def _associate_unassociate_md_defaults(self, action_md_ass, action_md_unass):
        """
        Unassociate old module defaults units first, wait until done and
        then start new units association
        """
        fts_unass = self._associate_unassociate_units(action_md_unass)
        self._wait_pulp(fts_unass)

        fts_ass = self._associate_unassociate_units(action_md_ass)
        self._wait_pulp(fts_ass)

    def _wait_pulp(self, futures):
        # wait for pulp tasks from futures
        for ft in as_completed(futures):
            tasks = ft.result()
            if tasks:
                self.pulp.wait_for_tasks(tasks)

    def log_curent_content(self, current_content):
        _LOG.info("Current modules in repo: %s", self.repos.out_repos.rpm.id)
        for module in current_content.modules:
            _LOG.info(module.nsvca)

        _LOG.info("Current module_defaults in repo: %s", self.repos.out_repos.rpm.id)
        for md_d in current_content.modulemd_defaults:
            _LOG.info("module_defaults: %s, profiles: %s", md_d.name, md_d.profiles)

        _LOG.info("Current rpms in repo: %s", self.repos.out_repos.rpm.id)
        for rpm in current_content.binary_rpms:
            _LOG.info(rpm.filename)

        _LOG.info("Current srpms in repo: %s", self.repos.out_repos.source.id)
        for rpm in current_content.source_rpms:
            _LOG.info(rpm.filename)

        if self.repos.out_repos.debug:
            _LOG.info("Current rpms in repo: %s", self.repos.out_repos.debug.id)
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
                    item.TYPE,
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
                    item.TYPE,
                    item.dst_repo.id,
                )

    def _get_current_content(self):
        """
        Gather current content of output repos
        """
        criteria = [Criteria.true()]
        current_modulemds = f_proxy(
            self._executor.submit(
                Matcher.search_modulemds, criteria, [self.repos.out_repos.rpm]
            )
        )
        current_modulemd_defaults = f_proxy(
            self._executor.submit(
                Matcher.search_modulemd_defaults, criteria, [self.repos.out_repos.rpm]
            )
        )
        current_rpms = f_proxy(
            self._executor.submit(
                Matcher.search_rpms, criteria, [self.repos.out_repos.rpm]
            )
        )
        current_srpms = f_proxy(
            self._executor.submit(
                Matcher.search_srpms, criteria, [self.repos.out_repos.source]
            )
        )

        if self.repos.out_repos.debug.result():
            current_debug_rpms = f_proxy(
                self._executor.submit(
                    Matcher.search_rpms, criteria, [self.repos.out_repos.debug]
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

    def _publish_out_repos(self):
        fts = []
        repos_to_publish = (
            self.repos.out_repos.rpm,
            self.repos.out_repos.debug,
            self.repos.out_repos.source,
        )
        options = PublishOptions(clean=True)
        for repo in repos_to_publish:
            if repo.result():
                fts.append(repo.publish(options))
        return fts
