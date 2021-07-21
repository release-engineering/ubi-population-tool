import logging
import re

from collections import defaultdict, deque, namedtuple
from concurrent.futures import as_completed
from itertools import chain
from pubtools.pulplib import Client, Criteria, PublishOptions

import ubiconfig

from more_executors import Executors
from more_executors.futures import f_sequence, f_proxy, f_return
from ubipop._pulp_client import Pulp, Package
from ubipop._utils import (
    split_filename,
    AssociateActionModules,
    AssociateActionModuleDefaults,
    AssociateActionRpms,
    UnassociateActionModules,
    UnassociateActionModuleDefaults,
    UnassociateActionRpms,
)
from ._matcher import ModularMatcher


_LOG = logging.getLogger("ubipop")


class RepoMissing(Exception):
    pass


class ConfigMissing(Exception):
    pass


class PopulationSourceMissing(Exception):
    pass


RepoSet = namedtuple("RepoSet", ["rpm", "source", "debug"])


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

    def get_output_repo_ids(self):
        repos = set([self.out_repos.rpm.id, self.out_repos.source.id])
        if self.out_repos.debug.result():
            repos.add(self.out_repos.debug.id)

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
            _LOG.warning("Input Debug repo does not exist")

        if not self.out_repos.rpm:
            fatal = True
            _LOG.error("Output Rpm repo does not exist")

        if not self.out_repos.source:
            fatal = True
            _LOG.error("Output Source repo does not exist")

        if not self.out_repos.debug:
            _LOG.warning("Output Debug repo does not exist")

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
        self._ubiconfig_map = None

    @property
    def ubiconfig_list(self):
        if self._ubiconfig_list is None:
            self._ubiconfig_list = self._load_ubiconfig(
                self._ubiconfig_filename_list,
                self._ubiconfig_dir_or_url,
                self._content_sets,
                self._repo_ids,
            )
        return self._ubiconfig_list

    @property
    def ubiconfig_map(self):
        if self._ubiconfig_map is None:
            self._ubiconfig_map = self._create_config_map()
        return self._ubiconfig_map

    @property
    def pulp_client(self):
        if self._pulp_client is None:
            self._pulp_client = self._make_pulp_client(
                self._pulp_hostname, self._pulp_auth, self._insecure
            )
        return self._pulp_client

    def _make_pulp_client(self, url, auth, insecure):
        return Client("https://" + url, auth=auth, verify=not insecure)

    def _load_ubiconfig(
        self, filenames, ubiconfig_dir_or_url, content_sets=None, repo_ids=None
    ):
        loader = ubiconfig.get_loader(ubiconfig_dir_or_url)
        ubi_conf_list = []

        if filenames:
            ubi_conf_list.extend(loader.load(filename) for filename in filenames)
        else:
            ubi_conf_list.extend(loader.load_all())

        return self._filter_ubi_conf_list(ubi_conf_list, content_sets, repo_ids)

    def _filter_ubi_conf_list(self, config_list, content_sets, repo_ids):
        """
        Reduces the list of UBI configurations to only those matching
        provided content sets and/or repo IDs.
        """

        filtered_conf_list = []

        content_sets = content_sets or []
        repo_ids = repo_ids or []

        if not content_sets and not repo_ids:
            return config_list

        if repo_ids:
            repos = [self.pulp_client.get_repository(repo_id) for repo_id in repo_ids]

            for repo in repos:
                content_sets.append(repo.content_set)

        for conf in config_list:
            for label in [
                conf.content_sets.rpm.input,
                conf.content_sets.rpm.output,
                conf.content_sets.srpm.input,
                conf.content_sets.srpm.output,
                conf.content_sets.debuginfo.input,
                conf.content_sets.debuginfo.output,
            ]:
                if label in content_sets:
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

    def _get_config(self, ubi_config_version, config):
        # get the right config file by ubi_config_version attr of a repository
        # if not found, try to fallback to the default version (major version)
        _ubi_config_version = ubi_config_version
        if _ubi_config_version not in self.ubiconfig_map:
            # if the config is missing, we need to use the default config branch
            _ubi_config_version = _ubi_config_version.split(".")[0]
        try:
            right_config = self.ubiconfig_map[_ubi_config_version][config.file_name]
        except KeyError:
            _LOG.error(
                "Config file %s missing from %s and default %s branches",
                config.file_name,
                ubi_config_version,
                ubi_config_version.split(".")[0],
            )
            raise ConfigMissing()

        return right_config

    def populate_ubi_repos(self):
        out_repos = set()
        used_content_sets = set()
        # since repos are searched by content sets, same repo could be searched and populated
        # multiple times, to avoid that, cache the content sets already used and skip the config
        # whose content sets are all in the cache

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

            for repo_set in repo_pairs:
                right_config = self._get_config(
                    repo_set.out_repos.rpm.ubi_config_version, config
                )
                UbiPopulateRunner(
                    self.pulp,
                    self.pulp_client,
                    repo_set,
                    right_config,
                    self.dry_run,
                    self._executor,
                ).run_ubi_population()

                out_repos.update(repo_set.get_output_repo_ids())

        if self.output_repos:
            with open(self.output_repos, "w") as f:
                for repo in out_repos:
                    f.write(repo.strip() + "\n")

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
        if not out_repo.population_sources:
            raise PopulationSourceMissing

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
    ):
        self.pulp = legacy_client
        self.pulp_client = pulp_client

        self.repos = output_repo_set
        self.ubiconfig = ubiconfig_item
        self.dry_run = dry_run
        self._executor = executor

    def _match_module_defaults(self):
        """Try to find modulemd_defaults units in the same repo with the same
        name/stream of a modulemd.
        """
        fts = {}
        for module in self.repos.modules:
            for in_repo_rpm in self.repos.in_repos.rpm:
                fts[
                    self._executor.submit(
                        self.pulp.search_module_defaults,
                        in_repo_rpm,
                        module.name,
                        str(module.stream),
                    )
                ] = module.name + str(module.stream)

        for ft in as_completed(fts):
            module_defaults = ft.result()
            if module_defaults:
                self.repos.module_defaults[fts[ft]].extend(module_defaults)

    def _get_pkgs_from_all_modules(self):
        modules = []
        for in_repo_rpm in self.repos.in_repos.rpm:
            modules.extend(self.pulp.search_modules(in_repo_rpm))
        pkgs = set()
        regex = r"\d+:"
        reg = re.compile(regex)
        for module in modules:
            for pkg in module.packages:
                rpm_without_epoch = reg.sub("", pkg)
                rpm_filename = rpm_without_epoch + ".rpm"
                pkgs.add(rpm_filename)

        return pkgs

    def _match_packages(self, input_repos, packages_dict):
        """
        Add matching packages from whitelist
        Globbing package name is not supported
        """
        modular_pkgs = self._get_pkgs_from_all_modules()
        fts = {}
        for package_pattern in self.ubiconfig.packages.whitelist:
            name = package_pattern.name
            arch = None if package_pattern.arch in ("*", None) else package_pattern.arch
            for repo in input_repos:
                fts[
                    (self._executor.submit(self.pulp.search_rpms, repo, name, arch))
                ] = name

        for ft in as_completed(fts):
            packages = ft.result()
            if packages:
                for pkg in packages:
                    # skip modular packages, those are handled separately
                    if pkg.filename in modular_pkgs:
                        continue

                    packages_dict[fts[ft]].append(pkg)

    def _match_binary_rpms(self):
        self._match_packages(self.repos.in_repos.rpm, self.repos.packages)

    def _match_debug_rpms(self):
        self._match_packages(self.repos.in_repos.debug, self.repos.debug_rpms)

    def _parse_blacklist_config(self):
        packages_to_exclude = []
        for package_pattern in self.ubiconfig.packages.blacklist:
            name_to_parse = package_pattern.name
            globbing = "*" in name_to_parse
            if globbing:
                name = package_pattern.name[:-1]
            else:
                name = package_pattern.name
            arch = None if package_pattern.arch in ("*", None) else package_pattern.arch

            packages_to_exclude.append((name, globbing, arch))

        return packages_to_exclude

    def _exclude_blacklisted_packages(self):
        blacklisted_binary = self.get_blacklisted_packages(
            list(chain.from_iterable(self.repos.packages.values()))
        )
        blacklisted_debug = self.get_blacklisted_packages(
            list(chain.from_iterable(self.repos.debug_rpms.values()))
        )

        for pkg in blacklisted_binary:
            # blacklist only non-modular pkgs
            self.repos.packages[pkg.name][:] = [
                _pkg
                for _pkg in self.repos.packages.get(pkg.name, [])
                if _pkg.is_modular
            ]

            # if there is nothing left, remove whole entry for package
            if not self.repos.packages[pkg.name]:
                self.repos.packages.pop(pkg.name, None)

        for pkg in blacklisted_debug:
            # blacklist only non-modular debug pkgs
            self.repos.debug_rpms[pkg.name][:] = [
                _pkg
                for _pkg in self.repos.debug_rpms.get(pkg.name, [])
                if _pkg.is_modular
            ]

            # if there is nothing left, remove whole entry for debug package
            if not self.repos.debug_rpms[pkg.name]:
                self.repos.debug_rpms.pop(pkg.name, None)

    def _finalize_rpms_output_set(self):
        for _, packages in self.repos.packages.items():
            self._finalize_output_units(packages, "rpm")

    def _finalize_debug_output_set(self):
        for _, packages in self.repos.debug_rpms.items():
            self._finalize_output_units(packages, "rpm")

    def _finalize_output_units(self, units, type_id):
        if type_id == "rpm":
            self.sort_packages(units)
            self.keep_n_latest_packages(
                units
            )  # with respect to packages referenced by modules

    def _create_srpms_output_set(self):
        rpms = chain.from_iterable(self.repos.packages.values())
        binary_source_repo_map = {}
        for package in rpms:
            if package.sourcerpm is None:
                _LOG.warning(
                    "Package %s doesn't reference its source rpm", package.name
                )
                continue
            in_repo = [
                r
                for r in self.repos.in_repos.rpm
                if r.id == package.associate_source_repo_id
            ][0]

            if in_repo.id not in binary_source_repo_map:
                binary_source_repo_map[in_repo.id] = in_repo.get_source_repository()

            associate_src_repo = binary_source_repo_map[in_repo.id]

            self.repos.source_rpms[package.name].append(
                Package(
                    package.name,
                    package.sourcerpm,
                    is_modular=package.is_modular,
                    src_repo_id=associate_src_repo.id,
                )
            )

        blacklisted_srpms = self.get_blacklisted_packages(
            list(chain.from_iterable(self.repos.source_rpms.values()))
        )

        for pkg in blacklisted_srpms:
            if not pkg.is_modular:
                self.repos.source_rpms.pop(pkg.name, None)

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
        module_defaults_list = list(chain.from_iterable(module_defaults.values()))
        return self._determine_pulp_actions(
            module_defaults_list,
            current,
            self._diff_md_defaults_by_profiles,
        )

    def _get_pulp_actions_pkgs(self, pkgs, current, modular_pkgs):
        pkgs_list = list(chain.from_iterable(pkgs.values()))
        return self._determine_pulp_actions(
            pkgs_list, current, self._diff_packages_by_filename, modular_pkgs
        )

    def _get_pulp_actions_src_pkgs(self, pkgs, current, modular):
        """
        Get required pulp actions to make sure existing and desired source packages are in
        match.
        """
        uniq_srpms = {}

        all_pkgs = list(chain.from_iterable(pkgs.values())) + list(modular)

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
        current_modules_ft,
        current_module_defaults_ft,
        current_rpms_ft,
        current_srpms_ft,
        current_debug_rpms_ft,
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
            self.repos.modules, current_modules_ft.result()
        )
        md_defaults_assoc, md_defaults_unassoc = self._get_pulp_actions_md_defaults(
            self.repos.module_defaults, current_module_defaults_ft.result()
        )

        rpms_assoc, rpms_unassoc = self._get_pulp_actions_pkgs(
            self.repos.packages, current_rpms_ft.result(), modular_binary
        )
        srpms_assoc, srpms_unassoc = self._get_pulp_actions_src_pkgs(
            self.repos.source_rpms, current_srpms_ft.result(), modular_source
        )

        debug_assoc = None
        debug_unassoc = None
        if current_debug_rpms_ft is not None:
            debug_assoc, debug_unassoc = self._get_pulp_actions_pkgs(
                self.repos.debug_rpms, current_debug_rpms_ft.result(), modular_debug
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
            module_defaults_1, module_defaults_2, "name_profiles"
        )

    def _diff_packages_by_filename(self, packages_1, packages_2):
        return self._diff_lists_by_attr(packages_1, packages_2, "filename")

    def _diff_lists_by_attr(self, list_1, list_2, attr):
        attrs_list_2 = [getattr(obj, attr) for obj in list_2]
        diff = [obj for obj in list_1 if getattr(obj, attr) not in attrs_list_2]

        return diff

    def run_ubi_population(self):
        (
            current_modules_ft,
            current_module_defaults_ft,
            current_rpms_ft,
            current_srpms_ft,
            current_debug_rpms_ft,
        ) = self._get_current_content()

        # start async querying for modulemds and modular packages
        mm = ModularMatcher(self.repos.in_repos, self.ubiconfig.modules).run()
        self.repos.modules = mm.modules

        self._match_binary_rpms()
        if self.repos.out_repos.debug:
            self._match_debug_rpms()
        self._exclude_blacklisted_packages()

        # only non-modular packages
        self._finalize_rpms_output_set()
        self._finalize_debug_output_set()
        self._create_srpms_output_set()

        self._match_module_defaults()

        (
            associations,
            unassociations,
            mdd_association,
            mdd_unassociation,
        ) = self._get_pulp_actions(
            current_modules_ft,
            current_module_defaults_ft,
            current_rpms_ft,
            current_srpms_ft,
            current_debug_rpms_ft,
            mm.binary_rpms,
            mm.debug_rpms,
            mm.source_rpms,
        )

        if self.dry_run:
            self.log_curent_content(
                current_modules_ft,
                current_module_defaults_ft,
                current_rpms_ft,
                current_srpms_ft,
                current_debug_rpms_ft,
            )
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

            # wait repo publication
            f_sequence(self._publish_out_repos()).result()

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

    def log_curent_content(
        self,
        current_modules_ft,
        current_module_defaults_ft,
        current_rpms_ft,
        current_srpms_ft,
        current_debug_rpms_ft,
    ):
        _LOG.info("Current modules in repo: %s", self.repos.out_repos.rpm.id)
        for module in current_modules_ft.result():
            _LOG.info(module.nsvca)

        _LOG.info("Current module_defaults in repo: %s", self.repos.out_repos.rpm.id)
        for md_d in current_module_defaults_ft.result():
            _LOG.info("module_defaults: %s, profiles: %s", md_d.name, md_d.profiles)

        _LOG.info("Current rpms in repo: %s", self.repos.out_repos.rpm.id)
        for rpm in current_rpms_ft.result():
            _LOG.info(rpm.filename)

        _LOG.info("Current srpms in repo: %s", self.repos.out_repos.source.id)
        for rpm in current_srpms_ft.result():
            _LOG.info(rpm.filename)

        if self.repos.out_repos.debug:
            _LOG.info("Current rpms in repo: %s", self.repos.out_repos.debug.id)
            for rpm in current_debug_rpms_ft.result():
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
        current_modules_ft = self._executor.submit(
            self.pulp.search_modules, self.repos.out_repos.rpm
        )
        current_module_defaults_ft = self._executor.submit(
            self.pulp.search_module_defaults, self.repos.out_repos.rpm
        )
        current_rpms_ft = self._executor.submit(
            self.pulp.search_rpms, self.repos.out_repos.rpm
        )
        current_srpms_ft = self._executor.submit(
            self.pulp.search_rpms, self.repos.out_repos.source
        )
        if self.repos.out_repos.debug:
            current_debug_rpms_ft = self._executor.submit(
                self.pulp.search_rpms, self.repos.out_repos.debug
            )
        else:
            current_debug_rpms_ft = None

        return (
            current_modules_ft,
            current_module_defaults_ft,
            current_rpms_ft,
            current_srpms_ft,
            current_debug_rpms_ft,
        )

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

    def get_blacklisted_packages(self, package_list):
        """
        Finds blacklisted packages in output sets
        """
        blacklisted_pkgs = []
        for pattern_name, globbing, pattern_arch in self._parse_blacklist_config():
            for package in package_list:
                name, _, _, _, arch = split_filename(package.filename)
                blacklisted = False
                if globbing:
                    if name.startswith(pattern_name):
                        blacklisted = True
                else:
                    if name == pattern_name:
                        blacklisted = True

                if pattern_arch:
                    if arch != pattern_arch:
                        blacklisted = False

                if blacklisted:
                    blacklisted_pkgs.append(package)

        return blacklisted_pkgs

    def sort_packages(self, packages):
        """
        Sort packages by vercmp
        """
        packages.sort()

    def keep_n_latest_packages(self, packages, n=1):
        """
        Keep n latest non-modular packages.

        Arguments:
            packages (List[Package]): Sorted, oldest goes first

        Keyword arguments:
            n (int): Number of non-modular package versions to keep

        Returns:
            None. The packages list is changed in-place
        """
        # Use a queue of n elements per arch
        pkgs_per_arch = defaultdict(lambda: deque(maxlen=n))

        for package in packages:
            _, _, _, _, arch = split_filename(package.filename)
            pkgs_per_arch[arch].append(package)

        latest_pkgs_per_arch = [
            pkg for pkg in chain.from_iterable(pkgs_per_arch.values())
        ]

        packages[:] = latest_pkgs_per_arch
