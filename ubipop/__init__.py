import logging
import re

from collections import defaultdict, deque, namedtuple
from concurrent.futures import as_completed
from itertools import chain

import ubiconfig

from more_executors import Executors
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

_LOG = logging.getLogger("ubipop")


class RepoMissing(Exception):
    pass


class ConfigMissing(Exception):
    pass


RepoSet = namedtuple('RepoSet', ['rpm', 'source', 'debug'])


class UbiRepoSet(object):
    def __init__(self, input_repos, output_repos):
        self.in_repos = input_repos
        self.out_repos = output_repos

        self.packages = defaultdict(list)
        self.debug_rpms = defaultdict(list)
        self.modules = defaultdict(list)
        self.module_defaults = defaultdict(list)
        self.pkgs_from_modules = defaultdict(list)
        self.source_rpms = defaultdict(list)

        self._ensure_repos_existence()

    def get_output_repo_ids(self):
        repos = set([self.out_repos.rpm.repo_id, self.out_repos.source.repo_id])
        if self.out_repos.debug:
            repos.add(self.out_repos.debug.repo_id)

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
    def __init__(self, pulp_hostname, pulp_auth, dry_run, ubiconfig_filename_list=None,
                 ubiconfig_dir_or_url=None, insecure=False, workers_count=4, output_repos=None,
                 **kwargs):

        self.pulp = Pulp(pulp_hostname, pulp_auth, insecure)
        self.dry_run = dry_run
        self.output_repos = output_repos
        self._executor = Executors.thread_pool(max_workers=workers_count).with_retry()
        self.ubiconfig_list = self._load_ubiconfig(ubiconfig_filename_list, ubiconfig_dir_or_url,
                                                   content_sets=kwargs.get('content_sets', None),
                                                   repo_ids=kwargs.get('repo_ids', None))
        self.ubiconfig_map = self._create_config_map()

    def _load_ubiconfig(self, filenames, ubiconfig_dir_or_url, content_sets=None, repo_ids=None):
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

        fts = [self._executor.submit(self.pulp.search_repo_by_id, r) for r in repo_ids]
        for repo_list in [ft.result() for ft in fts]:
            content_sets.extend(repo.content_set for repo in repo_list)

        for conf in config_list:
            for label in [
                    conf.content_sets.rpm.input, conf.content_sets.rpm.output,
                    conf.content_sets.srpm.input, conf.content_sets.srpm.output,
                    conf.content_sets.debuginfo.input, conf.content_sets.debuginfo.output,
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
            config_map.setdefault(config.version, {})\
                .setdefault(config.file_name, config)

        return config_map

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
                _LOG.debug("Skipping %s, since it's been used already", config.file_name)
                continue

            try:
                repo_pairs = self._get_ubi_repo_sets(config)

            except RepoMissing:
                _LOG.warning("Skipping current content triplet, some repos are missing")
                continue

            for repo_set in repo_pairs:
                ubi_config_version = repo_set.out_repos.rpm.ubi_config_version
                platform_full_version = repo_set.out_repos.rpm.platform_full_version
                platform_major_version = repo_set.out_repos.rpm.platform_major_version
                # get the right config file by ubi_config_version attr, if it's None,
                # then it's not a mainline repo, use platform_full_version instead.
                # config file could also be missing for specific version, then the
                # default config file will be used.
                version = ubi_config_version or platform_full_version
                right_config = self.ubiconfig_map\
                    .get(str(version), {})\
                    .get(config.file_name)\
                    or self.ubiconfig_map\
                        .get(str(platform_major_version), {})\
                        .get(config.file_name)

                # if config file is missing from wanted version, as well as default
                # branch, raise exception
                if not right_config:
                    _LOG.error(
                        'Config file %s missing from %s and default %s branches',
                        config.file_name,
                        version,
                        platform_full_version,
                    )
                    raise ConfigMissing()

                UbiPopulateRunner(self.pulp, repo_set, right_config, self.dry_run,
                                  self._executor).run_ubi_population()

                out_repos.update(repo_set.get_output_repo_ids())

        if self.output_repos:
            with open(self.output_repos, 'w') as f:
                for repo in out_repos:
                    f.write(repo.strip() + '\n')

    def _get_ubi_repo_sets(self, ubi_config_item):
        """
        Searches for ubi repository triplet (binary rpm, srpm, debug) for
        one ubi config item and tries to determine their population sources
        (input repositories). Returns list UbiRepoSet objects that provides
        input and output repositories that are used for population process.
        """
        rpm_repos_ft = self._executor.submit(self.pulp.search_repo_by_cs,
                                             ubi_config_item.content_sets.rpm.output)
        source_repos_ft = self._executor.submit(self.pulp.search_repo_by_cs,
                                                ubi_config_item.content_sets.srpm.output)
        debug_repos_ft = self._executor.submit(self.pulp.search_repo_by_cs,
                                               ubi_config_item.content_sets.debuginfo.output)

        ubi_repo_sets = []

        for out_rpm_repo in rpm_repos_ft.result():

            if not out_rpm_repo.ubi_population:
                # it is sufficient to check only binary from repo triplet for disabling population
                _LOG.debug(
                    "Skipping population for output binary repo and "
                    "related source and debug repos:\n\t%s",
                    out_rpm_repo.repo_id)
                continue

            out_source_repo = self.get_repo_counterpart(out_rpm_repo, source_repos_ft.result())
            out_debug_repo = self.get_repo_counterpart(out_rpm_repo, debug_repos_ft.result())

            in_rpm_repos = self._get_population_sources(out_rpm_repo,
                                                        ubi_config_item.content_sets.rpm.input)
            in_source_repos = self._get_population_sources(out_source_repo,
                                                           ubi_config_item.content_sets.srpm.input)
            in_debug_repos = self._get_population_sources(out_debug_repo,
                                                          ubi_config_item.content_sets.debuginfo
                                                          .input)

            out_repos = (out_rpm_repo, out_source_repo, out_debug_repo)
            in_repos = (in_rpm_repos, in_source_repos, in_debug_repos)

            ubi_repo_sets.append(UbiRepoSet(RepoSet(*in_repos), RepoSet(*out_repos)))

        return ubi_repo_sets

    def _get_population_sources(self, repo, input_cs):
        src_repos = []
        if repo.population_sources:
            fts = [self._executor.submit(self.pulp.search_repo_by_id, r)
                   for r in repo.population_sources]

            for ft in as_completed(fts):
                repo = ft.result()
                if repo:
                    src_repos.append(repo[0])
        else:
            in_repos_ft = self._executor.submit(self.pulp.search_repo_by_cs, input_cs)
            repo = self.get_repo_counterpart(repo, in_repos_ft.result())
            src_repos.append(repo)

        return src_repos

    @staticmethod
    def get_repo_counterpart(input_repo, repos_to_match):
        """
        Finds counterpart of input_repo in repos_to_match list by arch and platform_full_version.
        """
        for repo in repos_to_match:
            if input_repo.arch == repo.arch and \
                    input_repo.platform_full_version == repo.platform_full_version:
                return repo


class UbiPopulateRunner(object):
    def __init__(self, pulp, output_repo_set, ubiconfig_item, dry_run, executor):
        self.pulp = pulp
        self.repos = output_repo_set
        self.ubiconfig = ubiconfig_item
        self.dry_run = dry_run
        self._executor = executor

    def _match_modules(self):
        # Add matching modules
        fts = {}
        for module in self.ubiconfig.modules:
            for in_repo_rpm in self.repos.in_repos.rpm:
                fts[self._executor.submit(self.pulp.search_modules,
                                          in_repo_rpm, module.name,
                                          str(module.stream))] = \
                    (module.name + str(module.stream), module.profiles)

        for ft in as_completed(fts):
            input_modules = ft.result()
            if input_modules:
                # fts[ft][0] == module.name + str(module.stream)
                # fts[ft][1] == module.profiles
                name_stream = fts[ft][0]
                profiles = fts[ft][1]
                self.repos.modules[name_stream].extend(input_modules)
                if profiles:
                    # Include packages from module profiles only.
                    packages_names = self.get_packages_names_by_profiles(profiles, input_modules)
                    for package_name in packages_names:
                        module_packages = self.get_packages_from_module(input_modules,
                                                                        package_name)

                        rpms, debug_rpms = module_packages
                        # for reference which pkgs are from modules
                        self.repos.pkgs_from_modules[name_stream].extend(rpms + debug_rpms)
                        self.repos.packages[package_name].extend(rpms)
                        self.repos.debug_rpms[package_name].extend(debug_rpms)
                else:
                    # Include every package from module artifacts.
                    module_packages = self.get_packages_from_module(input_modules)
                    rpms, debug_rpms = module_packages
                    self.repos.pkgs_from_modules[name_stream].extend(rpms + debug_rpms)
                    for package in rpms:
                        self.repos.packages[package.name].append(package)
                    for package in debug_rpms:
                        self.repos.debug_rpms[package.name].append(package)

    def _match_module_defaults(self):
        """Try to find modulemd_defaults units in the same repo with the same
        name/stream of a modulemd.
        """
        fts = {}
        for _, modules in self.repos.modules.items():
            for md in modules:
                for in_repo_rpm in self.repos.in_repos.rpm:
                    fts[self._executor.submit(self.pulp.search_module_defaults,
                                              in_repo_rpm, md.name,
                                              str(md.stream))] = md.name + str(md.stream)
        for ft in as_completed(fts):
            module_defaults = ft.result()
            if module_defaults:
                self.repos.module_defaults[fts[ft]].extend(module_defaults)

    def _get_pkgs_from_all_modules(self):
        modules = []
        for in_repo_rpm in self.repos.in_repos.rpm:
            modules.extend(self.pulp.search_modules(in_repo_rpm))
        pkgs = set()
        regex = r'\d+:'
        reg = re.compile(regex)
        for module in modules:
            for pkg in module.packages:
                rpm_without_epoch = reg.sub('', pkg)
                rpm_filename = rpm_without_epoch + '.rpm'
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
            arch = None if package_pattern.arch in ('*', None) else package_pattern.arch
            for repo in input_repos:
                fts[(self._executor.submit(self.pulp.search_rpms,
                                           repo, name, arch))] = name

        for ft in as_completed(fts):
            packages = ft.result()
            if packages:
                for pkg in packages:
                    if pkg.filename in modular_pkgs:
                        pkg.is_modular = True
                packages_dict[fts[ft]].extend(packages)

    def _match_binary_rpms(self):
        self._match_packages(self.repos.in_repos.rpm, self.repos.packages)

    def _match_debug_rpms(self):
        self._match_packages(self.repos.in_repos.debug, self.repos.debug_rpms)

    def _parse_blacklist_config(self):
        packages_to_exclude = []
        for package_pattern in self.ubiconfig.packages.blacklist:
            name_to_parse = package_pattern.name
            globbing = '*' in name_to_parse
            if globbing:
                name = package_pattern.name[:-1]
            else:
                name = package_pattern.name
            arch = None if package_pattern.arch in ('*', None) else package_pattern.arch

            packages_to_exclude.append((name, globbing, arch))

        return packages_to_exclude

    def _exclude_blacklisted_packages(self):
        blacklisted_binary = self.get_blacklisted_packages(
            list(chain.from_iterable(self.repos.packages.values())))
        blacklisted_debug = self.get_blacklisted_packages(
            list(chain.from_iterable(self.repos.debug_rpms.values())))

        for pkg in blacklisted_binary:
            # blacklist only non-modular pkgs
            self.repos.packages[pkg.name][:] = [_pkg for _pkg in
                                                self.repos.packages.get(pkg.name, [])
                                                if _pkg.is_modular]

            # if there is nothing left, remove whole entry for package
            if not self.repos.packages[pkg.name]:
                self.repos.packages.pop(pkg.name, None)

        for pkg in blacklisted_debug:
            # blacklist only non-modular debug pkgs
            self.repos.debug_rpms[pkg.name][:] = [_pkg for _pkg in
                                                  self.repos.debug_rpms.get(pkg.name, [])
                                                  if _pkg.is_modular]

            # if there is nothing left, remove whole entry for debug package
            if not self.repos.debug_rpms[pkg.name]:
                self.repos.debug_rpms.pop(pkg.name, None)

    def _finalize_modules_output_set(self):
        for _, modules in self.repos.modules.items():
            self._finalize_output_units(modules, 'module')

    def _finalize_rpms_output_set(self):
        for _, packages in self.repos.packages.items():
            self._finalize_output_units(packages, 'rpm')

    def _finalize_debug_output_set(self):
        for _, packages in self.repos.debug_rpms.items():
            self._finalize_output_units(packages, 'rpm')

    def _finalize_output_units(self, units, type_id):
        if type_id == 'rpm':
            self.sort_packages(units)
            self.keep_n_latest_packages(units)  # with respect to packages referenced by modules
        else:
            self.sort_modules(units)
            self.keep_n_latest_modules(units)

    def _create_srpms_output_set(self):
        rpms = chain.from_iterable(self.repos.packages.values())
        for package in rpms:
            if package.sourcerpm_filename is None:
                _LOG.warning("Package %s doesn't reference its source rpm", package.name)
                continue
            in_repo = [r for r in self.repos.in_repos.rpm
                       if r.repo_id == package.associate_source_repo_id][0]

            associate_src_repo = UbiPopulate.get_repo_counterpart(in_repo,
                                                                  self.repos.in_repos.source)

            self.repos.source_rpms[package.name].append(
                Package(
                    package.name,
                    package.sourcerpm_filename,
                    is_modular=package.is_modular,
                    src_repo_id=associate_src_repo.repo_id)
            )

        blacklisted_srpms = self.get_blacklisted_packages(
            list(chain.from_iterable(self.repos.source_rpms.values()))
        )

        for pkg in blacklisted_srpms:
            if not pkg.is_modular:
                self.repos.source_rpms.pop(pkg.name, None)

    def _determine_pulp_actions(self, units, current, diff_f):
        expected = list(chain.from_iterable(units.values()))
        to_associate = diff_f(expected, current)
        to_unassociate = diff_f(current, expected)
        return to_associate, to_unassociate

    def _get_pulp_actions_mds(self, modules, current):
        return self._determine_pulp_actions(modules, current, self._diff_modules_by_nsvca)

    def _get_pulp_actions_md_defaults(self, module_defaults, current):
        return self._determine_pulp_actions(
            module_defaults,
            current,
            self._diff_md_defaults_by_profiles,
        )

    def _get_pulp_actions_pkgs(self, pkgs, current):
        return self._determine_pulp_actions(pkgs, current, self._diff_packages_by_filename)

    def _get_pulp_actions_src_pkgs(self, pkgs, current):
        """
        Get required pulp actions to make sure existing and desired source packages are in
        match.
        """
        src_pkgs = {}
        uniq_srpms = {}
        # filter out packages that share same source rpm
        for _, pkgs in pkgs.items():
            for pkg in pkgs:
                fn = pkg.filename or pkg.sourcerpm_filename
                uniq_srpms[fn] = pkg

        # remap uniq srpms to format accepted by _determine_pulp_actions
        for _, srpm in uniq_srpms.items():
            src_pkgs[(srpm.name, srpm.version, srpm.release)] = [srpm]

        return self._determine_pulp_actions(src_pkgs, current, self._diff_packages_by_filename)

    def _get_pulp_actions(self, current_modules_ft, current_module_defaults_ft, current_rpms_ft,
                          current_srpms_ft, current_debug_rpms_ft):
        """
        Determines expected pulp actions by comparing current content of output repos and
        expected content.

        Content that needs association: unit is in expected but not in current
        Content that needs unassociation: unit is in current but not in expected
        No action: unit is in current and in expected
        """
        modules_assoc, modules_unassoc = self._get_pulp_actions_mds(self.repos.modules,
                                                                    current_modules_ft.result())
        md_defaults_assoc, md_defaults_unassoc = \
            self._get_pulp_actions_md_defaults(self.repos.module_defaults,
                                               current_module_defaults_ft.result())

        rpms_assoc, rpms_unassoc = self._get_pulp_actions_pkgs(self.repos.packages,
                                                               current_rpms_ft.result())
        srpms_assoc, srpms_unassoc = self._get_pulp_actions_src_pkgs(self.repos.source_rpms,
                                                                     current_srpms_ft.result())

        debug_assoc = None
        debug_unassoc = None
        if current_debug_rpms_ft is not None:
            debug_assoc, debug_unassoc = self._get_pulp_actions_pkgs(self.repos.debug_rpms,
                                                                     current_debug_rpms_ft.result())

        associations = (AssociateActionModules(modules_assoc,
                                               self.repos.out_repos.rpm,
                                               self.repos.in_repos.rpm),
                        AssociateActionRpms(rpms_assoc,
                                            self.repos.out_repos.rpm,
                                            self.repos.in_repos.rpm),
                        AssociateActionRpms(srpms_assoc,
                                            self.repos.out_repos.source,
                                            self.repos.in_repos.source),
                        AssociateActionRpms(debug_assoc,
                                            self.repos.out_repos.debug,
                                            self.repos.in_repos.debug)
                       )

        unassociations = (UnassociateActionModules(modules_unassoc, self.repos.out_repos.rpm),
                          UnassociateActionRpms(rpms_unassoc, self.repos.out_repos.rpm),
                          UnassociateActionRpms(srpms_unassoc, self.repos.out_repos.source),
                          UnassociateActionRpms(debug_unassoc, self.repos.out_repos.debug))

        mdd_association = AssociateActionModuleDefaults(md_defaults_assoc,
                                                        self.repos.out_repos.rpm,
                                                        self.repos.in_repos.rpm)

        mdd_unassociation = UnassociateActionModuleDefaults(md_defaults_unassoc,
                                                            self.repos.out_repos.rpm)

        return associations, unassociations, mdd_association, mdd_unassociation

    def _diff_modules_by_nsvca(self, modules_1, modules_2):
        return self._diff_lists_by_attr(modules_1, modules_2, 'nsvca')

    def _diff_md_defaults_by_profiles(self, module_defaults_1, module_defaults_2):
        return self._diff_lists_by_attr(module_defaults_1, module_defaults_2, 'name_profiles')

    def _diff_packages_by_filename(self, packages_1, packages_2):
        return self._diff_lists_by_attr(packages_1, packages_2, 'filename')

    def _diff_lists_by_attr(self, list_1, list_2, attr):
        attrs_list_2 = [getattr(obj, attr) for obj in list_2]
        diff = [obj for obj in list_1 if getattr(obj, attr) not in attrs_list_2]

        return diff

    def run_ubi_population(self):
        current_modules_ft, current_module_defaults_ft, current_rpms_ft, \
            current_srpms_ft, current_debug_rpms_ft = self._get_current_content()

        self._match_modules()
        self._match_binary_rpms()
        if self.repos.out_repos.debug:
            self._match_debug_rpms()
        self._exclude_blacklisted_packages()
        self._finalize_modules_output_set()
        self._finalize_rpms_output_set()
        self._finalize_debug_output_set()
        self._match_module_defaults()
        self._create_srpms_output_set()

        associations, unassociations, mdd_association, mdd_unassociation = \
            self._get_pulp_actions(current_modules_ft,
                                   current_module_defaults_ft,
                                   current_rpms_ft,
                                   current_srpms_ft,
                                   current_debug_rpms_ft)

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

            self._associate_unassociate_md_defaults((mdd_association,), (mdd_unassociation,))

            # wait repo publication
            self._wait_pulp(self._publish_out_repos())

    def _associate_unassociate_units(self, action_list):
        fts = []
        for action in action_list:
            if action.units:
                fts.extend([self._executor.submit(*a) for a in action.get_actions(self.pulp)])

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

    def log_curent_content(self, current_modules_ft, current_module_defaults_ft,
                           current_rpms_ft, current_srpms_ft, current_debug_rpms_ft):
        _LOG.info("Current modules in repo: %s", self.repos.out_repos.rpm.repo_id)
        for module in current_modules_ft.result():
            _LOG.info(module.nsvca)

        _LOG.info("Current module_defaults in repo: %s", self.repos.out_repos.rpm.repo_id)
        for md_d in current_module_defaults_ft.result():
            _LOG.info("module_defaults: %s, profiles: %s", md_d.name, md_d.profiles)

        _LOG.info("Current rpms in repo: %s", self.repos.out_repos.rpm.repo_id)
        for rpm in current_rpms_ft.result():
            _LOG.info(rpm.filename)

        _LOG.info("Current srpms in repo: %s", self.repos.out_repos.source.repo_id)
        for rpm in current_srpms_ft.result():
            _LOG.info(rpm.filename)

        if self.repos.out_repos.debug:
            _LOG.info("Current rpms in repo: %s", self.repos.out_repos.debug.repo_id)
            for rpm in current_debug_rpms_ft.result():
                _LOG.info(rpm.filename)

    def log_pulp_actions(self, associations, unassociations):
        for item in associations:
            if item.units:
                for unit in item.units:
                    _LOG.info("Would associate %s from %s to %s", unit,
                              unit.associate_source_repo_id,
                              item.dst_repo.repo_id)

            else:
                _LOG.info("No association expected for %s from %s to %s", item.TYPE,
                          [r.repo_id for r in item.src_repos],
                          item.dst_repo.repo_id)

        for item in unassociations:
            if item.units:
                for unit in item.units:
                    _LOG.info("Would unassociate %s from %s", unit, item.dst_repo.repo_id)
            else:
                _LOG.info("No unassociation expected for %s from %s", item.TYPE,
                          item.dst_repo.repo_id)

    def _get_current_content(self):
        """
        Gather current content of output repos
        """
        current_modules_ft = self._executor.submit(self.pulp.search_modules,
                                                   self.repos.out_repos.rpm)
        current_module_defaults_ft = self._executor.submit(self.pulp.search_module_defaults,
                                                           self.repos.out_repos.rpm)
        current_rpms_ft = self._executor.submit(self.pulp.search_rpms,
                                                self.repos.out_repos.rpm)
        current_srpms_ft = self._executor.submit(self.pulp.search_rpms,
                                                 self.repos.out_repos.source)
        if self.repos.out_repos.debug:
            current_debug_rpms_ft = self._executor.submit(self.pulp.search_rpms,
                                                          self.repos.out_repos.debug)
        else:
            current_debug_rpms_ft = None

        return current_modules_ft, current_module_defaults_ft, current_rpms_ft, \
            current_srpms_ft, current_debug_rpms_ft

    def _publish_out_repos(self):
        fts = []
        repos_to_publish = (self.repos.out_repos.rpm,
                            self.repos.out_repos.debug,
                            self.repos.out_repos.source)

        for repo in repos_to_publish:
            if repo:
                fts.append(self._executor.submit(self.pulp.publish_repo, repo))
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

    def sort_modules(self, modules):
        """
        Sort modules by version
        """
        modules.sort(key=lambda module: module.version)

    def keep_n_latest_modules(self, modules, n=1):
        """
        Keeps n latest modules in modules sorted list
        """
        modules_to_keep = []
        versions_to_keep = sorted(set([m.version for m in modules]))[-n:]

        for module in modules:
            if module.version in versions_to_keep:
                modules_to_keep.append(module)

        modules[:] = modules_to_keep

    def sort_packages(self, packages):
        """
        Sort packages by vercmp
        """
        packages.sort()

    def get_packages_names_by_profiles(self, profiles, modules):
        """
        Gather package names by module profiles, if no profiles provided, add packages from
        all profiles

        Args:
            profiles (list of str):
                profiles ubi config
            modules (list of _pulp_client.Module):
                modules to process

        Returns:
            list of str:
                names of packages within matching modules & profiles
        """
        packages_names = []

        for module in modules:
            if profiles:
                for profile in profiles:
                    packages_names.extend(packages for packages in module.profiles.get(profile, []))
            else:
                for packages in module.profiles.values():
                    packages_names.extend(packages)

        return list(set(packages_names))

    def get_packages_from_module(self, input_modules, package_name=None):
        """
        Gathers packages from module.
        """
        ret_rpms = []
        ret_debug_rpms = []

        regex = r'\d+:'
        reg = re.compile(regex)
        for module in input_modules:
            for rpm_nevra in module.packages:
                rpm_without_epoch = reg.sub('', rpm_nevra)
                name, _, _, _, arch = split_filename(rpm_without_epoch)
                # skip source package, they are taken from pkgs metadata
                if arch == 'src':
                    continue
                if package_name and name != package_name:
                    continue
                rpm_filename = rpm_without_epoch + '.rpm'

                # Check existence of rpm in binary rpm repos
                rpms = []

                for in_repo_rpm in self.repos.in_repos.rpm:
                    res = self.pulp.search_rpms(in_repo_rpm, filename=rpm_filename)
                    if res:
                        rpms.extend(res)
                if rpms:
                    rpms[0].is_modular = True
                    ret_rpms.append(rpms[0])
                else:
                    # Check existence of rpm in debug repos
                    debug_rpms = []
                    for in_repo_debug in self.repos.in_repos.debug:
                        res = self.pulp.search_rpms(in_repo_debug, filename=rpm_filename)
                        if res:
                            debug_rpms.extend(res)

                    if debug_rpms:
                        debug_rpms[0].is_modular = True
                        ret_debug_rpms.append(debug_rpms[0])
                    else:
                        _LOG.warning("RPM %s is unavailable in input repos %s %s, skipping",
                                     rpm_filename,
                                     [r.repo_id for r in self.repos.in_repos.rpm],
                                     [r.repo_id for r in self.repos.in_repos.debug]
                                     )
        return ret_rpms, ret_debug_rpms

    def keep_n_latest_packages(self, packages, n=1):
        """
        Keep n latest non-modular packages.
        Modular packages are kept only if they are referenced by some of
        remaining modules.

        Arguments:
            packages (List[Package]): Sorted, oldest goes first

        Keyword arguments:
            n (int): Number of non-modular package versions to keep

        Returns:
            None. The packages list is changed in-place
        """

        packages_to_keep = []
        filenames_to_keep = set()  # from modular packages

        # Use a queue of n elements per arch
        pkgs_per_arch = defaultdict(lambda: deque(maxlen=n))

        # Set of package filenames from modules. Modular packages in
        # packages list are kept if referenced here.
        modular_packages_filenames = set()
        for module_name_stream, packages_in_module in self.repos.pkgs_from_modules.items():
            if module_name_stream in self.repos.modules:
                modular_packages_filenames |= set([pkg.filename for pkg in packages_in_module])

        for package in packages:
            if not package.is_modular:
                # filter non-modular pkgs per arches, there can be rpms
                # with different arches for package in one repository
                _, _, _, _, arch = split_filename(package.filename)
                pkgs_per_arch[arch].append(package)
            elif (package.filename in modular_packages_filenames
                  and package.filename not in filenames_to_keep):
                # this skips modular pkgs that are not referenced by module
                packages_to_keep.append(package)
                filenames_to_keep.add(package.filename)

        # Packages already included from modules are skipped
        latest_pkgs_per_arch = [pkg for pkg in chain.from_iterable(pkgs_per_arch.values())
                                if pkg.filename not in filenames_to_keep]

        packages[:] = latest_pkgs_per_arch + packages_to_keep
