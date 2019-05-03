import re
import logging
import ubiconfig
from more_executors import Executors
from concurrent.futures import as_completed
from collections import namedtuple, defaultdict
from ubipop._pulp_client import Pulp, Package
from ubipop._utils import (splitFilename, AssociateActionModules,
                           AssociateActionModuleDefaults,
                           AssociateActionRpms,
                           UnassociateActionModules,
                           UnassociateActionModuleDefaults,
                           UnassociateActionRpms)
from itertools import chain

_LOG = logging.getLogger("ubipop")


class RepoMissing(Exception):
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
                 ubiconfig_dir_or_url=None, insecure=False, workers_count=4,
                 output_repos=None):

        self.ubiconfig_list = self._load_ubiconfig(ubiconfig_filename_list,
                                                   ubiconfig_dir_or_url)
        self.pulp = Pulp(pulp_hostname, pulp_auth, insecure)
        self.dry_run = dry_run
        self.output_repos = output_repos
        self._executor = Executors.thread_pool(max_workers=workers_count).with_retry()

    def _load_ubiconfig(self, filenames, ubiconfig_dir_or_url):
        loader = ubiconfig.get_loader(ubiconfig_dir_or_url)
        ubi_conf_list = []
        if filenames:
            ubi_conf_list.extend(loader.load(filename) for filename in filenames)
        else:
            ubi_conf_list.extend(loader.load_all())

        return ubi_conf_list

    def populate_ubi_repos(self):
        out_repos = set()

        for config in self.ubiconfig_list:
            try:
                repo_pairs = self._get_input_and_output_repo_pairs(config)
            except RepoMissing:
                _LOG.warning("Skipping current content triplet, some repos are missing")
                continue

            for repo_set in repo_pairs:
                UbiPopulateRunner(self.pulp, repo_set, config, self.dry_run,
                                  self._executor).run_ubi_population()

                out_repos.update(repo_set.get_output_repo_ids())

        if self.output_repos:
            with open(self.output_repos, 'w') as f:
                for repo in out_repos:
                    f.write(repo.strip() + '\n')

    def _get_input_and_output_repo_pairs(self, ubiconfig_item):
        """
        Determines pairs of input and output repos and also find correct source and debuginfo
        counterpart of repos.
        """

        rpms_cs = ubiconfig_item.content_sets.rpm
        source_cs = ubiconfig_item.content_sets.srpm
        debug_cs = ubiconfig_item.content_sets.debuginfo
        _LOG.info(
            "Getting input repos for input content sets:\n\t%s\n\t%s\n\t%s",
            rpms_cs.input, source_cs.input, debug_cs.input)

        in_repos_ft = self._executor.submit(self.pulp.search_repo_by_cs, rpms_cs.input)
        in_source_repos_ft = self._executor.submit(self.pulp.search_repo_by_cs, source_cs.input)
        in_debug_repos_ft = self._executor.submit(self.pulp.search_repo_by_cs, debug_cs.input)

        _LOG.info(
            "Getting output repos for output content sets:\n\t%s\n\t%s\n\t%s",
            rpms_cs.output, source_cs.output, debug_cs.output)

        out_repos_ft = self._executor.submit(self.pulp.search_repo_by_cs, rpms_cs.output)
        out_source_repos_ft = self._executor.submit(self.pulp.search_repo_by_cs, source_cs.output)
        out_debug_repos_ft = self._executor.submit(self.pulp.search_repo_by_cs, debug_cs.output)

        repo_pairs = []
        for input_repo in in_repos_ft.result():
            rpm = input_repo
            source = self._get_repo_counterpart(input_repo, in_source_repos_ft.result())
            debug_info = self._get_repo_counterpart(input_repo, in_debug_repos_ft.result())

            rhel_repo_set = RepoSet(rpm, source, debug_info)

            rpm = self._get_repo_counterpart(input_repo, out_repos_ft.result())
            source = self._get_repo_counterpart(input_repo, out_source_repos_ft.result())
            debug_info = self._get_repo_counterpart(input_repo, out_debug_repos_ft.result())

            ubi_repo_set = RepoSet(rpm, source, debug_info)

            repo_pairs.append(UbiRepoSet(rhel_repo_set, ubi_repo_set))

        return repo_pairs

    def _get_repo_counterpart(self, input_repo, repos_to_match):
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
            fts[self._executor.submit(self.pulp.search_modules,
                                      self.repos.in_repos.rpm, module.name,
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
                        # for reference which pkgs are from modules
                        self.repos.pkgs_from_modules[name_stream].extend(module_packages)
                        self.repos.packages[package_name].extend(module_packages)
                else:
                    # Include every package from module artifacts.
                    module_packages = self.get_packages_from_module(input_modules)
                    self.repos.pkgs_from_modules[name_stream].extend(module_packages)
                    for package in module_packages:
                        self.repos.packages[package.name].append(package)

    def _match_module_defaults(self):
        """Try to find modulemd_defaults units in the same repo with the same
        name/stream of a modulemd.
        """
        fts = {}
        for _, modules in self.repos.modules.items():
            for md in modules:
                fts[self._executor.submit(self.pulp.search_module_defaults,
                                          self.repos.in_repos.rpm, md.name,
                                          str(md.stream))] = md.name + str(md.stream)
        for ft in as_completed(fts):
            module_defaults = ft.result()
            if module_defaults:
                self.repos.module_defaults[fts[ft]].extend(module_defaults)

    def _match_packages(self, repo, packages_dict):
        """
        Add matching packages from whitelist
        Globbing package name is not supported
        """
        fts = {}
        for package_pattern in self.ubiconfig.packages.whitelist:
            name = package_pattern.name
            arch = None if package_pattern.arch in ('*', None) else package_pattern.arch
            fts[(self._executor.submit(self.pulp.search_rpms,
                                       repo, name, arch))] = name

        for ft in as_completed(fts):
            packages = ft.result()
            if packages:
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

            self.repos.source_rpms[package.name].append(Package(package.name,
                                                                package.sourcerpm_filename))

        blacklisted_srpms = self.get_blacklisted_packages(
            list(chain.from_iterable(self.repos.source_rpms.values())))

        for pkg in blacklisted_srpms:
            self.repos.source_rpms.pop(pkg.name, None)

    def _determine_pulp_actions(self, units, current, diff_f):
        expected = list(chain.from_iterable(units.values()))
        to_associate = diff_f(expected, current)
        to_unassociate = diff_f(current, expected)
        return to_associate, to_unassociate

    def _get_pulp_actions_mds(self, modules, current):
        return self._determine_pulp_actions(modules, current, self._diff_modules_by_nsvca)

    def _get_pulp_actions_md_defaults(self, module_defaults, current):
        return self._determine_pulp_actions(module_defaults, current,
            self._diff_md_defaults_by_profiles)

    def _get_pulp_actions_pkgs(self, pkgs, current):
        return self._determine_pulp_actions(pkgs, current, self._diff_packages_by_filename)

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
        srpms_assoc, srpms_unassoc = self._get_pulp_actions_pkgs(self.repos.source_rpms,
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
                fts.append(self._executor.submit(*action.get_action(self.pulp)))

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
                    _LOG.info("Would associate %s from %s to %s", unit, item.src_repo.repo_id,
                              item.dst_repo.repo_id)

            else:
                _LOG.info("No association expected for %s from %s to %s", item.TYPE,
                          item.src_repo.repo_id,
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
                name, _, _, _, arch = splitFilename(package.filename)
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
        modules[:] = modules[-n:]

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

        return packages_names

    def get_packages_from_module(self, input_modules, package_name=None):
        """
        Gathers packages from module.
        """
        rpms = []
        regex = r'\d+:'
        reg = re.compile(regex)
        for module in input_modules:
            for rpm_nevra in module.packages:
                rpm_without_epoch = reg.sub('', rpm_nevra)
                name, _, _, _, arch = splitFilename(rpm_without_epoch)
                # skip source package, they are calculated in later stage
                if arch == 'src':
                    continue
                if package_name and name != package_name:
                    continue

                rpms.append(Package(name, rpm_without_epoch + '.rpm', is_modular=True))

        return rpms

    def keep_n_latest_packages(self, packages, n=1):
        """
        Keep n latest non-modular packages,
        modular packages are kept only if they are referenced by some of remaining modules
        Parameter packages: sorted list of Packages objects, oldest goes first
        """
        packages_to_keep = []
        non_modular_pkgs = []
        for package in packages:
            if package.is_modular:
                for module_name_stream, packages_ref_by_module in \
                        self.repos.pkgs_from_modules.items():
                    pkgs_filenames_from_modules = [pkg.filename for pkg in packages_ref_by_module]
                    if package.filename in pkgs_filenames_from_modules \
                            and module_name_stream in self.repos.modules:
                        # this skips modular pkgs that are not referenced by module
                        packages_to_keep.append(package)
            else:
                non_modular_pkgs.append(package)

        # filter non-modular pkgs per arches, there can be rpms with different arches
        # for package in one repository
        pkgs_per_arch = defaultdict(list)
        for pkg in non_modular_pkgs:
            _, _, _, _, arch = splitFilename(pkg.filename)
            pkgs_per_arch[arch].append(pkg)

        latest_pkgs_per_arch = []
        for pkgs in pkgs_per_arch.values():
            latest_pkgs_per_arch += pkgs[-n:]

        packages[:] = latest_pkgs_per_arch + packages_to_keep
