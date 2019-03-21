import re
import logging
import ubiconfig
from more_executors import Executors
from concurrent.futures import as_completed
from collections import namedtuple, defaultdict
from ubipop._pulp import Pulp, Package
from ubipop._utils import splitFilename
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
        self.modules = defaultdict(list)
        self.pkgs_from_modules = defaultdict(list)

        self.source_rpms = []
        self.debug_rpms = []
        self._ensure_repos_existence()

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
                 ubiconfig_dir_or_url=None, insecure=False, workers_count=4):

        self.ubiconfig_list = self._load_ubiconfig(ubiconfig_filename_list,
                                                   ubiconfig_dir_or_url)
        self.pulp = Pulp(pulp_hostname, pulp_auth, insecure)
        self.dry_run = dry_run
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
        for config in self.ubiconfig_list:
            try:
                output_repo_sets = self._get_input_and_output_repo_pairs(config)
            except RepoMissing:
                _LOG.warning("Skipping current content triplet, some repos are missing")
                continue

            for repo_set in output_repo_sets:
                UbiPopulateRunner(self.pulp, repo_set, config, self.dry_run, self._executor)\
                    .run_ubi_population()

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

        output_repo_sets = []
        for input_repo in in_repos_ft.result():
            rpm = input_repo
            source = self._get_repo_counterpart(input_repo, in_source_repos_ft.result())
            debug_info = self._get_repo_counterpart(input_repo, in_debug_repos_ft.result())

            rhel_repo_set = RepoSet(rpm, source, debug_info)

            rpm = self._get_repo_counterpart(input_repo, out_repos_ft.result())
            source = self._get_repo_counterpart(input_repo, out_source_repos_ft.result())
            debug_info = self._get_repo_counterpart(input_repo, out_debug_repos_ft.result())

            ubi_repo_set = RepoSet(rpm, source, debug_info)

            output_repo_sets.append(UbiRepoSet(rhel_repo_set, ubi_repo_set))

        return output_repo_sets

    def _get_repo_counterpart(self, input_repo, repos_to_match):
        for repo in repos_to_match:
            if input_repo.arch == repo.arch and \
                    input_repo.platform_full_version == repo.platform_full_version:
                return repo


class UbiPopulateRunner(object):
    def __init__(self, pulp, output_repo_set, ubiconfig_item, dry_run, executor):
        self.pulp = pulp
        self.out_repo_set = output_repo_set
        self.ubiconfig = ubiconfig_item
        self.dry_run = dry_run
        self._executor = executor

    def _match_modules(self):
        # Add matching modules

        fts = {}
        for module in self.ubiconfig.modules:
            fts[self._executor.submit(self.pulp.search_modules,
                                      self.out_repo_set.in_repos.rpm, module.name,
                                      str(module.stream))] = \
                (module.name + str(module.stream), module.profiles)

        for ft in as_completed(fts):
            input_modules = ft.result()
            if input_modules:
                # fts[ft][0] == module.name + str(module.stream)
                # fts[ft][1] == module.profiles
                name_stream = fts[ft][0]
                profiles = fts[ft][1]
                self.out_repo_set.modules[name_stream].extend(input_modules)

                # Add packages from module profiles
                packages_names = self.get_packages_names_by_profiles(profiles, input_modules)

                for package_name in packages_names:
                    module_packages = self.get_packages_from_module(package_name, input_modules)

                    # for reference which pkgs are from modules
                    self.out_repo_set.pkgs_from_modules[name_stream].extend(module_packages)
                    self.out_repo_set.packages[package_name].extend(module_packages)

    def _match_packages(self):
        # Add matching packages from whitelist
        # Globbing package name is not possible

        fts = {}
        for package_pattern in self.ubiconfig.packages.whitelist:
            name = package_pattern.name
            arch = None if package_pattern.arch in ('*', None) else package_pattern.arch
            fts[(self._executor.submit(self.pulp.search_rpms,
                                       self.out_repo_set.in_repos.rpm, name, arch))] = name

        for ft in as_completed(fts):
            packages = ft.result()
            if packages:
                self.out_repo_set.packages[fts[ft]].extend(packages)

    def _parse_blacklist_config(self):
        packages_to_exclude = []
        for package_pattern in self.ubiconfig.packages.blacklist:
            name_to_parse = package_pattern.name
            globbing = True if '*' in name_to_parse else False
            if globbing:
                name = package_pattern.name[:-1]
            else:
                name = package_pattern.name
            arch = None if package_pattern.arch in ('*', None) else package_pattern.arch

            packages_to_exclude.append((name, globbing, arch))

        return packages_to_exclude

    def _exclude_blacklisted_packages(self):
        blacklisted = self.get_blacklisted_packages(
            chain.from_iterable(self.out_repo_set.packages.values()))

        for pkg in blacklisted:
            self.out_repo_set.packages.pop(pkg.name, None)
            self.out_repo_set.pkgs_from_modules.pop(pkg.name, None)

    def _finalize_modules_output_set(self):
        for _, modules in self.out_repo_set.modules.items():
            self.sort_modules(modules)
            self.keep_n_latest_modules(modules)

    def _finalize_rpms_output_set(self):
        for _, packages in self.out_repo_set.packages.items():
            self.sort_packages(packages)
            self.keep_n_newest_packages(packages)  # with respect to packages referenced by modules

    def _create_srpms_output_set(self):
        packages = chain.from_iterable(self.out_repo_set.packages.values())
        for package in packages:
            if package.sourcerpm_filename is None:
                name, ver, rel, _, _ = splitFilename(package.filename)
                package.sourcerpm_filename = "{n}-{v}-{r}.src.rpm".format(n=name, v=ver, r=rel)

            self.out_repo_set.source_rpms.append(Package(package.name,
                                                         package.sourcerpm_filename))

        blacklisted = self.get_blacklisted_packages(self.out_repo_set.source_rpms)
        self._diff_packages_by_filename(self.out_repo_set.source_rpms, blacklisted)

    def _create_debuginfo_output_set(self):
        """
        Creates output set for debug repo. Content is based on current rpms output set.
        """
        packages = chain.from_iterable(self.out_repo_set.packages.values())
        for package in packages:
            name, ver, rel, _, arch = splitFilename(package.filename)
            debug_pkg_filename = "{n}-debuginfo-{v}-{r}.{a}.rpm".format(n=name,
                                                                        v=ver,
                                                                        r=rel,
                                                                        a=arch)
            self.out_repo_set.debug_rpms.append(Package(name, debug_pkg_filename))

        blacklisted = self.get_blacklisted_packages(self.out_repo_set.debug_rpms)
        self._diff_packages_by_filename(self.out_repo_set.debug_rpms, blacklisted)

    def _determine_pulp_actions(self, current_modules_ft, current_rpms_ft, current_srpms_ft,
                                current_debug_rpms_ft):
        """
        Determines expected pulp actions by comparing current content of output repos and
        expected content.

        Content that needs association: unit is in expected but not in current
        Content that needs unassociation: unit is in current but not in expected
        No action: unit is in current and in expected
        """
        expected_modules = list(chain.from_iterable(self.out_repo_set.modules.values()))
        modules_assoc = self._diff_modules_by_nsvca(expected_modules, current_modules_ft.result())
        modules_unassoc = self._diff_modules_by_nsvca(current_modules_ft.result(), expected_modules)

        expected_rpms = list(chain.from_iterable(self.out_repo_set.packages.values()))
        rpms_assoc = self._diff_packages_by_filename(expected_rpms, current_rpms_ft.result())
        rpms_unassoc = self._diff_packages_by_filename(current_rpms_ft.result(), expected_rpms)

        expected_srpms = self.out_repo_set.source_rpms
        srpms_assoc = self._diff_packages_by_filename(expected_srpms, current_srpms_ft.result())
        srpms_unassoc = self._diff_packages_by_filename(current_srpms_ft.result(), expected_srpms)

        debug_rpms_assoc = None
        debug_rpms_unassoc = None
        if current_debug_rpms_ft is not None:
            expected_debug_rpms = self.out_repo_set.debug_rpms
            debug_rpms_assoc = self._diff_packages_by_filename(expected_debug_rpms,
                                                               current_debug_rpms_ft.result())
            debug_rpms_unassoc = self._diff_packages_by_filename(current_debug_rpms_ft.result(),
                                                                 expected_debug_rpms)

        assoc_units_repo_triples = ((modules_assoc,  self.out_repo_set.in_repos.rpm,
                                     self.out_repo_set.out_repos.rpm),
                                    (rpms_assoc, self.out_repo_set.in_repos.rpm,
                                     self.out_repo_set.out_repos.rpm),
                                    (srpms_assoc, self.out_repo_set.in_repos.source,
                                     self.out_repo_set.out_repos.source),
                                    (debug_rpms_assoc, self.out_repo_set.in_repos.debug,
                                     self.out_repo_set.out_repos.debug))

        unassoc_units_repo_pairs = ((modules_unassoc, self.out_repo_set.out_repos.rpm),
                                    (rpms_unassoc, self.out_repo_set.out_repos.rpm),
                                    (srpms_unassoc, self.out_repo_set.out_repos.source),
                                    (debug_rpms_unassoc, self.out_repo_set.out_repos.debug))

        return assoc_units_repo_triples, unassoc_units_repo_pairs

    def _diff_modules_by_nsvca(self, modules_1, modules_2):
        return self._diff_lists_by_attr(modules_1, modules_2, 'nsvca')

    def _diff_packages_by_filename(self, packages_1, packages_2):
        return self._diff_lists_by_attr(packages_1, packages_2, 'filename')

    def _diff_lists_by_attr(self, list_1, list_2, attr):
        attrs_list_2 = [getattr(obj, attr) for obj in list_2]
        diff = [obj for obj in list_1 if getattr(obj, attr) not in attrs_list_2]

        return diff

    def run_ubi_population(self):
        current_modules_ft, current_rpms_ft, current_srpms_ft, current_debug_rpms_ft = \
            self._get_current_content()

        self._match_modules()
        self._match_packages()
        self._exclude_blacklisted_packages()
        self._finalize_modules_output_set()
        self._finalize_rpms_output_set()
        self._create_srpms_output_set()

        if self.out_repo_set.out_repos.debug:
            self._create_debuginfo_output_set()

        associate, unassociate = self._determine_pulp_actions(current_modules_ft, current_rpms_ft,
                                                              current_srpms_ft,
                                                              current_debug_rpms_ft)

        if self.dry_run:
            self.log_curent_content(current_modules_ft, current_rpms_ft, current_srpms_ft,
                                    current_debug_rpms_ft)
            self.log_pulp_actions(associate, unassociate)
        else:
            fts = []
            fts.extend(self._associate_modules(*associate[0]))
            fts.extend(self._associate_packages(associate[1:]))

            fts.extend(self._unassociate_modules(*unassociate[0]))
            fts.extend(self._unassociate_packages(unassociate[1:]))

            # wait for associate/unassociate tasks
            for ft in as_completed(fts):
                tasks = ft.result()
                if tasks:
                    self.pulp.wait_for_tasks(tasks)

            # wait repo publication
            for ft in as_completed(self._publish_out_repos()):
                self.pulp.wait_for_tasks(ft.result())

    def log_curent_content(self, current_modules_ft, current_rpms_ft, current_srpms_ft,
                           current_debug_rpms_ft):
        _LOG.info("Current modules in repo: %s", self.out_repo_set.out_repos.rpm.repo_id)
        for module in current_modules_ft.result():
            _LOG.info(module.nsvca)
        _LOG.info(
            "Current rpms in repo: %s", self.out_repo_set.out_repos.rpm.repo_id)
        for rpm in current_rpms_ft.result():
            _LOG.info(rpm.filename)

        _LOG.info(
            "Current srpms in repo: %s", self.out_repo_set.out_repos.source.repo_id)
        for rpm in current_srpms_ft.result():
            _LOG.info(rpm.filename)

        if self.out_repo_set.out_repos.debug:
            _LOG.info(
                "Current rpms in repo: %s", self.out_repo_set.out_repos.debug.repo_id)
            for rpm in current_debug_rpms_ft.result():
                _LOG.info(rpm.filename)

    def log_pulp_actions(self, associate, unassociate):
        modules, src_repo, dst_repo = associate[0]
        for module in modules:
            _LOG.info("Would associate %s from %s to %s", module.nsvca, src_repo.repo_id,
                      dst_repo.repo_id)

        for units, src_repo, dst_repo in associate[1:]:
            if units:
                for unit in units:
                    _LOG.info("Would associate %s from %s to %s", unit.filename, src_repo.repo_id,
                              dst_repo.repo_id)

        modules, dst_repo = unassociate[0]
        for module in modules:
            _LOG.info("Would unassociate %s from %s", module.nsvca, dst_repo.repo_id)

        for units, dst_repo in unassociate[1:]:
            if units:
                for unit in units:
                    _LOG.info("Would unassociate %s from %s", unit.filename, dst_repo.repo_id)

    def _get_current_content(self):
        """
        Gather current content of output repos
        """
        current_modules_ft = self._executor.submit(self.pulp.search_modules,
                                                   self.out_repo_set.out_repos.rpm)
        current_rpms_ft = self._executor.submit(self.pulp.search_rpms,
                                                self.out_repo_set.out_repos.rpm)
        current_srpms_ft = self._executor.submit(self.pulp.search_rpms,
                                                 self.out_repo_set.out_repos.source)
        if self.out_repo_set.out_repos.debug:
            current_debug_rpms_ft = self._executor.submit(self.pulp.search_rpms,
                                                          self.out_repo_set.out_repos.debug)
        else:
            current_debug_rpms_ft = None

        return current_modules_ft, current_rpms_ft, current_srpms_ft, current_debug_rpms_ft

    def _associate_modules(self, modules, src_repo, dst_repo):
        if modules:
            return [self._executor.submit(self.pulp.associate_modules, src_repo, dst_repo, modules)]
        else:
            return []

    def _unassociate_modules(self, modules, repo):
        if modules:
            return [self._executor.submit(self.pulp.unassociate_modules, modules, repo)]
        else:
            return []

    def _associate_packages(self, associate_triple_list):
        fts = []

        for units, src_repo, dst_repo in associate_triple_list:
            if not units:
                continue
            fts.append(self._executor.submit(self.pulp.associate_rpms, units, src_repo, dst_repo))
        return fts

    def _unassociate_packages(self, unassociate_triple_list):
        fts = []
        for units, repo in unassociate_triple_list:
            if not units:
                continue
            fts.append(self._executor.submit(self.pulp.unassociate_rpms, units, repo))
        return fts

    def _publish_out_repos(self):
        fts = []
        repos_to_publish = (self.out_repo_set.out_repos.rpm,
                            self.out_repo_set.out_repos.debug,
                            self.out_repo_set.out_repos.source)

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
            modules (list of _pulp.Module):
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

    def get_packages_from_module(self, package_name, input_modules):
        """
        Gathers packages from modules by package name
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
                if name == package_name:
                    rpms.append(Package(name, rpm_without_epoch + '.rpm'))

        return rpms

    def keep_n_newest_packages(self, packages, n=1):
        """
        Keep n latest packages,
        package is deleted from output set if it's not referenced by any remaining module
        """
        packages_to_delete = packages[:-n]

        packages_to_keep = []
        for package in packages_to_delete:
            for module_name_stream, packages_ref_by_module in \
                    self.out_repo_set.pkgs_from_modules.items():
                if package.filename in [pkg.filename for pkg in packages_ref_by_module] and\
                                        module_name_stream in self.out_repo_set.modules:
                    packages_to_keep.append(package)

        packages[:] = packages[-n:] + packages_to_keep
