import attr


@attr.s
class UbiManifest(object):
    repo_id = attr.ib()
    manifest = attr.ib()

    @classmethod
    def from_data(cls, data):
        repo_id = data["repo_id"]
        items = []
        for item in data["content"]:
            new_item = cls.make_ubi_unit(item, repo_id)
            if new_item:
                items.append(new_item)

        return cls(repo_id=repo_id, manifest=items)

    @staticmethod
    def make_ubi_unit(manifest_item, dst_repo_id):
        out = None

        unit_type = manifest_item["unit_type"]
        src_repo_id = manifest_item["src_repo_id"]
        value = manifest_item["value"]

        if unit_type == "RpmUnit":
            out = RpmUnit(src_repo_id, dst_repo_id, value)
        elif unit_type == "ModulemdUnit":
            out = ModulemdUnit.from_nsvca(value, src_repo_id, dst_repo_id)
        elif unit_type == "ModulemdDefaultsUnit":
            out = ModulemdDefaultsUnit.from_ns(value, src_repo_id, dst_repo_id)
        else:
            # unknown unit
            pass

        return out

    @property
    def packages(self):
        return self._filter_units_by_class(RpmUnit)

    @property
    def modules(self):
        return self._filter_units_by_class(ModulemdUnit)

    @property
    def modulemd_defaults(self):
        return self._filter_units_by_class(ModulemdDefaultsUnit)

    def _filter_units_by_class(self, klass):
        return [unit for unit in self.manifest if isinstance(unit, klass)]


@attr.s
class UbiCompatibleUnit(object):
    src_repo_id = attr.ib()
    dst_repo_id = attr.ib()

    @property
    def associate_source_repo_id(self):
        return self.src_repo_id


@attr.s
class RpmUnit(UbiCompatibleUnit):
    filename = attr.ib()


@attr.s
class ModulemdUnit(UbiCompatibleUnit):
    name = attr.ib()
    stream = attr.ib()
    version = attr.ib()
    context = attr.ib()
    arch = attr.ib()

    @classmethod
    def from_nsvca(cls, nsvca, src_repo_id, dst_repo_id):
        n, s, v, c, a = nsvca.split(":")
        return cls(
            name=n,
            stream=s,
            version=int(v),
            context=c,
            arch=a,
            src_repo_id=src_repo_id,
            dst_repo_id=dst_repo_id,
        )

    @property
    def nsvca(self):
        return ":".join(
            (self.name, self.stream, str(self.version), self.context, self.arch)
        )


@attr.s
class ModulemdDefaultsUnit(UbiCompatibleUnit):
    name = attr.ib()
    stream = attr.ib()

    @classmethod
    def from_ns(cls, ns, src_repo_id, dst_repo_id):
        n, s = ns.split(":")

        return cls(name=n, stream=s, src_repo_id=src_repo_id, dst_repo_id=dst_repo_id)
