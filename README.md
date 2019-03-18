# **ubi-population-tool**

A python library and cli for populating ubi repositories.

The library provides convenient means how to populate ubi repositories: 
- consumes ubi config using *ubi-config* tool
- calculates expected content of ubi repositories
- determines pulp actions which will ensure expected content to be in ubi repos

# Library usage
Example of typical usage of library follows:

 
```python
from ubipop import UbiPopulate

ubi = UbiPopulate(content_sets, pulp_url, ("user", "pass"), dry_run=False)
ubi.populate_ubi_repos()
```

Required arguments are:
- **content_sets**: list of content sets that will be used for reading config
- **pulp_url**: url of pulp_server
- **tuple** of username nad password of pulp server
- **dry_run**: boolean, if True, it calculates and prints expected pulp actions, if False execute pulp actions

By calling *populate_ubi_repos()* whole process of calculation of desired content of
ubi repos and required action is started.

# Cli usage

Cli can be run by *ubi_population_cli* with arguments:

- positional arguments:
  - content_sets: list of content sets to be processed

- optional arguments:
  -  -h, --help: show this help message and exit
  -  --pulp_url PULP_URL: url of pulp_server
  - --user USER: pulp user
  -  --password PASSWORD: pulp password
  -  --dry_run: if True, print pulp actions only, do not execute
  