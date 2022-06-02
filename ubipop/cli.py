import argparse
import logging
import sys

import ubipop

DEFAULT_LOG_FMT = "%(asctime)s [%(levelname)-8s] %(message)s"
DEFAULT_DATE_FMT = "%Y-%m-%d %H:%M:%S %z"

_LOG = logging.getLogger("ubipop")
_LOG.setLevel(logging.DEBUG)


def parse_args(args):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "input", action="store", nargs="*", help="path to ubi config file"
    )
    parser.add_argument(
        "--content-sets",
        action="store",
        nargs="+",
        type=str,
        required=False,
        help="content set labels from which to source ubi config",
    )
    parser.add_argument(
        "--repo-ids",
        action="store",
        nargs="+",
        type=str,
        required=False,
        help="repo IDs from which to source ubi config",
    )
    parser.add_argument(
        "--conf-src",
        action="store",
        required=False,
        help="source of ubi config, directory or url",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="if True, print pulp actions",
    )
    parser.add_argument(
        "--pulp-hostname", action="store", required=True, help="hostname of pulp_server"
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        default=False,
        help="use insecure connection to pulp server",
    )
    parser.add_argument("--user", action="store", required=False, help="pulp user")
    parser.add_argument(
        "--password", action="store", required=False, help="pulp password"
    )
    parser.add_argument(
        "--cert", action="store", required=False, help="path to to user cert"
    )
    parser.add_argument(
        "--workers",
        action="store",
        type=int,
        default=4,
        help="Number of workers for parallel execution",
    )
    parser.add_argument(
        "--output-repos",
        action="store",
        required=False,
        help="Path to output file."
        "If provided, file containing repo ids of all out repos is created.",
    )
    parser.add_argument(
        "--version",
        action="store",
        required=False,
        help="Major version of ubi content set to be populated.",
    )
    parser.add_argument(
        "--content-set-regex",
        action="store",
        required=False,
        help="Regular expression of ubi content set to be populated.",
    )
    parser.add_argument(
        "--ubi-manifest-url",
        action="store",
        required=False,  # TODO change to True, when we move to ubi-manifest approach only, without fallback to legacy code path
        help="URL of ubi-manifest service",
    )

    parsed = parser.parse_args(args)

    auth_err_msg = "Provide --user and --password options or --cert"
    if all((parsed.user, parsed.password, parsed.cert)):
        parser.error(auth_err_msg)

    auth = None
    if parsed.user and parsed.password:
        auth = (parsed.user, parsed.password)
    elif parsed.user and not parsed.password or not parsed.user and parsed.password:
        parser.error(auth_err_msg)
    elif parsed.cert:
        auth = (parsed.cert,)
    else:
        parser.error(auth_err_msg)

    return parser.parse_args(args), auth


def main(args):
    logging.basicConfig(format=DEFAULT_LOG_FMT, datefmt=DEFAULT_DATE_FMT)
    logging.getLogger("pubtools.pulplib").setLevel(logging.INFO)
    opts, auth = parse_args(args)

    ubipop.UbiPopulate(
        opts.pulp_hostname,
        auth,
        opts.dry_run,
        opts.input,
        opts.conf_src,
        opts.insecure,
        opts.workers,
        opts.output_repos,
        content_sets=opts.content_sets,
        repo_ids=opts.repo_ids,
        version=opts.version,
        content_set_regex=opts.content_set_regex,
        ubi_manifest_url=opts.ubi_manifest_url,
    ).populate_ubi_repos()


def entry_point():
    main(sys.argv[1:])


if __name__ == "__main__":
    entry_point()
