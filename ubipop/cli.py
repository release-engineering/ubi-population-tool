import argparse
import logging
import re
import sys

from functools import partial

import ubipop

DEFAULT_LOG_FMT = "%(asctime)s [%(levelname)-8s] %(message)s"
DEFAULT_DATE_FMT = "%Y-%m-%d %H:%M:%S %z"

FOREIGN_LOGGERS = ("pubtools.pulplib", "fastpurge", "ubiconfig")
_LOG = logging.getLogger("ubipop")
_LOG.setLevel(logging.DEBUG)


URL_REGEX = r"""^(?:[a-z]+:\/\/)?  # optional scheme
                (?:[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b)?  # optional main part
                (?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)$"""
FILE_PATH_REGEX = r"^[^\x00]+$"  # allow all chars but null byte
PULP_HOSTNAME_REGEX = r"^[A-Za-z0-9_\-\.]{1,200}$"
CONTENT_SET_REGEX = r"^[A-Za-z0-9_\-\.]{1,200}$"
VERSION_REGEX = r"^[0-9]+(\.[0-9]+)?$"
REPO_REGEX = r"^[A-Za-z0-9_\-\.]{1,200}$"
USERNAME_REGEX = r"^\S+$"  # allow all non-white chars
PASSWORD_REGEX = r"^[^\x00]+$"  # allow all chars but null byte


def parse_args(args):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "input",
        action="store",
        nargs="*",
        type=file_path_str,
        help="path to ubi config file",
    )
    parser.add_argument(
        "--content-sets",
        action="store",
        nargs="+",
        type=content_set_str,
        required=False,
        help="content set labels from which to source ubi config",
    )
    parser.add_argument(
        "--repo-ids",
        action="store",
        nargs="+",
        type=repo_str,
        required=False,
        help="repo IDs from which to source ubi config",
    )
    parser.add_argument(
        "--conf-src",
        action="store",
        type=dir_or_url_str,
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
        "--pulp-hostname",
        action="store",
        type=pulp_hostname_str,
        required=True,
        help="hostname of pulp_server",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        default=False,
        help="use insecure connection to pulp server",
    )
    parser.add_argument(
        "--user", action="store", type=username_str, required=False, help="pulp user"
    )
    parser.add_argument(
        "--password",
        action="store",
        type=password_str,
        required=False,
        help="pulp password",
    )
    parser.add_argument(
        "--cert",
        action="store",
        type=file_path_str,
        required=False,
        help="path to to user cert for pulp authentication",
    )
    parser.add_argument(
        "--key",
        action="store",
        type=file_path_str,
        required=False,
        help="path to to user key for pulp authentication",
    )
    parser.add_argument(
        "--workers",
        action="store",
        type=positive_int,
        default=4,
        help="Number of workers for parallel execution",
    )
    parser.add_argument(
        "--output-repos",
        action="store",
        type=file_path_str,
        required=False,
        help="Path to output file."
        "If provided, file containing repo ids of all out repos is created.",
    )
    parser.add_argument(
        "--version",
        action="store",
        type=version_str,
        required=False,
        help="Major version of ubi content set to be populated.",
    )
    parser.add_argument(
        "--content-set-regex",
        action="store",
        type=compilable_regex,
        required=False,
        help="Regular expression of ubi content set to be populated.",
    )
    parser.add_argument(
        "--ubi-manifest-url",
        action="store",
        type=url_str,
        required=True,
        help="URL of ubi-manifest service",
    )

    parsed = parser.parse_args(args)

    auth_err_msg = "Provide --user and --password options or --cert and --key"
    if all((parsed.user, parsed.password, parsed.cert, parsed.key)):
        parser.error(auth_err_msg)

    auth = (None, None)
    if parsed.user and parsed.password:
        auth = (parsed.user, parsed.password)
    elif parsed.cert and parsed.key:
        auth = (parsed.cert, parsed.key)

    if not all(auth):
        parser.error(auth_err_msg)

    return parsed, auth


def compilable_regex(value):
    try:
        re.compile(value)
        return value
    except re.error as e:
        raise argparse.ArgumentTypeError(
            f"Value '{value}' could not be compiled into a regex.\nError: {e.msg}"
        )


def dir_or_url_str(value):
    value = str(value)
    if value.lower().startswith(("http://", "https://")):
        regex = URL_REGEX
    else:
        regex = FILE_PATH_REGEX
    if not re.match(regex, value, re.VERBOSE):
        raise argparse.ArgumentTypeError(
            f"Value '{value}' doesn't match regular expression '{regex}'."
        )
    return value


def positive_int(value):
    value = int(value)
    if value < 1:
        raise argparse.ArgumentTypeError("Number of workers must be positive.")
    return value


def str_match_regex(regex, value):
    """
    Checks if the value is a string matching the given regular expression.
    Returns str or raises ArgumentTypeError
    """
    value = str(value)
    if not re.match(regex, value, re.VERBOSE):
        raise argparse.ArgumentTypeError(
            f"Value '{value}' doesn't match regular expression '{regex}'."
        )
    return value


def main(args):
    logging.basicConfig(format=DEFAULT_LOG_FMT, datefmt=DEFAULT_DATE_FMT)
    for logger in FOREIGN_LOGGERS:
        logging.getLogger(logger).setLevel(logging.INFO)

    opts, auth = parse_args(args)

    ubipop.UbiPopulate(
        opts.pulp_hostname,
        auth,
        opts.dry_run,
        opts.input,
        opts.conf_src,
        not opts.insecure,
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


file_path_str = partial(str_match_regex, FILE_PATH_REGEX)
username_str = partial(str_match_regex, USERNAME_REGEX)
url_str = partial(str_match_regex, URL_REGEX)
repo_str = partial(str_match_regex, REPO_REGEX)
version_str = partial(str_match_regex, VERSION_REGEX)
content_set_str = partial(str_match_regex, CONTENT_SET_REGEX)
password_str = partial(str_match_regex, PASSWORD_REGEX)
pulp_hostname_str = partial(str_match_regex, PULP_HOSTNAME_REGEX)


if __name__ == "__main__":
    entry_point()
