import argparse
import logging
import sys

from airiam.Reporter import Reporter, OutputFormat
from airiam.find_unused.find_unused import find_unused
from airiam.recommend_groups.recommend_groups import recommend_groups
from airiam.terraform.TerraformTransformer import TerraformTransformer


def configure_logger(logging_level=logging.INFO):
    logging.basicConfig(level=logging_level)
    # define a Handler which writes INFO messages or higher to the sys.stderr
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    # set a format which is simpler for console use
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    # tell the handler to use this format
    console.setFormatter(formatter)
    return logging


def run():
    logger = configure_logger()

    Reporter.print_prelude()
    args = parse_args(sys.argv[1:])

    runtime_results = find_unused(logger, args.profile, args.no_cache, args.last_used_threshold, args.command)

    if args.command == 'find_unused':
        Reporter.report_unused(runtime_results)
        exit()

    if args.command == 'recommend_groups' or args.command == 'terraform' and not args.without_groups:
        report_with_recommendations = recommend_groups(logger, runtime_results, args.last_used_threshold)
        if args.command == 'recommend_groups':
            Reporter.report_groupings(report_with_recommendations)
            exit()

    if args.command == 'terraform':
        entities_terraformed, result_dir = TerraformTransformer(logger, args.profile, args.directory)\
            .transform(runtime_results, args.without_unused, args.without_groups, args.without_import)
        Reporter.report_terraform(entities_terraformed, result_dir)


def parse_args(args):
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-v', '--version', help='Get AirIAM\'s version', action='store_true')

    sub_parsers = parser.add_subparsers(title='commands', dest='command')
    find_unused_parser = sub_parsers.add_parser('find_unused', help='Scan your runtime IAM for unused entities',
                                                formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    find_unused_parser.add_argument('-p', '--profile', help='AWS profile to be used', type=str, default=None)
    find_unused_parser.add_argument('-l', '--last-used-threshold', help='"Last Used" threshold, in days, for an entity to be considered unused',
                                    type=int, default=90)
    find_unused_parser.add_argument('--no-cache', help='Generate a fresh set of data from AWS IAM API calls', action='store_true')
    find_unused_parser.add_argument('-o', '--output', help='Output format', type=OutputFormat,
                                    choices=[output.name for output in OutputFormat], default=OutputFormat.cli)

    recommend_groups_parser = sub_parsers.add_parser('recommend_groups', help='Recommend IAM groups according to IAM users and their in-use privileges',
                                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    recommend_groups_parser.add_argument('-p', '--profile', help='AWS profile to be used', type=str, default=None)
    recommend_groups_parser.add_argument('-o', '--output', help='Output format', type=OutputFormat,
                                         choices=[output.name for output in OutputFormat], default=OutputFormat.cli)
    recommend_groups_parser.add_argument('-l', '--last-used-threshold', type=int, default=90,
                                         help='"Last Used" threshold, in days, for an entity to be considered unused')
    recommend_groups_parser.add_argument('--no-cache', help='Generate a fresh set of data from AWS IAM API calls', action='store_true')

    tf_parser = sub_parsers.add_parser('terraform', help='Terraformize your runtime AWS IAM configurations',
                                       formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    tf_parser.add_argument('-p', '--profile', help='AWS profile to be used', type=str)
    tf_parser.add_argument('-d', '--directory', help='Path where the output terraform code and state will be stored', type=str, default='results')
    tf_parser.add_argument('--without-unused', help='Create terraform code without unused entities', action='store_true')
    tf_parser.add_argument('--without-groups', help='Create terraform code without recommendation for user groups', action='store_true')
    tf_parser.add_argument('-l', '--last-used-threshold', help='"Last Used" threshold, in days, for an entity to be considered unused', type=int,
                           default=90)
    tf_parser.add_argument('--no-cache', help='Generate a fresh set of data from AWS IAM API calls', action='store_true')
    tf_parser.add_argument('--without-import', help='Import the resulting entities to terraform\'s state file. Note - this might take a long time',
                           action='store_true')
    result = parser.parse_args(args)
    if result.version:
        Reporter.print_version()
        exit(0)
    if not result.command:
        parser.print_help(sys.stderr)
        sys.exit(1)

    return result
