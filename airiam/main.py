import argparse
import logging

from airiam.runtime_iam_evaluator.RuntimeIamEvaluator import RuntimeIamEvaluator
from airiam.terraformer.TerraformTransformer import TerraformTransformer
from airiam.version import version
from airiam.Reporter import Reporter


def configure_logger():
    logging.basicConfig(level=logging.ERROR)
    # define a Handler which writes INFO messages or higher to the sys.stderr
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    # set a format which is simpler for console use
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    # tell the handler to use this format
    console.setFormatter(formatter)
    return logging


def run():
    logger = configure_logger()
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', help='Get AirIAM\'s version', action='store_true')
    parser.add_argument('-r', '--refresh', help='Do not use local data, get fresh data from AWS API', action='store_true')
    parser.add_argument('-p', '--profile', help='The AWS profile to be used', type=str)
    parser.add_argument('-t', '--threshold', help='The unused threshold, in days', type=int, default=90)

    Reporter.print_art()
    args = parser.parse_args()
    if args.version:
        logging.info('AirIAM v{}'.format(version))
        return

    runtime_results = RuntimeIamEvaluator(logger, args.profile).evaluate_runtime_iam(args.refresh, args.threshold)

    Reporter.report_runtime(runtime_results)

    terraform_results = TerraformTransformer(logger, args.profile).transform(runtime_results)
    if not terraform_results.get('Success', False):
        logger.error("Failed to create the terraform module")
        exit(1)

    Reporter.report_terraform(terraform_results)
