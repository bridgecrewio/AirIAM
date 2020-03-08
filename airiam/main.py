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
    parser.add_argument('-r', '--rightsize', help='Rightsize IAM permissions according to Access Advisor usage data', action='store_true')
    parser.add_argument('-p', '--profile', help='The AWS profile to be used', type=str)
    parser.add_argument('-u', '--unused', help='The unused threshold, in days', type=int, default=90)
    parser.add_argument('-f', '--folder', help='The path where the output terraform code and state will be stored', type=str, default=None)

    Reporter.print_art()
    args = parser.parse_args()
    if args.version:
        logging.info('AirIAM v{}'.format(version))
        return

    runtime_results = RuntimeIamEvaluator(logger, args.profile).evaluate_runtime_iam(args.rightsize, args.unused)

    Reporter.report_runtime(args.rightsize, runtime_results)

    terraform_results = TerraformTransformer(logger, args.profile).transform(runtime_results)
    if not terraform_results.get('Success', False):
        logger.error("Failed to create the terraform module")
        exit(1)

    Reporter.report_terraform(terraform_results)
