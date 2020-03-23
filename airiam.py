import argparse
import logging

from Reporter import Reporter
from runtime_iam_evaluator.RuntimeIamEvaluator import RuntimeIamEvaluator
from terraformer.TerraformTransformer import TerraformTransformer


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
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', help='Get AirIAM\'s version', action='store_true')
    parser.add_argument('-r', '--rightsize', help='Rightsize IAM permissions according to Access Advisor usage data', action='store_true')
    parser.add_argument('-p', '--profile', help='The AWS profile to be used', type=str)
    parser.add_argument('-u', '--unused', help='The unused threshold, in days', type=int, default=90)
    parser.add_argument('-f', '--folder', help='The path where the output terraform code and state will be stored', type=str, default='results')

    Reporter.print_prelude()
    args = parser.parse_args()
    if args.version:
        Reporter.print_version()
        exit(0)

    runtime_results = RuntimeIamEvaluator(logger, args.profile).evaluate_runtime_iam(args.rightsize, args.unused)

    Reporter.report_runtime(args.rightsize, runtime_results)

    terraform_results = TerraformTransformer(logger, args.profile, args.folder).transform(args.rightsize, runtime_results)
    if terraform_results != 'Success':
        logger.error("Failed to create the terraform module")
        exit(1)

    Reporter.report_terraform(terraform_results)


if __name__ == '__main__':
    run()
