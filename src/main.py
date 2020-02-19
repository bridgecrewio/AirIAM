import logging
import argparse

from src.version import version
from src.runtime_iam_evaluator.RuntimeIamEvaluator import RuntimeIamEvaluator


def configure_logger():
    logging.basicConfig(level=logging.INFO)
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
    parser.add_argument('-v', '--version', help='Get AirIAM\'s version')
    parser.add_argument('-p', '--profile', help='The AWS profile to be used', default=None)
    parser.add_argument('-r', '--refresh', help='Do not use local data, get fresh data from AWS API', action='store_true')
    parser.add_argument('-t', '--threshold', help='The unused threshold, in days', default=None)

    args = parser.parse_args()
    if args.version:
        logging.info('AirIAM v{}'.format(version))
        return

    RuntimeIamEvaluator(logger, args.profile).evaluate_runtime_iam(args.refresh)
