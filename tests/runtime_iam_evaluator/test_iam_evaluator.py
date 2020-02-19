import os
import unittest
import shutil

from src.main import configure_logger
from src.runtime_iam_evaluator.RuntimeIamEvaluator import RuntimeIamEvaluator


class TestRuntimeIamEvaluator(unittest.TestCase):

    def test_evaluator(self):
        current_dir = os.path.dirname(os.path.realpath(__file__))
        shutil.copyfile(current_dir + "/iam_data.json", current_dir + "/../../src/runtime_iam_evaluator/iam_data.json")
        logger = configure_logger()
        RuntimeIamEvaluator(logger).evaluate_runtime_iam(False)
