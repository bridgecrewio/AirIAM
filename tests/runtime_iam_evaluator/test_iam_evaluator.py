import os
import unittest
import shutil

from airiam.main import configure_logger
from airiam.runtime_iam_evaluator.RuntimeIamEvaluator import RuntimeIamEvaluator


class TestRuntimeIamEvaluator(unittest.TestCase):

    def test_evaluator(self):
        current_dir = os.path.abspath(os.path.dirname(__file__))
        evaluator_dir = current_dir[:current_dir.index("tests")] + 'airiam/runtime_iam_evaluator'
        shutil.copyfile(current_dir + "/iam_data.json", evaluator_dir + "/iam_data.json")
        logger = configure_logger()
        RuntimeIamEvaluator(logger).evaluate_runtime_iam(False)
        self.assertTrue(os.path.exists('user_clusters.csv'))


if __name__ == '__main__':
    unittest.main()
