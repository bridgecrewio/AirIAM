import os
import unittest
import json

from airiam.main import configure_logger
from airiam.runtime_iam_evaluator.UserOrganizer import UserOrganizer


class TestUserOrganizer(unittest.TestCase):
    def test_user_organizer(self):
        current_dir = os.path.abspath(os.path.dirname(__file__))
        with open("{}/{}".format(current_dir, "../iam_data.json")) as f:
            iam_data = json.loads(json.load(f))
        logger = configure_logger()
        clusters = UserOrganizer(logger).get_user_clusters(iam_data)
        self.assertEqual(len(clusters.keys()), 26)
        self.assertTrue('arn:aws:iam::aws:policy/AdministratorAccess' in clusters.keys())
        self.assertEqual(len(clusters['arn:aws:iam::aws:policy/AdministratorAccess'].split(', ')), 6)
