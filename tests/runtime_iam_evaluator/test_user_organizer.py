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
        unused_threshold = 90 + UserOrganizer.days_from_today('2020-02-17T11:41:00+00:00')
        logger = configure_logger()
        user_clusters, unused_users, service_users, human_users = UserOrganizer(logger, unused_threshold).get_user_clusters(iam_data)
        self.assertEqual(len(user_clusters.keys()), 26)
        self.assertTrue('arn:aws:iam::aws:policy/AdministratorAccess' in user_clusters.keys())
        self.assertEqual(len(user_clusters['arn:aws:iam::aws:policy/AdministratorAccess'].split(', ')), 6)
